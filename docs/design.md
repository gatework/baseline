# baseline 设计

## 问题

现网是异构多厂商组网：同一台账里有 H3C 交换机与无线控制器、Cisco NX-OS 数据中心交换机、IOS/Centec、Hillstone 与 Palo Alto 防火墙、Radware 负载均衡。基线要求本身是厂商无关的（"管理登录先走 TACACS+ 且保留本地兜底""NTP 主用 A、备用 B""关闭 Telnet"），但每个厂商的写法、默认值和能力都不同；有的厂商根本没有 802.1X 或 VTY 的概念；不同地区、站点、角色的期望值也不同（802.1X 认证域按地区：sha/ckg/szx）。

纯文本正则基线（"必须包含/不得包含"）在这里会失效：同一要求要为每个厂商各写一遍，次序、默认值、引用关系（VTY → 方法列表 → 服务器组 → 服务器）无法表达，厂商不支持与"违规"无法区分。

## 方案：语义模型 + 文本规则双层

```
备份目录 ─▶ 清单分类（主机名 → region/site/role）
         ─▶ Extractor[厂商] ─▶ Posture + Coverage（每维度 complete/partial/unsupported）
策略 YAML ─▶ Resolve(设备) ─▶ assess.Policy（变量已展开）
                         ─▶ assess.Engine[*Posture]：语义检查 + 厂商文本规则
                         ─▶ 豁免标注 ─▶ 报告 / 合规矩阵
全量 Posture ─▶ survey：分布 + 共识 ─▶ 草案策略
```

1. **语义层（主体）**：每个厂商一个 `Extractor`，把配置解码成 `baseline.Posture`。检查只读 Posture，所以"NTP 服务器须为 A>B"只写一次，覆盖所有厂商。提取器负责厂商默认值（H3C 未写 `ssh server enable` 即关闭；NX-OS 未写 `no feature ssh` 即开启），检查不关心。
2. **文本层（补充）**：厂商特有、没有语义对应的最佳实践（H3C `password-recovery enable`、NX-OS `no password strength-check`）用 netops `baseline.Rule` 的 require/forbid 正则表达，嵌在 `vendors/<厂商>/rules.yml`，用户可在策略 `text_rules` 追加。文本规则依赖 `dialect.<厂商>` 维度，因此只在该厂商设备上运行，其他厂商报"不支持"。

两层都落成 `assess.Rule[*Posture]`，共用一个引擎、一套策略、一份报告。

## 模型要点

- **有序服务器**：`Server{Host, Port, VRF, Source, Rank, Function, Keyed, Line}`。`Rank` 区分显式 primary/secondary（H3C hwtacacs、PAN-OS、Alteon）与按配置次序（NX-OS aaa group、H3C NTP/loghost）；`baseline.Ordered`/`Hosts` 给出有效次序。比较方式 `strict|primary|any` 借鉴 Nautobot Golden Config 的 `config_ordered`。
- **AAA 引用链**：`Line.MethodSet` → `AAA.Sets`（H3C ISP 域 / Cisco method list）→ `MethodList`（group/local/none）→ `AAA.Groups` → `Server`。检查沿引用链求"管理登录实际用哪组服务器"。
- **可用性**：`Line.Usable()` 区分实际可登录的线路（H3C 未设密码的 password 线路、VTY 不允许任何协议时不可登录），避免对无效线路误报；`Account.CanLogin()` 同理。
- **秘密**：密钥只记 `Keyed`，团体名是 `secret.Secret`。

## 覆盖度：不支持 ≠ 违规

每个提取器声明自己支持的维度。netops `assess.Engine` 在规则 `Requires` 的维度不完整时跳过规则并记 `insufficient_evidence`；报告把它呈现为"不支持"。提取器遇到属于某维度却无法解析的语句，把该维度降为 partial（依赖它的检查同样跳过），并记录只含前导关键字的 Issue，`coverage` 命令按次数聚合，指导补全提取器。

## 策略：分层、变量、例外

- **层**：`default` → 角色 → 地区 → 站点……任意层次，按声明顺序叠加；`scope`/`except` 复用 netops `device.Selector`，并支持 `region=`。
- **启停与参数**：`enable`/`disable` glob 批量启停；`checks` 精确设置严重级与参数，后层逐个参数覆盖。
- **变量**：`${region}` 等设备变量与 `vars` 查表在解析期展开，列表变量可整体替换或拼接进列表。
- **三种"不检查"**：disabled（策略关闭）、unsupported（厂商不支持）、waived（检查执行但被豁免，带原因/责任人/到期日，到期失效）。借鉴 Cisco Catalyst Center 的 Acknowledge 与 STIG POA&M：豁免不删除结果，只改变状态，保证可审计。
- 每种不同的有效策略只构建一次引擎并缓存。

## 自举

`survey` 对全量 Posture 的可参数化设置（NTP、syslog、AAA 服务器、Trap 接收者、时区、802.1X 域、源接口）按全局、地区、站点统计分布，用 netops `drift.Consensus` 按 quorum 求共识；没有该设置的设备也计入分母，避免"335 台中 1 台配置即 100% 共识"。草案策略：全局共识进 default 层；与上级不同的地区/站点共识生成对应层；各地区共识恰为地区名时生成 `${region}`。源接口因站点与厂商而异，只统计不起草。离群设备即整改或豁免候选。

## 商用产品借鉴

| 产品 | 机制 | 本模块 |
|---|---|---|
| SolarWinds NCM、ManageEngine NCM | 策略报告→策略→规则；规则为必须/不得包含的字符串、正则、配置块；按设备类型筛选；修复脚本 | 文本层 `rules.yml` 与 `text_rules`；`Remediation` 建议 |
| Nautobot Golden Config | 每平台的 feature 规则、`config_ordered`、intended vs actual 合规矩阵 | `order` 参数；`check -f matrix` |
| Batfish | 多厂商配置解析成厂商无关模型后提问 | `Extractor` → `Posture`，检查只读模型 |
| Cisco Catalyst Center | 合规分类；违规 Acknowledge | 检查类别；带到期日的 waiver |
| DISA STIG、CIS Benchmark | 规则 ID、严重级、检查/修复文本、例外流程 | `assess.Meta`、`messages.go`、waiver |
| H3C iMC / U-Center 配置基线 | 基线模板 + 设备分组 + 例外设备 | 分层 `layers` + 选择器 + `except` |

差异：上述产品多以文本规则为主、按平台复制规则；本模块以语义模型为主，规则写一次覆盖所有厂商，文本规则只做补充；并把"现网共识"作为基线来源（自举），而不是从空白模板开始。

## 扩展

- **新厂商**：在 `vendors/<名称>` 实现 `baseline.Extractor`（声明支持的维度、填厂商默认值、遮蔽敏感字段），在 `vendors/registry.go` 登记别名与内容识别，加合成样例测试与 `FuzzExtract`。
- **新检查**：在 `check` 对应领域文件加 `assess.Rule`，声明 `Requires` 维度与类型化参数，文案进 `messages.go`。
- **新数据源**：实现 `workflow.Source`（如经 net-connector 在线拉取 running-config），在 `internal/bootstrap` 组装。

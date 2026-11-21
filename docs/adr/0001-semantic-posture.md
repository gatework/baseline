# ADR 0001：以厂商无关的管理面模型做基线检查，文本规则只作补充

- 状态：已接受（2026-11-20）

## 背景

现网 981 台设备覆盖 6 类配置语法。基线要求厂商无关，但写法、默认值与能力各异；部分厂商没有 802.1X、VTY 等概念；服务器主备次序有业务含义；期望值按地区、站点、角色变化。netops 已有 `baseline` 包（分层 Profile + 正则 require/forbid + Derive），只能做文本级检查。

## 决策

1. 新建独立模块 `github.com/gatework/baseline`，消费 netops，不把厂商语法放进内核。
2. 以 `baseline.Posture` 为检查对象：每个厂商一个提取器，检查只读模型。
3. 维度覆盖度（`evidence.Coverage`）驱动检查跳过：厂商不支持的维度报"不支持"，不报违规。
4. 厂商特有最佳实践复用 netops `baseline.Rule` 文本规则，转成依赖 `dialect.<厂商>` 维度的检查。
5. 策略在本模块实现（分层选择器、glob 启停、变量、豁免），最终落成 netops `assess.Policy`；不使用 netops `baseline.Profile` 的 default/role/site 固定层次，因为需要任意层次、排除与豁免。
6. 首期只读离线备份目录；在线采集作为 `workflow.Source` 的第二个实现。

## 后果

- 新增一条要求只写一次即覆盖全部支持该维度的厂商；新增厂商只需写提取器。
- 提取器需要维护厂商默认值，这是正确性的主要风险点；私有语料测试要求 H3C/NX-OS 全维度完整、无未识别语句。
- 豁免、变量、分层若被其他模块需要，再下沉到 netops（ARC-3）。
- netops Cisco 方言未遮蔽 IOS `tacacs server` 块内的 `key 7`，本模块的 IOS 方言补充了该模式；应在 netops 修复后移除。

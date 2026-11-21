# baseline 开发说明

遵循 [gatework Go 工程规范（go-standards/STANDARD.md）](https://github.com/gatework/go-standards/blob/v1.2.0/STANDARD.md)；提交前运行 `make check`。

本模块面向网络运维管理：对异构多厂商设备的配置做基线检查，覆盖 3A、syslog、NTP、时区、SNMP、VTY/Console、SSH ACL、本地账户、802.1X/MAC 认证、接口与厂商最佳实践。设计见 [docs/design.md](docs/design.md)，决策见 [docs/adr](docs/adr)，术语见 [GLOSSARY.md](GLOSSARY.md)。

成熟度：v0，未投产，不承诺兼容（GEN-1）。

## 边界

- 共享机制来自 [netops](../netops)：配置解析与秘密遮蔽（`config`、`parse`）、设备与选择器（`device`）、规则引擎与策略（`assess`）、证据覆盖度（`evidence`）、文本规则（`baseline`）、共识（`drift`）、并发批处理（`batch`）。本模块不重新实现这些机制；通用缺口应补到 netops。
- 根包 `baseline` 是厂商无关的管理面模型 `Posture` 与 `Extractor` 端口，不做 I/O。
- `vendors/<厂商>` 只负责一种配置语法 → `Posture`，并声明各维度（Facet）是完整支持还是不支持；厂商之间互不依赖。新厂商实现 `baseline.Extractor` 并在 `vendors/registry.go` 登记别名与识别规则。
- `check` 只读 `Posture`，不读厂商语法；期望值是类型化参数，由策略注入。厂商最佳实践中没有语义对应的项写进 `vendors/<厂商>/rules.yml`（netops 文本规则），由 `check.Text` 转成检查项。
- `policy` 只按检查项 ID 认识检查：分层（scope/except）、启停（enable/disable glob）、参数、变量、豁免（waiver）、自定义文本规则。
- `survey` 从现网配置统计分布、求共识并起草策略（自举）。
- `internal/workflow` 只用注入端口（Source、Vendors）；`internal/source` 读备份目录；`internal/inventory` 由主机名推导 region/site/role；`internal/bootstrap` 组装；`internal/cli` 负责参数、渲染与退出码。中文文案集中在 `check/messages.go`、`internal/cli/messages.go`。

`architecture.yaml` 声明并由 `make check` 强制以上依赖方向。

## 语义约定

- 未配置的语句取厂商默认值（见各 `vendors/*/doc.go`），由提取器负责，检查不关心厂商默认。
- 服务器列表保留有效次序：显式 primary/secondary（H3C hwtacacs、PAN-OS、Alteon）优先，其余按配置次序；`prefer`/`priority` 视为首选。
- 三种"不检查"严格区分：disabled（策略关闭）、unsupported（厂商缺少所需维度）、waived（检查执行但违规被豁免，仍在报告中）。
- 提取器遇到属于某维度却无法解析的语句，记为 `evidence.Issue` 并把该维度降为 partial，不吞掉；Issue 只记录前导关键字，不含配置值。

## 安全语义

- 模型不保存密钥与密码：共享密钥只记"已配置"，SNMP 团体名是 `secret.Secret`，JSON 输出为 `[REDACTED]`。
- 报告只引用行号与遮蔽后的文本；各厂商方言补充了 netops 未覆盖的敏感字段（IOS `key 7`、Alteon `esecret`、PAN-OS `phash` 等）。
- 终端输出前转义控制字符。

## 测试

- 单元测试只用 `testdata/` 中的合成样例（RFC 5737 地址），真实配置不进仓库（TST-3）。
- 私有语料：`make corpus BASELINE_CORPUS=<备份目录>`，断言全部配置被识别和提取、H3C/NX-OS 各维度完整且无未识别语句，只输出聚合计数。
- 模糊测试：`make fuzz`。
- 在线采集（net-connector）尚未实现，离线备份目录是唯一数据源。

# 术语

| 术语 | 含义 |
| --- | --- |
| 基线（Baseline） | 设备配置应满足的要求集合：检查项 + 期望值 + 适用范围 + 例外 |
| 管理面模型（Posture） | 从一台设备配置提取出的厂商无关模型：AAA、syslog、NTP、SNMP、线路、服务、账户、802.1X、接口、ACL |
| 维度（Facet） | Posture 的一个组成部分，如 aaa、ntp、line；检查声明依赖哪些维度 |
| 覆盖度（Coverage） | 某提取器对每个维度的能力：complete（完整）、partial（有无法解析的语句）、unsupported（厂商无此概念） |
| 提取器（Extractor） | 一种配置语法到 Posture 的解码器，如 comware、nxos |
| 方言（Dialect） | 配置文本的结构规则：注释、分隔符、易变行、敏感字段（netops config） |
| 检查项（Check） | 一条语义规则，ID 如 `ntp.servers`；或厂商文本规则，ID 如 `text.comware.password_recovery` |
| 文本规则（Text rule） | 在匹配的配置块内要求或禁止某些命令的正则规则（netops baseline.Rule） |
| 方法集（Method set） | 一组登录使用的 AAA 方法列表：H3C 的 ISP 域、Cisco 的 method list |
| 次序（Order） | 服务器列表的比较方式：strict（逐一按序）、primary（只看首选）、any（不看次序） |
| 首选/备用（Primary/Secondary） | 服务器在有序列表中的角色；未显式声明时按配置次序 |
| 策略（Policy） | 分层的基线配置：layers、vars、waivers、text_rules |
| 层（Layer） | 策略的一级：scope 选中的设备上启停与调参检查，后层覆盖前层 |
| 作用域（Scope） | 设备选择器：名称 glob、IP、前缀、site=、role=、vendor=、region=、label:k= |
| 变量（Variable） | 参数中的 `${region}` 等设备变量，或按设备变量取值的查表 |
| 豁免（Waiver） | 有原因、责任人、到期日的风险接受；命中的问题标为 waived，到期自动失效 |
| 地区（Region） | 主机名前缀的城市代码（sha、ckg、szx、huz），用于地区差异化基线 |
| 站点（Site） | 地区 + 园区号，如 LAB1、TST2 |
| 自举（Survey） | 统计现网配置分布，按 quorum 求共识，起草策略并列出离群设备 |
| 合规矩阵（Matrix） | 设备 × 检查项的状态表：pass、fail、waived、unsupported、disabled、error |

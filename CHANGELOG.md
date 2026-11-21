# Changelog

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循语义化版本。

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- 厂商无关管理面模型 `Posture` 与 `Extractor` 端口；维度覆盖度驱动检查跳过。
- 提取器：H3C Comware（含无线 AC）与 Cisco NX-OS 全维度；Cisco IOS/IOS-XE 与 Centec 全维度；Hillstone、PAN-OS、Radware Alteon 管理面子集。
- 检查目录：AAA（远端优先、本地兜底、命令授权、计费、服务器与主备、共享密钥）、syslog、NTP、时区、SNMP、VTY/Console、服务、SSH ACL、本地账户、802.1X、接口；Comware 与 NX-OS 最佳实践文本规则。
- 策略：分层作用域、enable/disable glob、类型化参数、设备变量与查表、带到期日的豁免、自定义文本规则。
- 自举：按全局/地区/站点统计分布、求共识、起草策略。
- 配置按 `$BASELINE_CONFIG` → `./baseline.yml` → `~/.gatework/baseline.yml` 发现；`policy` 可为路径或内联文档。
- CLI 帮助、参数说明与用法错误全部中文；移除 shell 补全子命令。
- CLI：`check`（table/json/matrix、`--fail-on`）、`coverage`、`survey`、`explain`、`checks`。

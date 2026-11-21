# baseline

多厂商网络设备配置基线检查。把每台设备的配置提取成厂商无关的**管理面模型**，再按**可分层、可例外、可自举**的策略检查：

3A（TACACS+/RADIUS、方法列表、命令授权与计费、主备服务器）· syslog · NTP（含主备次序）· 时区 · SNMP · VTY/Console · 管理服务（Telnet/HTTP/SSHv1）与 SSH ACL · 本地账户 · 802.1X/MAC 认证 · 接口 · 厂商最佳实践。

## 快速开始

```sh
go install github.com/gatework/baseline/cmd/baseline@v0.1.0
# 1. 看各厂商覆盖了哪些维度
baseline coverage -s ./testdata/backup
# 2. 从现网自举一份草案策略（并列出离群设备）
baseline survey -s ./testdata/backup --draft policy.draft.yml
# 3. 审阅草案，写进 ~/.gatework/baseline.yml 后，不必再带参数
baseline check --fail-on high
baseline check -f matrix > matrix.csv      # 设备 × 检查项合规矩阵
baseline check -f json   > report.json     # 完整报告
baseline explain ntp.servers --device LAB1-10-SW01
```

上述示例在源码目录中使用合成备份。也可以运行 `make build`，生成 `bin/baseline`。

配置文件按 `$BASELINE_CONFIG` → `./baseline.yml` → `~/.gatework/baseline.yml` 查找（gatework 各工具统一布局，见 netops `bootstrap`）。`policy:` 可以写策略文件路径，也可以把策略直接内联在同一文件里；`-s`、`-p` 覆盖文件中的值。示例见 [examples/baseline.yml](examples/baseline.yml)（引用 [examples/policy.yml](examples/policy.yml)）。

数据源是配置备份目录：`plan.json`（含 host/name/vendor/backup_filename）加 `<名称>-<IP>.txt`；没有 `plan.json` 时按文件名扫描并按内容识别厂商。

退出码：0 通过；1 存在不低于 `--fail-on` 的未豁免问题；2 错误；3 有设备无法检查。

## 厂商覆盖

| 提取器 | 厂商/平台键 | aaa | logging | ntp | clock | snmp | line | service | account | nac | interface | acl |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| comware | h3c, h3c_wireless | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| nxos | cisco_nxos | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ios | cisco_ios, centec | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| hillstone | hillstone | ✓ | ✓ | ✓ | ✓ | ✓ | – | ✓ | ✓ | – | – | ✓ |
| panos | palo_alto | ✓ | ✓ | ✓ | ✓ | ✓ | – | ✓ | ✓ | – | – | ✓ |
| alteon | radware | ✓ | ✓ | ✓ | ✓ | ✓ | – | ✓ | ✓ | – | – | ✓ |

"–" 表示厂商没有该概念：依赖它的检查报告为"不支持"，不会误报。

## 策略要点

- **分层**：`layers` 由通用到具体，`scope`/`except` 用设备选择器（名称 glob、IP/前缀、`site=`、`role=`、`vendor=`、`region=`、`label:k=`）；后层覆盖前层的启停、严重级与单个参数。
- **启停**：`enable`/`disable` 支持 glob（`nac.*`、`text.*.banner`）。
- **参数与次序**：服务器类检查有 `servers`、`order: strict|primary|any`、`exclusive`、`min`。
- **变量**：`${region}`、`${site}`、`${role}`、`${vendor}`、`${name}`、`${label.k}`，以及按设备变量查表的 `vars`。
- **豁免**：`waivers` 需写原因、责任人、到期日；命中的问题保留在报告中标为"豁免"，过期自动失效并提示。
- **自定义文本规则**：`text_rules` 按方言追加 require/forbid 正则规则。

`baseline checks` 列出全部检查项及其依赖维度。

## 测试层次

- `make check`：格式、tidy、vet、lint、架构、`go test -race`、govulncheck（单元测试只用 `testdata/` 合成样例）。
- `make corpus BASELINE_CORPUS=<备份目录>`：私有真实语料，只输出聚合计数。
- `make fuzz`：提取器模糊测试。

独立构建使用 `go.mod` 锁定的 netops 版本。跨模块联调可以用本地 `go.work`。

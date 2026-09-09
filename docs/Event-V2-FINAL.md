# 统一数据契约 · Event V2 FINAL（唯一权威版本）

> **状态**：2026-09-08 A 发布冻结（Event V2 FINAL）；2026-09-09 补充批次隔离约定、`case_id`、`source=firewall/waf` 与 EventOut 说明。
> **取代**：`docs/数据格式契约-v1.md`（其中 event_id 命名已废止，见第 2 条）。
> **执行**：A/B/C/D/F 全部以本文档为准；修改需全组同步。
> **校验卡点**：`backend/parsers/network/normalize.py` 的 `validate_events` / `validate_eventout`；
> 文件级守卫：`tests/test_contract_guard.py`。

## 1. 两个 ID 千万别混

- `id`：后端 SQLite 入库时自动生成，系统内部唯一。D 的 `evidence_event_ids` 只保存这个 id（如 [12, 13, 17]）。
- `source_event_id`：原始日志自带的事件编号（Windows 4624 / 4688 / Sysmon 1/3/11/13）。
  **改名历史**：v1 契约曾命名为 event_id，FINAL 起统一改为 source_event_id（避免与数据库 id 混淆）。
  Zeek / PCAP：`source_event_id: null`。后端不会用数据库 id 覆盖它。
- 数据库列名 `event_id` 仅为内部实现细节，**对外（API 输出/文档/各模块）一律用 `source_event_id`**。

## 2. Event V2 公共字段（19 个，输入）

timestamp, host, source, source_event_id, event_type, user, process,
src_ip, dst_ip, dst_port, protocol, logon_type, session_id, cmdline,
detail, description, anomaly_flags, severity, raw_log

后端入库后额外增加 `id`（EventOut = 19 + id，共 20 个字段，D 直接消费）。

## 3. source 枚举

`windows_evtx` / `sysmon` / `linux_auth` / `linux_audit` / `network_pcap` / `network_zeek` / `firewall` / `waf`

使用约定：

- `network_pcap`：PCAP / PCAPNG 直接解析结果。
- `network_zeek`：Zeek 日志或 CSV 连接日志兜底格式。
- `firewall`：防火墙、网关、边界设备访问日志。
- `waf`：WAF 或 Web 攻击告警。
- `source` 表示证据来源，`event_type` 仍表示行为类型。例如 WAF 的 Web 请求仍写 `event_type=http_request`。

## 4. null 规则

允许为 null：source_event_id、user、process、src_ip、dst_ip、dst_port、protocol、
logon_type、session_id、cmdline。
缺失一律传 `null`；**禁止**用 "unknown"、0、空字符串、"-" 制造占位值
（校验器会阻断；dst_port 缺失传 null 而非 0）。

## 5. detail 规则

各事件独有字段统一放 detail（必填对象，无内容传 `{}`），不再新增公共字段：
parent_process、file_path、registry_key、registry_value_name、registry_value_data、
registry_operation、src_port、hashes、bytes_in、bytes_out、domain、uri、method、
status_code、attack_stage、mitre_technique 等。

**批次标签约定（2026-09-09 补充）**：每条事件 detail.batch_id 标记来源批次
（如 case01 / apt29_day1 / e_case01）。多批数据**不得**混库，D/前端按 batch_id 过滤；
导出流程见 `scripts/reset_import_export.py`（一批一库，id 每批从 1 起）。

## 6. IP → Host 映射

不新增 host_ip 公共字段。A 后端维护 Host Mapping（`/api/hosts`），D 使用 events + host_map。
host 字段只放主机名；映射不到时 AttackStep 的 target_host = null 并保留 target_ip，
前端用 `target_host ?? target_ip`。（过渡期说明：后端 schema host 暂为非空，
网络事件未映射时 host 暂填 IP 并由校验器 warning 标注，待后端放宽为可空后归零。）

## 7. D 的输入/输出

- D 直接消费后端 EventOut；source_type→source、command_line→cmdline、
  parent_process/registry_* 从 detail 读取。
- D 输出 AttackStep：step_id、case_id、stage、technique_id、technique_name、timestamp、
  source_host、target_host、source_ip、target_ip、description、evidence_event_ids（存数据库 id）。

## 8. 时间

B/C 所有数据统一转成 UTC+8；后端保存 ISO8601（如 2026-09-08T13:10:00+08:00），
入库时不转 UTC。

# 网络流量解析与异常检测模块（network event parser）

> 负责人：成员C ｜ 所属题目：题3《基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现》
> **输出已对齐全组冻结的 Event V2 契约与 event_type 枚举规范（2026-09-07）**

本模块是系统的**网络流量数据入口**：把 PCAP / Zeek 日志 / CSV 连接日志解析为 Event V2
统一事件，并基于规则检出网络侧攻击行为，供后端（A）入库、关联引擎（D）做攻击链重建。

对应任务书要求：**流量捕获与解析、网络会话重建、异常协议行为建模、隐蔽信道检测（DNS/HTTP/ICMP）**。

---

## 1. 快速开始

```bash
# 安装依赖（Windows / Linux 通用，离线解析无需管理员权限）
pip install -r requirements.txt

# 生成一套覆盖完整攻击链的样例数据（Case01，可跳过）
python scripts/gen_sample_pcap.py

# 解析并输出 Event V2 统一事件 JSON（--summary-json 同时产出 Dashboard 汇总）
python -m backend.parsers.network data/network_logs/case01_enterprise_attack.pcap --hosts data/hosts.csv --out out/network_events.json --summary-json out/summary.json

# 生成 Case02 双攻击链样例（两个攻击者独立成链，含 SSH 爆破）
python scripts/gen_sample_pcap.py --case02

# 联调：导入 A 的后端并做 round-trip 校验（先启动 uvicorn backend.main:app）
python scripts/post_events.py out/network_events.json --sync-hosts data/hosts.csv
```

CLI 运行时会做 **Event V2 契约自检**（19 字段、event_type 枚举、severity 取值、时间格式等），
不合规会直接打印问题。

| 参数 | 说明 |
| --- | --- |
| `inputs`（必填） | 一个或多个输入：`.pcap/.pcapng/.cap`、Zeek 日志目录、`.csv` 连接日志 |
| `--hosts` | IP→主机名映射 CSV（列：`ip,hostname,role`），用于 `host` 字段 |
| `--out` | Event V2 事件 JSON 输出路径（JSON 数组） |
| `--anomalies-only` | 只输出告警事件，不含普通会话事件 |
| `--internal` | 内网网段（逗号分隔），默认 RFC1918 |
| `--config` | 阈值 JSON 配置文件（键与 `config.DetectionConfig` 字段同名） |

## 2. 支持的输入格式与 source 枚举

| 格式 | source 值 | 说明 |
| --- | --- | --- |
| PCAP / PCAPNG | `network_pcap` | scapy 流式读取，五元组聚合会话；提取 DNS 查询、明文 HTTP 请求、ICMP 载荷 |
| Zeek 日志目录 | `network_zeek` | `conn.log`（必需）+ `dns.log` / `http.log`（可选），TSV/JSON 均支持，支持 `.gz`；**原始日志行进 `raw_log`（含 uid，可回溯原始记录）** |
| CSV 连接日志 | `network_zeek` | 列：`timestamp,src_ip,src_port,dst_ip,dst_port,protocol[,bytes,duration,packets]`（E 靶场没有 Zeek 时的兜底格式） |

## 3. 检测规则（阈值见 `config.py`，均可用 `--config` 覆盖）

| 规则 | 检测规则（anomaly_flags[0]） | 默认阈值 | ATT&CK（detail.mitre_technique） |
| --- | --- | --- | --- |
| 端口扫描 | `port_scan` | 同源对同目标 ≥10 个不同端口 | T1046（侦察） |
| Web 攻击载荷 | `http_attack` | 请求行/体命中 SQLi、路径穿越、Webshell 等特征 | T1190（初始访问） |
| 可疑端口连接 | `suspicious_port` | 目的端口 ∈ {4444,4445,5555,1337,31337,6666,6667,9999} | T1571（命令与控制） |
| 内网横向连接 | `remote_service_connection` | 内→内访问 22/23/139/445/3389/5985/5986 | T1021（横向移动） |
| C2 心跳外联 | `c2_beacon` | ≥4 次外连，间隔 5s~1h，抖动(σ/μ) ≤0.35 | T1071（命令与控制） |
| DNS 隐蔽信道 | `dns_tunnel` | 域名标签 ≥25 字符且熵 ≥3.5；或同源同域 TXT ≥6 次 | T1071.004（命令与控制） |
| 数据外传 | `exfiltration` | 内→外单会话 ≥1MB；或时长 ≥300s 且 ≥200KB | T1048（数据外传） |
| ICMP 隐蔽信道 | `icmp_tunnel` | 单包载荷 ≥256B；或同会话 ≥20 包 | T1095（命令与控制） |
| 登录爆破（网络侧） | `brute_force_evidence` | 同源对同端口 300s 内 ≥15 连接且 ≥50% 未完成 | T1110（凭证访问） |

**event_type 映射（对齐全组冻结枚举）**：告警不再自造 event_type——
端口扫描/可疑端口/C2心跳/横向移动/数据外传/ICMP隧道 一律映射为 `network_connection`，
Web攻击载荷 → `http_request`，DNS隧道 → `dns_query`；检测规则名放在 `anomaly_flags[0]`，
ATT&CK 阶段/技术号在 `detail.attack_stage` / `detail.mitre_technique`。
普通会话事件 event_type：`network_connection`（含 ICMP，用 `protocol: "icmp"` 区分）/
`dns_query` / `http_request`。protocol 输出小写（tcp/udp/icmp），与规范示例一致。

**初始入侵点标记**：解析完成后自动按"外部攻击者 IP"分组，给每组最早的高优先级对内告警
（Initial Access > Reconnaissance > Credential Access）追加 flag `entry_point_candidate`、
`detail.entry_point = true`、description 前缀【疑似入侵点】——候选标记，最终裁决权在 D。
多攻击者场景（Case02）各自成链互不干扰。

## 4. 输出：Event V2（19 个公共字段，契约冻结）

```json
{
  "timestamp": "2026-09-07T09:04:20.000+08:00",
  "host": "core-server",
  "source": "network_pcap",
  "source_event_id": null,
  "event_type": "network_connection",
  "user": null,
  "process": null,
  "src_ip": "10.0.0.10",
  "dst_ip": "185.199.108.153",
  "dst_port": 8443,
  "protocol": "tcp",
  "logon_type": null,
  "session_id": null,
  "cmdline": null,
  "detail": {
    "attack_stage": "Command and Control",
    "attack_stage_zh": "命令与控制",
    "mitre_technique": "T1071",
    "connection_count": 6, "mean_interval_sec": 60.0, "jitter_ratio": 0.0,
    "first_seen": "09:04:20", "last_seen": "09:09:20",
    "src_port": null, "end_time": "2026-09-07T09:09:20.520+08:00"
  },
  "description": "C2心跳外联: 10.0.0.10 以平均 60s 的固定间隔（抖动 0.00）向 185.199.108.153:8443 回连 6 次",
  "anomaly_flags": ["c2_beacon", "T1071"],
  "severity": 3,
  "raw_log": "DETECT[c2_beacon] C2心跳外联: ..."
}
```

网络模块对契约的实现约定：

- **timestamp**：UTC+8 ISO8601（`...+08:00`），毫秒精度。
- **source_event_id**：网络事件（PCAP/Zeek）按契约传 `null`；Zeek uid 保留在 `raw_log` 中可回溯原始记录，后端不会用内部 id 覆盖该字段。
- **severity**：普通会话 `0`；告警按规则级别映射 1/2/3（模块内部 critical 收敛为 3）。
- **anomaly_flags**：无异常 `[]`；告警为 `[检测规则名, ATT&CK技术号]`，如 `["c2_beacon","T1071"]`。
- **detail**（必填对象）：网络事件特有字段全部在此——`src_port`、`peer_host`、`direction`
  （internal/outbound/inbound/external）、`packets/bytes/duration_sec/flow_key/end_time`、
  `bytes_in/bytes_out`（发起方发送/对端返回字节，D 推荐键名）、`tcp_flags`、
  `domain`（DNS 域名 / HTTP Host）、`method/uri`（HTTP）、`dns_queries`、`http_requests`、
  `icmp_*`；告警事件额外带 `attack_stage` / `attack_stage_zh` / `mitre_technique` 及各规则证据字段。
- **host**：内网侧主机名（来自 hosts.csv，无映射则 IP）；对端在 `detail.peer_host`。
- **raw_log**（必填）：Zeek/CSV 保留原始日志行；PCAP 无日志行，输出一行规范化摘要
  （`FLOW <五元组> start=... pkts=... bytes=...`）；检测告警为 `DETECT[规则] 描述`。
- **缺失即 null**：ICMP 无端口 → `dst_port: null`（不是 0）；主机侧字段（user/process/
  cmdline/logon_type/session_id）网络事件恒为 `null`。
- 契约校验函数（**三层守卫，任何数据出入口都会执行**）：
  - `validate_events(events)`：解析器输出（19 字段）阻断级校验——字段集、event_type 冻结枚举、
    source 枚举、severity 0-3、UTC+8 且可解析、必填非空、**禁止占位值**（unknown/空串/dst_port=0）、
    网络事件 source_event_id 必须 null；
  - `validate_eventout(events)`：D 的输入（19 字段 + 数据库 id）阻断级校验——id 唯一正整数；
  - `collect_warnings(events)`：非阻断警告（当前仅 host 为 IP 字符串一项，待后端放宽 host 可空后归零）。
  - 接入点：CLI 运行时自检（本模块）、`scripts/post_events.py`（导入前阻断 + 回拉后校验）、
    `scripts/export_for_d.py`（落盘前阻断）；`tests/test_contract_guard.py` 含文件级守卫，
    `data/sample_events/` 下任何新放的 `*_eventout.json` 都会被自动检查。

## 5. 与其他成员的对接

### A（后端/集成）
- `--out` 的 JSON 数组直接 `POST /api/events/import`；或在后端内调用：

```python
from backend.parsers.network import analyze_paths, load_host_map, DetectionConfig
from backend.parsers.network.normalize import validate_events

events, flows, anomalies, stats = analyze_paths(
    ["data/network_logs/case01_enterprise_attack.pcap"],
    host_map=load_host_map("data/hosts.csv"),
    cfg=DetectionConfig(),
)
assert validate_events(events) == []   # 导入前契约自检
```

- `include_flows=False` 可只产出告警事件。数据库内部 `id` 由后端生成，本模块不关心。
- **联调冒烟**：`python scripts/post_events.py out/network_events.json --sync-hosts data/hosts.csv`
  ——本地契约自检 → hosts.csv 同步到 `/api/hosts`（逐条、容忍 409）→ 批量 `/api/events/import`
  （422 时打印 Pydantic 错误明细）→ GET 回拉做 **round-trip 逐字段比对**。
  已验证：case01 70 条 + case02 96 条全部往返一致。
- **Dashboard 汇总**：`--summary-json out/summary.json` 产出 F 可直接消费的 JSON：
  `total_events / anomaly_events / severity_counts / event_type_counts / anomaly_flag_counts /
  attack_stage_sequence / attack_timeline（阶段时间线，含 entry_point）/ hosts_involved /
  top_external_dst_by_bytes（外联 top10）/ time_range`。

### D（事件关联 / 攻击链重建）——消费后端返回的 EventOut
- event_type 分发：只会在 `network_connection` / `dns_query` / `http_request` 三种上触发；
  进一步的分类看 `anomaly_flags[0]`（检测规则名）。
- ATT&CK 阶段与技术：`detail.attack_stage` / `detail.mitre_technique`。
- 攻击图构建：`src_ip/dst_ip/host/detail.direction`；横向移动告警
  （`anomaly_flags` 含 `remote_service_connection`）即内网跳板候选链路。
- `detail.bytes_in/bytes_out` 可直接用于外传量统计。
- `evidence_event_ids` 存后端 `events.id`；本模块普通会话事件（severity=0）入库后即可作为
  告警事件的证据源（通过 `detail.flow_key` + 时间窗口关联到对应会话）。

### E（靶场 / 数据）——三种接入方式任选
1. 网关/镜像口抓包：`tcpdump -i eth0 -w case01.pcap`（或 Wireshark 导出）→ 直接喂给本模块（source=network_pcap）；
2. 靶场装 Zeek（`zeek -C -r case01.pcap` 或实时模式）→ 日志目录传入（source=network_zeek）；
3. 防火墙/交换机连接日志 → 整理成 CSV（列名见第 2 节）。

请把靶场 8 节点实际 IP 计划同步到 `data/hosts.csv`（否则 `host` 字段显示 IP）。
`scripts/gen_sample_pcap.py` 顶部拓扑常量与该文件一致，可整体替换成靶场实际 IP 重新生成。

## 6. 测试

```bash
python -m pytest tests -q
```

覆盖：熵计算、内网判定、8 个检测器（正/负用例）、PCAP 端到端、Zeek TSV（uid/raw_log/方向字节）、
CSV、Event V2 契约（19 字段、event_type 冻结枚举、null 语义、severity 数字、anomaly_flags、UTC+8）。

## 7. 边界与说明

- HTTPS 内容加密，本模块只做会话级统计，不做 TLS 解密（明文 HTTP/DNS 已够演示场景）。
- 检测为**规则引擎**而非 ML/IDS：阈值按课程场景标定，接真实流量时用 `--config` 调整。
- C2 心跳规则只看外联方向，内网 DNS 等周期性正常流量零误报。
- 大 PCAP 流式读取，内存占用与会话数成正比，与总包数无关。
- 契约变更需全组同步：Event V2 与 event_type 枚举冻结后，本模块不再单方面修改。

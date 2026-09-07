# 网络流量解析与异常检测模块（network event parser）

> 负责人：成员C ｜ 所属题目：题3《基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现》

本模块是系统的**网络流量数据入口**：把 PCAP / Zeek 日志 / CSV 连接日志解析为统一格式的
安全事件，并基于规则检出网络侧的攻击行为，供后端（A）入库、关联引擎（D）做攻击链重建。

对应任务书要求：**流量捕获与解析、网络会话重建、异常协议行为建模、隐蔽信道检测（DNS/HTTP/ICMP）**。

---

## 1. 快速开始

```bash
# 安装依赖（Windows / Linux 通用，离线解析无需管理员权限）
pip install -r requirements.txt

# 生成一套覆盖完整攻击链的样例数据（Case01，可跳过）
python scripts/gen_sample_pcap.py

# 解析并输出统一事件 JSON
python -m backend.parsers.network data/network_logs/case01_enterprise_attack.pcap ^
       --hosts data/hosts.csv --out out/network_events.json
```

Linux 下路径分隔符用 `/`。CLI 参数：

| 参数 | 说明 |
| --- | --- |
| `inputs`（必填） | 一个或多个输入：`.pcap/.pcapng/.cap`、Zeek 日志目录、`.csv` 连接日志 |
| `--hosts` | IP→主机名映射 CSV（列：`ip,hostname,role`），用于事件里的 `host` 字段 |
| `--out` | 统一事件 JSON 输出路径（JSON 数组） |
| `--anomalies-only` | 只输出告警事件，不含普通会话事件 |
| `--internal` | 内网网段（逗号分隔），默认 RFC1918 |
| `--config` | 阈值 JSON 配置文件（键与 `config.DetectionConfig` 字段同名） |

## 2. 支持的输入格式

| 格式 | 说明 |
| --- | --- |
| PCAP / PCAPNG | scapy 流式读取，按五元组聚合会话；提取 DNS 查询、明文 HTTP 请求、ICMP 载荷统计 |
| Zeek 日志目录 | `conn.log`（必需）+ `dns.log` / `http.log`（可选），TSV 与 JSON 两种风格都支持，支持 `.gz` |
| CSV 连接日志 | 列：`timestamp,src_ip,src_port,dst_ip,dst_port,protocol[,bytes,duration,packets]`（E 靶场没有 Zeek 时的兜底格式） |

## 3. 检测规则（阈值见 `config.py`，均可用 `--config` 覆盖）

| 规则 | event_type | 默认阈值 | ATT&CK 映射 |
| --- | --- | --- | --- |
| 端口扫描 | `port_scan` | 同源对同目标 ≥10 个不同端口 | Reconnaissance / T1046 |
| Web 攻击载荷 | `http_attack` | 请求行/体命中 SQLi、路径穿越、Webshell 等特征 | Initial Access / T1190 |
| 可疑端口连接 | `suspicious_port` | 目的端口 ∈ {4444,4445,5555,1337,31337,6666,6667,9999} | Command and Control / T1571 |
| 内网横向连接 | `lateral_movement` | 内→内访问 22/23/139/445/3389/5985/5986 | Lateral Movement / T1021 |
| C2 心跳外联 | `c2_beacon` | ≥4 次外连，间隔 5s~1h，抖动(σ/μ) ≤0.35 | Command and Control / T1071 |
| DNS 隐蔽信道 | `dns_tunnel` | 域名标签 ≥25 字符且熵 ≥3.5；或同源同域 TXT ≥6 次 | Command and Control / T1071.004 |
| 数据外传 | `exfiltration` | 内→外单会话 ≥1MB；或时长 ≥300s 且 ≥200KB | Exfiltration / T1048 |
| ICMP 隐蔽信道 | `icmp_tunnel` | 单包载荷 ≥256B；或同会话 ≥20 包 | Command and Control / T1095 |

## 4. 输出：统一安全事件

输出为 JSON 数组（`--out` 文件或 `analyze_paths()` 返回值），可直接 `POST /api/events/import`。
字段与《分工》的统一事件模型对齐：

```json
{
  "event_id": "NW-000042",
  "timestamp": "2026-09-07T09:04:20.030",
  "source": "network_traffic",
  "event_type": "c2_beacon",
  "severity": "high",
  "src_ip": "10.0.0.10", "src_port": 0,
  "dst_ip": "185.199.108.153", "dst_port": 8443,
  "protocol": "TCP",
  "host": "core-server",          // 内网侧主机名（来自 hosts.csv，无映射则为 IP）
  "peer_host": "185.199.108.153",
  "direction": "outbound",        // inbound / outbound / internal / external
  "attack_stage": "Command and Control",
  "attack_stage_zh": "命令与控制",
  "mitre_technique": "T1071",
  "description": "C2心跳外联: 10.0.0.10 以平均 60s 的固定间隔（抖动 0.00）向 185.199.108.153:8443 回连 6 次",
  "evidence": { "connection_count": 6, "intervals_sec": [60.0, 60.0, "..."], "mean_interval_sec": 60.0, "jitter_ratio": 0.0, "...": "..." }
}
```

事件类型：普通会话事件 `network_connection` / `dns_query` / `http_request` / `icmp_traffic`
（severity=info，原始会话证据），加上第 3 节的 8 类告警事件（severity=low~critical）。

## 5. 与其他成员的对接

### A（后端/集成）
- 事件数组直接对应 `POST /api/events/import`；也可以在后端里直接调用本模块：

```python
from backend.parsers.network import analyze_paths, load_host_map, DetectionConfig

events, flows, anomalies, stats = analyze_paths(
    ["data/network_logs/case01_enterprise_attack.pcap"],
    host_map=load_host_map("data/hosts.csv"),
    cfg=DetectionConfig(),
)
```

- `include_flows=False` 可只返回告警事件。

### D（事件关联 / 攻击链重建）
关联引擎可直接依赖的字段：
- `timestamp`：ISO 字符串，排序即时间序（主机日志对齐时以此为基准）
- `src_ip/dst_ip/host/peer_host/direction`：构建 攻击者→Web→办公机→核心服务器→C2 的图
- `event_type + attack_stage + mitre_technique`：直接映射 ATT&CK 阶段
- `lateral_movement` 告警给出了内网跳板候选链路（源主机→目标主机:服务）
- `evidence` 中保留原始会话/包统计，供前端展示"点开看证据"

### E（靶场 / 数据）
三种接入方式任选：
1. 靶场网关/镜像口抓包：`tcpdump -i eth0 -w case01.pcap`（或 Windows 上 Wireshark 导出），直接喂给本模块；
2. 靶场上装 Zeek（`zeek -C -r case01.pcap` 或实时模式），把日志目录传给本模块；
3. 交换机/防火墙导出连接级日志 → 整理成 CSV（列名见第 2 节）。

同时提供 `data/hosts.csv`（IP→主机名映射）。**请把靶场 8 节点的实际 IP 计划同步到该文件**，
否则事件里的 `host` 字段显示 IP。样例生成脚本 `scripts/gen_sample_pcap.py` 顶部的
拓扑常量（ATTACKER/WEB/CORE/C2 等）与该文件一致，可整体替换成靶场实际 IP 重新生成。

## 6. 测试

```bash
python -m pytest tests -q
```

覆盖：熵计算、内网判定、8 个检测器（正/负用例）、PCAP 端到端、Zeek TSV、CSV、事件标准化。

## 7. 边界与说明

- HTTPS 内容加密，本模块只做会话级统计，不做 TLS 解密（3 天范围内明文 HTTP/DNS 已够演示）。
- 检测为**规则引擎**而非 ML/IDS：阈值按 3 天课程场景标定，接真实流量时可能需要调 `--config`。
- C2 心跳规则只看外联方向（对内网 DNS 等周期性正常流量零误报）。
- 大 PCAP 用流式读取，内存占用与会话数成正比，与总包数无关。

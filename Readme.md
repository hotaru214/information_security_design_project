# 恶意攻击行为溯源分析系统

网络空间安全课程设计 题3：**基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现**

系统把不同机器产生的安全数据（Windows/Linux 主机日志、主机行为、企业网络流量）采集进来，
统一为 Event V2 格式入库，自动关联分析后告诉用户：**攻击者什么时候从哪里进来、做了什么、
经过哪些机器、最后干了什么**。

## 架构总览

```text
             浏览器（F：Web Dashboard）
                    │
                    ▼
        FastAPI 后端 + SQLite（A）
        /api/events/import  /api/attack-chain
                    │
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
 主机日志解析(B)  网络流量解析(C)  事件关联/ATT&CK映射(D)
 b_host_parser/  backend/parsers/  correlation/
      │             │             ▲
      └─────────────┴─────────────┘
       统一 Event V2 事件流（UTC+8）
                    ▲
             靶场/实验数据（E：8节点拓扑）
```

| 成员 | 模块 | 位置 |
| --- | --- | --- |
| A | 后端架构、数据库、API、集成 | `backend/main.py`、`backend/routers/`、`backend/schemas/` |
| B | Windows/Linux 主机日志解析 | `b_host_parser/` |
| C | 网络流量解析与异常检测 | `backend/parsers/network/` |
| D | 事件关联、ATT&CK 映射、攻击链 | correlation（开发中） |
| E | 8 节点靶场与实验数据 | 靶场环境 |
| F | 前端可视化 + LLM 分析 | frontend（开发中） |

## 快速开始

### 0. 环境准备（Python 3.12+）

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 1. 启动后端（A）

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

- Swagger 接口文档：<http://127.0.0.1:8000/docs>
- 健康检查：<http://127.0.0.1:8000/health>

### 2. 网络流量解析（C）

```bash
# 生成样例攻击链 PCAP（可跳过，已随仓库提供）
python scripts/gen_sample_pcap.py

# 解析并输出 Event V2 统一事件 JSON
python -m backend.parsers.network data/network_logs/case01_enterprise_attack.pcap --hosts data/hosts.csv --out out/network_events.json
```

支持三种输入：PCAP/PCAPNG（source=`network_pcap`）、Zeek 日志目录（source=`network_zeek`）、
CSV 连接日志。自动检测 8 类攻击行为：端口扫描、Web 攻击载荷、可疑端口、横向移动连接、
C2 心跳、DNS 隧道、数据外传、ICMP 隧道。详见 [backend/parsers/network/README.md](backend/parsers/network/README.md)。

### 3. 主机日志解析（B）

解析 Windows EVTX（4624/4625/Sysmon 等）为 Event V2 事件，入口与用法见
[b_host_parser/README.md](b_host_parser/README.md)。

## Event V2 数据契约（全组冻结，2026-09-07）

所有模块输出的统一事件共 **19 个公共字段**：

`timestamp, host, source, source_event_id, event_type, user, process, src_ip, dst_ip, dst_port, protocol, logon_type, session_id, cmdline, detail, description, anomaly_flags, severity, raw_log`

要点：

- **时间**：统一 UTC+8，后端标准化为 ISO8601（`2026-09-08T13:10:00+08:00`）。
- **severity**：`0` 正常/未标记、`1` 低、`2` 中、`3` 高。
- **event_type**：使用全组冻结枚举（30 个值）；网络模块只输出 `network_connection` /
  `dns_query` / `http_request` 三种，检测规则名放 `anomaly_flags`，protocol 为小写。
- **缺失即 null**：不允许用 `"unknown"`、`0`、空字符串占位。
- **detail 必填对象**：各模块独有字段（`parent_process`、`file_path`、`registry_*`、`src_port`、
  `attack_stage`、`mitre_technique` 等）全部放 `detail`，不再新增公共字段。
- **anomaly_flags 必填**：无异常 `[]`。
- **source_event_id 与数据库 id 区分**：`source_event_id` 是原始日志自带编号（Windows 4624 /
  Sysmon 1 等），网络事件（PCAP/Zeek）传 `null`；后端 SQLite 另生成内部主键 `id`，
  D 的 `evidence_event_ids` 只用这个 `id`。
- **source 枚举**：`windows_evtx` / `sysmon` / `linux_auth` / `linux_audit` / `network_pcap` / `network_zeek`。

契约变更需全组同步，任何模块不得单方面修改字段。

## 目录结构

```text
├── backend/                  # A：FastAPI 后端（schemas/routers/database）+ C：网络解析模块
│   ├── main.py               #    应用入口
│   ├── parsers/network/      #    网络流量解析与异常检测（含详细 README）
│   └── ...
├── b_host_parser/            # B：主机日志解析模块（含详细 README）
├── data/
│   ├── hosts.csv             #    IP→主机名映射（网络模块用）
│   ├── network_logs/         #    样例 PCAP
│   └── sample_logs/          #    B 的样例 EVTX
├── scripts/
│   └── gen_sample_pcap.py    #    样例攻击链 PCAP 生成器
├── tests/                    #    网络模块测试（pytest）
├── docs/                     #    各模块开发文档/踩坑笔记
└── requirements.txt          #    合并后的依赖清单
```

## 测试

```bash
python -m pytest tests -q
```

## 提交材料（对照任务书）

任务分工说明、作品技术原理介绍、概要设计报告、详细设计报告、测试分析报告、
程序编译和安装使用文档、程序源代码、PPT、截屏录像 —— 2026-09-12 沙河 N103 验收。

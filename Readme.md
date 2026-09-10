# 恶意攻击行为溯源分析系统

网络空间安全课程设计 题3：**基于主机日志、主机行为、网络流量的恶意攻击行为溯源分析系统设计与实现**

系统把不同机器产生的安全数据（Windows/Linux 主机日志、主机行为、企业网络流量）采集进来，
后端现已支持 Event V2 多源安全事件校验、SQLite 存储、查询和 Host Mapping。
攻击关联、AttackStep、ATT&CK Mapping、LLM、前端及靶场联调属于后续目标，未由本次后端实现。

## 目标架构（含尚未实现的模块与接口）

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

## 当前后端 Event V2 数据契约

当前后端要求的 Event 输入共 **19 个公共字段**：

`timestamp, host, source, source_event_id, event_type, user, process, src_ip, dst_ip, dst_port, protocol, logon_type, session_id, cmdline, detail, description, anomaly_flags, severity, raw_log`

> **权威契约文档：[docs/Event-V2-FINAL.md](docs/Event-V2-FINAL.md)**（2026-09-09 落定；事件输出字段名统一为 source_event_id，并补充批次隔离约定 detail.batch_id）。

要点：

- **时间**：必须携带 `+08:00` 时区；缺少时区或使用其他偏移返回 422。按 ISO8601 保存，不转 UTC。
- **severity**：`0` 正常/未标记、`1` 低、`2` 中、`3` 高。
- **event_type**：后端接受非空字符串，不使用严格 Enum，支持 `log_cleared`；类型名称由团队协调。网络模块输出 `network_connection` /
  `dns_query` / `http_request` 三种，检测规则名放 `anomaly_flags`，protocol 为小写。
- **可空字段**：缺少值时显式传 `null`；后端不自动把占位字符串或 `0` 转换成 null。
- **detail 必填对象**：各模块独有字段（`parent_process`、`file_path`、`registry_*`、`src_port`、
  `attack_stage`、`mitre_technique` 等）全部放 `detail`，不再新增公共字段。
- **anomaly_flags 必填**：无异常 `[]`。
- **source_event_id 与数据库 id 区分**：`source_event_id` 是原始日志自带编号（Windows 4624 /
  Sysmon 1 等），网络事件（PCAP/Zeek）传 `null`；后端 SQLite 另生成内部主键 `id`，
  D 的 `evidence_event_ids` 只用这个 `id`。数据库列名 `event_id` 仅为内部实现细节。
- **source 枚举**：`windows_evtx` / `sysmon` / `linux_auth` / `linux_audit` / `network_pcap` / `network_zeek` /
  `firewall`（边界设备）/ `waf`（2026-09-09 扩充，source=证据来源、event_type=行为类型）。

所有 19 个输入字段均必填；可空字段需显式传 `null`。`host`、`source`、`event_type`、`description`、`raw_log` 非空；端口非空时为 1～65535，severity 为 0～3。

**字段名定案（2026-09-09，按 Event V2 FINAL）**：公共字段正式名称为 `source_event_id`，API 输出亦用此名（输入端保留 `event_id` 作为兼容别名）。数据库列名 `event_id` 为内部实现细节，不对外。
批次隔离：多批数据不得混库，每批独立入库（id 每批从 1 起），事件 `detail.batch_id` 标记批次；流程见 `scripts/reset_import_export.py`，已交付 D 的五份 EventOut（data/sample_events/）均含批次标签。

### 当前后端 API

- `GET /health`：健康检查。
- `POST /api/events`：保存单条 Event，返回 201 和含内部 `id` 的 Event。
- `POST /api/events/batch`：保存数组，返回 `{"inserted": N}`。
- `POST /api/events/import`：同一批量写入逻辑，返回 `{"imported": N, "failed": 0}`。
- `GET /api/events`：按内部 `id` 升序返回全部 Event。
- `GET /api/events/{id}`：按数据库主键取完整证据（含 detail、raw_log），不存在返回 404。
- `POST /api/hosts`、`POST /api/hosts/batch`：保存 hostname、ip、可空 role；hostname 或 ip 重复返回 409，批量冲突整批回滚。
- `GET /api/hosts`：全部 Host。
- `GET /api/hosts/map`：IP 到 hostname 的 JSON 对象，空库返回 `{}`。

Host Mapping 假设一个 hostname 对应一个主要 IP，不做自动更新。D 可调用 `backend.database.get_host_by_ip()` 和 `get_host_map()`。Event 的 detail 和 anomaly_flags 在 SQLite 中保存为 JSON 文本，API 返回对象和数组。

### 从本地 Event V1 升级

如果从早期 Event V1 本地开发环境升级，需要先停止本项目服务，删除本地忽略的 `data/attack_trace.db` 后重新启动；正式提交不包含数据库文件。此方式仅用于可丢弃的开发测试库，不适用于正式数据。不要删除 data 下团队样例文件。

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

# D 攻击关联模块说明

## 模块定位

D 模块负责攻击事件关联与溯源分析。它不直接解析原始日志，而是消费 A 后端返回的标准化 `EventOut`，将离散事件转换为可展示、可回查证据的攻击步骤。

核心接口：

```python
def correlate_events(events: list[dict], host_map: dict[str, str] | None = None) -> list[dict]:
    ...
```

其中：

- `events`：标准化事件列表，字段遵循 Event V2。
- `host_map`：IP 到主机名的映射，由后端或靶场资产表提供。
- 返回值：攻击步骤列表 `attack_steps`。

## 输入依赖

D 直接消费 Event V2，重点使用以下字段：

```text
id
timestamp
host
source
source_event_id
event_type
user
process
src_ip
dst_ip
dst_port
protocol
logon_type
session_id
cmdline
detail
description
anomaly_flags
severity
raw_log
```

其中 `id` 是后端数据库内部唯一 ID，D 的 `evidence_event_ids` 必须保存这个 ID，不保存原始日志的 `source_event_id`。

事件特有字段从 `detail` 中读取：

```text
parent_process
file_path
registry_key
registry_value_name
registry_value_data
registry_operation
src_port
hashes
bytes_in
bytes_out
domain
uri
method
status_code
```

## 输出格式

每条攻击步骤输出：

```json
{
  "step_id": "S001",
  "stage": "Lateral Movement",
  "technique_id": "T1021",
  "technique_name": "Remote Services",
  "timestamp": "2026-09-08T13:10:00+08:00",
  "source_host": "web-server",
  "target_host": "office-pc",
  "source_ip": "192.168.1.10",
  "target_ip": "192.168.1.20",
  "description": "web-server connected to office-pc through SMB remote service",
  "evidence_event_ids": [12, 13, 17]
}
```

如果 IP 无法映射到主机名，则 `source_host` 或 `target_host` 保持 `null`，同时保留真实 `source_ip` / `target_ip`。

## 内部处理流程

```text
标准化 EventOut
    ↓
预处理：处理 null、解析时间、读取 detail
    ↓
索引构建：按 host、IP、event_type、session_id 聚合
    ↓
规则检测：识别单类攻击步骤
    ↓
时间窗口关联：补充前后文证据
    ↓
ATT&CK 映射：填充 stage / technique_id / technique_name
    ↓
去重与排序：生成 S001、S002 ...
    ↓
输出 attack_steps
```

## 第一版支持的攻击阶段

| 攻击阶段 | 检测依据 | ATT&CK 映射 |
| --- | --- | --- |
| Initial Access | 外部 IP 访问可疑 HTTP 路径 | `T1190 Exploit Public-Facing Application` |
| Execution | 可疑进程或命令解释器启动 | `T1059 Command and Scripting Interpreter` |
| Persistence | 注册表 Run 键、计划任务、服务创建 | `T1547.001`, `T1053`, `T1543.003` |
| Privilege Escalation | sudo、管理员组变更、权限变化 | `T1548.003`, `T1078` |
| Lateral Movement | 内网主机访问 22/445/3389/5985 等远程服务端口 | `T1021 Remote Services` |
| Collection | 读取敏感文件或执行压缩打包命令 | `T1005 Data from Local System` |
| Command and Control | 内网主机连接外部可疑端口或周期性外联 | `T1071 Application Layer Protocol` |
| Exfiltration | 数据收集后出现大流量外联 | `T1041 Exfiltration Over C2 Channel` |
| Defense Evasion | 日志清除事件 | `T1070.002 Clear Windows Event Logs` |

## 关键算法

### 基于规则的攻击步骤识别

模块使用可解释规则识别攻击行为。例如：

```text
event_type = process_start
process/cmdline 命中 powershell、cmd、bash、curl、wget、nc 等关键词
=> Execution / T1059
```

```text
event_type = registry_set
detail.registry_key 命中 CurrentVersion\Run
=> Persistence / T1547.001
```

### 时间窗口关联

对于横向移动、数据外传等不能只靠单条事件判断的阶段，模块会在事件前后查找上下文证据。

横向移动示例：

```text
源主机前 10 分钟出现可疑执行
随后源主机连接目标主机 445/3389/22/5985
目标主机后 10 分钟出现登录成功或进程启动
=> Lateral Movement / T1021
```

### 图建模

模块提供 `build_attack_graph(attack_steps)`，将攻击步骤抽象为有向图：

```text
节点：主机、外部 IP、C2 IP
边：攻击步骤
```

例如：

```text
45.77.11.23 -> web-server -> office-pc -> core-server -> 47.88.10.9
```

模块还提供 `find_attack_paths(attack_steps)`，用于从攻击图中提取主要攻击路径。

## 当前文件

- `backend/analysis/correlation.py`：D 关联分析核心代码。
- `data/sample_events/d_attack_chain_events.json`：D 模块样例输入数据。
- `scripts/run_correlation_demo.py`：本地演示脚本。

## 运行演示

在项目根目录执行：

```powershell
python scripts/run_correlation_demo.py
```

脚本会输出：

- 攻击步骤 `attack_steps`
- 攻击图 `attack_graph`
- 攻击路径 `attack_paths`


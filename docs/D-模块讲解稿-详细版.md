# D 模块详细讲解稿：攻击关联、攻击链图与攻击者画像溯源

## 1. D 模块在系统中的位置

D 模块负责的是“分析”和“关联”，不是原始数据解析，也不是数据库管理。

系统整体流程可以理解为：

```text
原始数据
  ├─ Windows / Linux 主机日志
  ├─ Sysmon / auditd / auth 日志
  ├─ PCAP / Zeek / 防火墙 / WAF 流量
  ↓
B/C 解析模块
  ↓
统一 Event V2 标准事件
  ↓
A 后端 SQLite 入库并生成数据库内部 id
  ↓
D 关联分析模块
  ├─ ATT&CK 攻击步骤识别
  ├─ 攻击链关联
  ├─ 攻击图构建
  ├─ 证据事件回溯
  └─ 攻击者画像与 APT 相似性分析
  ↓
F 前端展示
```

所以 D 的一句话定位是：

> D 将 A/B/C 提供的标准化 EventOut 事件流，转换为可解释的 ATT&CK 攻击步骤、攻击链图和攻击者画像。

D 不直接读原始 EVTX、PCAP，也不直接解析 raw log。D 假设输入已经是统一格式，重点解决三个问题：

1. 单条事件属于哪个攻击阶段？
2. 多条事件之间是否能组成攻击链？
3. 这些攻击行为体现出什么攻击者工具、脚本、C2 和 TTP 特征？

## 2. 输入与输出

### 2.1 输入函数

D 的主入口是：

```python
correlate_events(events, host_map=None, internal_networks=None)
```

参数含义：

| 参数 | 含义 |
| --- | --- |
| `events` | A 后端返回的 EventOut 列表，已经带数据库内部 `id` |
| `host_map` | IP 到主机名映射，例如 `10.10.30.20 -> core-server` |
| `internal_networks` | 内网网段列表，例如 `10.10.20.0/24`、`10.10.30.0/24` |

### 2.2 EventOut 中 D 主要使用的字段

| 字段 | D 中的作用 |
| --- | --- |
| `id` | 数据库内部事件 ID，用于 evidence 回溯 |
| `case_id` / `detail.batch_id` | 批次隔离，防止不同攻击数据串链 |
| `timestamp` | 时间排序、时间窗口关联 |
| `host` | 主机侧事件所属主机 |
| `source` | 数据来源，例如 `windows_evtx`、`linux_audit`、`network_pcap`、`firewall`、`waf` |
| `event_type` | 行为类型，例如 `process_start`、`http_request`、`network_connection` |
| `user` | 登录、执行、权限变化相关用户 |
| `process` | 进程名，用于执行、持久化、提权、工具识别 |
| `src_ip` / `dst_ip` | 网络关联中的源和目标 |
| `dst_port` / `protocol` | 判断远程服务、C2、HTTP、DNS 等 |
| `logon_type` / `session_id` | 登录会话和横向移动辅助证据 |
| `cmdline` | 命令行特征，识别脚本、工具、压缩、下载、执行 |
| `detail` | 存放特殊字段，例如 `parent_process`、`file_path`、`registry_key`、`uri`、`bytes_out` |
| `anomaly_flags` | B/C 标注的异常语义，例如 `initial_access`、`c2`、`exfiltration` |
| `severity` | 异常严重程度，辅助规则判定 |
| `raw_log` | 原始日志，D 不直接依赖解析，但保留给 evidence 展示 |

### 2.3 输出 AttackStep

D 输出的是攻击步骤列表。每个 AttackStep 表示一次可解释的攻击行为：

```json
{
  "step_id": "S008",
  "stage": "Collection",
  "technique_id": "T1005",
  "technique_name": "Data from Local System",
  "timestamp": "2026-09-09T12:10:54+08:00",
  "source_host": "win10-jump",
  "target_host": "core-server",
  "source_ip": "10.10.30.10",
  "target_ip": "10.10.30.20",
  "description": "win10-jump retrieved sensitive internal resource /finance_demo.txt from core-server",
  "evidence_event_ids": [12345, 12346],
  "case_id": "e_final"
}
```

字段解释：

| 字段 | 含义 |
| --- | --- |
| `step_id` | D 生成的攻击步骤编号 |
| `stage` | ATT&CK 战术阶段 |
| `technique_id` | ATT&CK 技术编号 |
| `technique_name` | ATT&CK 技术名称 |
| `timestamp` | 该攻击步骤的代表时间 |
| `source_host` / `source_ip` | 攻击行为发起方 |
| `target_host` / `target_ip` | 攻击行为目标方 |
| `description` | 面向前端和报告的自然语言解释 |
| `evidence_event_ids` | 支撑该判断的数据库内部 `events.id` |
| `case_id` | 所属攻击批次 |

特别强调：

> `evidence_event_ids` 保存的是数据库内部 `events.id`，不是 Windows 4624、Sysmon 1 这类原始日志编号。

这样前端点击某个攻击步骤时，可以通过这些 ID 反查完整事件、detail 和 raw_log。

## 3. 总体算法流程

D 的主流程不是一个单独的大模型判断，而是“规则关联 + 图建模 + 画像匹配”的组合算法。

整体流程：

```text
输入 EventOut 列表
  ↓
1. 参数校验
  ↓
2. 事件预处理
  ↓
3. 按 case_id / batch_id 分组
  ↓
4. 针对每个 case 独立运行 ATT&CK 检测器
  ↓
5. 生成 AttackStep
  ↓
6. AttackStep 去重、排序、编号
  ↓
7. 基于 AttackStep 构建攻击图
  ↓
8. 提取攻击路径与关键分支
  ↓
9. 提取攻击者指纹、C2 基础设施、APT 相似性候选
```

伪代码如下：

```python
def correlate_events(events, host_map=None, internal_networks=None):
    host_map = host_map or {}
    networks = compile_internal_networks(internal_networks)

    normalized = preprocess_events(events)
    normalized.sort(key=lambda e: e["_time"])

    grouped_events = group_events_by_case(normalized)

    steps = []
    for case_events in grouped_events.values():
        steps.extend(correlate_case_events(case_events, host_map, networks))

    steps = deduplicate_steps(steps)
    steps.sort(key=lambda s: s["timestamp"])

    for index, step in enumerate(steps, start=1):
        step["step_id"] = f"S{index:03d}"

    return steps
```

## 4. 事件预处理算法

### 4.1 为什么要预处理

B/C/A 给 D 的事件字段是统一的，但不同来源的数据有几个现实差异：

- 有的事件有 `host`，有的只有 IP。
- 有的行为在 `event_type` 中，有的补充语义在 `anomaly_flags` 或 `detail` 中。
- 时间需要统一转换成可排序的 `datetime`。
- detail 中的字段可能包含注册表、文件路径、HTTP URI、hash 等。

所以 D 会先把 Event 变成内部增强结构。

### 4.2 预处理做了什么

每条 Event 会补充这些内部字段：

| 内部字段 | 来源 | 用途 |
| --- | --- | --- |
| `_time` | `timestamp` | 时间排序、时间窗口判断 |
| `_detail` | `detail` | 安全读取 detail 内字段 |
| `_event_type` | `event_type.lower()` | 统一事件类型比较 |
| `_host` | `host` | 主机索引 |
| `_source` | `source.lower()` | 区分 WAF、防火墙、PCAP、主机日志 |
| `_user` | `user` | 用户实体 |
| `_process` | `process.lower()` | 进程规则 |
| `_cmdline` | `cmdline.lower()` | 命令行规则 |
| `_parent_process` | `detail.parent_process` | 父进程链分析 |
| `_file_path` | `detail.file_path` | 文件行为 |
| `_registry_key` | `detail.registry_key` | 注册表持久化 |
| `_registry_value_data` | `detail.registry_value_data` | 注册表值数据 |
| `_anomaly_flags` | `anomaly_flags` | 异常语义集合 |
| `_case_id` | `case_id` 或 `detail.case_id` / `detail.batch_id` | 批次隔离 |

## 5. case 隔离算法

为了避免不同攻击样本混在一个数据库里时互相串链，D 会按 `case_id` 或 `detail.batch_id` 分组。

核心思想：

```text
同一个 case 内的事件可以互相关联；
不同 case 的事件不能互相作为 evidence，也不能组成同一条攻击链。
```

这样做的好处：

1. 多个攻击数据可以放在同一个 SQLite 库里。
2. D 不会把 APT29 的主机日志和 CTU13 的网络流量误连起来。
3. 前端可以按批次展示攻击链。
4. evidence_event_ids 仍然是全库唯一的数据库 ID。

## 6. Host Mapping 与网络边界判断

### 6.1 IP 到主机名映射

网络事件里经常只有 IP，例如：

```json
{
  "src_ip": "10.10.30.10",
  "dst_ip": "10.10.30.20",
  "event_type": "http_request"
}
```

D 会通过 `host_map` 把它转换成：

```text
10.10.30.10 -> win10-jump
10.10.30.20 -> core-server
```

这样攻击图里就不是一堆裸 IP，而是有语义的主机节点。

### 6.2 内外网判断

D 使用 `internal_networks` 来判断 IP 属于内网还是外网。

例如 E 数据中：

```text
10.10.20.0/24 -> DMZ 区
10.10.30.0/24 -> 内网办公区 / 服务器区
```

则：

```text
10.10.10.10 -> 外部攻击者
10.10.10.20 -> 外部 C2
10.10.20.10 -> DMZ web-server
10.10.30.10 -> 内网 win10-jump
10.10.30.20 -> 内网 core-server
```

内外网判断是很多规则的基础：

| 行为 | 源 | 目标 |
| --- | --- | --- |
| Initial Access | 外网 | 内网 / DMZ |
| Lateral Movement | 内网 | 内网 |
| Collection | 内网主机 | 内网服务器 / 本机文件 |
| C2 | 内网 | 外网 |
| Exfiltration | 内网 | 外网 |

## 7. ATT&CK 攻击步骤检测算法

D 采用多个检测器，每个检测器负责一个或一类 ATT&CK 阶段。

目前主流程包括：

```text
detect_initial_access
detect_execution
detect_persistence
detect_privilege_escalation
detect_lateral_movement
detect_collection
detect_c2
detect_exfiltration
detect_defense_evasion
```

### 7.1 Initial Access：初始访问

对应 ATT&CK：

```text
T1190 Exploit Public-Facing Application
```

主要判定思路：

```text
外部 IP 访问内部 / DMZ 服务
并且满足以下任一条件：
  - URI 含有明显攻击关键字
  - anomaly_flags 标记 initial_access / web_attack 等
  - WAF 报警
  - 防火墙允许了边界 Web 访问
  - severity >= 2
```

典型输入：

```text
event_type = http_request
src_ip = 10.10.10.10
dst_ip = 10.10.20.10
detail.uri = /vulnerabilities/exec/source.php?cmd=whoami
anomaly_flags = ["initial_access"]
severity = 2
```

输出：

```text
Initial Access / T1190
attack-external -> web-server
```

算法重点：

1. 必须是外部到内部。
2. 不能把普通内部访问当成初始入侵。
3. 会用 `host_map` 把攻击源 IP 和目标 IP 转成节点名称。
4. 会在目标主机后续 10 分钟内找 `process_start` 作为辅助证据。

### 7.2 Execution：命令执行

对应 ATT&CK：

```text
T1059 Command and Scripting Interpreter
```

主要判定思路：

```text
event_type = process_start
并且进程或命令行体现出异常执行语义：
  - powershell / cmd / bash / sh / python 等脚本解释器
  - curl / wget / certutil 等下载执行工具
  - mshta / rundll32 / wmic 等常见 LOLBin
  - 命令行中包含 encoded command、download、反弹 shell 等特征
```

输出一般是本机自环边：

```text
Execution / T1059
web-server -> web-server
```

为什么是自环：

执行行为通常发生在某台主机本机上，不一定有明确远程目标，所以攻击图里用主机到自身表示“该主机上发生了执行行为”。

### 7.3 Persistence：持久化

主要覆盖：

```text
T1547.001 Registry Run Keys / Startup Folder
T1053.005 Scheduled Task
T1543.003 Windows Service
```

判定思路：

1. 注册表持久化：

```text
event_type = registry_set / registry_create
detail.registry_key 命中 Run / RunOnce / Startup 等启动项路径
```

例如：

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

2. 计划任务持久化：

```text
event_type = scheduled_task_created
或 process_start 中出现 schtasks /create
```

3. 服务持久化：

```text
event_type = service_created
或命令行中出现 sc create / New-Service
```

输出：

```text
Persistence / T1547.001
win10-jump -> win10-jump
```

### 7.4 Privilege Escalation：权限提升

主要覆盖：

```text
T1078 Valid Accounts
T1548.003 Sudo and Sudo Caching
```

判定思路：

1. 权限变化事件：

```text
event_type = privilege_change
```

2. 用户被加入管理员组：

```text
event_type = group_member_added
detail.group_name 包含 admin / sudo
```

3. sudo 或高权限命令执行：

```text
event_type = process_start
cmdline 或 process 中体现 sudo / su / 高权限执行语义
```

输出：

```text
Privilege Escalation / T1548.003
core-server -> core-server
```

### 7.5 Lateral Movement：横向移动

对应 ATT&CK：

```text
T1021 Remote Services
```

判定思路：

```text
event_type = network_connection
src_ip 是内网
dst_ip 是内网
dst_port 是远程服务端口
```

典型远程服务：

| 端口 | 服务 |
| --- | --- |
| 22 | SSH |
| 3389 | RDP |
| 445 | SMB |
| 5985 / 5986 | WinRM |

输出：

```text
Lateral Movement / T1021
web-server -> win10-jump
```

关联证据增强：

1. 在源主机前 10 分钟查找可疑 `process_start`。
2. 在目标主机后 10 分钟查找 `login_success`、`process_start`、`service_created`。
3. 这些事件都会放进 `evidence_event_ids`。

这说明 D 不是只看一条网络连接，而是把连接前后的主机行为也纳入证据。

### 7.6 Collection：数据收集

对应 ATT&CK：

```text
T1005 Data from Local System
```

Collection 有三类来源：

1. 敏感文件读取 / 创建 / 写入：

```text
event_type in file_read / file_write / file_create
file_path 命中敏感目录、敏感后缀或敏感文件名
```

2. 压缩打包命令：

```text
process_start 中出现 zip / rar / tar / 7z / Compress-Archive 等
```

3. 内网 HTTP 资源访问：

```text
event_type = http_request
src_ip 是内网主机
dst_ip 是内网服务器
method = GET
uri 指向文件或资源
并且目标主机附近存在敏感文件行为，或 URI 本身是敏感资源
```

E 数据中的关键例子：

```text
10.10.30.10 -> 10.10.30.20:9100
GET /finance_demo.txt HTTP/1.1
```

经过 host_map：

```text
win10-jump -> core-server
```

D 判定为：

```text
Collection / T1005
win10-jump retrieved sensitive internal resource /finance_demo.txt from core-server
```

注意这里没有硬编码：

```text
没有硬编码 10.10.30.10
没有硬编码 10.10.30.20
没有硬编码 9100
没有硬编码 /finance_demo.txt
```

它判断的是通用语义：

```text
内部主机 -> 内部服务器
HTTP GET 文件资源
资源名或目标侧文件行为体现敏感数据访问
```

为什么不判成 Lateral Movement：

`win10-jump -> core-server` 这一步不是 SSH/RDP/SMB/WinRM 远程登录或远程服务控制，而是 HTTP 读取内部文件资源，所以更符合 Collection，而不是 T1021 横向移动。

### 7.7 Command and Control：C2 通信

对应 ATT&CK：

```text
T1071 Application Layer Protocol
```

判定思路：

```text
内网主机 -> 外部 IP / 域名
并且满足以下任一条件：
  - 短时间内重复连接
  - 目标端口属于可疑 C2 端口
  - anomaly_flags 中有 c2 / beacon / external_connection
  - DNS 查询过长或被标记为 dns_tunnel / c2
```

重复连接规则：

```text
同一 source_host + dst_ip + dst_port
30 分钟内出现 >= 3 次
```

误报控制：

如果某个外部 IP 已经被识别为 Initial Access 的攻击源，例如：

```text
10.10.10.10 -> web-server
```

那么后续内网对 `10.10.10.10` 的普通回连，不能轻易再判成 C2，除非它有强 C2 证据：

```text
c2 / beacon 标记
可疑 C2 端口
明确 external_connection 语义
```

这样可以避免把“攻击者入口 IP”误标成“C2 服务器”。

E 数据中正确结果：

```text
attack-external 10.10.10.10 是攻击源
c2-server 10.10.10.20 是 C2
```

### 7.8 Exfiltration：数据外传

对应 ATT&CK：

```text
T1041 Exfiltration Over C2 Channel
```

判定思路：

```text
内网主机 -> 外部目标
并且满足：
  - bytes_out >= 5MB
  - 或 anomaly_flags 包含 exfiltration / large_upload
```

为了降低误报，D 还会检查该主机此前 30 分钟是否出现：

```text
敏感文件读取
压缩打包命令
数据收集行为
```

也就是 D 希望看到：

```text
先收集数据，再向外传输
```

而不是单独看到一次大流量就马上判定为外传。

### 7.9 Defense Evasion：防御规避

对应 ATT&CK：

```text
T1070.002 Clear Windows Event Logs
```

判定思路：

```text
event_type = log_cleared
```

这是攻击者抹除痕迹的典型动作。如果 B/C/A 提供 `log_cleared`，D 会映射到 Defense Evasion 阶段。

## 8. 时间窗口关联算法

D 中很多攻击步骤不是单事件判断，而是“主事件 + 附近证据”的组合。

核心函数思想：

```python
find_events_in_window(
    events,
    center_time,
    before_minutes=10,
    after_minutes=10,
    event_types={"process_start", "login_success"}
)
```

含义：

```text
以某个关键事件为中心，
向前或向后查找指定时间窗口内的相关事件，
把它们合并为同一个 AttackStep 的 evidence。
```

例子：

```text
web-server -> win10-jump 的 SSH 连接
```

D 会补充查找：

```text
连接前 web-server 上是否有可疑命令执行
连接后 win10-jump 上是否有登录成功或进程启动
```

这样输出的不是孤立的一条网络边，而是跨源证据组合：

```text
网络连接 + 源主机执行 + 目标主机登录/执行
```

这正好对应课程题目里要求的：

> 主机日志、主机行为、网络流量等多源数据采集与融合。

## 9. 攻击图构建算法

### 9.1 节点和边的抽象

D 会把 AttackStep 转成图结构。

节点：

```text
主机
攻击者外部 IP
C2 服务器
内部服务器
```

边：

```text
一次 AttackStep
```

例如：

```json
{
  "source": "host:win10-jump",
  "target": "host:core-server",
  "attack_stage": "Collection",
  "mitre_technique": "T1005",
  "evidence_event_ids": [120, 121]
}
```

### 9.2 图论模型

攻击图本质上是一个有向图：

```text
G = (V, E)
```

其中：

```text
V = 主机、攻击者、C2、外部基础设施
E = 攻击步骤
```

一条边表示：

```text
攻击行为从 source 指向 target
```

例如：

```text
attack-external -> web-server
web-server -> win10-jump
win10-jump -> core-server
win10-jump -> c2-server
```

### 9.3 路径搜索算法

为了从攻击图中提取攻击路径，D 使用 BFS 思想搜索路径。

基本思路：

1. 先统计所有节点的入边。
2. 入度为 0 的节点作为可能入口。
3. 从入口开始广度优先搜索。
4. 避免路径中重复节点，防止环路无限扩展。
5. 记录所有长度大于 1 的路径。
6. 按路径长度排序，得到候选攻击路径。

伪代码：

```python
def find_attack_paths(attack_steps):
    graph = build_attack_graph(attack_steps)
    adjacency = build_adjacency(graph.edges)
    entries = nodes_without_incoming_edges()

    paths = []
    for entry in entries:
        queue = [(entry, [entry])]
        while queue:
            current, path = queue.pop(0)
            next_nodes = adjacency[current]

            if not next_nodes:
                paths.append(path)
                continue

            for next_node in next_nodes:
                if next_node not in path:
                    queue.append((next_node, path + [next_node]))

    return sorted(paths, key=len, reverse=True)
```

### 9.4 攻击链和攻击图的关系

可以这样讲：

```text
攻击链是图中的一条路径；
攻击图是多条路径和分支叠加后的整体结构。
```

例如 E 数据不是一条完全直线，而是有分支：

```text
attack-external
      ↓
web-server
      ↓
win10-jump
   ├──→ core-server
   └──→ c2-server
```

其中：

```text
attack-external -> web-server -> win10-jump -> core-server
```

是数据访问路径。

```text
attack-external -> web-server -> win10-jump -> c2-server
```

是 C2 通信路径。

所以攻击图比攻击链更完整。前端图展示的是整体攻击图，报告里的主路径则是从图中提取出的关键叙事路径。

## 10. 生命周期叙事路径算法

实际攻击图可能存在并行分支。如果只取 BFS 最长路径，可能出现问题：

```text
win10-jump 同时指向 core-server 和 c2-server
```

如果两个分支长度相同，普通 BFS 可能选中 C2 分支，导致报告里看不到 core-server。

所以 D 在报告路径中增加了生命周期叙事路径：

```text
Initial Access
  ↓
Lateral Movement
  ↓
Collection
  ↓
Command and Control / Exfiltration
```

对于 E 数据，最终叙事路径是：

```text
attack-external -> web-server -> win10-jump -> core-server -> c2-server
```

这里要注意：

```text
core-server -> c2-server 不一定表示真实网络边；
它表示报告叙事顺序中先访问核心数据，再发生 C2 / 外传相关行为。
```

真实图边仍然是：

```text
win10-jump -> core-server
win10-jump -> c2-server
```

也就是说：

```text
图负责表达真实关系；
报告路径负责表达攻击过程叙事。
```

## 11. evidence 证据保留机制

D 的每个判断都尽量保留证据。

例如横向移动步骤可能包含：

```text
网络连接事件 id
源主机可疑命令执行事件 id
目标主机登录成功事件 id
目标主机进程启动事件 id
```

这些 ID 统一放在：

```json
"evidence_event_ids": [12, 13, 17]
```

设计目的：

1. 前端可以点击攻击步骤查看原始证据。
2. 报告中的结论不是黑箱生成。
3. 老师追问“你为什么这么判断”时，可以回到具体事件。
4. D 不需要保存 raw_log 副本，只保存数据库 ID，避免数据冗余。

## 12. 攻击者画像与身份溯源算法

攻击者画像模块入口：

```python
build_attribution_profile(events, attack_steps, host_map, apt_profiles, threat_intel, internal_networks)
```

它解决的是课程要求中的：

> 从攻击工具、脚本、配置文件中提取攻击者指纹特征，分析攻击者和 C2 服务器的基础设施关联信息，开展行为模式分析和组织特征匹配。

### 12.1 画像提取对象

D 会从事件和 AttackStep 中提取：

| 类型 | 来源 |
| --- | --- |
| ATT&CK 技术编号 | AttackStep 的 `technique_id` |
| ATT&CK 阶段序列 | AttackStep 的 `stage` 时间序列 |
| 工具 | `process`、`cmdline`、`raw_log` |
| 脚本 | `.ps1`、`.bat`、`.sh`、`.py` 等路径 |
| 配置文件 | `.conf`、`.cfg`、`.ini`、`.json`、`.xml`、`.yaml` 等 |
| 压缩包 | `.zip`、`.rar`、`.7z`、`.tar.gz` 等 |
| 注册表键 | `detail.registry_key` |
| 文件 hash | `detail.hashes` |
| 域名 | URL、DNS query、HTTP Host |
| 外部 IP | C2、外传目标、攻击源 |
| 用户 | 相关事件中的 `user` |
| 命令行 | 高价值事件中的 `cmdline` |

为了减少噪声，画像模块不是扫描所有普通事件，而是优先扫描：

```text
AttackStep 的 evidence 事件
带 anomaly_flags 的异常事件
severity >= 2 的高风险事件
```

### 12.2 工具和脚本指纹

工具提取主要看：

```text
process
cmdline
raw_log
description
```

例如：

```text
powershell.exe
cmd.exe
bash
curl
wget
certutil
mshta
rundll32
wmic
nmap
netcat
```

脚本和配置文件通过路径正则识别，例如：

```text
C:\Users\Public\updater.ps1
/tmp/reverse.sh
config.json
c2_profile.conf
```

这些特征的意义是：

```text
不同攻击组织或攻击工具链往往有稳定的工具偏好、脚本形态和配置习惯。
```

### 12.3 C2 基础设施提取

C2 基础设施来自两类证据：

1. AttackStep 中的 C2 / Exfiltration 目标。
2. 原始事件中被标记为 C2、beacon、external_connection、dns_tunnel、large_upload 的外部连接或 DNS 查询。

提取字段包括：

```text
ip
domains
ports
protocols
first_seen
last_seen
source_hosts
source_ips
evidence_event_ids
registration
history
related_domains
intel
```

其中：

| 字段 | 含义 |
| --- | --- |
| `registration` | 注册信息，例如组织、国家、ASN、注册商等 |
| `history` | 历史观察记录，例如曾被用作 C2、恶意样本回连等 |
| `related_domains` | 关联域名 |
| `intel` | 本地威胁情报命中详情 |

当前实现是课程设计合理范围内的本地威胁情报增强：

```text
data/threat_intel/c2_intel.json
```

也就是说，它不是实时联网查 WHOIS，而是模拟真实安全平台中常见的“本地威胁情报库匹配”。

这样做有两个好处：

1. 演示稳定，不受网络影响。
2. 老师可以看到 C2 注册信息、历史记录、关联域名这类字段已经进入算法和前端。

### 12.4 APT 相似性匹配

画像模块会把观测到的攻击者画像和本地 APT 画像库比较。

APT 画像库位置：

```text
data/threat_intel/apt_profiles.json
```

每个 APT profile 可以包含：

```text
group_id
name
aliases
techniques
technique_names
tools
behavior_sequence
infrastructure_tags
description
source_refs
```

匹配不是“确认归属”，而是“行为相似性候选”。

输出中会明确说明：

```text
TTP similarity match only, not confirmed attribution.
```

### 12.5 相似度算法

当前相似度由两部分组成：

```text
最终分数 = 0.7 * 规则相似度 + 0.3 * 语义相似度
```

规则相似度又由四部分构成：

```text
规则相似度 =
  0.55 * technique_score
  + 0.20 * tool_score
  + 0.15 * sequence_score
  + 0.10 * infra_score
```

解释：

| 分数 | 含义 |
| --- | --- |
| `technique_score` | ATT&CK 技术编号重合度 |
| `tool_score` | 工具重合度 |
| `sequence_score` | 攻击阶段序列相似度 |
| `infra_score` | C2 / 基础设施标签相似度 |
| `semantic_score` | 文本画像的 token cosine 相似度 |

#### technique_score

计算方式：

```text
观测到的 technique_id 与 APT profile 中 technique_id 的交集覆盖率
```

例如：

```text
观测：T1190, T1059, T1021, T1005, T1071
APT29：T1059, T1021, T1005, T1071, T1567
匹配：T1059, T1021, T1005, T1071
```

匹配越多，分数越高。

#### tool_score

计算方式：

```text
观测工具集合 与 APT profile 工具集合 的归一化匹配程度
```

会做简单标准化，例如：

```text
powershell.exe -> powershell
cmd.exe -> cmd
```

#### sequence_score

使用最长公共子序列思想：

```text
Observed sequence:
Initial Access -> Execution -> Lateral Movement -> Collection -> C2

APT profile sequence:
Initial Access -> Execution -> Persistence -> Lateral Movement -> Collection -> C2
```

两者的共同顺序越一致，说明行为模式越接近。

这里用 LCS 的原因是：

```text
攻击步骤中可能缺少某些阶段，或者检测结果有噪声；
但只要整体顺序相似，仍然应该得到一定分数。
```

#### infra_score

比较 C2 基础设施标签，例如：

```text
cloud-hosting
dynamic-dns
bulletproof-hosting
known-c2
```

#### semantic_score

把观测画像拼成文本，再和 APT profile 文本做 token cosine 相似度。

当前是轻量文本相似度，不依赖外部 embedding 服务。

设计原因：

1. 小学期项目需要可离线运行。
2. 不依赖 API key。
3. 结果可解释。

如果后续扩展，可以把这一项替换为 embedding 相似度：

```text
semantic_score = cosine(embedding(observed_profile_text), embedding(apt_profile_text))
```

但当前实现选择轻量算法，更适合演示环境。

### 12.6 无证据时的保护

如果没有有效 Event、AttackStep、TTP 或 C2 证据，画像模块不会强行返回 APT29/APT28/FIN7。

而是返回：

```text
attribution_status = insufficient_evidence
apt_matches = []
```

这样避免“没有证据也硬猜一个组织”的问题。

## 13. E 数据上的实际分析结果

当前 E 数据导入后：

```text
事件数：47775
主机映射：9
批次：e_final
```

攻击图包含 5 个关键节点：

```text
attack-external
web-server
win10-jump
core-server
c2-server
```

关键攻击边：

```text
Initial Access:
attack-external 10.10.10.10 -> web-server 10.10.20.10

Lateral Movement:
web-server 10.10.20.10 -> win10-jump 10.10.30.10

Collection:
win10-jump 10.10.30.10 -> core-server 10.10.30.20

Command and Control:
win10-jump 10.10.30.10 -> c2-server 10.10.10.20
```

叙事路径：

```text
attack-external -> web-server -> win10-jump -> core-server -> c2-server
```

对应课程 PDF 中的要求：

| PDF 要求 | D 中的实现 |
| --- | --- |
| 通过边界设备日志识别初始入侵点 | Initial Access 检测外部到 DMZ / 内网的 WAF、防火墙、HTTP 异常 |
| 基于认证日志和网络连接追踪内网移动路径 | Lateral Movement 结合内网远程服务连接、登录和进程行为 |
| 分析权限提升路径 | privilege_change、group_member_added、sudo / 高权限命令 |
| 跟踪数据从存储到外传路径 | Collection + Exfiltration / C2，识别内部文件资源访问和外部连接 |
| 构建攻击点关系图 | AttackStep 转有向图节点和边 |
| 与已知 APT 组织 TTP 匹配 | APT profile 相似度匹配 |
| 攻击者身份溯源 | 提取工具、脚本、配置、注册表、C2 和基础设施特征 |

## 14. D 模块的技术特点

### 14.1 多源事件融合

D 同时使用：

```text
主机日志
主机行为
网络流量
防火墙
WAF
```

例如横向移动不是只看网络连接，还会补充前后主机事件。

### 14.2 可解释规则

每条 AttackStep 都能解释：

```text
为什么是这个阶段
为什么是这个技术编号
证据事件有哪些
源和目标是谁
```

这比单纯用大模型输出结论更适合课程答辩。

### 14.3 图论表达攻击链

D 不是只输出文字，而是把攻击行为抽象成：

```text
节点 + 有向边 + evidence
```

这样前端可以展示攻击图，也可以从图中抽取路径。

### 14.4 批次隔离

按 case 分析，防止多数据集混合时串链。

### 14.5 误报控制

例如 C2 规则中：

```text
初始攻击源 IP 不会因为普通回连被误判成 C2
```

Collection 规则中：

```text
普通 HTTP 文件访问不会直接判定为数据收集；
需要敏感资源语义或目标主机附近有敏感文件行为。
```

### 14.6 画像结果谨慎表达

APT 匹配输出的是：

```text
行为相似性候选
```

不是：

```text
确定真实攻击组织
```

这符合安全分析中的严谨表述。

## 15. 可以在答辩中重点讲的算法点

### 15.1 规则检测不是简单 if-else，而是多条件证据组合

例如横向移动：

```text
内网到内网
远程服务端口
源主机前序可疑执行
目标主机后续登录/执行
```

这些证据共同支撑 T1021。

### 15.2 使用时间窗口进行跨源关联

例如：

```text
网络连接发生后 10 分钟内目标主机出现登录成功
```

比单条日志判断更可信。

### 15.3 使用图算法表示攻击关系

D 把 AttackStep 转成有向图，然后用 BFS 提取路径。

这个图既能表示主线攻击链，也能表示分支行为。

### 15.4 使用 LCS 比较行为序列

APT 相似性不是只看单个工具，而是看攻击阶段顺序是否接近。

例如：

```text
Initial Access -> Execution -> Persistence -> Lateral Movement -> Collection -> C2
```

这种序列比单点 IOC 更能体现 TTP。

### 15.5 使用 evidence_event_ids 保证可追溯

D 每一步输出都保留数据库事件 ID，可以反查原始日志。

这使系统具备：

```text
可解释性
可验证性
可审计性
```

## 16. 局限性与合理说明

答辩时如果被问到局限，可以这样说：

1. D 当前是规则驱动为主，优点是可解释，缺点是依赖 B/C 解析出的语义质量。
2. C2 注册信息、历史记录、关联域名当前来自本地威胁情报库，不是实时联网查询。
3. APT 匹配是 TTP 相似性，不代表法律意义上的攻击者身份确认。
4. 如果输入事件缺少关键字段，例如没有 `src_ip`、`dst_ip`、`event_type` 或 `detail.uri`，部分规则无法触发。
5. 攻击图展示真实关系，报告叙事路径展示生命周期顺序，两者关注点不同。

## 17. 讲解时可以直接使用的总结

D 模块首先对 A 后端返回的统一 EventOut 进行预处理，统一时间、事件类型、detail 字段和 case_id。然后按批次隔离事件，避免不同攻击样本互相串链。在每个 case 内，D 使用一组面向 ATT&CK 的检测器，分别识别初始访问、命令执行、持久化、权限提升、横向移动、数据收集、C2 通信、数据外传和防御规避等阶段。

每个检测器不是只依赖单条日志，而是结合内外网方向、端口、命令行、异常标记、severity、host_map 和时间窗口进行综合判断。例如横向移动要求内网到内网的远程服务连接，并补充连接前后的主机执行或登录证据；数据收集会识别敏感文件访问、压缩命令以及内网 HTTP 文件资源读取。

识别出的攻击行为会被转换为 AttackStep，每个 AttackStep 都包含 ATT&CK 阶段、技术编号、源主机、目标主机、描述和 evidence_event_ids。这里的 evidence_event_ids 使用数据库内部事件 ID，因此前端可以回溯到完整原始日志。

随后 D 将 AttackStep 构造成有向攻击图，节点表示攻击者、主机、核心服务器和 C2 基础设施，边表示攻击步骤。攻击链可以看作攻击图中的一条路径，而攻击图可以表示多条路径和分支活动的叠加。对于 E 数据，系统识别出的关键过程是 attack-external 入侵 web-server，随后 web-server 横向移动到 win10-jump，win10-jump 访问 core-server 上的内部数据资源，并与 c2-server 发生 C2 通信。

最后，D 会从攻击步骤和证据事件中提取攻击者画像，包括工具、脚本、配置文件、注册表键、外部 IP、域名、C2 基础设施和 ATT&CK TTP 序列，并与本地 APT 画像库进行相似性匹配。匹配算法结合技术编号覆盖率、工具重合度、行为序列 LCS 相似度、基础设施标签和文本语义相似度，输出的是行为相似性候选，而不是绝对身份确认。

## 18. 讲解关键词

可以记住这几个关键词：

```text
EventOut
AttackStep
ATT&CK Mapping
case_id 隔离
host_map 映射
时间窗口关联
多源证据融合
有向攻击图
BFS 路径搜索
生命周期叙事路径
evidence_event_ids 回溯
攻击者指纹
C2 基础设施
APT TTP 相似性匹配
```


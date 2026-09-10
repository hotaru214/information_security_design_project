# B模块：主机日志解析器

把 Windows/Linux 主机日志解析成全组统一的标准安全事件JSON。**契约：Event V2 FINAL（2026-09-08 A发布冻结，19字段；原始事件编号字段统一命名 `source_event_id`；`detail.batch_id` 由批次导入流程 `scripts/reset_import_export.py` 注入）**，见 `../../docs/Event-V2-FINAL.md`（唯一权威版本；旧版 `数据格式契约-v1.md` 已废止）。
（2026-09-08 起本模块位于 `backend/b_host_parser/`，与A的后端同仓。）

## 当前能力（Day 2）

| 输入 | 事件 | 输出 event_type |
|---|---|---|
| Windows Security .evtx | 4624 登录成功 | login_success（含session_id） |
| Windows Security .evtx | 4625 登录失败 | login_failed（含SubStatus失败原因） |
| Windows Security .evtx | 4634/4647 注销 | logout（session_id与4624同键，供会话配对） |
| Windows Security .evtx | 4688 进程创建 | process_start（cmdline取决于审核策略，没有就null） |
| Windows Security .evtx | 1102 审计日志被清除 | log_cleared（T1070.002） |
| Windows Security .evtx | 4720 新建账号 | user_created |
| Windows Security .evtx | 4728 成员加入组 | group_member_added（detail里组名/成员分开） |
| Windows Security .evtx | 4673 权限使用 | privilege_change |
| Windows Security .evtx | 7045 服务安装 | service_created（持久化证据） |
| Windows Security .evtx | 4698 计划任务创建 | scheduled_task_created（持久化证据） |
| Sysmon .evtx | ID 1 进程创建 | process_start（cmdline+父进程+哈希） |
| Sysmon .evtx | ID 3 网络连接 | network_connection（src/dst IP+端口+协议，对齐网络事件字段） |
| Sysmon .evtx | ID 11 文件创建 | file_create |
| Sysmon .evtx | ID 13 注册表键值 | registry_set |
| Linux auth.log | sshd Accepted/Failed | login_success / login_failed（含invalid_user线索；合成样本见 data/sample_logs/linux/） |
| Linux audit.log | sudo USER_CMD（HEX命令解码） | process_start（sudo信息放detail，D决议） |
| Linux audit（原始/ausearch -i解释 双格式） | execve + EXECVE | process_start（完整命令行cmdline） |
| Linux audit（同上） | open/openat + PATH/CWD | file_read / file_write（按open flags区分读写，D的外传/落盘匹配用；相对路径自动拼CWD成绝对路径） |
| Linux audit（同上） | connect/accept + SOCKADDR(仅inet) | network_connection（本地unix socket噪音自动跳过） |
| Linux audit（同上） | SERVICE_START / SERVICE_STOP | service_started / service_stopped |

auditd双格式说明：E交付的 `audit.log` 是原始格式（epoch+数字字段+行尾AUID富字段），`ausearch -i` 导出的txt是解释格式（中文locale时间戳+名字字段）——两种都直接吃，同一事件跨文件按审计序号自动去重。E真实数据样例在 `data/e_case01_linux/`。

附加能力（Day2）：
- **会话重建**（`sessions.py`）：4624↔4634/4647 按 `(host, LogonId)` 配对成会话，登录事件补 `logout_time/session_duration_s`，未注销标 `active`，孤儿注销标 `no_login_record`；整批汇总存 `all_sessions.json`。
- **异常预标记**（`anomaly.py`）：5条规则（offhour_login/brute_force/username_enumeration/encoded_exec/remote_download）→ `anomaly_flags` + `severity(0-3)`，幂等可重跑。
- **全量导入**（`run_parse.py --dir`）：递归解析文件夹，双层容错（按条+按文件），末尾打印按文件分组统计，直接抄进《测试分析报告》。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 解析样例（项目自带4份真实攻击样本evtx，见 ../../data/sample_logs/）
python run_parse.py "..\..\data\sample_logs\sample_4624_4625.evtx"

# 3. 结果落地 .jsonl（A的接口没就绪时的标准用法）
python run_parse.py "..\..\data\sample_logs\sample_4624_4625.evtx" --out "..\..\data\output\events.jsonl"

# 4. 任务9·全量导入整个文件夹（末尾打印统计）
python run_parse.py --dir "..\..\data\sample_logs"

# 5. 联调：直接发给A的后端（A启动FastAPI后）
python run_parse.py <文件.evtx> --post http://127.0.0.1:8000/api/events/import
```

自检：`python verify_day1.py`（Day1产出回归）+ `python verify_day2.py`（Day2新功能，6项）。

## 文件结构

```
backend/b_host_parser/
├── schema.py          # 标准事件结构（任务1契约的代码版，19字段+V2词表），所有解析器共用
├── windows_evtx.py    # Windows Security解析器（4624/4625/4634/4647/4688/1102/4720/4728/4673/7045/4698）
├── sysmon.py          # Sysmon日志解析器（ID 1/3/11/13）
├── sysmon_json.py     # JSON行格式Windows日志适配器（APT29等已导出数据集）
├── sessions.py        # 任务7b：登录↔注销会话重建（(host,LogonId)配对）
├── anomaly.py         # 任务8：异常预标记规则引擎（5条规则→anomaly_flags+severity）
├── import_client.py   # 落地.jsonl / 批量POST给A
├── run_parse.py       # 命令行入口（单文件 / --dir 全量导入）
├── verify_day1.py     # 一键自检（Day1产出回归，7项）
├── verify_day2.py     # 一键自检（Day2新功能，6项）
└── requirements.txt
```

## E 最终批次导出（2026-09-09，A 封箱合并用）

一条命令从 E 最终原始主机日志复现整批标准事件（47,055 条，全过 C 侧 `validate_events` 预检）：

```bash
python backend/b_host_parser/build_e_final_batch.py          # → data/output/e_final_host_events.json
python scripts/reset_import_export.py --name e_final_host \
    --events data/output/e_final_host_events.json --hosts data/hosts_e_case01.csv
# → data/sample_events/e_final_host_eventout.json（EventOut，id 1~47055，batch_id=e_final_host）
```

覆盖输入：core-server 的 `core-auth.log`（**rsyslog ISO 8601 时间格式已支持**，见 linux_log.py `_AUTH_HEAD_ISO`）+ 三个 auditd txt、web-server 的三个 auditd txt、office-win 的 `security-final.evtx` + `system-final.evtx`。evtx 的 Computer 字段（DESKTOP-88HQCN9/WIN-UL7KE8FN5I6）自动对齐成 `hosts_e_case01.csv` 里的靶机名 win10-jump。eventout 约 72MB，按 apt29 先例保持未跟踪、不进 git。

## 给A同学（联调状态：✅ 已打通）

- **模块已在本仓库 `backend/b_host_parser/`**，与你的 FastAPI 同仓，无框架依赖（只依赖 `python-evtx`、`requests`）。
- **你的后端已按契约对齐**（19字段 `/api/events/import` + hosts表），2026-09-08 实测：B 解析的 220 条 E 真实事件全部入库，`detail`/`anomaly_flags` JSON 列无损，`GET /api/events` 核对一致。
- 主机名映射：E 的 `data/hosts.csv` 可用你的 `POST /api/hosts/batch` 直接导入；B 侧 Linux 事件用 `--linux-host` 传主机名（E 的 auditd 行内没有主机名，当前按 hosts.csv 定为 `core-server`，待E最终确认）。
- **还差的**：`POST /api/db/reset` 清库接口（Day3 任务10 回归测试要用）；F 页面侧验证（任务4的最后一环）。

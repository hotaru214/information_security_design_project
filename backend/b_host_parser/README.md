# B模块：主机日志解析器

把 Windows/Linux 主机日志解析成全组统一的标准安全事件JSON。**契约：Event V2（2026-09-07冻结，19字段；2026-09-08 D确认补充 `log_cleared`）**，见 `../../docs/数据格式契约-v1.md`。
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
| Linux auth.log | sshd Accepted/Failed | login_success / login_failed（E数据到位后联调） |
| Linux audit.log | sudo USER_CMD / 敏感文件 | process_start(带sudo detail) / file_read（E数据到位后联调） |

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
├── sessions.py        # 任务7b：登录↔注销会话重建（(host,LogonId)配对）
├── anomaly.py         # 任务8：异常预标记规则引擎（5条规则→anomaly_flags+severity）
├── import_client.py   # 落地.jsonl / 批量POST给A
├── run_parse.py       # 命令行入口（单文件 / --dir 全量导入）
├── verify_day1.py     # 一键自检（Day1产出回归，7项）
├── verify_day2.py     # 一键自检（Day2新功能，6项）
└── requirements.txt
```

## 给A同学（合并工程时看）

- 把本目录4个py文件拷进 `backend/parsers/` 即可，无第三方框架依赖，只依赖 `python-evtx` 和 `requests`（requests仅在import_client用到）。
- 建表按契约的17个字段来，`detail` 用JSON字符串列存。
- 清库请提供 `POST /api/db/reset`，B不直接操作数据库。

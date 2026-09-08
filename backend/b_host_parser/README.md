# B模块：主机日志解析器

把 Windows/Linux 主机日志解析成全组统一的标准安全事件JSON。**契约：Event V2（2026-09-07冻结，19字段）**，见 `../../docs/数据格式契约-v1.md`。

## 当前能力（Day 1.5）

| 输入 | 事件 | 输出 event_type |
|---|---|---|
| Windows Security .evtx | 4624 登录成功 | login_success（含session_id） |
| Windows Security .evtx | 4625 登录失败 | login_failed（含SubStatus失败原因） |
| Windows Security .evtx | 4688 进程创建 | process_start（cmdline取决于审核策略，没有就null） |
| Sysmon .evtx | ID 1 进程创建 | process_start（cmdline+父进程+哈希） |
| Sysmon .evtx | ID 3 网络连接 | network_connection（src/dst IP+端口+协议，对齐网络事件字段） |
| Sysmon .evtx | ID 11 文件创建 | file_create |
| Sysmon .evtx | ID 13 注册表键值 | registry_set |

event_type词表按D《Event V2 event_type 规范》冻结；解析器自动识别日志类型（Security还是Sysmon）。其他事件ID计入统计，不中断。
Day 2 待扩展：4634/4647会话重建、按D最小集合补齐4720/4728/4673/7045/4698、1102（log_cleared待D确认）、Linux auth.log/auditd、异常预标记规则。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 解析样例（项目自带两份真实攻击样本evtx，见 ../../data/sample_logs/）
python run_parse.py "..\..\data\sample_logs\sample_4624_4625.evtx"

# 3. 结果落地 .jsonl（A的接口没就绪时的标准用法）
python run_parse.py "..\..\data\sample_logs\sample_4624_4625.evtx" --out "..\..\data\output\events.jsonl"

# 4. 联调：直接发给A的后端（A启动FastAPI后）
python run_parse.py <文件.evtx> --post http://127.0.0.1:8000/api/events/import
```

## 文件结构

```
b_host_parser/
├── schema.py          # 标准事件结构（任务1契约的代码版，19字段），所有解析器共用
├── windows_evtx.py    # Windows系统日志解析器（4624/4625/4688）
├── sysmon.py          # Sysmon日志解析器（ID 1/3/11/13）
├── import_client.py   # 落地.jsonl / 批量POST给A
├── run_parse.py       # 命令行入口（自动识别Sysmon/Security日志）
├── verify_day1.py     # 一键自检脚本
└── requirements.txt
```

## 给A同学（合并工程时看）

- 把本目录4个py文件拷进 `backend/parsers/` 即可，无第三方框架依赖，只依赖 `python-evtx` 和 `requests`（requests仅在import_client用到）。
- 建表按契约的17个字段来，`detail` 用JSON字符串列存。
- 清库请提供 `POST /api/db/reset`，B不直接操作数据库。

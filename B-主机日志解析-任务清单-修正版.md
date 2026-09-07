# B（主机日志解析）三天任务清单 · 修正版

> **你的定位**：把 Windows/Linux 主机日志变成全组共用的"标准化安全事件流"。
> **依据**：《2026网络空间安全课程设计》任务书·题目3 原文——你负责的部分有 **4条硬要求**，下表是本清单与它的对应关系（验收时按这个查）：

| 任务书对"主机日志"的要求 | 覆盖任务 |
|---|---|
| 1. 时间序列对齐、统一时钟源 | 任务1（时区约定）+ 任务3（UTC→UTC+8转换） |
| 2. 日志范式解析（统一格式） | 任务3、6、7（核心工作） |
| 3. 关键实体提取：**用户、进程、文件、注册表键值** | 任务7（Sysmon 1/11/13）+ 任务6（Linux） |
| 4. **登录会话重建**（登录/注销→会话时间线+源IP） | 任务7b（新增，任务书原文要求，别漏） |

**日程锚点**：Day1=9/8（周二）、Day2=9/9（周三）、Day3=9/10（周四）；**9/11 全组预演 + 去沙河N103试演示环境**（任务书明确建议提前一天试）；**9/12 验收考核**（每组15分钟 PPT+演示），**当晚20:00前**提交全部材料。三天刚好，一天都不能往后拖。

---

## 📅 Day 1（9/8）：打通"原始日志 → 标准JSON → 数据库 → 页面"链路

**目标：一条真实Windows日志，今晚出现在前端Dashboard上。**

- [ ] **任务1：对齐数据格式（与A、D开小会，30分钟，今天最重要的一件事）**
  定死四件事，之后谁都不许单方面改：
  - **JSON契约**（见文末附录A的标准事件结构）；
  - **event_type 枚举**（统一词表，和C共用一套）：`login_success / login_failure / logoff / process_create / file_create / registry_set / network_connect / account_created / log_cleared`；
  - **host 命名规则**：统一用靶机主机名（如 `web-server`），Windows取evtx的Computer字段，需要的话配一张"主机名↔IP"映射表给D——D的关联引擎全靠这个字段join；
  - **时区约定**：所有事件统一输出 **UTC+8**（`2026-09-08 13:05:02+08:00`），同步给C，否则时间线对不齐、凌晨规则全错。
  - 顺带建议A：导入接口支持**一次POST一个数组**，别一条一POST。
- [ ] **任务2：搭环境 + 数据不等E**
  - `pip install python-evtx requests`（可选：chardet）。
  - **上午就能开跑的样例数据**（任务书原文就要求"收集互联网数据集"，不等E）：
    - 自己电脑的管理员cmd执行 `wevtutil epl Security C:\temp\Security.evtx`，导出本机真实日志；
    - GitHub 下载 **YamatoSecurity/EVTX-ATTACK-SAMPLES**（带ATT&CK标注的攻击样本evtx，与题目完美对口）。
  - **同日找E确认三件事**（决定你Day2写什么代码）：
    1. Windows靶机**装不装Sysmon**（不装就没有进程/文件/注册表数据，任务7白写，4688只能当兜底）；
    2. 给你的是 `.evtx` 原始文件还是事件查看器导出的XML/文本（**python-evtx只认.evtx**）；
    3. Linux是 `auth.log`(Ubuntu/Debian)、`secure`(CentOS) 还是 journalctl 导出。
- [ ] **任务3：写第一个解析函数 `parse_windows_evtx(file_path)`**
  - 先做 **4624（登录成功）/ 4625（登录失败）**：提取时间、用户、源IP、LogonType；
  - ⚠️ **源IP只在远程登录（LogonType 3/10）时有值**，本地交互登录该字段是 `-`，必须处理空值（置None），否则入库就炸；
  - ⚠️ EVTX内部时间戳是**UTC**，统一转UTC+8再输出；
  - 4625顺带提取 **SubStatus**：`0xC0000064`=用户不存在、`0xC000006A`=密码错误——能区分"用户名枚举"和"爆破"，答辩加分。
- [ ] **任务4：入库联调（与A）**
  - **A接口没好之前不空等**：先解析落地成本地 `.jsonl` 文件开发，A就绪后再接 `requests.post`；
  - 发1条→A的数据库可见→F的页面能刷出来。打通即收工。
- [ ] **任务5：踩坑笔记**
  记下编码问题、时间格式化方式、python-evtx的API用法，第二天直接复用。

---

## 📅 Day 2（9/9）：覆盖全类型日志 + 异常预标记

**目标：E的全量数据吃得下，D要的"可疑点"标得出。**

- [ ] **任务6：补齐Linux解析器**
  - `parse_linux_auth(file_path)`：正则抓 sshd 的 `Accepted password`（成功）/ `Failed password`（失败），提取用户、src_ip；
  - `parse_linux_audit(file_path)`：抓 sudo 提权（`USER_CMD`）和敏感文件访问（`SYSCALL`/`PATH`）。
- [ ] **任务7：扩充Windows解析深度（Sysmon四件套）**
  同一套XML解析逻辑，边际成本低，但正好补齐任务书要的"文件、注册表键值"两个实体：
  - **ID 1** 进程创建：`CommandLine`、`ParentImage`（父进程）、`ParentCommandLine`——D分析恶意执行全靠这个；
  - **ID 11** 文件创建：`TargetFilename`；
  - **ID 13** 注册表键值：`TargetObject`、`Details`；
  - **ID 3** 网络连接：`SourceIp`/`DestinationIp`/`DestinationPort`——顺手桥接C的网络数据，D做主机↔流量关联省大事；
  - 无Sysmon时用 **4688**（进程创建）兜底。
- [ ] **任务7b：登录会话重建（任务书硬要求，新增）**
  - 解析 **4634/4647（注销）**，用 `(host, LogonId)` 把 4624登录 ↔ 4634注销 配对成会话；
  - 每条登录/注销事件都带上 `session_id`（=`主机名:LogonId`），D就能直接算"谁、从哪个IP、何时上机、活跃多久"——横向移动分析的原料。
- [ ] **任务8：异常预标记（与D确认规则后实现）**
  - `is_anomaly` 布尔改成 **`"anomaly_flags": ["规则名", ...]` + `"severity": 0-3`**——对D的关联引擎有用得多，报告里也好写；
  - 首版规则：
    | 规则ID | 条件 | severity |
    |---|---|---|
    | `offhour_login` | 00:00–06:00 的登录成功（依赖任务3的时区转换正确） | 2 |
    | `brute_force` | 同一(用户,src_ip) 5分钟滑动窗口内登录失败≥3次 | 3 |
    | `username_enumeration` | SubStatus=0xC0000064 密集出现 | 3 |
    | `encoded_exec` | 命令行含 `powershell -enc/-EncodedCommand`、`-w hidden` | 3 |
    | `remote_download` | 命令行含 `wget`/`curl`/`certutil -urlcache`/`Invoke-WebRequest` | 2 |
- [ ] **任务8b：低成本高回报事件（新增）**
  - **1102**（审计日志被清——攻击者抹痕迹的标志动作，演示效果好）；
  - **4720**（新建账号）。
- [ ] **任务9：全量导入E的靶场数据**
  - 跑通整个文件夹，几十上百条不崩；
  - ⚠️ **try-except 按"条"包，不按"文件"包**——一条坏记录不能废掉整个文件；
  - 每次导入末尾打印统计：`成功N条 / 失败M条 / 跳过K条（按文件分组）`——这些数字直接抄进《测试分析报告》。

---

## 📅 Day 3（9/10）：稳定性、交付物与演示支持

**目标：演示不翻车，交出干净代码和文档。**

- [ ] **任务10：端到端回归测试**
  - ⚠️ 清空数据库是**A的动作**（找他要个reset接口或让他手动清，你的红线1）；
  - 重新导入E的最终数据集，无报错；F的页面上事件数量、时间线正确。
- [ ] **任务11：性能检查（可选）**
  文件>100MB才考虑 `yield` 生成器逐条返回；课程数据量大概率用不上，别为它花超过1小时。
- [ ] **任务12：代码注释 + README**
  - 每个函数写清输入/输出格式；
  - README注明依赖（`python-evtx`、`requests`）、运行命令、输入输出示例——A合并工程、写《程序编译和安装使用文档》都靠它。
- [ ] **任务13：报告"3.2 主机日志标准化模块"章节**
  - 内容：处理的日志类型、**字段映射表（见附录B，直接搬）**、异常标记规则表、会话重建方法；
  - 叙事要点：把预标记逻辑包装成 **"日志分析Agent的规则层"**，呼应任务书"大模型多智能体协调技术"关键词。
- [ ] **任务14：最终演示预演**
  老师问"数据从哪里来/怎么保证时间对得上"时，你站出来讲：**原始evtx/auth.log → 解析 → 标准事件（统一UTC+8）→ 入库 → 时间线**。

---

## ⚠️ 三大红线（打死不能碰）

1. **不改A的数据库表结构**（字段对不上喊他改，别自己偷偷建表；清库也归他管）。
2. **不解析二进制恶意软件样本**（只解析文本/事件日志，不是杀毒引擎）。
3. **不等数据完美才动手**（Day1上午本机导出Security.evtx就开跑，迭代优化）。

---

## 附录A：标准事件JSON契约（任务1讨论稿）

```json
{
  "timestamp": "2026-09-08 13:05:02+08:00",
  "host": "web-server",
  "source": "windows_evtx",
  "event_id": 4624,
  "event_type": "login_success",
  "user": "alice",
  "process": "cmd.exe",
  "src_ip": "1.2.3.4",
  "dst_ip": null,
  "logon_type": 10,
  "session_id": "web-server:0x1234A567",
  "cmdline": null,
  "detail": {"substatus": null},
  "description": "远程登录成功（RDP）",
  "anomaly_flags": ["offhour_login"],
  "severity": 2,
  "raw_log": "<原始XML片段，截断到2000字符>"
}
```

`source` 枚举：`windows_evtx / sysmon / linux_auth / linux_audit`。字段允许为 `null`，但键必须全都在（A建表按这个来）。

## 附录B：字段映射表（报告3.2节直接用）

| 来源 | 原始字段 | 标准字段 |
|---|---|---|
| Windows 4624/4625 | TimeCreated / Computer / TargetUserName / IpAddress / LogonType | timestamp / host / user / src_ip / logon_type |
| Windows 4625 | SubStatus | detail.substatus |
| Windows 4634/4647 | TargetLogonId | session_id（配对键） |
| Sysmon ID 1 | UtcTime / Image / User / CommandLine / ParentImage | timestamp / process / user / cmdline / detail.parent_process |
| Sysmon ID 11 | TargetFilename | detail.file_path |
| Sysmon ID 13 | TargetObject / Details | detail.registry_key / detail.value |
| Sysmon ID 3 | SourceIp / DestinationIp / DestinationPort | src_ip / dst_ip / dst_port |
| Windows 1102 / 4720 | — | event_type=`log_cleared` / `account_created` |
| Linux auth.log | `Accepted password for u from IP` / `Failed password for u from IP` | event_type=`login_success`/`login_failure`，user / src_ip |
| Linux auditd | `type=USER_CMD`（sudo） / `type=SYSCALL`+`PATH` | event_type=`sudo_exec` / `file_access`，user / detail |

## 附录C：事件ID速查

| 事件 | 含义 | 价值 |
|---|---|---|
| 4624 / 4625 | 登录成功 / 失败 | 溯源主力，src_ip是横向移动关键 |
| 4634 / 4647 | 注销 / 主动注销 | 会话重建（任务书要求） |
| 4688 | 进程创建（无Sysmon兜底） | 需开启审核策略 |
| 1102 | 审计日志被清除 | 攻击者抹痕迹的标志动作 |
| 4720 | 新建用户账号 | 持久化痕迹 |
| Sysmon 1 / 3 / 11 / 13 | 进程 / 网络连接 / 文件 / 注册表 | 实体提取四件套 |

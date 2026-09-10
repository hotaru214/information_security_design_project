# -*- coding: utf-8 -*-
"""
任务1（代码部分）：标准事件结构定义
====================================
这里定义的 dict 结构就是全组的"JSON契约"，文档版见 docs/Event-V2-FINAL.md（唯一权威版本）。

规矩（任务1开小会时要和A、D确认的）：
  1. 每个标准事件的键必须全部存在，没有的值填 None（不许删键）——
     这样A建表有唯一依据，D写关联规则也不用判断"这个字段存不存在"。
  2. timestamp 统一输出 UTC+8（任务书要求"时间序列对齐、统一时钟源"），
     且和C同学的网络流量解析保持同一时区，否则时间线对不齐。
  3. host 统一用靶机主机名（如 web-server），Windows 取 evtx 的 Computer 字段。
     D 的关联引擎靠 host / src_ip 把主机事件和网络事件连起来。
  4. event_type 全组共用一套枚举（C 的网络事件也从这里取词）。
"""

# 标准事件的全部字段：所有解析器生成的事件都必须有这些键
# v1.1：新增 dst_port / protocol（与A后端的网络事件字段对齐，仅Sysmon ID 3有值）
STANDARD_FIELDS = [
    "timestamp",     # str  统一UTC+8，ISO8601 T分隔，如 "2026-09-08T13:05:02+08:00"
    "host",          # str  主机名，如 "web-server"
    "source",        # str  数据来源，见 SOURCES
    "source_event_id",  # int  原始事件ID，如 4624（Event V2 FINAL：由v1的event_id改名，避免与入库id混淆）
    "event_type",    # str  统一事件类型，见 EVENT_TYPES
    "user",          # str  涉及的用户名，如 "alice"
    "process",       # str  进程名（可执行文件名），如 "chrome.exe"
    "src_ip",        # str  源IP（本地登录时为 None！Windows里该字段是"-"）
    "dst_ip",        # str  目的IP（仅Sysmon ID 3网络连接有值，其余事件null）
    "dst_port",      # int  目的端口（仅Sysmon ID 3有值。注意4624里的IpPort是源端口，放detail.src_port）
    "protocol",      # str  传输协议 "TCP"/"UDP"（仅Sysmon ID 3有值，与C同学网络事件同构）
    "logon_type",    # int  Windows登录类型，含义见 LOGON_TYPES
    "session_id",    # str  登录会话键 "主机名:LogonId"，会话重建的配对依据
    "cmdline",       # str  命令行参数（Sysmon ID 1 / 4688 才有）
    "detail",        # dict 其它有价值的原始字段（substatus、父进程、文件路径等）
    "description",   # str  人话描述，前端列表直接展示
    "anomaly_flags", # list 异常预标记的规则名列表，如 ["offhour_login"]（规则引擎填）
    "severity",      # int  严重级别 0-3（0=正常，3=高危），异常规则来填
    "raw_log",       # str  原始XML片段（截断），F的前端"查看证据"用
]

# event_type 枚举：Event V2 冻结词表（2026-09-07 A发布；2026-09-08 D确认补充 log_cleared）
# 全组共用，不许私造新词。Linux sudo提权按D决议映射为 process_start（sudo信息放detail），
# 文件访问按 D 的细分（file_read/write/modify/delete），不使用笼统的 sudo_exec/file_access。
EVENT_TYPES = [
    # 登录与会话
    "login_success",         # 登录成功        (4624 / sshd Accepted)
    "login_failed",          # 登录失败        (4625 / sshd Failed)
    "logout",                # 注销            (4634/4647，会话重建用)
    # 进程
    "process_start",         # 进程创建        (Sysmon 1 / 4688 / Linux sudo USER_CMD)
    "process_end",           # 进程结束        (Sysmon 5，暂不解析)
    # 网络
    "network_connection",    # 主机发起的网络连接 (Sysmon 3 + C的流量事件)
    "dns_query",             # DNS查询         (C)
    "http_request",          # HTTP请求        (C)
    # 文件
    "file_create",           # 文件创建        (Sysmon 11)
    "file_read",             # 文件读取        (Linux auditd SYSCALL/PATH)
    "file_write",            # 文件写入        (Linux auditd)
    "file_modify",           # 文件修改        (Linux auditd)
    "file_delete",           # 文件删除        (Linux auditd)
    # 注册表
    "registry_set",          # 注册表键值修改  (Sysmon 13)
    "registry_create",       # 注册表键创建    (Sysmon 12，暂不解析)
    "registry_delete",       # 注册表键删除    (Sysmon 12，暂不解析)
    "registry_query",        # 注册表查询      (Sysmon 15，暂不解析)
    # 账户与权限
    "user_created",          # 新建账号        (4720)
    "user_deleted",          # 删除账号        (4726)
    "user_modified",         # 修改账号        (4738)
    "group_member_added",    # 成员加入组      (4728)
    "group_member_removed",  # 成员移出组      (4729)
    "privilege_change",      # 权限使用/提权   (4673)
    # 服务与计划任务
    "service_created",       # 服务安装        (7045，持久化证据)
    "service_started",       # 服务启动        (7036)
    "service_stopped",       # 服务停止        (7036)
    "service_deleted",       # 服务删除        (7026)
    "scheduled_task_created",# 计划任务创建    (4698，持久化证据)
    "scheduled_task_run",    # 计划任务执行    (4699)
    "scheduled_task_deleted",# 计划任务删除    (4700)
    # 防御规避
    "log_cleared",           # 审计日志被清除  (1102，攻击者抹痕迹，ATT&CK T1070.002；D已于2026-09-08确认加入)
]

# source 枚举：这条事件是从哪类日志里解析出来的
# Event V2（2026-09-07 契约冻结，A发布）：全组统一，改动需全组同步
SOURCES = [
    "windows_evtx",
    "sysmon",
    "linux_auth",
    "linux_audit",
    "network_pcap",   # C同学：PCAP解析
    "network_zeek",   # C同学：Zeek日志
    "firewall",       # C/E：防火墙或边界设备日志
    "waf",            # C/E：WAF或Web攻击告警
]

# Windows 登录类型含义（解析4624/4625时给人看的说明）
LOGON_TYPES = {
    2: "交互式登录(本地键盘)",
    3: "网络登录(共享/IPC)",
    4: "批处理(计划任务)",
    5: "服务登录",
    7: "解锁屏幕",
    8: "网络明文登录",
    9: "新凭据(runas)",
    10: "远程交互(RDP远程桌面)",
    11: "缓存域凭据登录",
}

# 4625 常见 SubStatus（失败子状态码）——能区分"用户名枚举"和"密码爆破"
SUB_STATUS = {
    "0xC0000064": "用户不存在",
    "0xC000006A": "密码错误",
    "0xC0000072": "账号被禁用",
    "0xC0000234": "账号被锁定",
}


def make_event(**kwargs) -> dict:
    """造一个标准事件：所有键先填默认值，再用传入参数覆盖。

    用法示例：
        ev = make_event(timestamp=..., host=..., event_type="login_success", ...)
    好处：保证17个键一个不少，字段名写错会直接报错（防止静默产生脏数据）。
    """
    ev = {k: None for k in STANDARD_FIELDS}
    ev["detail"] = {}
    ev["anomaly_flags"] = []
    ev["severity"] = 0
    for key, value in kwargs.items():
        if key not in STANDARD_FIELDS:
            raise KeyError(f"未知字段 '{key}'，契约字段只有这些: {STANDARD_FIELDS}")
        ev[key] = value
    return ev

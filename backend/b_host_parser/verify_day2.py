# -*- coding: utf-8 -*-
"""
一键自检脚本（Day2）：验证会话重建 / 新事件ID / 异常预标记 / 全量导入
====================================================================
用法（在本目录下）:
    python verify_day2.py

与 verify_day1.py 的分工：day1管"Day1产出没被改坏"，day2管"Day2新功能是对的"。
任何一个 [FAIL] 会打印原因，直接把原因发给ZCode就能修。
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent        # backend/b_host_parser/
PROJECT = HERE.parent.parent                  # 仓库根目录
sys.path.insert(0, str(HERE))

results = []


def check(tag, desc, fn):
    """跑一项验证，通过打[OK]，失败打[FAIL]+原因（不中断后面的检查）。"""
    try:
        fn()
        results.append(True)
        print(f"[OK]   {tag}  {desc}")
    except Exception as e:
        results.append(False)
        print(f"[FAIL] {tag}  {desc}")
        print(f"       └─ 原因: {type(e).__name__}: {e}")


# ---------- 合成XML工具：不依赖evtx二进制就能测xml_to_event ----------
def ev_xml(event_id, host="MSEDGEWIN10", ts="2020-09-09T13:18:23.627951Z",
           provider="Microsoft-Windows-Security-Auditing", **data):
    """拼一条evtx记录的XML文本（字段结构照真实Security事件，python-evtx导出格式）。"""
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="{ts}"/><Computer>{host}</Computer></System>'
            f'<EventData>{items}</EventData></Event>')


# ---------- t1：EVENT_TYPES 与 V2 契约文档一致（防再次漂移） ----------
def t1():
    from schema import EVENT_TYPES
    v2 = {
        # 登录与会话
        "login_success", "login_failed", "logout",
        # 进程
        "process_start", "process_end",
        # 网络
        "network_connection", "dns_query", "http_request",
        # 文件
        "file_create", "file_read", "file_write", "file_modify", "file_delete",
        # 注册表
        "registry_set", "registry_create", "registry_delete", "registry_query",
        # 账户与权限
        "user_created", "user_deleted", "user_modified",
        "group_member_added", "group_member_removed", "privilege_change",
        # 服务与计划任务
        "service_created", "service_started", "service_stopped", "service_deleted",
        "scheduled_task_created", "scheduled_task_run", "scheduled_task_deleted",
        # 防御规避（2026-09-08 D确认加入）
        "log_cleared",
    }
    assert len(EVENT_TYPES) == len(set(EVENT_TYPES)), "EVENT_TYPES里有重复词"
    missing = v2 - set(EVENT_TYPES)
    extra = set(EVENT_TYPES) - v2
    assert not missing, f"V2要求但缺失: {missing}"
    assert not extra, f"不在V2词表里(不许私造): {extra}"


check("契约", "EVENT_TYPES与V2冻结词表逐词一致(31词, 含D确认的log_cleared)", t1)


# ---------- t2：任务8b 六个新事件ID + 任务7b 注销事件（合成XML逐个断言） ----------
def t2():
    from windows_evtx import xml_to_event

    # 4634 系统发起注销 → logout，session_id与4624同键
    e = xml_to_event(ev_xml(4634, ts="2020-09-09T14:30:00Z",
                            TargetUserName="IEUser", TargetDomainName="MSEDGEWIN10",
                            TargetLogonId="0x8F1A5", LogonType="2"))
    assert e["event_type"] == "logout" and e["event_id"] == 4634
    assert e["session_id"] == "MSEDGEWIN10:0x8F1A5", f"注销也要带配对键: {e['session_id']}"
    assert e["detail"]["logon_id"] == "0x8F1A5" and e["user"] == "IEUser"
    assert e["logon_type"] == 2

    # 4647 用户主动注销 → logout
    e = xml_to_event(ev_xml(4647, ts="2020-09-09T14:31:00Z",
                            TargetUserName="IEUser", TargetLogonId="0x8F1A5"))
    assert e["event_type"] == "logout" and e["session_id"] == "MSEDGEWIN10:0x8F1A5"
    assert "主动" in e["description"]

    # 1102 审计日志被清除 → log_cleared（D确认的正式词）
    e = xml_to_event(ev_xml(1102, ts="2020-09-09T14:35:00Z",
                            SubjectUserName="IEUser", SubjectDomainName="MSEDGEWIN10"))
    assert e["event_type"] == "log_cleared" and e["user"] == "IEUser"
    assert "审计日志被清除" in e["description"] and e["raw_log"]

    # 4720 新建账号 → user_created，user=新账号，detail带操作者
    e = xml_to_event(ev_xml(4720, ts="2020-09-09T14:40:00Z",
                            TargetUserName="hacker", TargetDomainName="MSEDGEWIN10",
                            TargetUserSid="S-1-5-21-1001",
                            SubjectUserName="admin", SubjectLogonId="0x3E7"))
    assert e["event_type"] == "user_created" and e["user"] == "hacker"
    assert e["detail"]["target_user"] == "hacker" and e["detail"]["creator"] == "admin"
    assert e["detail"]["target_sid"] == "S-1-5-21-1001"

    # 4728 成员加入组 → group_member_added；4728里TargetUserName是组名
    e = xml_to_event(ev_xml(4728, ts="2020-09-09T14:41:00Z",
                            MemberName="hacker", MemberSid="S-1-5-21-1001",
                            TargetUserName="Administrators", TargetDomainName="Builtin",
                            SubjectUserName="admin"))
    assert e["event_type"] == "group_member_added"
    assert e["detail"]["group_name"] == "Administrators"
    assert e["detail"]["target_user"] == "hacker" and e["detail"]["member_sid"] == "S-1-5-21-1001"

    # 4673 特权服务调用 → privilege_change
    e = xml_to_event(ev_xml(4673, ts="2020-09-09T14:42:00Z",
                            SubjectUserName="IEUser",
                            ObjectServer="NT Local Security Authority / Authentication Service",
                            ServiceName="LsaRegisterLogonProcess",
                            ProcessName="C:\\Windows\\System32\\svchost.exe",
                            PrivilegeList="-"))
    assert e["event_type"] == "privilege_change" and e["user"] == "IEUser"
    assert e["process"] == "svchost.exe", "4673的进程应从ProcessName路径取文件名"
    assert "privileges" in e["detail"] and "object_server" in e["detail"]

    # 7045 新服务安装 → service_created（System日志提供者，测试provider不影响解析）
    e = xml_to_event(ev_xml(7045, ts="2020-09-09T14:45:00Z",
                            provider="Service Control Manager",
                            ServiceName="evilsvc",
                            ImagePath="C:\\Users\\IEUser\\AppData\\evil.exe",
                            ServiceType="own process", StartType="auto start",
                            AccountName="LocalSystem"))
    assert e["event_type"] == "service_created"
    assert e["detail"]["service_name"] == "evilsvc"
    assert e["detail"]["service_file"] == "C:\\Users\\IEUser\\AppData\\evil.exe"
    assert e["detail"]["start_type"] == "auto start"
    assert e["process"] == "evil.exe", "7045应从ImagePath提取服务可执行文件名"

    # 4698 计划任务创建 → scheduled_task_created（TaskContent本体是XML，测试里用转义后的实体）
    e = xml_to_event(ev_xml(4698, ts="2020-09-09T14:50:00Z",
                            SubjectUserName="IEUser", TaskName="\\evil_task",
                            TaskContent="&lt;Task&gt;&lt;Actions&gt;cmd&lt;/Actions&gt;&lt;/Task&gt;"))
    assert e["event_type"] == "scheduled_task_created"
    assert e["detail"]["task_name"] == "\\evil_task" and e["detail"]["task_content"]
    assert e["user"] == "IEUser"

    # 老三个ID不被改坏（回归）
    e = xml_to_event(ev_xml(4624, ts="2020-09-09T13:00:00Z",
                            TargetUserName="IEUser", LogonType="2", IpAddress="-",
                            TargetLogonId="0x8F1A5"))
    assert e["event_type"] == "login_success" and e["session_id"] == "MSEDGEWIN10:0x8F1A5"
    e = xml_to_event(ev_xml(4625, ts="2020-09-09T13:01:00Z",
                            TargetUserName="IEUser", SubStatus="0xc000006a"))
    assert e["event_type"] == "login_failed" and e["detail"]["substatus_desc"] == "密码错误"
    e = xml_to_event(ev_xml(4688, ts="2020-09-09T13:02:00Z",
                            SubjectUserName="IEUser", NewProcessName="C:\\Windows\\a.exe",
                            CommandLine="ping 1.2.3.4"))
    assert e["event_type"] == "process_start" and e["cmdline"] == "ping 1.2.3.4"


check("任务8b+7b", "8个新事件ID: logout×2/log_cleared/user_created/group_member_added/"
                   "privilege_change/service_created/scheduled_task_created + 老ID回归", t2)


# ---------- t3：任务7b 会话重建 ----------
def t3():
    from windows_evtx import xml_to_event
    from sessions import rebuild_sessions

    def login(user, ip, logon_id, ts, logon_type="3"):
        return xml_to_event(ev_xml(4624, ts=ts, TargetUserName=user,
                                   LogonType=logon_type, IpAddress=ip,
                                   TargetLogonId=logon_id))

    def logout(logon_id, ts):
        return xml_to_event(ev_xml(4634, ts=ts, TargetUserName="IEUser",
                                   TargetLogonId=logon_id, LogonType="3"))

    ev_complete = login("bob", "10.0.2.17", "0x100", "2020-09-09T13:00:00Z")
    ev_logout = logout("0x100", "2020-09-09T14:30:00Z")          # 90分钟会话
    ev_active = login("alice", "-", "0x200", "2020-09-09T13:10:00Z")   # 没等到注销
    ev_orphan = logout("0x300", "2020-09-09T13:20:00Z")          # 没有对应登录

    events = [ev_logout, ev_active, ev_orphan, ev_complete]      # 故意乱序
    events, sess = rebuild_sessions(events)

    assert len(sess) == 2, f"应配出2个会话(有登录的), 实际: {sess}"
    s_bob = next(s for s in sess if s["user"] == "bob")
    s_alice = next(s for s in sess if s["user"] == "alice")
    assert s_bob["complete"] and s_bob["duration_s"] == 5400, f"90分钟=5400秒: {s_bob}"
    assert s_bob["src_ip"] == "10.0.2.17" and s_bob["session_id"] == "MSEDGEWIN10:0x100"
    assert not s_alice["complete"] and s_alice["logout_time"] is None

    # 事件detail被就地补全
    assert ev_complete["detail"]["logout_time"] == ev_logout["timestamp"]
    assert ev_complete["detail"]["session_duration_s"] == 5400
    assert ev_logout["detail"]["login_time"] == ev_complete["timestamp"]
    assert ev_active["detail"]["session_state"] == "active", "没等到注销要标active不是null"
    assert ev_orphan["detail"]["session_state"] == "no_login_record"

    # 按登录时间升序
    assert [s["login_time"] for s in sess] == sorted(s["login_time"] for s in sess)


check("任务7b", "会话重建: 4624↔4634按(host,LogonId)配对算时长 / 未注销标active / 孤儿注销标no_login_record", t3)


# ---------- 汇总 ----------
print("-" * 56)
if all(results):
    print(f"全部验证通过：{sum(results)}/{len(results)} 项 [OK]")
else:
    print(f"有 {results.count(False)} 项未通过，把 [FAIL] 的原因发给ZCode即可修")
    sys.exit(1)

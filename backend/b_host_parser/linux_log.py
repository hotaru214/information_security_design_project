# -*- coding: utf-8 -*-
"""
任务6：Linux 日志解析器（auth.log/secure + auditd）
====================================================
输入 : 文本日志文件（utf-8，坏行按行跳过）
输出 : 标准事件 dict 列表（结构见 schema.py，19字段齐全）

parse_linux_auth  —— SSH登录（sshd）
    "Accepted password for alice from 10.0.2.17 port 51234 ssh2" → login_success
    "Failed password for invalid user admin from 1.2.3.4 ..."    → login_failed
    ⚠️ auth.log 的时间没有年份（"Jan 12 02:55:01"），用文件mtime的年份补全；
    ⚠️ auth.log 是靶机本地时间——靶场按全组约定统一UTC+8，直接打时区标记。
      （若E的靶机时区不是UTC+8，只需调整 _AUTH_TZ 一处）

parse_linux_audit —— auditd（sudo提权 + 敏感文件访问）
    type=USER_CMD → process_start（D决议：sudo映射为process_start，sudo信息放detail）
        ⚠️ cmd= 是HEX编码（auditd标准行为），必须解码
    type=SYSCALL + type=PATH（同一次审计事件按序号配对）→ file_read
        只取"打开文件"类syscall（open/openat），PATH取item最大的那条（item=0是父目录）
    其余类型（USER_ACCT等）计入 skipped_other

统计 dict 与 Windows 解析器同构: {"parsed", "skipped_other", "failed", "by_event_id"}。
Windows侧 by_event_id 键是事件ID；这里没有数字ID，用记录类型作键（sshd:accepted等），
报告里的"事件分布"列照样能看。

用法:
    from linux_log import parse_linux_auth, parse_linux_audit
    events = parse_linux_auth(r"..\..\data\sample_logs\linux\auth_sample_attack.log")
"""
import re
from datetime import datetime, timezone
from pathlib import Path

from schema import make_event
from windows_evtx import to_utc8, UTC8, _clean

_AUTH_TZ = UTC8  # auth.log是靶机本地时间；靶场约定统一UTC+8

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# auth.log行头： "Jan 12 02:55:01 host prog[pid]: message"
_AUTH_HEAD = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^\[\s]+)(?:\[\d+\])?:\s(.*)$")
# sshd的登录成功/失败消息（"invalid user"前缀=用户不存在，Linux版的用户名枚举指纹）
_SSHD_MSG = re.compile(
    r"^(Accepted|Failed)\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")

# auditd行头： type=TYPE msg=audit(秒.毫秒:序号): 其余字段
_AUDIT_HEAD = re.compile(r"^type=(\S+)\s+msg=audit\((\d+)\.(\d+):(\d+)\):\s*(.*)$")
_AUDIT_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')  # key="value" 或 key=value


def _kv_pairs(text: str) -> dict:
    """key="value" / key=value 通用解析。

    ⚠️ 坑（Day2踩坑笔记#8）：findall对"没参与匹配的捕获组"返回空字符串''而不是None，
    所以不能用findall——必须用finditer按group是否参与来精确取值。
    """
    kv = {}
    for m in _AUDIT_KV.finditer(text):
        quoted, bare = m.group(2), m.group(3)
        kv[m.group(1)] = quoted if quoted is not None else bare
    return kv


def _audit_ts(seconds: str, millis: str) -> str:
    """auditd的epoch时间（UTC）→ 契约的UTC+8 ISO8601字符串。"""
    dt = datetime.fromtimestamp(int(seconds) + int(millis) / 1000.0, tz=timezone.utc)
    return to_utc8(dt)


def _hex_cmd(hex_str: str):
    """auditd的cmd=字段是HEX编码的命令行（如 636174202F657463... = 'cat /etc/shadow'）。"""
    if not hex_str or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", hex_str.strip()):
        return None
    try:
        return bytes.fromhex(hex_str.strip()).decode("utf-8", errors="replace")
    except ValueError:
        return None


def _new_event(ts, host, source, event_type, user, process, src_ip,
               detail, description, raw_line):
    return make_event(
        timestamp=ts, host=host, source=source, event_id=None,
        event_type=event_type, user=user, process=process, src_ip=src_ip,
        dst_ip=None, dst_port=None, protocol=None, logon_type=None,
        session_id=None, cmdline=None, detail=detail,
        description=description, anomaly_flags=[], severity=0,
        raw_log=raw_line[:2000],
    )


def parse_linux_auth(file_path: str, stats: dict = None) -> list:
    """解析 auth.log/secure（sshd登录日志），返回标准事件列表。"""
    events = []
    if stats is None:
        stats = {}
    stats.update(parsed=0, skipped_other=0, failed=0, by_event_id={})
    # auth.log没有年份——用文件mtime的年份补全（文档化假设，报告里要写）
    year = datetime.fromtimestamp(Path(file_path).stat().st_mtime).year

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                head = _AUTH_HEAD.match(line)
                if head is None:
                    stats["skipped_other"] += 1
                    continue
                mon, day, hh, mm, ss, host, prog, msg = head.groups()
                m = _SSHD_MSG.match(msg)
                if m is None or prog != "sshd":
                    stats["skipped_other"] += 1
                    continue
                result, method, user, src_ip, src_port = m.groups()
                ts = to_utc8(datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                                      tzinfo=_AUTH_TZ))
                invalid_user = "invalid user" in msg
                port = int(src_port) if src_port.isdigit() else None
                if result == "Accepted":
                    event_type = "login_success"
                    description = f"用户 {user} 通过{method}从 {src_ip} 登录成功"
                else:
                    event_type = "login_failed"
                    description = f"用户 {user} 登录失败（来自 {src_ip}，方式: {method}）"
                ev = _new_event(
                    ts=ts, host=host, source="linux_auth", event_type=event_type,
                    user=user, process="sshd", src_ip=src_ip,
                    detail={"method": method,
                            "src_port": port,
                            "invalid_user": True if invalid_user else None},
                    description=description, raw_line=line)
                events.append(ev)
                stats["parsed"] += 1
                key = f"sshd:{'accepted' if result == 'Accepted' else 'failed'}"
                stats["by_event_id"][key] = stats["by_event_id"].get(key, 0) + 1
            except Exception:
                stats["failed"] += 1
                print(f"  [跳过损坏行] {line[:80]}")
    return events


def parse_linux_audit(file_path: str, stats: dict = None, host: str = None) -> list:
    """解析 auditd 日志（sudo提权 USER_CMD + 敏感文件访问 SYSCALL/PATH配对）。

    host : auditd行内没有主机名（host是契约必填字段），优先用调用方传入的值；
           不传则从文件名推导（去掉 _audit/-audit 后缀）——E的文件命名要配合。
    """
    events = []
    if stats is None:
        stats = {}
    stats.update(parsed=0, skipped_other=0, failed=0, by_event_id={})
    if host is None:
        stem = Path(file_path).stem
        host = re.sub(r"[_-]audit$", "", stem) or stem  # web-server_audit → web-server

    # 第一遍：把行分类收集（SYSCALL和PATH按审计序号配对，必须整文件看完才能配）
    user_cmds = []            # (行原文, 公共字段dict, 内层msg字段dict)
    syscalls = {}             # 序号 -> (公共字段, kv字段dict)
    paths = {}                # 序号 -> [PATH name, ...]（按item升序，item大的才是目标文件）
    other = failed = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                head = _AUDIT_HEAD.match(line)
                if head is None:
                    other += 1
                    continue
                rtype, sec, ms, serial, rest = head.groups()
                if rtype == "USER_CMD":
                    kv = _kv_pairs(rest)
                    inner = re.search(r"msg='(.*)'\s*$", rest)
                    ikv = _kv_pairs(inner.group(1)) if inner else {}
                    user_cmds.append((line, {"ts": _audit_ts(sec, ms),
                                             "serial": serial, **kv}, ikv))
                elif rtype == "SYSCALL":
                    syscalls[serial] = ({"ts": _audit_ts(sec, ms)}, _kv_pairs(rest))
                elif rtype == "PATH":
                    kv = _kv_pairs(rest)
                    name = kv.get("name")
                    if name and name != "(null)":
                        paths.setdefault(serial, []).append((int(kv.get("item", 0)), name))
                else:
                    other += 1
            except Exception:
                failed += 1
                print(f"  [跳过损坏行] {line[:80]}")

    # USER_CMD → process_start（sudo提权，D决议：不新增event_type，sudo信息放detail）
    for line, pub, ikv in user_cmds:
        cmd = _hex_cmd(ikv.get("cmd", ""))
        # sudo跑的命令一般是绝对路径或命令名；process取第一个token的文件名
        first_tok = (cmd or "").split()[0] if cmd else None
        process = first_tok.replace("\\", "/").split("/")[-1] if first_tok else None
        detail = {"sudo_command": cmd,
                  "cwd": ikv.get("cwd") or None,
                  "terminal": ikv.get("terminal") or None,
                  "res": ikv.get("res") or None,
                  "uid": pub.get("uid"), "auid": pub.get("auid")}
        ev = _new_event(
            ts=pub["ts"], host=host, source="linux_audit",
            event_type="process_start", user=None, process=process,
            src_ip=None, detail=detail,
            description=f"sudo提权执行: {cmd or '命令未解码'}"
                        + (f"（uid {pub.get('uid')}）" if pub.get("uid") else ""),
            raw_line=line)
        events.append(ev)
        stats["by_event_id"]["USER_CMD"] = stats["by_event_id"].get("USER_CMD", 0) + 1

    # SYSCALL+PATH配对 → file_read（敏感文件访问；只取"打开"类syscall）
    OPEN_SYSCALLS = {"2": "open", "257": "openat", "304": "open_by_handle_at"}  # x86_64
    for serial, (pub, kv) in syscalls.items():
        syscall_no = kv.get("syscall")
        if kv.get("success") != "yes" or syscall_no not in OPEN_SYSCALLS:
            other += 1  # 只关心成功的文件打开；其他syscall不在本任务范围
            continue
        names = sorted(paths.get(serial, []), key=lambda p: p[0])
        file_path_name = names[-1][1] if names else None  # item最大的那条才是目标文件
        exe = kv.get("exe") or None
        process = exe.replace("\\", "/").split("/")[-1] if exe else None
        detail = {"file_path": file_path_name,
                  "syscall": OPEN_SYSCALLS[syscall_no],
                  "audit_key": kv.get("key") if kv.get("key") not in (None, "(null)") else None,
                  "comm": kv.get("comm") or None,
                  "uid": kv.get("uid"), "auid": kv.get("auid")}
        raw = f"SYSCALL: {kv}\nPATH: {sorted(paths.get(serial, []))}"  # 两行原文都留作证据
        ev = _new_event(
            ts=pub["ts"], host=host, source="linux_audit",
            event_type="file_read", user=None, process=process,
            src_ip=None, detail=detail,
            description=f"敏感文件访问: {file_path_name or '路径未记录'}"
                        f"（进程: {process or '未知'}，syscall: {OPEN_SYSCALLS[syscall_no]}）",
            raw_line=raw)
        events.append(ev)
        stats["by_event_id"]["SYSCALL"] = stats["by_event_id"].get("SYSCALL", 0) + 1

    stats["parsed"] = len(events)
    stats["skipped_other"] = other
    stats["failed"] = failed
    return events


def detect_linux_parser(file_path) -> str:
    """按首行内容判断Linux日志类型：type=开头→audit，月名开头→auth。判断不了返回None。"""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("type=") and "msg=audit(" in line:
                return "linux_audit"
            if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s", line):
                return "linux_auth"
            return None  # 第一条非空行认不出来就不硬猜
    return None

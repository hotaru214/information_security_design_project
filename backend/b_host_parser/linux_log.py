# -*- coding: utf-8 -*-
"""
任务6：Linux 日志解析器（auth.log/secure + auditd）
====================================================
输入 : 文本日志文件（utf-8，坏行按行跳过）
输出 : 标准事件 dict 列表（结构见 schema.py，19字段齐全）

parse_linux_auth  —— SSH登录（sshd）
    "Accepted password for alice from 10.0.2.17 port 51234 ssh2" → login_success
    "Failed password for invalid user admin from 1.2.3.4 ..."    → login_failed
    ⚠️ 传统auth.log的时间没有年份（"Jan 12 02:55:01"），用文件mtime的年份补全；
    ⚠️ auth.log 是靶机本地时间——靶场按全组约定统一UTC+8，直接打时区标记。
    （E最终数据 core-auth.log 是 rsyslog 的ISO 8601形态"2026-09-07T23:48:31.575069+08:00"，
    年月日/时区直接取自行内，任意时区偏移一律换算成UTC+8——2026-09-09 按A集成要求补）

parse_linux_audit —— auditd（2026-09-08按E真实数据适配，支持两种形态）
    E实际交付了两种格式，都要吃：
    ① 原始格式（audit.log）：msg=audit(1788835692.378:3024)，字段是数字（uid=1000），
       行尾带ausearch富字段（AUID="mxy" UID="root"，用来还原用户名）；
    ② 解释格式（ausearch -i 的txt）：msg=audit(2026年09月08日 10:49:21.804:1281)，
       字段是名字（auid=mxy uid=root syscall=openat）。
       已验证E的VM时区就是UTC+8（同一事件的epoch和解释时间完全吻合），直接按+08:00解析。

    事件映射（按E的case01审计规则对齐D的需求）：
      type=USER_CMD（sudo提权，cmd是HEX编码）      → process_start（D决议，sudo信息放detail）
      SYSCALL execve + EXECVE（argv配对）          → process_start（进程+完整命令行，D的核心需求）
      SYSCALL open/openat + PATH（敏感文件访问）    → file_read（相对路径会和CWD拼成绝对路径）
      SYSCALL connect/accept + SOCKADDR（仅inet）   → network_connection（本地unix socket是噪音，跳过）
      SERVICE_START / SERVICE_STOP                 → service_started / service_stopped
      其余（CONFIG_CHANGE/BPF/USER_AUTH/...）       → skipped_other 计数

    每条事件 detail 带 audit_serial（审计序号）——D溯源用，也是跨文件去重的键
    （同一个事件会同时出现在 audit.log 和 ausearch 按规则提取的 .txt 里）。

统计 dict 与 Windows 解析器同构: {"parsed", "skipped_other", "failed", "by_event_id"}，
by_event_id 用记录类型作键（USER_CMD/execve/file_open/connect_inet/...）。

用法:
    from linux_log import parse_linux_auth, parse_linux_audit
    events = parse_linux_audit(r"..\..\data\e_case01_linux\audit.log", host="ubuntu-vm")
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from schema import make_event
from windows_evtx import to_utc8, UTC8, _clean, _basename

_AUTH_TZ = UTC8  # auth.log是靶机本地时间；靶场约定统一UTC+8

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# auth.log行头： "Jan 12 02:55:01 host prog[pid]: message"
_AUTH_HEAD = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^\[\s]+)(?:\[\d+\])?:\s(.*)$")
# auth.log行头（ISO 8601形态，Ubuntu 24.04 rsyslog 默认，E最终数据core-auth.log实测）：
# "2026-09-07T23:48:31.575069+08:00 host prog[pid]: message"——带年份/微秒/时区
_AUTH_HEAD_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(Z|[+-]\d{2}:?\d{2})\s+(\S+)\s+([^\[\s]+)(?:\[\d+\])?:\s(.*)$")
# sshd的登录成功/失败消息（"invalid user"前缀=用户不存在，Linux版的用户名枚举指纹）
_SSHD_MSG = re.compile(
    r"^(Accepted|Failed)\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")

# auditd行头两种形态：原始(epoch.毫秒:序号) / 解释模式(中文locale时间)
# ⚠️ 分隔符两种写法都存在："): "（原始）和 ") : "（ausearch -i 的txt输出），都要兼容
_AUDIT_HEAD_EPOCH = re.compile(
    r"^type=(\S+)\s+msg=audit\((\d+)\.(\d+):(\d+)\)\s*:\s*(.*)$")
_AUDIT_HEAD_INTERP = re.compile(
    r"^type=(\S+)\s+msg=audit\((\d{4})年(\d{1,2})月(\d{1,2})日\s+"
    r"(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\.(\d+))?:(\d+)\)\s*:\s*(.*)$")
_AUDIT_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')  # key="value" 或 key=value

# syscall编号→名字（x86_64；解释模式里直接就是名字）
_SYSCALL_NUM2NAME = {
    "2": "open", "257": "openat", "304": "open_by_handle_at",
    "59": "execve",
    "42": "connect", "43": "accept", "288": "accept4",
}
FILE_OPEN_SYSCALLS = {"open", "openat", "open_by_handle_at"}
EXEC_SYSCALLS = {"execve"}
CONNECT_SYSCALLS = {"connect"}
ACCEPT_SYSCALLS = {"accept", "accept4"}


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


def _audit_ts_epoch(seconds: str, millis: str) -> str:
    """原始格式的epoch时间（UTC）→ 契约的UTC+8 ISO8601字符串。"""
    dt = datetime.fromtimestamp(int(seconds) + int(millis) / 1000.0, tz=timezone.utc)
    return to_utc8(dt)


def _audit_ts_interp(y, mo, d, h, mi, s, ms) -> str:
    """解释模式的时间（E的VM就是UTC+8，直接打时区标记，不做时区换算）。"""
    micro = int(ms) * 10 ** (6 - len(ms)) if ms else 0
    dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=UTC8)
    return dt.isoformat()


def _iso_ts_to_utc8(y, mo, d, hh, mm, ss, frac, tzs) -> str:
    """ISO 8601行内时间戳 → 统一UTC+8字符串。

    年月日和时区都取自行内（rsyslog新格式自带，不再依赖mtime补年份）；
    任意偏移（Z / ±HH:MM / ±HHMM）都换算成UTC+8——靶机时区配错日志也能对齐。
    """
    micro = int(frac.ljust(6, "0")[:6]) if frac else 0
    if tzs == "Z":
        tz = timezone.utc
    else:
        sign = 1 if tzs[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(tzs[1:3]), minutes=int(tzs[-2:])))
    dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), micro, tzinfo=tz)
    return to_utc8(dt)


def _parse_head(line: str):
    """识别auditd行头，返回 (type, timestamp, serial, rest) 或 None。"""
    m = _AUDIT_HEAD_EPOCH.match(line)
    if m:
        rtype, sec, ms, serial, rest = m.groups()
        return rtype, _audit_ts_epoch(sec, ms), int(serial), rest
    m = _AUDIT_HEAD_INTERP.match(line)
    if m:
        rtype, y, mo, d, h, mi, s, ms, serial, rest = m.groups()
        return rtype, _audit_ts_interp(y, mo, d, h, mi, s, ms), int(serial), rest
    return None


def _hex_cmd(hex_str: str):
    """auditd的cmd=/proctitle=字段是HEX编码（如 636174202F657463... = 'cat /etc/shadow'）。"""
    if not hex_str or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", hex_str.strip()):
        return None
    try:
        return bytes.fromhex(hex_str.strip()).decode("utf-8", errors="replace")
    except ValueError:
        return None


def _decode_arg(v: str):
    """EXECVE单个参数：可能是裸HEX（二进制/特殊字符时auditd转hex），或带\\0NN八进制转义。"""
    if not v:
        return v
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}){2,}", v):
        decoded = _hex_cmd(v)
        if decoded:
            return decoded
    return re.sub(r"\\([0-7]{1,3})", lambda m: chr(int(m.group(1), 8)), v)


def _resolve_user(kv: dict):
    """从auditd字段还原用户名：富字段AUID="mxy" > 解释模式的auid=mxy > null。
    数字auid（1000）没有富字段对照时宁可用null——不猜用户名（契约：缺失传null）。"""
    v = kv.get("AUID")
    if v and v not in ("unset", "(null)"):
        return v
    v = kv.get("auid")
    if v and not v.isdigit() and v not in ("unset", "(null)"):
        return v
    return None


def _parse_sockaddr(rest: str):
    """SOCKADDR行 → (family, ip, port) 或 None（本地unix socket/netlink=噪音）。

    原始格式：saddr=02000050C0A80166...（kernel sockaddr结构的hex：
    前2字节family小端，inet的端口2字节大端，IPv4地址4字节）；
    解释格式：saddr={ saddr_fam=inet laddr=1.2.3.4 lport=80 }。
    """
    m = re.search(r"saddr=([0-9a-fA-F]{8,})", rest)
    if m:
        b = bytes.fromhex(m.group(1))
        fam = int.from_bytes(b[:2], "little")
        if fam == 2 and len(b) >= 8:  # AF_INET
            port = int.from_bytes(b[2:4], "big")
            ip = ".".join(str(x) for x in b[4:8])
            return "inet", ip, port
        if fam == 10 and len(b) >= 24:  # AF_INET6
            port = int.from_bytes(b[2:4], "big")
            ip = str(ipaddress.IPv6Address(b[8:24]))
            return "inet6", ip, port
        return None  # AF_LOCAL(1)/AF_NETLINK(16)... 本地噪音
    m = re.search(r"saddr_fam=inet6?\b", rest)  # 解释模式兜底
    if m:
        ip = re.search(r"(?:[lr]addr|addr)=([0-9a-fA-F:.]+)", rest)
        port = re.search(r"(?:[lr]port|port)=(\d+)", rest)
        if ip:
            return "inet", ip.group(1), int(port.group(1)) if port else None
    return None


def _new_event(ts, host, source, event_type, user, process, src_ip,
               detail, description, raw_line, cmdline=None):
    return make_event(
        timestamp=ts, host=host, source=source, source_event_id=None,
        event_type=event_type, user=user, process=process, src_ip=src_ip,
        dst_ip=None, dst_port=None, protocol=None, logon_type=None,
        session_id=None, cmdline=cmdline, detail=detail,
        description=description, anomaly_flags=[], severity=0,
        raw_log=raw_line[:2000] if raw_line else None,
    )


def parse_linux_auth(file_path: str, stats: dict = None, host: str = None) -> list:
    """解析 auth.log/secure（sshd登录日志），返回标准事件列表。

    host : 可选覆盖——行内有主机名时默认用行内的；E没给主机名时用 --linux-host 统一。
    """
    events = []
    if stats is None:
        stats = {}
    stats.update(parsed=0, skipped_other=0, failed=0, by_event_id={})
    # auth.log没有年份——用文件mtime的年份补全（文档化假设，报告里要写）
    year = datetime.fromtimestamp(Path(file_path).stat().st_mtime).year

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")  # E的文件是CRLF——只strip\n会残留\r污染raw_log
            if not line.strip():
                continue
            try:
                head = _AUTH_HEAD.match(line)     # 传统格式："Sep  8 13:05:02"（无年份）
                iso = None if head else _AUTH_HEAD_ISO.match(line)  # ISO格式（E最终数据）
                if head is not None:
                    mon, day, hh, mm, ss, line_host, prog, msg = head.groups()
                    ts = to_utc8(datetime(year, MONTHS[mon], int(day), int(hh), int(mm),
                                          int(ss), tzinfo=_AUTH_TZ))
                elif iso is not None:
                    y, mo, d, hh, mm, ss, frac, tzs, line_host, prog, msg = iso.groups()
                    ts = _iso_ts_to_utc8(y, mo, d, hh, mm, ss, frac, tzs)
                else:
                    stats["skipped_other"] += 1
                    continue
                m = _SSHD_MSG.match(msg)
                if m is None or prog != "sshd":
                    stats["skipped_other"] += 1
                    continue
                result, method, user, src_ip, src_port = m.groups()
                invalid_user = "invalid user" in msg
                port = int(src_port) if src_port.isdigit() else None
                if result == "Accepted":
                    event_type = "login_success"
                    description = f"用户 {user} 通过{method}从 {src_ip} 登录成功"
                else:
                    event_type = "login_failed"
                    description = f"用户 {user} 登录失败（来自 {src_ip}，方式: {method}）"
                ev = _new_event(
                    ts=ts, host=host or line_host, source="linux_auth", event_type=event_type,
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
    """解析 auditd 日志（原始/解释双格式），按审计序号配对成标准事件。

    host : auditd行内没有主机名（host是契约必填字段），优先用调用方传入的值
           （run_parse 的 --linux-host）；不传则从文件名推导。
    """
    events = []
    if stats is None:
        stats = {}
    stats.update(parsed=0, skipped_other=0, failed=0, by_event_id={})
    if host is None:
        stem = Path(file_path).stem
        host = re.sub(r"[_-]audit$", "", stem) or stem
    other = failed = 0
    user_cmds = []   # (ts, 外层kv, 内层ikv, 原始行)
    groups = {}      # 审计序号 -> {ts, raw, syscall, execve, paths, cwd, sockaddr, proctitle}

    # ---- 第一遍：按行归类（SYSCALL/EXECVE/PATH/CWD/SOCKADDR要按序号配对，必须整文件看完）----
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")  # E的文件是CRLF——只strip\n会残留\r污染raw_log
            if not line.strip() or line.strip() == "----":  # ausearch输出的分隔行
                continue
            try:
                head = _parse_head(line)
                if head is None:
                    other += 1
                    continue
                rtype, ts, serial, rest = head
                if rtype == "USER_CMD":
                    # ⚠️ 行尾还有 UID="mxy" AUID="mxy" 富字段，msg='...'不在行尾，
                    # 不能用$锚定——单引号只出现在msg定界符上，贪婪匹配到闭合引号即可
                    inner = re.search(r"msg='(.*)'", rest)
                    user_cmds.append((ts, serial, _kv_pairs(rest),
                                      _kv_pairs(inner.group(1)) if inner else {}, line))
                    continue
                if rtype in ("SERVICE_START", "SERVICE_STOP"):
                    inner = re.search(r"msg='(.*)'", rest)
                    kv = _kv_pairs(inner.group(1)) if inner else {}
                    unit = kv.get("unit")
                    started = rtype == "SERVICE_START"
                    events.append(_new_event(
                        ts=ts, host=host, source="linux_audit",
                        event_type="service_started" if started else "service_stopped",
                        user=_resolve_user(kv), process=_basename(kv.get("comm")),
                        src_ip=None,
                        detail={"service_name": unit, "res": kv.get("res"),
                                "audit_serial": serial},
                        description=f"服务{'启动' if started else '停止'}: {unit or '未记录'}",
                        raw_line=line))
                    stats["by_event_id"][rtype] = stats["by_event_id"].get(rtype, 0) + 1
                    continue
                if rtype in ("SYSCALL", "EXECVE", "PATH", "CWD", "SOCKADDR", "PROCTITLE"):
                    # 组件记录：按审计序号归组，等SYSCALL来配对
                    g = groups.setdefault(serial, {"ts": ts, "raw": []})
                    g["raw"].append(line)
                    if rtype == "SYSCALL":
                        g["syscall"] = _kv_pairs(rest)
                    elif rtype == "EXECVE":
                        g["execve"] = _kv_pairs(rest)
                    elif rtype == "PATH":
                        kv = _kv_pairs(rest)
                        name = kv.get("name")
                        if name and name != "(null)":
                            g.setdefault("paths", []).append((int(kv.get("item") or 0), name))
                    elif rtype == "CWD":
                        g["cwd"] = _kv_pairs(rest).get("cwd")
                    elif rtype == "SOCKADDR":
                        g["sockaddr"] = rest
                    else:  # PROCTITLE
                        g["proctitle"] = _kv_pairs(rest).get("proctitle")
                else:
                    other += 1  # CONFIG_CHANGE / BPF / CRED_* / USER_AUTH / USER_START / ...
            except Exception:
                failed += 1
                print(f"  [跳过损坏行] {line[:80]}")

    # ---- USER_CMD → process_start（sudo提权；D决议：不新增event_type，sudo信息放detail）----
    for ts, serial, pub, ikv, line in user_cmds:
        cmd = _hex_cmd(ikv.get("cmd", ""))
        first_tok = (cmd or "").split()[0] if cmd else None
        detail = {"sudo_command": cmd,
                  "cwd": ikv.get("cwd") or None,
                  "terminal": ikv.get("terminal") or None,
                  "res": ikv.get("res") or None,
                  "uid": pub.get("uid"), "auid": pub.get("auid"),
                  "audit_serial": serial}
        events.append(_new_event(
            ts=ts, host=host, source="linux_audit", event_type="process_start",
            user=_resolve_user(pub), process=_basename(first_tok),
            src_ip=None, detail=detail,
            description=f"sudo提权执行: {cmd or '命令未解码'}",
            raw_line=line))
        stats["by_event_id"]["USER_CMD"] = stats["by_event_id"].get("USER_CMD", 0) + 1

    # ---- 第二遍：SYSCALL组按类别生成事件 ----
    for serial, g in groups.items():
        sk = g.get("syscall")
        if not sk:
            other += 1
            continue
        if sk.get("success") != "yes":
            other += 1  # 失败的系统调用不入库（爆破探测类噪音），计数即可
            continue
        name = _SYSCALL_NUM2NAME.get(sk.get("syscall") or "", sk.get("syscall"))
        user = _resolve_user(sk)
        audit_key = sk.get("key") if sk.get("key") not in (None, "(null)") else None
        base_detail = {"audit_serial": serial, "audit_key": audit_key,
                       "uid": sk.get("uid"), "auid": sk.get("auid"),
                       "tty": sk.get("tty") or None}

        if name in FILE_OPEN_SYSCALLS:  # 敏感文件访问 → file_read
            paths = sorted(g.get("paths", []), key=lambda p: p[0])
            fname = paths[-1][1] if paths else None  # item最大的那条才是目标文件
            if fname and not fname.startswith("/") and g.get("cwd"):
                fname = g["cwd"].rstrip("/") + "/" + fname  # 相对路径拼CWD成绝对路径
            exe = sk.get("exe")
            process = _basename(exe) or _basename(sk.get("comm"))
            events.append(_new_event(
                ts=g["ts"], host=host, source="linux_audit", event_type="file_read",
                user=user, process=process, src_ip=None,
                detail={**base_detail, "file_path": fname, "syscall": name,
                        "comm": sk.get("comm") or None, "exe": exe},
                description=f"敏感文件访问: {fname or '路径未记录'}（进程: {process or '未知'}）",
                raw_line="\n".join(g["raw"])))
            stats["by_event_id"]["file_open"] = stats["by_event_id"].get("file_open", 0) + 1

        elif name in EXEC_SYSCALLS:  # 进程执行 → process_start（EXECVE带完整argv）
            args = []
            ekv = g.get("execve")
            if ekv:
                argc = int(ekv.get("argc") or 0)
                args = [_decode_arg(ekv[f"a{i}"]) for i in range(argc) if ekv.get(f"a{i}")]
            if not args and g.get("proctitle"):
                decoded = _hex_cmd(g["proctitle"])
                args = [a for a in decoded.split("\x00") if a] if decoded else []
            cmdline = " ".join(args) if args else None
            process = _basename(args[0]) if args else _basename(sk.get("exe"))
            events.append(_new_event(
                ts=g["ts"], host=host, source="linux_audit", event_type="process_start",
                user=user, process=process, src_ip=None,
                detail={**base_detail, "exe": sk.get("exe"), "ppid": sk.get("ppid")},
                cmdline=cmdline,
                description=f"进程执行: {cmdline or process or '未知'}"
                            + (f"（用户: {user}）" if user else ""),
                raw_line="\n".join(g["raw"])))
            stats["by_event_id"]["execve"] = stats["by_event_id"].get("execve", 0) + 1

        elif name in CONNECT_SYSCALLS or name in ACCEPT_SYSCALLS:  # 网络连接
            addr = _parse_sockaddr(g.get("sockaddr") or "")
            if addr is None:
                other += 1  # 本地unix socket/netlink——噪音，不入库
                continue
            fam, ip, port = addr
            if name in CONNECT_SYSCALLS:  # 主动外连：对端=目的
                events.append(_new_event(
                    ts=g["ts"], host=host, source="linux_audit",
                    event_type="network_connection", user=user,
                    process=_basename(sk.get("exe") or sk.get("comm")),
                    src_ip=None, detail={**base_detail, "syscall": name,
                                         "src_port": None, "addr_family": fam},
                    description=f"主机发起{'IPv6' if fam == 'inet6' else ''}连接 → {ip}"
                                f"{':' + str(port) if port else ''}",
                    raw_line="\n".join(g["raw"])))
                ev = events[-1]
                # 契约：dst_port缺失传null不传0（E数据里确实有port=0的connect记录）
                ev["dst_ip"], ev["dst_port"] = ip, (port or None)
            else:  # accept：对端=来源（谁连进来了——横向移动的关键证据）
                events.append(_new_event(
                    ts=g["ts"], host=host, source="linux_audit",
                    event_type="network_connection", user=user,
                    process=_basename(sk.get("exe") or sk.get("comm")),
                    src_ip=ip, detail={**base_detail, "syscall": name,
                                       "src_port": port, "addr_family": fam},
                    description=f"接受来自 {ip}:{port or '?'} 的连接",
                    raw_line="\n".join(g["raw"])))
            stats["by_event_id"][f"{name}_inet"] = stats["by_event_id"].get(f"{name}_inet", 0) + 1

        else:
            other += 1  # bind/sendto等其他syscall不在本任务范围

    events.sort(key=lambda e: e["timestamp"] or "")  # 统一时间序（SERVICE类在收集阶段就生成了）
    stats["parsed"] = len(events)
    stats["skipped_other"] = other
    stats["failed"] = failed
    return events


def detect_linux_parser(file_path) -> str:
    """按内容判断Linux日志类型：type=开头→audit；月名或ISO时间戳开头→auth。
    跳过ausearch的----分隔行。"""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line == "----":  # ausearch -i 的分隔行
                continue
            if line.startswith("type=") and "msg=audit(" in line:
                return "linux_audit"
            if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s", line):
                return "linux_auth"
            if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line):
                return "linux_auth"  # rsyslog ISO形态（E最终数据core-auth.log）
            return None  # 第一条有效行认不出来就不硬猜
    return None

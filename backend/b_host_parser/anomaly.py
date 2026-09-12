# -*- coding: utf-8 -*-
"""
任务8：异常预标记（规则引擎）
=============================
解析器只负责"如实转译"，这里是"第一层判读"：把明显的可疑行为直接标在事件上，
D的关联引擎和F的前端可以直接用，不必每条事件都等D二次计算。

设计（任务清单任务8，与D确认的方案）：is_anomaly 布尔升级为两个字段——
  - anomaly_flags: 命中的规则名列表（一条事件可同时命中多条）
  - severity     : 取所有命中规则的最高严重级（0正常/1低/2中/3高）

首版5条规则：
  | 规则ID               | 条件                                                | severity |
  | offhour_login        | 00:00–06:00 的登录成功                               | 2        |
  | brute_force          | 同(用户,src_ip) 5分钟滑动窗口内登录失败≥3次           | 3        |
  | username_enumeration | SubStatus=0xC0000064(用户不存在) 同src_ip 5分钟≥3次   | 3        |
  | encoded_exec         | 命令行含 powershell -enc/-EncodedCommand/-w hidden    | 3        |
  | remote_download      | 命令行含 wget/curl/certutil -urlcache/Invoke-WebRequest | 2      |

2026-09-12 追加3条内存注入规则（任务书第4条，只作用于 process_access / remote_thread_create）：
  | 规则ID                  | 条件                                                  | severity |
  | lsass_access            | Sysmon10 目标是 lsass.exe 且 GrantedAccess ∈ 可疑掩码集  | 3        |
  |                         | 或 CallTrace 含无模块裸地址（凭据转储特征，T1003.001）     |          |
  |                         | ⚠️ 不加掩码条件会大量误报——实测svchost良性查询lsass        |          |
  |                         |    286次全是0x1000，真正的转储是0x1FFFFF/0x1F3FFF         |          |
  | suspicious_memory_access| Sysmon10 GrantedAccess ∈ 全权/读写掩码集                | 2        |
  | reflective_load         | Sysmon10 CallTrace 含无模块裸地址段（非模块内存执行）     | 3        |
  |                         | 或 Sysmon8 跨进程远程线程且 StartModule 无归属          |          |

⚠️ 两个依赖：
  1. offhour_login 依赖任务3的时区转换正确——timestamp必须已是UTC+8
     （解析器入口 to_utc8() 已保证；直接拿原始日志时间喂进来的结果不可信）。
  2. brute_force/username_enumeration 是跨事件时间窗规则，必须在"同一批"事件上
     整体跑——全量导入时先合并所有文件的事件再调用本函数，逐文件调用会漏报。

用法:
    from anomaly import apply_anomaly_rules
    stats = apply_anomaly_rules(all_events)   # 就地填anomaly_flags/severity
    # stats = {"flagged": 被标记的事件数, "by_rule": {"offhour_login": x, ...}}
"""
import re
from datetime import datetime, timedelta

BRUTE_FORCE_WINDOW = timedelta(minutes=5)
BRUTE_FORCE_THRESHOLD = 3
ENUM_WINDOW = timedelta(minutes=5)
ENUM_THRESHOLD = 3          # "密集"的阈值暂定同src_ip 5分钟≥3次，待D复核
ENUM_SUBSTATUS = "0xc0000064"  # 用户不存在——枚举用户名的指纹（比较时统一小写）

# 规则名 → severity（唯一权威定义，_flag()从这里取值）
SEVERITY = {
    "offhour_login": 2,
    "brute_force": 3,
    "username_enumeration": 3,
    "encoded_exec": 3,
    "remote_download": 2,
    "lsass_access": 3,
    "suspicious_memory_access": 2,
    "reflective_load": 3,
}

# powershell编码执行/隐藏窗口（忽略大小写；-w hidden与-windowstyle hidden等价写法都覆盖）
_ENCODED_RE = re.compile(r"-enc\b|-encodedcommand|-w\s*hidden|-windowstyle\s*hidden", re.I)
# 远程下载工具（wget/curl是词边界匹配，防止误伤"curlxxx"这类子串）
_DOWNLOAD_RE = re.compile(r"\bwget\b|\bcurl\b|certutil\s+.*-urlcache|invoke-webrequest", re.I)

# ---- 内存注入规则（任务书第4条）----
# 全权/读写掩码集：PROCESS_ALL_ACCESS(0x1FFFFF)及其常用变体、可读写虚拟内存组合
# （0x143A=OPERATION|READ|WRITE|QUERY_INFORMATION 等）。良性查询类(0x1000/0x1400/0x1010)不命中
_SUSPICIOUS_ACCESS_MASKS = {0x1FFFFF, 0x1F0FFF, 0x1F1FFF, 0x1F2FFF, 0x1F3FFF,
                            0x143A, 0x147A, 0x1F03FF}
# CallTrace里的裸地址段：正常帧是"模块路径+偏移"，无模块的裸 0x 地址=非模块内存执行（反射加载指纹）
_UNBACKED_FRAME_RE = re.compile(r"(?:^|\|)0x[0-9a-fA-F]{4,}(?:\||$)")


def _parse_ts(ts: str):
    """ISO8601 → datetime，失败返回None（坏时间只影响该条的判定，不让规则崩掉）。"""
    try:
        return datetime.fromisoformat(ts) if ts else None
    except (ValueError, TypeError):
        return None


def _flag(ev, rule: str):
    """给事件打上规则标记；severity取历史最高（幂等：重复跑整个规则集结果一致）。"""
    if rule not in ev["anomaly_flags"]:
        ev["anomaly_flags"].append(rule)
    if SEVERITY[rule] > ev["severity"]:
        ev["severity"] = SEVERITY[rule]


def apply_anomaly_rules(events: list) -> dict:
    """对标准事件列表做异常预标记（就地修改ev["anomaly_flags"]/ev["severity"]）。

    返回统计 {"flagged": 被标记的事件总数, "by_rule": {规则名: 命中事件数}}——
    数字直接抄进《测试分析报告》。
    """
    # ---- 单事件规则：逐条判 ----
    for ev in events:
        if ev["event_type"] == "login_success":
            ts = _parse_ts(ev.get("timestamp"))
            if ts is not None and 0 <= ts.hour < 6:  # timestamp已是UTC+8（见模块docstring）
                _flag(ev, "offhour_login")
        cmdline = ev.get("cmdline") or ""
        if cmdline:
            if _ENCODED_RE.search(cmdline):
                _flag(ev, "encoded_exec")
            if _DOWNLOAD_RE.search(cmdline):
                _flag(ev, "remote_download")

    # ---- 内存注入规则（只作用于 process_access / remote_thread_create）----
    for ev in events:
        et = ev.get("event_type")
        if et == "process_access":
            detail = ev.get("detail") or {}
            target = (detail.get("target_image") or "").lower()
            granted = (detail.get("granted_access") or "").strip()
            try:
                mask = int(granted, 16) if granted.startswith("0x") else None
            except ValueError:
                mask = None
            call_trace = detail.get("call_trace") or ""
            unbacked = bool(call_trace and _UNBACKED_FRAME_RE.search(call_trace))
            if target == "lsass.exe" and (mask in _SUSPICIOUS_ACCESS_MASKS or unbacked):
                _flag(ev, "lsass_access")
            if mask in _SUSPICIOUS_ACCESS_MASKS:
                _flag(ev, "suspicious_memory_access")
            if unbacked:
                _flag(ev, "reflective_load")
        elif et == "remote_thread_create":
            detail = ev.get("detail") or {}
            source = (detail.get("source_image") or "").lower()
            target = (detail.get("target_image") or "").lower()
            # 跨进程远程线程本身就是注入动作；起始地址无归属模块（"-"）是反射加载的直接证据。
            # 进程自己创建自己的线程（源=目标）不算跨进程注入。
            if source and target and source != target \
                    and detail.get("start_module") in (None, "-"):
                _flag(ev, "reflective_load")

    # ---- 跨事件时间窗规则：把登录失败事件分给两条规则 ----
    failures = [ev for ev in events if ev["event_type"] == "login_failed"]
    _window_rule(failures,
                 key=lambda ev: (ev.get("user"), ev.get("src_ip")),
                 window=BRUTE_FORCE_WINDOW, threshold=BRUTE_FORCE_THRESHOLD,
                 rule="brute_force")
    # 用户名枚举按src_ip聚合（枚举的特征恰恰是"换着用户名试"），且只看"用户不存在"
    _window_rule(failures,
                 key=lambda ev: ev.get("src_ip"),
                 window=ENUM_WINDOW, threshold=ENUM_THRESHOLD,
                 rule="username_enumeration",
                 extra_filter=lambda ev: str((ev.get("detail") or {}).get("substatus") or "")
                 .lower() == ENUM_SUBSTATUS)

    # ---- 统计 ----
    flagged = 0
    by_rule = {}
    for ev in events:
        if ev["anomaly_flags"]:
            flagged += 1
        for rule in ev["anomaly_flags"]:
            by_rule[rule] = by_rule.get(rule, 0) + 1
    return {"flagged": flagged, "by_rule": by_rule}


def _window_rule(events: list, key, window: timedelta, threshold: int,
                 rule: str, extra_filter=None):
    """滑动时间窗规则：同组内 window 时长里出现 ≥threshold 条就全标。

    为什么标窗口内全部而不是只标最后一条：D的关联引擎和前端时间线需要
    看到完整的攻击片段，只标最后一条会丢上下文。
    """
    groups = {}
    for ev in events:
        if extra_filter is not None and not extra_filter(ev):
            continue
        k = key(ev)
        if k is None:
            continue
        groups.setdefault(k, []).append(ev)

    for group in groups.values():
        timed = sorted(((_parse_ts(ev.get("timestamp")), ev) for ev in group),
                       key=lambda pair: pair[0] or datetime.min)
        for i in range(len(timed)):
            if timed[i][0] is None:
                continue  # 坏时间戳没法参与窗口计算
            window_members = [timed[i][1]]
            for j in range(i - 1, -1, -1):  # 从i向左收窗口内的成员，超出窗口即停
                if timed[j][0] is None:
                    continue
                if timed[i][0] - timed[j][0] <= window:
                    window_members.append(timed[j][1])
                else:
                    break
            if len(window_members) >= threshold:
                for ev in window_members:
                    _flag(ev, rule)

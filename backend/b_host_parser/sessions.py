# -*- coding: utf-8 -*-
"""
任务7b：登录会话重建（任务书硬要求）
====================================
为什么需要：4624登录、4634/4647注销在原始日志里是散落的事件，任务书要求
"把分散事件还原成完整会话"。D做横向移动分析（谁、从哪个IP、何时上机、活跃多久）
需要的是会话粒度，不是事件粒度。

原理（Windows审计机制的天然优势）：
  同一次登录会话里，4624(登录)和4634/4647(注销)的 EventData 都带同一个
  TargetLogonId——配对键 (host, LogonId) 就是标准事件的 session_id
  （"主机名:LogonId"，登录解析时已在 windows_evtx.py 生成）。

产出（不新增契约字段，全部放在 detail 里）：
  - 配对成功的登录事件：detail.logout_time + detail.session_duration_s（秒）
  - 配对成功的注销事件：detail.login_time   + detail.session_duration_s
  - 日志窗口内没等到注销的登录：detail.session_state = "active"（会话仍在进行，
    不是数据缺失——攻击者可能还在线）
  - 找不到对应登录的注销：detail.session_state = "no_login_record"
    （登录发生在日志采集窗口之前，如实标注不硬凑）

用法:
    from sessions import rebuild_sessions, print_session_summary
    events, sessions = rebuild_sessions(all_events)   # events被就地补全
    print_session_summary(sessions)                   # 报告用的会话清单
"""
from datetime import datetime


def _parse_ts(ts: str):
    """契约里的timestamp（ISO8601字符串）→ datetime，失败返回None。"""
    try:
        return datetime.fromisoformat(ts) if ts else None
    except (ValueError, TypeError):
        return None


def rebuild_sessions(events: list):
    """把登录/注销事件按 (host, LogonId) 配对成会话。

    events : 标准事件dict列表（解析产物；login_success/logout 类型会被就地补全detail）
    返回   : (events, sessions)
             sessions = [{session_id, host, user, src_ip, logon_type, login_time,
                          logout_time, duration_s, complete}, ...] 按登录时间升序，
             直接给D当"横向移动分析"的原料，也可整表贴进《测试分析报告》。
    """
    logins = {}    # session_id -> 登录事件（同一会话只登录一次，重复取最早一条）
    logouts = {}   # session_id -> [注销事件, ...]

    for ev in events:
        sid = ev.get("session_id")
        if not sid:
            continue
        if ev["event_type"] == "login_success" and ev["event_id"] == 4624:
            if sid not in logins:  # 先到先得 = 时间最早（解析产物通常按日志顺序）
                logins[sid] = ev
        elif ev["event_type"] == "logout":
            logouts.setdefault(sid, []).append(ev)

    sessions = []
    for sid, login_ev in logins.items():
        ts_in = _parse_ts(login_ev["timestamp"])
        # 找该会话里"不早于登录时间"的最早一次注销（注销不可能发生在登录之前）
        matched = None
        if ts_in is not None:
            candidates = []
            for out_ev in logouts.get(sid, []):
                ts_out = _parse_ts(out_ev["timestamp"])
                if ts_out is not None and ts_out >= ts_in:
                    candidates.append((ts_out, out_ev))
            if candidates:
                matched = min(candidates, key=lambda pair: pair[0])

        if matched is not None:
            ts_out, out_ev = matched
            duration = int((ts_out - ts_in).total_seconds())
            login_ev["detail"]["logout_time"] = out_ev["timestamp"]
            login_ev["detail"]["session_duration_s"] = duration
            out_ev["detail"]["login_time"] = login_ev["timestamp"]
            out_ev["detail"]["session_duration_s"] = duration
            logout_time, complete = out_ev["timestamp"], True
        else:
            # 没等到注销：会话在本批日志里仍活跃（攻击者可能还在线，D要重点关注）
            login_ev["detail"]["session_state"] = "active"
            logout_time, complete = None, False

        sessions.append({
            "session_id": sid,
            "host": login_ev["host"],
            "user": login_ev["user"],
            "src_ip": login_ev["src_ip"],
            "logon_type": login_ev["logon_type"],
            "login_time": login_ev["timestamp"],
            "logout_time": logout_time,
            "duration_s": login_ev["detail"].get("session_duration_s"),
            "complete": complete,
        })

    # 有注销没登录：登录发生在采集窗口之前，如实标注，不硬凑配对
    for sid, outs in logouts.items():
        if sid in logins:
            continue
        for out_ev in outs:
            out_ev["detail"]["session_state"] = "no_login_record"

    sessions.sort(key=lambda s: s["login_time"] or "")
    return events, sessions


def print_session_summary(sessions: list):
    """打印会话汇总（导入末尾统计 + 报告素材）。"""
    if not sessions:
        print("      会话重建: 本批没有可配对的登录/注销事件")
        return
    done = [s for s in sessions if s["complete"]]
    avg = (sum(s["duration_s"] for s in done) / len(done)) if done else 0
    print(f"      会话重建: 共{len(sessions)}个会话 | 完整配对{len(done)}个 | "
          f"仍活跃{len(sessions) - len(done)}个 | 平均时长{avg:.0f}秒")
    for s in sessions[:10]:  # 只展开前10个，几百条时防止刷屏
        dur = f"{s['duration_s']}秒" if s["complete"] else "进行中"
        ip = s["src_ip"] or "本地"
        print(f"        {s['login_time'][:19]}  {s['user']}@{s['host']}"
              f"  来源:{ip}  时长:{dur}")
    if len(sessions) > 10:
        print(f"        ...（其余{len(sessions) - 10}个会话见 all_sessions.json）")

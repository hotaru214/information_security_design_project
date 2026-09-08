# -*- coding: utf-8 -*-
"""
任务3：Windows EVTX 解析器
==========================
输入 : .evtx 文件路径（Windows事件日志的二进制原始文件，python-evtx负责解码）
输出 : 标准事件 dict 列表（结构见 b_host_parser/schema.py / docs/数据格式契约-v1.md）

Day 1 支持的事件:
    4624  登录成功  → event_type = login_success
    4625  登录失败  → event_type = login_failure
Day 1.5 追加（应用A同学"要进程启动样例"的需求，从Day2提前）:
    4688  进程创建  → event_type = process_create（无Sysmon时的兜底来源）
Day 2 待扩展: 4634/4647(注销→会话重建)、1102、4720、Linux auth.log/auditd
Sysmon 的 1/3/11/13 在 sysmon.py 里（Security日志和Sysmon日志分开解析）。

用法:
    from windows_evtx import parse_windows_evtx
    events = parse_windows_evtx(r"..\..\data\sample_logs\sample_4624_4625.evtx")
"""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

from schema import make_event, LOGON_TYPES, SUB_STATUS

# evtx导出的XML固定命名空间，解析时都要带这个前缀
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
UTC8 = timezone(timedelta(hours=8))  # 全组约定的统一时区

# 本文件当前关心的事件ID → event_type 映射（词表按D《Event V2 event_type规范》）
SUPPORTED = {
    4624: "login_success",
    4625: "login_failed",
    4688: "process_start",
}


def to_utc8(dt: datetime) -> str:
    """把时间统一转成 UTC+8 字符串（任务书第1条：时间序列对齐/统一时钟源）。

    python-evtx 从文件里读出的 timestamp 是 UTC 时间（不带时区的 naive datetime），
    如果直接当本地时间用，"凌晨00:00-06:00登录"这类规则会全部判错，
    和C同学网络流量的时间线也永远对不上——所以必须在入口处统一转换。
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # evtx内部时间就是UTC，补上时区标记
    # Event V2：ISO8601 T分隔格式（2026-09-08T13:10:00+08:00），保留微秒（真实精度）
    return dt.astimezone(UTC8).isoformat()


def _clean(value):
    """Windows事件里没值的字段一律填'-'，统一转成 None（契约规定空值=Null）。

    典型场景：4624本地交互登录时 IpAddress 就是"-"。
    不处理的话，"-"会被当成IP写进数据库，D那边按IP关联就会出错。
    """
    if value is None:
        return None
    v = str(value).strip()
    return v if v not in ("", "-") else None


def _basename(path: str) -> str:
    """'C:\\Windows\\System32\\svchost.exe' → 'svchost.exe'"""
    if not path:
        return None
    return path.replace("\\", "/").split("/")[-1]


def _norm_substatus(sub):
    """把 '0xc000006a' / '0XC000006A' 统一成 '0xC000006A' 再查码表。

    ⚠️ 坑：直接 .upper() 会把 '0x' 变成 '0X'，导致查表永远失配
    （这是端到端测试抓出来的真实bug，Day1踩坑笔记里有记录）。
    """
    if not sub:
        return None
    body = sub.strip()
    if body.lower().startswith("0x"):
        return "0x" + body[2:].upper()
    return body.upper()


def _record_to_event(record) -> dict:
    """把单条evtx记录(record)转成标准事件dict。

    返回 None 表示这条记录不是我们关心的事件ID（由调用方计入 skipped_other）。
    解析异常会抛出（由调用方按"条"捕获，一条坏了不能影响整个文件）。
    """
    xml_text = record.xml()  # 原始XML，留作raw_log证据
    root = ET.fromstring(xml_text)

    # --- System节点：事件ID、时间、主机名 ---
    event_id_text = root.findtext(f"{NS}System/{NS}EventID")
    if event_id_text is None:
        return None
    event_id = int(event_id_text.strip())
    if event_id not in SUPPORTED:
        return None

    # 时间：优先取XML里的 TimeCreated/SystemTime——这才是事件查看器显示的
    # 事件发生时间（实测它和记录头时间可能差1~2秒，以XML为准）；
    # 取不到再退回 record.timestamp()（evtx记录头的FILETIME，UTC）。
    ts = None
    tc = root.find(f"{NS}System/{NS}TimeCreated")
    if tc is not None:
        raw = (tc.get("SystemTime") or "").strip().rstrip("Z").replace(" UTC", "")
        if raw:
            try:
                ts = to_utc8(datetime.fromisoformat(raw))
            except ValueError:
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                    try:
                        ts = to_utc8(datetime.strptime(raw, fmt))
                        break
                    except ValueError:
                        continue
    if ts is None:
        try:
            ts = to_utc8(record.timestamp())
        except Exception:
            ts = None

    host = _clean(root.findtext(f"{NS}System/{NS}Computer"))

    # --- EventData节点：业务字段都在这里（Name→值 的字典） ---
    data = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = d.text

    user = _clean(data.get("TargetUserName"))
    src_ip = _clean(data.get("IpAddress"))  # ⚠️ 本地登录这里是None，远程登录才有值
    logon_type = _clean(data.get("LogonType"))
    logon_type = int(logon_type) if logon_type else None
    process = _basename(_clean(data.get("ProcessName")))
    logon_id = _clean(data.get("TargetLogonId"))
    cmdline = None  # 登录类事件没有命令行；只有4688分支会赋真值

    lt_desc = LOGON_TYPES.get(logon_type, f"类型{logon_type}")
    if event_id == 4624:
        event_type = SUPPORTED[event_id]
        # 会话重建（Day2）的配对键：同一(host, LogonId)的4624↔4634配成一对
        session_id = f"{host}:{logon_id}" if logon_id else None
        description = f"用户 {user} 登录成功（{lt_desc}）"
        src_port = _clean(data.get("IpPort"))  # 远程登录时的来源端口
        detail = {"logon_id": logon_id,
                  "domain": _clean(data.get("TargetDomainName")),
                  "src_port": int(src_port) if src_port and src_port.isdigit() else src_port}
    elif event_id == 4625:  # 登录失败
        event_type = SUPPORTED[event_id]
        session_id = None  # 登录失败没有会话
        sub = _clean(data.get("SubStatus"))
        sub_desc = SUB_STATUS.get(_norm_substatus(sub), sub)
        description = f"用户 {user} 登录失败（{lt_desc}，原因: {sub_desc}）"
        detail = {"substatus": sub, "substatus_desc": sub_desc,
                  "failure_reason": _clean(data.get("FailureReason")),
                  "workstation": _clean(data.get("WorkstationName"))}
    else:  # 4688 进程启动
        event_type = SUPPORTED[event_id]
        # 4688没有TargetUserName，发起进程的账号是SubjectUserName
        user = _clean(data.get("SubjectUserName"))
        process = _basename(_clean(data.get("NewProcessName")))
        session_id = None
        # ProcessName（老系统）/ParentProcessName（Win10+）是创建者（父）进程的路径；
        # 老格式（如本样例）两个都没有 → parent为null，如实空缺
        parent = _basename(_clean(data.get("ParentProcessName")) or _clean(data.get("ProcessName")))
        # ⚠️ CommandLine只有开启"进程创建命令行审核策略"才有值——没有就null，不造假
        cmdline = _clean(data.get("CommandLine"))
        parent_desc = parent if parent else "无记录"
        description = f"进程创建: {process}（发起用户: {user}，父进程: {parent_desc}）"
        detail = {"parent_process": parent,
                  "creator_process_id": _clean(data.get("ProcessId")),
                  "new_process_id": _clean(data.get("NewProcessId")),
                  "token_elevation": _clean(data.get("TokenElevationType"))}

    return make_event(
        timestamp=ts,
        host=host,
        source="windows_evtx",
        event_id=event_id,
        event_type=event_type,
        user=user,
        process=process,
        src_ip=src_ip,
        dst_ip=None,           # 主机日志没有目的IP（Sysmon ID 3才有，见sysmon.py）
        logon_type=logon_type,
        session_id=session_id,
        cmdline=cmdline,       # 4688/Sysmon1才有；登录类事件恒为None
        detail=detail,
        description=description,
        anomaly_flags=[],      # 异常预标记规则来填
        severity=0,
        raw_log=xml_text[:2000],  # 截断保存，前端"查看证据"用
    )


def parse_windows_evtx(file_path: str, stats: dict = None) -> list:
    """解析 .evtx 文件（Windows Security等系统日志），返回标准事件列表。
    支持: 4624登录成功 / 4625登录失败 / 4688进程创建。
    Sysmon日志用 sysmon.py 的 parse_sysmon_evtx。

    file_path : .evtx 文件路径
    stats     : 可选。传入一个空dict，函数会把统计写进去：
                {"parsed": 成功条数, "skipped_other": 非目标事件条数,
                 "failed": 解析失败条数, "by_event_id": {事件ID: 条数}}

    ⚠️ try-except 是按"条"包的：一条记录损坏只丢这一条并计数，
       绝不让整个文件中断（全量导入E的数据时靠这个保命）。
    """
    events = []
    if stats is None:
        stats = {}
    stats.update(parsed=0, skipped_other=0, failed=0, by_event_id={})

    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                ev = _record_to_event(record)
                if ev is None:
                    # 不是4624/4625，也统计一下原始事件ID分布（写报告有用）
                    stats["skipped_other"] += 1
                    try:
                        raw_id = record.xml()
                        root = ET.fromstring(raw_id)
                        oid = root.findtext(f"{NS}System/{NS}EventID")
                        if oid:
                            key = f"other:{oid.strip()}"
                            stats["by_event_id"][key] = stats["by_event_id"].get(key, 0) + 1
                    except Exception:
                        pass
                    continue
                events.append(ev)
                stats["parsed"] += 1
                key = str(ev["event_id"])
                stats["by_event_id"][key] = stats["by_event_id"].get(key, 0) + 1
            except Exception as e:
                # 一条坏了：计数、继续处理下一条（绝不中断整个文件）
                stats["failed"] += 1
                print(f"  [跳过损坏记录] {e}")
    return events


if __name__ == "__main__":
    # 单独调试本文件用：python windows_evtx.py <某个.evtx>
    import sys, json
    if len(sys.argv) < 2:
        print("用法: python windows_evtx.py <文件.evtx>")
        sys.exit(1)
    st = {}
    result = parse_windows_evtx(sys.argv[1], st)
    print(f"解析出 {len(result)} 条标准事件, 统计: {st}")
    if result:
        print(json.dumps(result[0], ensure_ascii=False, indent=2))

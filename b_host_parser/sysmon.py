# -*- coding: utf-8 -*-
"""
Sysmon 日志解析器（Day2任务7提前完成——应A同学"要进程/文件操作样例"的需求）
==========================================================================
输入 : Sysmon的 .evtx 文件（Provider是 "Microsoft-Windows-Sysmon" 的那种）
输出 : 标准事件 dict 列表（结构见 schema.py，19字段齐全，空值一律null不造假）

支持的事件（这正是任务书"关键实体提取：用户、进程、文件、注册表键值"的来源）:
    ID 1   进程创建      → process_create（cmdline + 父进程，D分析恶意执行的关键）
    ID 3   网络连接      → network_connect（src/dst IP + 端口 + 协议，桥接C的流量数据）
    ID 11  文件创建      → file_create
    ID 13  注册表键值修改 → registry_set

用法:
    from sysmon import parse_sysmon_evtx
    events = parse_sysmon_evtx(r"..\data\sample_logs\sample_sysmon_1_3.evtx")
"""
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

from schema import make_event
from windows_evtx import NS, to_utc8, _clean, _basename

# Sysmon事件ID → event_type（词表按D《Event V2 event_type规范》）
SUPPORTED = {
    1: "process_start",
    3: "network_connection",
    11: "file_create",
    13: "registry_set",
}


def _record_to_event(record) -> dict:
    """把单条Sysmon记录转成标准事件。不关心的ID返回None，异常向上抛。"""
    xml_text = record.xml()
    root = ET.fromstring(xml_text)

    event_id_text = root.findtext(f"{NS}System/{NS}EventID")
    if event_id_text is None:
        return None
    event_id = int(event_id_text.strip())
    if event_id not in SUPPORTED:
        return None

    # 时间：与windows_evtx相同策略——以XML的TimeCreated为准（UTC→UTC+8）
    ts = None
    tc = root.find(f"{NS}System/{NS}TimeCreated")
    if tc is not None:
        raw = (tc.get("SystemTime") or "").strip().rstrip("Z").replace(" UTC", "")
        if raw:
            ts = to_utc8(_try_iso(raw))
    if ts is None:
        try:
            ts = to_utc8(record.timestamp())
        except Exception:
            ts = None

    host = _clean(root.findtext(f"{NS}System/{NS}Computer"))

    data = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = d.text

    image = _basename(_clean(data.get("Image")))  # Sysmon里Image=产生本事件的进程
    user = _clean(data.get("User"))
    event_type = SUPPORTED[event_id]

    if event_id == 1:  # 进程创建
        cmdline = _clean(data.get("CommandLine"))
        parent = _basename(_clean(data.get("ParentImage")))
        description = f"进程创建: {image}（父进程: {parent}）"
        detail = {"parent_process": parent,
                  "parent_cmdline": _clean(data.get("ParentCommandLine")),
                  "hashes": _clean(data.get("Hashes"))}
        extra = dict(cmdline=cmdline)

    elif event_id == 3:  # 网络连接：唯一会填 dst_ip/dst_port/protocol 的主机事件
        dst_ip = _clean(data.get("DestinationIp"))
        dst_port = _clean(data.get("DestinationPort"))
        protocol = _clean(data.get("Protocol"))
        src_port = _clean(data.get("SourcePort"))
        tail = f":{dst_port}" if dst_port else ""
        description = f"主机发起{protocol or ''}连接 → {dst_ip}{tail}（进程: {image}）"
        detail = {"src_port": int(src_port) if src_port and src_port.isdigit() else src_port,
                  "initiated": _clean(data.get("Initiated"))}
        extra = dict(dst_ip=dst_ip,
                     dst_port=int(dst_port) if dst_port else None,
                     protocol=protocol)

    elif event_id == 11:  # 文件创建
        target = _clean(data.get("TargetFilename"))
        description = f"文件创建: {target}（进程: {image}）"
        detail = {"file_path": target,
                  "creation_utc_time": _clean(data.get("CreationUtcTime"))}
        extra = dict()

    else:  # ID 13 注册表键值修改（detail键名按Event V2契约）
        target = _clean(data.get("TargetObject"))
        value = _clean(data.get("Details"))
        # TargetObject形如 HKLM\...\Shares\staging，末段就是值名称
        value_name = target.rsplit("\\", 1)[-1] if target else None
        description = f"注册表写入: {target} = {value}"
        detail = {"registry_key": target,
                  "registry_value_name": value_name,
                  "registry_value_data": value,
                  "registry_operation": _clean(data.get("EventType"))}
        extra = dict()

    return make_event(
        timestamp=ts,
        host=host,
        source="sysmon",
        event_id=event_id,
        event_type=event_type,
        user=user,
        process=image,
        src_ip=_clean(data.get("SourceIp")) if event_id == 3 else None,
        detail=detail,
        description=description,
        raw_log=xml_text[:2000],  # 契约必填：前端"查看证据"用（v1.1审计补上，之前漏传）
        **extra,
    )


def _try_iso(raw: str):
    """XML里的SystemTime字符串 → datetime（失败返回None，交给上层兜底）"""
    from datetime import datetime
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def parse_sysmon_evtx(file_path: str, stats: dict = None) -> list:
    """解析Sysmon的.evtx文件，返回标准事件列表。

    stats 写法与 parse_windows_evtx 相同：parsed / skipped_other / failed / by_event_id。
    同样按"条"try-except，坏一条不坏整个文件。
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
                    stats["skipped_other"] += 1
                    continue
                events.append(ev)
                stats["parsed"] += 1
                key = str(ev["event_id"])
                stats["by_event_id"][key] = stats["by_event_id"].get(key, 0) + 1
            except Exception as e:
                stats["failed"] += 1
                print(f"  [跳过损坏记录] {e}")
    return events

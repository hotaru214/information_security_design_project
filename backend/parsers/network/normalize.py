"""统一安全事件输出 —— Event V2 契约（全组冻结，2026-09-07）。

输出严格为 19 个公共字段，不多不少；后端 SQLite 另生成内部主键 `id`，
`event_id` 只放原始日志自带编号（Zeek uid 等），PCAP 无则 null。

  timestamp   UTC+8 ISO8601（2026-09-08T13:10:00+08:00）
  host / source / event_id / event_type / user / process
  src_ip / dst_ip / dst_port / protocol
  logon_type / session_id / cmdline
  detail(必填对象) / description
  anomaly_flags(必填数组，无异常 []) / severity(0正常 1低 2中 3高) / raw_log(必填)

网络事件特有信息全部放 detail（src_port/packets/bytes/direction/attack_stage/
mitre_technique/dns_queries/http_requests/tcp_flags/...）。
缺失数据一律 null，不用 "unknown"/0/空串占位。
"""
import csv
import json
import os
from datetime import datetime, timedelta, timezone

from .config import DetectionConfig
from .detectors import STAGE_ZH, _base_domain
from .models import Anomaly, FlowRecord

TZ_CN = timezone(timedelta(hours=8))

EVENT_V2_FIELDS = (
    "timestamp", "host", "source", "source_event_id", "event_type", "user", "process",
    "src_ip", "dst_ip", "dst_port", "protocol",
    "logon_type", "session_id", "cmdline",
    "detail", "description", "anomaly_flags", "severity", "raw_log",
)

# event_type 冻结枚举（全组规范，B 起草 2026-09-07）
EVENT_TYPE_ENUM = {
    # 登录与会话
    "login_success", "login_failed", "logout",
    # 进程行为
    "process_start", "process_end",
    # 网络行为
    "network_connection", "dns_query", "http_request",
    # 文件行为
    "file_create", "file_read", "file_write", "file_modify", "file_delete",
    # 注册表行为
    "registry_set", "registry_create", "registry_delete", "registry_query",
    # 账户与权限
    "user_created", "user_deleted", "user_modified",
    "group_member_added", "group_member_removed", "privilege_change",
    # 服务与计划任务
    "service_created", "service_started", "service_stopped", "service_deleted",
    "scheduled_task_created", "scheduled_task_run", "scheduled_task_deleted",
    "log_cleared",
}

# 网络侧告警 -> 冻结 event_type 映射（检测名称一律放 anomaly_flags，不再自造 event_type）
ANOMALY_EVENT_TYPE = {
    "port_scan": "network_connection",
    "suspicious_port": "network_connection",
    "c2_beacon": "network_connection",
    "exfiltration": "network_connection",
    "icmp_tunnel": "network_connection",
    "lateral_movement": "network_connection",
    "brute_force_evidence": "network_connection",
    "cc_rotation": "network_connection",
    "http_attack": "http_request",
    "dns_tunnel": "dns_query",
}

# 个别 flag 名对齐规范示例（规范 network_connection 示例用 remote_service_connection）
ANOMALY_FLAG_NAME = {
    "lateral_movement": "remote_service_connection",
}

# 模块内部分级 -> Event V2 数字 severity（critical 收敛为 3）
SEVERITY_MAP = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}


def load_host_map(path: str) -> dict:
    """加载 IP→主机名映射 CSV（列: ip,hostname[,role]）。"""
    host_map = {}
    if not path or not os.path.isfile(path):
        return host_map
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            ip = (row.get("ip") or "").strip()
            name = (row.get("hostname") or "").strip()
            if ip and name:
                host_map[ip] = name
    return host_map


def _iso8601_cn(ts: float) -> str:
    """unix 时间戳 -> UTC+8 ISO8601（毫秒）。"""
    return datetime.fromtimestamp(ts, TZ_CN).isoformat(timespec="milliseconds")


def _direction(src_ip: str, dst_ip: str, cfg: DetectionConfig) -> str:
    s, d = cfg.is_internal(src_ip), cfg.is_internal(dst_ip)
    if s and d:
        return "internal"
    if s:
        return "outbound"
    if d:
        return "inbound"
    return "external"


def _flow_type(rec: FlowRecord) -> str:
    """会话 -> 冻结 event_type。ICMP 归 network_connection，用 protocol=icmp 区分。"""
    if rec.dns_queries:
        return "dns_query"
    if rec.http_requests:
        return "http_request"
    return "network_connection"


def _host_side(rec: FlowRecord, cfg: DetectionConfig) -> tuple:
    """返回 (内网侧IP, 对端IP)；两侧都是内网时 host 取目的侧（服务方）。"""
    if cfg.is_internal(rec.dst_ip):
        return rec.dst_ip, rec.src_ip
    return rec.src_ip, rec.dst_ip


def flow_to_event(rec: FlowRecord, host_map: dict, cfg: DetectionConfig) -> dict:
    """普通会话事件（severity=0, anomaly_flags=[]）。"""
    host_ip, peer_ip = _host_side(rec, cfg)
    has_ports = rec.protocol in ("TCP", "UDP")

    detail = {
        "src_port": rec.src_port if has_ports and rec.src_port else None,
        "peer_host": host_map.get(peer_ip, peer_ip),
        "direction": _direction(rec.src_ip, rec.dst_ip, cfg),
        "packets": rec.packets,
        "bytes": rec.bytes_total,
        "duration_sec": round(rec.duration, 3),
        "flow_key": rec.flow_key,
        "end_time": _iso8601_cn(rec.end_ts),
    }
    # D 推荐键名：bytes_out=发起方发送字节，bytes_in=对端返回字节
    if rec.src_bytes is not None:
        detail["bytes_out"] = rec.src_bytes
        detail["bytes_in"] = rec.dst_bytes or 0
    if rec.protocol == "TCP":
        detail["tcp_flags"] = {"src": sorted(rec.src_flags), "dst": sorted(rec.dst_flags)}
    if rec.dns_queries:
        detail["domain"] = _base_domain(rec.dns_queries[0].qname)   # D 推荐键名
        detail["dns_queries"] = [{"qname": q.qname, "qtype": q.qtype}
                                 for q in rec.dns_queries[:50]]
        detail["dns_query_count"] = len(rec.dns_queries)
    if rec.http_requests:
        first = rec.http_requests[0]
        detail["method"] = first.method        # D 推荐键名
        detail["uri"] = first.uri
        detail["domain"] = first.host or None
        detail["http_requests"] = [
            {"method": r.method, "host": r.host, "uri": r.uri,
             "user_agent": r.user_agent, "body": r.body}
            for r in rec.http_requests[:50]
        ]
        detail["http_request_count"] = len(rec.http_requests)
    if rec.protocol == "ICMP":
        detail["icmp_count"] = rec.icmp_count
        detail["icmp_max_payload_bytes"] = rec.icmp_max_payload
    if getattr(rec, "dataset_label", None):
        detail["dataset_label"] = rec.dataset_label   # 公开数据集标签（评估用）

    port_part = f":{rec.dst_port}" if has_ports and rec.dst_port else ""
    description = (f"{rec.src_ip} → {rec.dst_ip}{port_part} {rec.protocol} 会话，"
                   f"{rec.packets} 包 / {rec.bytes_total} 字节，持续 {rec.duration:.1f} 秒")
    # PCAP 无原始日志行，生成一行规范化摘要作为 raw_log；Zeek/CSV 保留原始行
    raw_log = rec.raw_log or (
        f"FLOW {rec.flow_key} start={_iso8601_cn(rec.start_ts)} "
        f"pkts={rec.packets} bytes={rec.bytes_total}")

    return {
        "timestamp": _iso8601_cn(rec.start_ts),
        "host": host_map.get(host_ip, host_ip),
        "source": rec.source,
        "source_event_id": rec.source_event_id,   # Event V2 FINAL：网络事件恒为 null
        "event_type": _flow_type(rec),
        "user": None,
        "process": None,
        "src_ip": rec.src_ip,
        "dst_ip": rec.dst_ip,
        "dst_port": rec.dst_port if has_ports and rec.dst_port else None,
        "protocol": rec.protocol.lower(),
        "logon_type": None,
        "session_id": None,
        "cmdline": None,
        "detail": detail,
        "description": description,
        "anomaly_flags": [],
        "severity": 0,
        "raw_log": raw_log,
    }


def anomaly_to_event(a: Anomaly, host_map: dict, cfg: DetectionConfig) -> dict:
    """告警事件：anomaly_flags=[检测规则, ATT&CK技术]，ATT&CK 阶段放 detail。"""
    s, d = cfg.is_internal(a.src_ip), cfg.is_internal(a.dst_ip)
    # host 取内网侧（都内网取 dst=被访问方；都外网取 src）
    if d and not s:
        host_ip, peer_ip = a.dst_ip, a.src_ip
    else:
        host_ip, peer_ip = a.src_ip, a.dst_ip

    detail = dict(a.evidence)
    detail.update({
        "attack_stage": a.attack_stage,
        "attack_stage_zh": STAGE_ZH.get(a.attack_stage, a.attack_stage),
        "mitre_technique": a.mitre,
        "end_time": _iso8601_cn(a.end_ts),
        "src_port": None,
    })

    raw_log = f"DETECT[{a.kind}] {a.description}"

    flags = [ANOMALY_FLAG_NAME.get(a.kind, a.kind), a.mitre]
    if a.entry_point:
        flags.append("entry_point_candidate")   # D 的关联引擎据此裁决攻击链起点

    return {
        "timestamp": _iso8601_cn(a.start_ts),
        "host": host_map.get(host_ip, host_ip),
        "source": a.source,
        "source_event_id": None,        # 检测器产物，无原始日志编号
        "event_type": ANOMALY_EVENT_TYPE[a.kind],   # 冻结枚举，检测名放 anomaly_flags
        "user": None,
        "process": None,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "dst_port": a.dst_port or None,
        "protocol": a.protocol.lower(),
        "logon_type": None,
        "session_id": None,
        "cmdline": None,
        "detail": detail,
        "description": a.description,
        "anomaly_flags": flags,
        "severity": SEVERITY_MAP[a.severity],
        "raw_log": raw_log,
    }


def build_events(flows: list, anomalies: list, host_map: dict = None,
                 cfg: DetectionConfig = None, include_flows: bool = True) -> list:
    """会话 + 告警 -> Event V2 列表（按 timestamp 排序）。不做任何 event_id 改写。"""
    if host_map is None:
        host_map = {}
    if cfg is None:
        cfg = DetectionConfig()
    events = []
    if include_flows:
        events.extend(flow_to_event(rec, host_map, cfg)
                      for rec in sorted(flows, key=lambda r: (r.start_ts, r.flow_key)))
    events.extend(anomaly_to_event(a, host_map, cfg) for a in anomalies)
    events.sort(key=lambda e: e["timestamp"])
    return events


# 后端入库必填的非空字段（对应 A 的 EventCreate: min_length=1 / 必填）
_REQUIRED_NON_EMPTY = ("host", "description", "raw_log")
# 禁止的占位值：契约规定缺失一律 null，不允许 unknown/0/空串制造占位
_PLACEHOLDERS = ("", "unknown", "Unknown", "UNKNOWN", "-", "N/A", "none")
_SOURCES = ("windows_evtx", "sysmon", "linux_auth", "linux_audit",
            "network_pcap", "network_zeek", "firewall", "waf")


def _is_ip_like(value) -> bool:
    return isinstance(value, str) and value.replace(".", "").isdigit() and value.count(".") == 3


def validate_events(events: list) -> list:
    """Event V2 契约自检（阻断级）：返回问题列表（空列表=全部合规）。

    覆盖：19 个基础字段 + 可选 case_id、event_type 冻结枚举、source 枚举、severity 0-3、
    时间 UTC+8 且可解析、必填字段非空、禁止占位值（unknown/空串/0）、
    网络事件 source_event_id 必须 null、detail/anomaly_flags 类型。
    """
    problems = []
    required = set(EVENT_V2_FIELDS)
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            problems.append(f"事件#{i} 不是对象")
            continue
        keys = set(e.keys())
        if keys - {"case_id"} != required:
            missing, extra = required - keys, keys - required - {"case_id"}
            problems.append(f"事件#{i} 字段不符: 缺 {missing or '{}'} 多 {extra or '{}'}")
            continue
        if e.get("case_id") is not None and (not isinstance(e["case_id"], str) or not e["case_id"]):
            problems.append(f"事件#{i} case_id 必须为非空字符串或 null")
        if not isinstance(e["detail"], dict):
            problems.append(f"事件#{i} detail 不是对象")
        if not isinstance(e["anomaly_flags"], list):
            problems.append(f"事件#{i} anomaly_flags 不是数组")
        elif not all(isinstance(f, str) for f in e["anomaly_flags"]):
            problems.append(f"事件#{i} anomaly_flags 含非字符串元素")
        if e["severity"] not in (0, 1, 2, 3):
            problems.append(f"事件#{i} severity 非法: {e['severity']!r}")
        if e["event_type"] not in EVENT_TYPE_ENUM:
            problems.append(f"事件#{i} event_type 不在冻结枚举: {e['event_type']!r}")
        if e["source"] not in _SOURCES:
            problems.append(f"事件#{i} source 非法: {e['source']!r}")
        if e["source"] in ("network_pcap", "network_zeek") and e["source_event_id"] is not None:
            problems.append(f"事件#{i} 网络事件 source_event_id 应为 null: {e['source_event_id']!r}")
        # 时间：字符串形态 + 可解析
        ts = e["timestamp"]
        if not isinstance(ts, str) or not ts.endswith("+08:00"):
            problems.append(f"事件#{i} 时间戳非 UTC+8 ISO8601: {ts!r}")
        else:
            try:
                datetime.fromisoformat(ts)
            except ValueError:
                problems.append(f"事件#{i} 时间戳无法解析: {ts!r}")
        # 必填非空 + 占位值扫描（公共字段层面；detail 内自由字段不做深度扫描）
        for field in _REQUIRED_NON_EMPTY:
            v = e.get(field)
            if v is None or (isinstance(v, str) and (not v.strip() or v.strip() in _PLACEHOLDERS)):
                problems.append(f"事件#{i} 必填字段 {field} 为空/占位: {v!r}")
        if e.get("dst_port") is not None:
            dp = e["dst_port"]
            if not isinstance(dp, int) or not (1 <= dp <= 65535):
                problems.append(f"事件#{i} dst_port 非法（缺失应为 null 而非 0/越界）: {dp!r}")
    return problems


def collect_warnings(events: list) -> list:
    """非阻断性契约警告。当前唯一已知项：host 为 IP 字符串
    （数据集未建映射或后端 host 未放宽为可空前的兜底），待 A 放宽后归零。"""
    problems = []
    for i, e in enumerate(events):
        if _is_ip_like(e.get("host")):
            problems.append(f"事件#{i} host 为 IP 字符串({e['host']})——待后端 host 放宽为可空后应改 null")
    return problems


def validate_eventout(events: list) -> list:
    """D 的输入（后端 EventOut = 19 字段 + 数据库 id）契约校验（阻断级）。

    在 validate_events 之上增加：id 必须为正整数且全局唯一；多余/缺失 id 字段报错。
    """
    problems = []
    required = set(EVENT_V2_FIELDS) | {"id"}
    seen_ids = set()
    bodies = []
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            problems.append(f"事件#{i} 不是对象")
            continue
        keys = set(e.keys())
        if keys - {"case_id"} != required:
            missing, extra = required - keys, keys - required - {"case_id"}
            problems.append(f"EventOut#{i} 字段不符: 缺 {missing or '{}'} 多 {extra or '{}'}")
            continue
        eid = e["id"]
        if not isinstance(eid, int) or isinstance(eid, bool) or eid <= 0:
            problems.append(f"EventOut#{i} id 非法（应为正整数）: {eid!r}")
        elif eid in seen_ids:
            problems.append(f"EventOut#{i} id 重复: {eid}")
        seen_ids.add(eid)
        bodies.append({k: v for k, v in e.items() if k != "id"})
    return problems + validate_events(bodies)


def build_summary(events: list) -> dict:
    """事件列表 -> 前端 Dashboard 汇总（--summary-json 输出）。

    F 的首页四宫格与时间线页可直接消费，无需自己写统计逻辑。
    """
    from collections import Counter

    severity_counts = Counter(e["severity"] for e in events)
    type_counts = Counter(e["event_type"] for e in events)
    alarmed = [e for e in events if e["anomaly_flags"]]

    # 攻击阶段时间线：每条告警 -> 阶段/规则/ATT&CK/主机/描述
    timeline = []
    for e in alarmed:
        d = e.get("detail") or {}
        timeline.append({
            "timestamp": e["timestamp"],
            "attack_stage": d.get("attack_stage"),
            "attack_stage_zh": d.get("attack_stage_zh"),
            "flag": e["anomaly_flags"][0],
            "mitre_technique": d.get("mitre_technique") or (e["anomaly_flags"][1] if len(e["anomaly_flags"]) > 1 else None),
            "severity": e["severity"],
            "host": e["host"],
            "src_ip": e["src_ip"], "dst_ip": e["dst_ip"],
            "description": e["description"],
            "entry_point": bool(d.get("entry_point")),
        })
    timeline.sort(key=lambda t: t["timestamp"])

    # 告警涉及主机（去重排序）
    hosts_involved = sorted({e["host"] for e in alarmed if e["host"]})

    # 外部目的 top10（按上行字节）——从 flow 事件 detail 取
    ext_stats = {}
    for e in events:
        if e["event_type"] != "network_connection" or not e["anomaly_flags"]:
            d = e.get("detail") or {}
            if d.get("direction") != "outbound":
                continue
            key = e["dst_ip"]
            stat = ext_stats.setdefault(key, {"ip": key, "hostname": d.get("peer_host"), "bytes_out": 0, "connections": 0})
            stat["bytes_out"] += d.get("bytes_out") or 0
            stat["connections"] += 1
    top_external = sorted(ext_stats.values(), key=lambda s: -s["bytes_out"])[:10]

    # 告警规则计数（flags[0]）
    flag_counts = Counter(e["anomaly_flags"][0] for e in alarmed)

    return {
        "total_events": len(events),
        "anomaly_events": len(alarmed),
        "severity_counts": {str(k): v for k, v in sorted(severity_counts.items())},
        "event_type_counts": dict(sorted(type_counts.items())),
        "anomaly_flag_counts": dict(sorted(flag_counts.items())),
        "attack_stage_sequence": [t["flag"] for t in timeline],
        "attack_timeline": timeline,
        "hosts_involved": hosts_involved,
        "top_external_dst_by_bytes": top_external,
        "time_range": {
            "first": events[0]["timestamp"] if events else None,
            "last": events[-1]["timestamp"] if events else None,
        },
    }


def save_events(events: list, out_path: str):
    """事件列表写入 JSON 文件（UTF-8，中文不转义），可直接用于 POST /api/events/import。"""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(events, fh, ensure_ascii=False, indent=2)
    return out_path

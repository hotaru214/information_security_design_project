"""统一安全事件输出：FlowRecord + Anomaly → 统一事件 JSON（成员C → 后端A / 关联引擎D）。

事件字段与《分工》文档中的统一事件模型对齐：
{
  "event_id", "timestamp", "source", "event_type", "severity",
  "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
  "host", "peer_host", "direction",
  "attack_stage", "mitre_technique",
  "description", "evidence"
}

timestamp 为本地时间 ISO 格式（如 2026-09-07T09:01:40.123），字符串排序即时间排序，
便于 D 做时间线对齐与关联。
"""
import csv
import json
import os
from datetime import datetime

from .config import DetectionConfig, SERVICE_NAMES
from .detectors import STAGE_ZH
from .models import Anomaly, FlowRecord

SEVERITY_ZH = {"info": "信息", "low": "低危", "medium": "中危", "high": "高危", "critical": "严重"}


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


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")


def _name(ip: str, host_map: dict) -> str:
    return host_map.get(ip, ip)


def _internal_side(rec: FlowRecord, cfg: DetectionConfig) -> str:
    """返回内网侧端点在 src/dst 中的位置，用于确定 host 字段。"""
    if cfg.is_internal(rec.src_ip):
        return "src"
    if cfg.is_internal(rec.dst_ip):
        return "dst"
    return "src"


def _direction_of(rec: FlowRecord, cfg: DetectionConfig) -> str:
    s, d = cfg.is_internal(rec.src_ip), cfg.is_internal(rec.dst_ip)
    if s and d:
        return "internal"
    if s and not d:
        return "outbound"
    if d and not s:
        return "inbound"
    return "external"


def _flow_type(rec: FlowRecord) -> str:
    if rec.dns_queries:
        return "dns_query"
    if rec.http_requests:
        return "http_request"
    if rec.protocol == "ICMP":
        return "icmp_traffic"
    return "network_connection"


def flow_to_event(rec: FlowRecord, host_map: dict, cfg: DetectionConfig, seq: int) -> dict:
    internal_side = _internal_side(rec, cfg)
    if internal_side == "src":
        host_ip, peer_ip = rec.src_ip, rec.dst_ip
    else:
        host_ip, peer_ip = rec.dst_ip, rec.src_ip

    src_name, dst_name = _name(rec.src_ip, host_map), _name(rec.dst_ip, host_map)
    port_part = f":{rec.dst_port}" if rec.dst_port else ""
    description = (f"{src_name} → {dst_name}{port_part} {rec.protocol} 会话，"
                   f"{rec.packets} 包 / {rec.bytes_total} 字节，持续 {rec.duration:.1f} 秒")

    evidence = {
        "packets": rec.packets,
        "bytes": rec.bytes_total,
        "duration_sec": round(rec.duration, 3),
        "flow_key": rec.flow_key,
    }
    if rec.protocol == "TCP":
        evidence["tcp_flags"] = {
            "src": sorted(rec.src_flags),
            "dst": sorted(rec.dst_flags),
        }
    if rec.dns_queries:
        evidence["dns_queries"] = [{"qname": q.qname, "qtype": q.qtype}
                                   for q in rec.dns_queries[:50]]
        evidence["dns_query_count"] = len(rec.dns_queries)
    if rec.http_requests:
        evidence["http_requests"] = [
            {"method": r.method, "host": r.host, "uri": r.uri, "user_agent": r.user_agent}
            for r in rec.http_requests[:50]
        ]
        evidence["http_request_count"] = len(rec.http_requests)
    if rec.protocol == "ICMP":
        evidence["icmp_count"] = rec.icmp_count
        evidence["icmp_max_payload_bytes"] = rec.icmp_max_payload

    return {
        "event_id": f"NW-{seq:06d}",
        "timestamp": _iso(rec.start_ts),
        "source": "network_traffic",
        "event_type": _flow_type(rec),
        "severity": "info",
        "src_ip": rec.src_ip,
        "src_port": rec.src_port,
        "dst_ip": rec.dst_ip,
        "dst_port": rec.dst_port,
        "protocol": rec.protocol,
        "host": host_map.get(host_ip, host_ip),
        "peer_host": host_map.get(peer_ip, peer_ip),
        "direction": _direction_of(rec, cfg),
        "attack_stage": None,
        "mitre_technique": None,
        "description": description,
        "evidence": evidence,
    }


def anomaly_to_event(a: Anomaly, host_map: dict, cfg: DetectionConfig, seq: int) -> dict:
    """告警 → 统一事件。host 取内网侧主机（都内网取 dst，都外网取 src）。"""
    s, d = cfg.is_internal(a.src_ip), cfg.is_internal(a.dst_ip)
    if s and not d:
        host_ip, peer_ip = a.src_ip, a.dst_ip
    elif d and not s:
        host_ip, peer_ip = a.dst_ip, a.src_ip
    elif d and s:
        host_ip, peer_ip = a.dst_ip, a.src_ip
    else:
        host_ip, peer_ip = a.src_ip, a.dst_ip

    evidence = dict(a.evidence)
    evidence["related_src"] = a.src_ip
    evidence["related_dst"] = a.dst_ip

    return {
        "event_id": f"NW-{seq:06d}",
        "timestamp": _iso(a.start_ts),
        "source": "network_traffic",
        "event_type": a.kind,
        "severity": a.severity,
        "src_ip": a.src_ip,
        "src_port": 0,
        "dst_ip": a.dst_ip,
        "dst_port": a.dst_port,
        "protocol": a.protocol,
        "host": host_map.get(host_ip, host_ip),
        "peer_host": host_map.get(peer_ip, peer_ip),
        "direction": _direction_of_simple(s, d),
        "attack_stage": a.attack_stage,
        "attack_stage_zh": STAGE_ZH.get(a.attack_stage, a.attack_stage),
        "mitre_technique": a.mitre,
        "description": a.description,
        "evidence": evidence,
    }


def _direction_of_simple(src_internal: bool, dst_internal: bool) -> str:
    if src_internal and dst_internal:
        return "internal"
    if src_internal:
        return "outbound"
    if dst_internal:
        return "inbound"
    return "external"


def build_events(flows: list, anomalies: list, host_map: dict = None,
                 cfg: DetectionConfig = None, include_flows: bool = True) -> list:
    """会话 + 告警 → 统一事件列表（按时间排序、统一编号）。"""
    if host_map is None:
        host_map = {}
    if cfg is None:
        cfg = DetectionConfig()
    events = []
    seq = 1
    if include_flows:
        for rec in sorted(flows, key=lambda r: (r.start_ts, r.flow_key)):
            events.append(flow_to_event(rec, host_map, cfg, seq))
            seq += 1
    for a in anomalies:
        events.append(anomaly_to_event(a, host_map, cfg, seq))
        seq += 1
    events.sort(key=lambda e: e["timestamp"])
    for i, event in enumerate(events, 1):
        event["event_id"] = f"NW-{i:06d}"
    return events


def save_events(events: list, out_path: str):
    """事件列表写入 JSON 文件（UTF-8，中文不转义），可直接用于 POST /api/events/import。"""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(events, fh, ensure_ascii=False, indent=2)
    return out_path

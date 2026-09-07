"""基于规则的网络异常检测。

覆盖任务书要求的"异常协议行为建模"与"隐蔽信道检测"：
端口扫描 / C2 心跳(beaconing) / 可疑端口 / DNS 隧道 / 数据外传 / ICMP 隧道 /
内网横向移动连接 / HTTP 攻击载荷。

每条 Anomaly 携带 ATT&CK 战术阶段与技术编号，供 D 的关联引擎直接使用。
"""
import math
import re
import statistics
from collections import defaultdict
from datetime import datetime

from .config import DetectionConfig, SERVICE_NAMES
from .models import Anomaly, FlowRecord

STAGE_ZH = {
    "Reconnaissance": "侦察",
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Lateral Movement": "横向移动",
    "Collection": "收集",
    "Command and Control": "命令与控制",
    "Exfiltration": "数据外传",
}


def shannon_entropy(text: str) -> float:
    """字符串香农熵（比特/字符）。随机 base32/hex 编码串通常 >4.0，正常单词 <3.0。"""
    if not text:
        return 0.0
    freq = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def _hhmmss(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _base_domain(qname: str) -> str:
    """取注册域（最后两段）。内网练习场景足够。"""
    parts = qname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return qname


# ---------------------------------------------------------------- 检测器

def detect_port_scans(flows, cfg: DetectionConfig):
    """同一源IP对同一目标IP 触碰大量不同端口 → 端口扫描（Reconnaissance, T1046）。"""
    groups = defaultdict(list)
    for rec in flows:
        if rec.protocol != "TCP":
            continue
        syn_from_src = any(f == "S" for f in rec.src_flags)
        if syn_from_src:
            groups[(rec.src_ip, rec.dst_ip)].append(rec)

    results = []
    for (src, dst), recs in groups.items():
        ports = sorted({rec.dst_port for rec in recs})
        if len(ports) < cfg.scan_port_threshold:
            continue
        open_ports = sorted({rec.dst_port for rec in recs
                             if any("S" in f and "A" in f for f in rec.dst_flags)})
        packets = sum(rec.packets for rec in recs)
        start = min(rec.start_ts for rec in recs)
        end = max(rec.end_ts for rec in recs)
        results.append(Anomaly(
            kind="port_scan", severity="medium", attack_stage="Reconnaissance", mitre="T1046",
            src_ip=src, dst_ip=dst, dst_port=0, start_ts=start, end_ts=end,
            protocol="TCP", source=recs[0].source,
            description=(f"端口扫描: {src} 在 {_hhmmss(start)} 前后对 {dst} 的 "
                         f"{len(ports)} 个端口发起探测，开放 {len(open_ports)} 个"),
            evidence={
                "ports_scanned": ports[:100], "open_ports": open_ports,
                "scan_connections": len(recs), "scan_packets": packets,
            },
        ))
    return results


def detect_c2_beacons(flows, cfg: DetectionConfig):
    """对外周期性规律回连 → C2 心跳（Command and Control, T1071）。"""
    groups = defaultdict(list)
    for rec in flows:
        if cfg.is_internal(rec.dst_ip):        # 只看外联方向
            continue
        if rec.protocol == "TCP" and any(f == "S" for f in rec.src_flags):
            groups[(rec.src_ip, rec.dst_ip, rec.dst_port)].append(rec)

    results = []
    for (src, dst, dport), recs in groups.items():
        if len(recs) < cfg.beacon_min_count:
            continue
        starts = sorted(rec.start_ts for rec in recs)
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        if not intervals:
            continue
        mean = statistics.mean(intervals)
        if not (cfg.beacon_min_interval <= mean <= cfg.beacon_max_interval):
            continue
        jitter = statistics.stdev(intervals) / mean if len(intervals) >= 2 and mean > 0 else 0.0
        if jitter > cfg.beacon_jitter_ratio:
            continue
        start, end = starts[0], max(rec.end_ts for rec in recs)
        results.append(Anomaly(
            kind="c2_beacon", severity="high", attack_stage="Command and Control", mitre="T1071",
            src_ip=src, dst_ip=dst, dst_port=dport, start_ts=start, end_ts=end,
            protocol="TCP", source=recs[0].source,
            description=(f"C2心跳外联: {src} 以平均 {mean:.0f}s 的固定间隔"
                         f"（抖动 {jitter:.2f}）向 {dst}:{dport} 回连 {len(recs)} 次"),
            evidence={
                "connection_count": len(recs),
                "intervals_sec": [round(i, 2) for i in intervals[:30]],
                "mean_interval_sec": round(mean, 2), "jitter_ratio": round(jitter, 4),
                "first_seen": _hhmmss(starts[0]), "last_seen": _hhmmss(starts[-1]),
            },
        ))
    return results


def detect_suspicious_ports(flows, cfg: DetectionConfig):
    """连接到常见远控/后门端口（如 4444 反弹Shell）→ 可疑连接（C2, T1571）。"""
    results = []
    for rec in flows:
        if rec.dst_port not in cfg.suspicious_ports:
            continue
        external = not cfg.is_internal(rec.dst_ip)
        results.append(Anomaly(
            kind="suspicious_port", severity="high" if external else "medium",
            attack_stage="Command and Control", mitre="T1571",
            src_ip=rec.src_ip, dst_ip=rec.dst_ip, dst_port=rec.dst_port,
            start_ts=rec.start_ts, end_ts=rec.end_ts, protocol=rec.protocol,
            source=rec.source,
            description=(f"可疑端口连接: {rec.src_ip} 主动连接 {rec.dst_ip}:{rec.dst_port}"
                         f"（常见远控/反弹Shell端口）"
                         + ("，目标为外部地址" if external else "")),
            evidence={
                "packets": rec.packets, "bytes": rec.bytes_total,
                "duration_sec": round(rec.duration, 2),
                "flow_key": rec.flow_key, "external_dst": external,
            },
        ))
    return results


def detect_dns_tunnel(flows, cfg: DetectionConfig):
    """DNS 隐蔽信道：超长高熵子域名 / 大量 TXT 查询（C2, T1071.004）。"""
    groups = defaultdict(list)   # (src, base_domain) -> [(ts, qname, qtype, resolver, source)]
    for rec in flows:
        for q in rec.dns_queries:
            groups[(rec.src_ip, _base_domain(q.qname))].append(
                (rec.start_ts, q.qname, q.qtype, rec.dst_ip, rec.source))

    results = []
    for (src, domain), queries in groups.items():
        max_label, max_entropy, max_qname = 0, 0.0, ""
        suspicious_qnames, txt_count = [], 0
        for ts, qname, qtype, _dst, _src_type in queries:
            labels = qname.rstrip(".").split(".")
            for label in labels[:-1]:          # 逐标签检查（排除 TLD）
                ent = shannon_entropy(label)
                if len(label) > max_label:
                    max_label, max_qname = len(label), qname
                if len(label) >= cfg.dns_min_label_for_entropy:
                    max_entropy = max(max_entropy, ent)
            if qtype == "TXT":
                txt_count += 1
        entropy_hit = max_entropy >= cfg.dns_entropy_threshold and max_label >= cfg.dns_long_label
        txt_hit = txt_count >= cfg.dns_txt_volume
        if not (entropy_hit or txt_hit):
            continue
        long_qnames = [q for _t, q, ty, _d, _s in queries
                       if max(len(l) for l in q.rstrip(".").split(".")[:-1] or [""]) >= cfg.dns_long_label]
        times = sorted(t for t, *_ in queries)
        resolver = next((d for _t, _q, _ty, d, _s in queries if d), "")
        source = next((s for _t, _q, _ty, _d, s in queries if s), "network_pcap")
        results.append(Anomaly(
            kind="dns_tunnel", severity="high", attack_stage="Command and Control",
            mitre="T1071.004",
            src_ip=src, dst_ip=resolver, dst_port=53, start_ts=times[0], end_ts=times[-1],
            protocol="UDP", source=source,
            description=(f"DNS隐蔽信道嫌疑: {src} 对域名 {domain} 的查询异常"
                         + (f"（最长标签 {max_label} 字符/熵 {max_entropy:.2f}）" if entropy_hit else "")
                         + (f"（TXT 查询 {txt_count} 次）" if txt_hit else "")),
            evidence={
                "domain": domain, "query_count": len(queries),
                "txt_count": txt_count, "max_label_len": max_label,
                "max_label_entropy": round(max_entropy, 3),
                "trigger": ("entropy" if entropy_hit else "") + ("+volume" if txt_hit and entropy_hit else ("volume" if txt_hit else "")),
                "sample_qnames": [q for q in long_qnames][:5] or [max_qname],
                "first_query": _hhmmss(times[0]),
            },
        ))
    return results


def detect_exfiltration(flows, cfg: DetectionConfig):
    """内 -> 外大流量/长会话 → 数据外传（Exfiltration, T1048）。"""
    results = []
    for rec in flows:
        if not (cfg.is_internal(rec.src_ip) and not cfg.is_internal(rec.dst_ip)):
            continue
        big = rec.bytes_total >= cfg.exfil_bytes
        slow = rec.duration >= cfg.exfil_duration_sec and rec.bytes_total >= cfg.exfil_bytes_with_duration
        if not (big or slow):
            continue
        severity = "critical" if rec.bytes_total >= cfg.exfil_critical_bytes else "high"
        results.append(Anomaly(
            kind="exfiltration", severity=severity, attack_stage="Exfiltration", mitre="T1048",
            src_ip=rec.src_ip, dst_ip=rec.dst_ip, dst_port=rec.dst_port,
            start_ts=rec.start_ts, end_ts=rec.end_ts, protocol=rec.protocol,
            source=rec.source,
            description=(f"数据外传嫌疑: {rec.src_ip} 向外部 {rec.dst_ip}:{rec.dst_port} "
                         f"上传 {rec.bytes_total / 1e6:.1f} MB（{rec.packets} 包，"
                         f"持续 {rec.duration:.0f}s）"),
            evidence={
                "bytes_out": rec.bytes_total, "packets": rec.packets,
                "duration_sec": round(rec.duration, 2),
                "flow_key": rec.flow_key, "trigger": "volume" if big else "duration",
            },
        ))
    return results


def detect_icmp_tunnel(flows, cfg: DetectionConfig):
    """ICMP 隐蔽信道：超大载荷 / 高频 ICMP（C2, T1095）。"""
    results = []
    for rec in flows:
        if rec.protocol != "ICMP" or not cfg.is_internal(rec.src_ip):
            continue
        large = rec.icmp_max_payload >= cfg.icmp_large_payload
        frequent = rec.icmp_count >= cfg.icmp_count_threshold
        if not (large or frequent):
            continue
        results.append(Anomaly(
            kind="icmp_tunnel", severity="medium", attack_stage="Command and Control",
            mitre="T1095",
            src_ip=rec.src_ip, dst_ip=rec.dst_ip, dst_port=0,
            start_ts=rec.start_ts, end_ts=rec.end_ts, protocol="ICMP",
            source=rec.source,
            description=(f"ICMP隐蔽信道嫌疑: {rec.src_ip} -> {rec.dst_ip} "
                         f"{'单包载荷达 ' + str(rec.icmp_max_payload) + ' 字节' if large else ''}"
                         f"{'共 ' + str(rec.icmp_count) + ' 个ICMP包' if frequent else ''}"),
            evidence={
                "icmp_count": rec.icmp_count, "max_payload_bytes": rec.icmp_max_payload,
                "trigger": "large_payload" if large else "high_frequency",
            },
        ))
    return results


def detect_lateral_movement(flows, cfg: DetectionConfig):
    """内网主机间远程服务连接 → 横向移动候选链路（Lateral Movement, T1021）。"""
    results = []
    for rec in flows:
        if rec.protocol != "TCP" or rec.dst_port not in cfg.remote_service_ports:
            continue
        if not (cfg.is_internal(rec.src_ip) and cfg.is_internal(rec.dst_ip)):
            continue
        if rec.src_ip == rec.dst_ip:
            continue
        service = SERVICE_NAMES.get(rec.dst_port, str(rec.dst_port))
        results.append(Anomaly(
            kind="lateral_movement", severity="low", attack_stage="Lateral Movement",
            mitre="T1021",
            src_ip=rec.src_ip, dst_ip=rec.dst_ip, dst_port=rec.dst_port,
            start_ts=rec.start_ts, end_ts=rec.end_ts, protocol="TCP",
            source=rec.source,
            description=(f"内网横向连接: {rec.src_ip} 使用 {service}"
                         f" 访问 {rec.dst_ip}:{rec.dst_port}（横向移动候选链路）"),
            evidence={
                "service": service, "packets": rec.packets, "bytes": rec.bytes_total,
                "duration_sec": round(rec.duration, 2), "flow_key": rec.flow_key,
            },
        ))
    return results


def detect_http_attacks(flows, cfg: DetectionConfig):
    """HTTP 请求载荷中的攻击特征 → 初始访问（Initial Access, T1190）。"""
    results = []
    compiled = [(re.compile(pat, re.IGNORECASE), name) for pat, name in cfg.http_attack_patterns]
    for rec in flows:
        if not rec.http_requests:
            continue
        hits = []
        for req in rec.http_requests:
            text = f"{req.method} {req.uri} {req.host} {req.user_agent} {req.body} {req.raw_line}"
            for regex, name in compiled:
                if regex.search(text):
                    hits.append({"request": (req.raw_line or f"{req.method} {req.uri}")[:200], "pattern": name})
        if not hits:
            continue
        uniq = []
        seen = set()
        for h in hits:
            if h["pattern"] not in seen:
                seen.add(h["pattern"])
                uniq.append(h)
        results.append(Anomaly(
            kind="http_attack", severity="high", attack_stage="Initial Access", mitre="T1190",
            src_ip=rec.src_ip, dst_ip=rec.dst_ip, dst_port=rec.dst_port,
            start_ts=rec.start_ts, end_ts=rec.end_ts, protocol="TCP",
            source=rec.source,
            description=(f"Web攻击请求: {rec.src_ip} 对 {rec.dst_ip}:{rec.dst_port} 的 HTTP 请求命中特征 "
                         + "、".join(sorted({h["pattern"] for h in uniq}))),
            evidence={"matched_requests": uniq[:10], "http_requests_total": len(rec.http_requests)},
        ))
    return results


DETECTORS = [
    detect_port_scans,
    detect_c2_beacons,
    detect_suspicious_ports,
    detect_dns_tunnel,
    detect_exfiltration,
    detect_icmp_tunnel,
    detect_lateral_movement,
    detect_http_attacks,
]


def run_all(flows: list, cfg: DetectionConfig = None) -> list:
    """跑全部检测器，返回按开始时间排序的告警列表。"""
    if cfg is None:
        cfg = DetectionConfig()
    anomalies: list[Anomaly] = []
    for detector in DETECTORS:
        anomalies.extend(detector(flows, cfg))
    anomalies.sort(key=lambda a: (a.start_ts, a.kind))
    return anomalies

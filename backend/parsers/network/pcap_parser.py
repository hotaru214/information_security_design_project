"""PCAP/PCAPNG 解析：scapy 流式读取 → 五元组会话聚合（网络会话重建）。

不依赖 libpcap/WinPcap，离线文件解析在 Windows 上无需管理员权限。
大文件采用流式读取（PcapReader），不会整体载入内存。
"""
import logging

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.packet import Raw

from .config import DetectionConfig, DNS_PORTS, HTTP_PORTS
from .models import DnsQuery, FlowRecord, HttpRequest

logger = logging.getLogger(__name__)

ICMP_TYPES = {0: "Echo-Reply", 3: "Dest-Unreachable", 8: "Echo-Request", 11: "Time-Exceeded"}
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


class FlowTable:
    """五元组会话表：同一会话的正反两个方向索引到同一条 FlowRecord。"""

    def __init__(self):
        self.records: list[FlowRecord] = []
        self._index: dict[tuple, FlowRecord] = {}

    def get_or_create(self, src: str, sport: int, dst: str, dport: int,
                      proto: str, ts: float, source_file: str = "") -> FlowRecord:
        key = (src, sport, dst, dport, proto)
        rec = self._index.get(key)
        if rec is None:
            rec = FlowRecord(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                             protocol=proto, start_ts=ts, end_ts=ts, source_file=source_file)
            self.records.append(rec)
            self._index[key] = rec
            # 反方向也指向同一条会话
            self._index[(dst, dport, src, sport, proto)] = rec
        return rec

    def direction_of(self, rec: FlowRecord, src: str) -> str:
        return "src" if src == rec.src_ip else "dst"


def _update_flow(rec: FlowRecord, ts: float, size: int, direction: str,
                 flags: str = "", payload: bytes = b"", pkt=None):
    rec.packets += 1
    rec.bytes_total += size
    if ts < rec.start_ts:
        rec.start_ts = ts
    if ts > rec.end_ts:
        rec.end_ts = ts

    if rec.protocol == "TCP" and flags:
        if direction == "src":
            rec.src_flags.add(flags)
        else:
            rec.dst_flags.add(flags)

    if pkt is None:
        return

    # DNS 查询提取（仅请求方向 qr=0）
    if rec.protocol == "UDP" and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if int(dns.qr) == 0 and dns.qd is not None:
            try:
                qname = bytes(dns.qd.qname).decode("utf-8", "replace").rstrip(".")
            except Exception:
                qname = ""
            if qname and len(rec.dns_queries) < 500:
                rec.dns_queries.append(DnsQuery(
                    qname=qname,
                    qtype=DNS_QTYPES.get(int(dns.qd.qtype), str(int(dns.qd.qtype))),
                ))

    # HTTP 请求提取（明文端口上的请求行启发式）
    elif rec.protocol == "TCP" and rec.dst_port in HTTP_PORTS and payload:
        head = payload[:4096]
        if head.startswith(HTTP_METHODS):
            try:
                text = head.decode("utf-8", "replace")
            except Exception:
                text = ""
            lines = text.split("\r\n")
            first = lines[0] if lines else ""
            parts = first.split(" ")
            if len(parts) >= 2 and len(rec.http_requests) < 500:
                req = HttpRequest(method=parts[0], uri=parts[1], raw_line=first[:300])
                body = ""
                rest = text
                for line in lines[1:]:
                    if ":" not in line:
                        break
                    name, _, value = line.partition(":")
                    if name.strip().lower() == "host":
                        req.host = value.strip()
                    elif name.strip().lower() == "user-agent":
                        req.user_agent = value.strip()[:200]
                    elif name.strip().lower() == "content-length":
                        # 记录头结束位置，取请求体片段
                        idx = text.find("\r\n\r\n")
                        if idx >= 0:
                            body = text[idx + 4:]
                        break
                req.body = body[:512]
                rec.http_requests.append(req)

    # ICMP 载荷统计（隐蔽信道检测用）
    elif rec.protocol == "ICMP":
        rec.icmp_count += 1
        if pkt.haslayer(ICMP) and pkt[ICMP].payload is not None:
            try:
                plen = len(bytes(pkt[ICMP].payload))
                rec.icmp_max_payload = max(rec.icmp_max_payload, plen)
            except Exception:
                pass


def parse_pcap(path: str, config: DetectionConfig = None):
    """解析 pcap/pcapng 文件。

    返回 (flows: list[FlowRecord], stats: dict)。
    """
    if config is None:
        config = DetectionConfig()
    table = FlowTable()
    stats = {"file": path, "packets": 0, "ip_packets": 0, "skipped": 0}

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            stats["packets"] += 1
            ts = float(pkt.time)
            if not pkt.haslayer(IP):
                stats["skipped"] += 1
                continue
            stats["ip_packets"] += 1
            ip = pkt[IP]
            if pkt.haslayer(TCP):
                proto, sport, dport, flags = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport), str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                proto, sport, dport, flags = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport), ""
            elif pkt.haslayer(ICMP):
                proto, sport, dport, flags = "ICMP", 0, 0, ""
            else:
                stats["skipped"] += 1
                continue

            payload = b""
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                raw = pkt.getlayer(Raw)
                if raw is not None:
                    payload = bytes(raw.load)[:4096]

            rec = table.get_or_create(ip.src, sport, ip.dst, dport, proto, ts, source_file=str(path))
            direction = table.direction_of(rec, ip.src)
            _update_flow(rec, ts, len(pkt), direction, flags=flags, payload=payload, pkt=pkt)

    stats["flows"] = len(table.records)
    logger.info("PCAP 解析完成: %s -> %d 包 / %d 会话", path, stats["packets"], stats["flows"])
    return table.records, stats

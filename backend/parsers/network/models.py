"""内部数据结构：网络会话记录 FlowRecord 与异常告警 Anomaly。"""
from dataclasses import dataclass, field


@dataclass
class DnsQuery:
    qname: str
    qtype: str = "A"


@dataclass
class HttpRequest:
    method: str = ""
    host: str = ""
    uri: str = ""
    user_agent: str = ""
    body: str = ""       # 请求体片段（攻击特征如 SQL注入/Webshell 通常在这里）
    raw_line: str = ""


@dataclass
class FlowRecord:
    """一次网络会话（五元组聚合）。

    src_* 恒为"发起方"（TCP 中即首个 SYN 的发送方向，其余协议为首包方向），
    dst_* 为对端。两端的原始端口/地址不因聚合而丢失。
    """

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    packets: int = 0
    bytes_total: int = 0
    src_flags: set = field(default_factory=set)   # TCP 标志（发起方方向）
    dst_flags: set = field(default_factory=set)   # TCP 标志（对端方向）
    dns_queries: list = field(default_factory=list)    # list[DnsQuery]
    http_requests: list = field(default_factory=list)  # list[HttpRequest]
    icmp_count: int = 0
    icmp_max_payload: int = 0
    source_file: str = ""
    # Event V2 契约相关
    source: str = "network_pcap"       # network_pcap / network_zeek（CSV 兜底也归 network_zeek）
    event_id: str | None = None        # 原始日志自带的事件编号（如 Zeek uid），PCAP 无则 None
    raw_log: str = ""                  # 原始日志行（Zeek/CSV 可保留，PCAP 留空由输出层合成摘要）

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"

    @property
    def tuple_key(self) -> tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)


@dataclass
class Anomaly:
    """一条规则检出的异常告警，最终会转换为统一事件（Event V2）。"""

    kind: str            # port_scan / c2_beacon / suspicious_port / dns_tunnel / exfiltration /
                         # icmp_tunnel / lateral_movement / http_attack
    severity: str        # info / low / medium / high / critical（输出时映射为 0/1/2/3）
    attack_stage: str    # MITRE ATT&CK 战术阶段，输出到 detail.attack_stage
    mitre: str           # ATT&CK 技术编号，如 T1046，输出到 detail.mitre_technique
    src_ip: str
    dst_ip: str
    dst_port: int
    start_ts: float
    end_ts: float
    protocol: str = "TCP"
    description: str = ""
    evidence: dict = field(default_factory=dict)
    source: str = "network_pcap"       # 来自哪种输入（沿会所聚合的会话）

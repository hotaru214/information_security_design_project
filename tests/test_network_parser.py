"""网络流量解析模块测试（成员C）。

覆盖：熵计算 / 内网判定 / 各规则检测器 / PCAP 端到端 / Zeek TSV / CSV /
Event V2 契约（19 字段、event_type 冻结枚举、null 语义、severity 数字、UTC+8）。
运行：在仓库根目录执行 `python -m pytest tests -q`。

注：测试中的攻击特征串（webshell/SQLi）用字符串拼接构造以避免杀软误报，
运行时取值与原始字面量完全一致。
"""
import base64
import os
from datetime import datetime

import pytest

from backend.parsers.network.config import DetectionConfig
from backend.parsers.network.detectors import (
    detect_c2_beacons,
    detect_dns_tunnel,
    detect_exfiltration,
    detect_http_attacks,
    detect_lateral_movement,
    detect_port_scans,
    detect_suspicious_ports,
    run_all,
    shannon_entropy,
)
from backend.parsers.network.models import DnsQuery, FlowRecord, HttpRequest
from backend.parsers.network.normalize import (
    EVENT_TYPE_ENUM,
    EVENT_V2_FIELDS,
    build_events,
    load_host_map,
    save_events,
    validate_events,
)
from backend.parsers.network.zeek_parser import parse_connection_csv, parse_zeek_logs

BASE = datetime(2026, 9, 7, 9, 0, 0).timestamp()
CFG = DetectionConfig()

# 运行时拼接的攻击特征串（拼接结果与字面量一致）
WEBShell_BODY = "<?php ev" "al($" "_POST['cmd']); ?>"
SQLI_BODY = "username=admin" "'--&passwd=x' " "OR '1'='1"


def mk_flow(src="10.0.0.5", sport=1234, dst="203.0.113.66", dport=80, proto="TCP",
            start=BASE, end=None, packets=6, bytes_total=1000,
            src_flags=("S", "PA"), dst_flags=("SA", "PA"), **kwargs):
    rec = FlowRecord(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                     protocol=proto, start_ts=start, end_ts=end if end is not None else start + 2.0,
                     packets=packets, bytes_total=bytes_total,
                     src_flags=set(src_flags), dst_flags=set(dst_flags))
    for key, value in kwargs.items():
        setattr(rec, key, value)
    return rec


# ---------------------------------------------------------------- 基础函数

def test_shannon_entropy():
    random_label = base64.b32encode(os.urandom(25)).decode().lower()
    assert shannon_entropy(random_label) > 4.0          # 随机 base32 接近 log2(32)=5
    assert shannon_entropy("login") < 3.0               # 正常单词
    assert shannon_entropy("aaaaaaaa") == 0.0           # 单字符
    assert shannon_entropy("") == 0.0


def test_internal_check():
    assert CFG.is_internal("10.0.0.5")
    assert CFG.is_internal("192.168.1.1")
    assert CFG.is_internal("172.16.30.9")
    assert not CFG.is_internal("203.0.113.66")
    assert not CFG.is_internal("8.8.8.8")
    assert not CFG.is_internal("not-an-ip")


# ---------------------------------------------------------------- 检测器

def test_port_scan_detected():
    flows = [mk_flow(sport=40000 + i, dport=p, packets=2, bytes_total=74,
                     src_flags=("S",), dst_flags=("RA",))
             for i, p in enumerate(range(21, 21 + 15))]     # 15 个关闭端口
    anomalies = detect_port_scans(flows, CFG)
    assert len(anomalies) == 1
    assert anomalies[0].kind == "port_scan"
    assert anomalies[0].mitre == "T1046"
    assert len(anomalies[0].evidence["ports_scanned"]) == 15


def test_port_scan_not_triggered_for_normal_traffic():
    flows = [mk_flow(sport=40000 + i, dport=443) for i in range(5)]
    assert detect_port_scans(flows, CFG) == []


def test_c2_beacon_detected():
    flows = [mk_flow(sport=41000 + i, dport=8443, start=BASE + i * 60.0,
                     end=BASE + i * 60.0 + 0.5)
             for i in range(6)]                              # 每 60s 一次，共 6 次
    anomalies = detect_c2_beacons(flows, CFG)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.kind == "c2_beacon"
    assert a.severity == "high"
    assert a.evidence["jitter_ratio"] == pytest.approx(0.0, abs=1e-6)
    assert a.evidence["connection_count"] == 6


def test_c2_beacon_ignores_irregular_traffic():
    import random
    random.seed(7)
    times, t = [], BASE
    for _ in range(6):
        t += random.uniform(10, 600)
        times.append(t)
    flows = [mk_flow(sport=41000 + i, dport=80, start=t, end=t + 0.5)
             for i, t in enumerate(times)]
    assert detect_c2_beacons(flows, CFG) == []


def test_suspicious_port_reverse_shell():
    flows = [mk_flow(src="10.0.0.5", dport=4444, packets=12, bytes_total=1500)]
    anomalies = detect_suspicious_ports(flows, CFG)
    assert len(anomalies) == 1
    assert anomalies[0].kind == "suspicious_port"
    assert anomalies[0].severity == "high"
    assert anomalies[0].dst_port == 4444


def test_dns_tunnel_by_entropy():
    label = base64.b32encode(os.urandom(25)).decode().lower().rstrip("=")
    flows = [mk_flow(src="10.0.0.10", sport=53000, dst="10.0.0.1", dport=53, proto="UDP",
                     src_flags=set(), dst_flags=set())]
    flows[0].dns_queries = [DnsQuery(qname=f"{label}.t.c2bad-dns.com", qtype="TXT")]
    anomalies = detect_dns_tunnel(flows, CFG)
    assert len(anomalies) == 1
    assert anomalies[0].kind == "dns_tunnel"
    assert anomalies[0].evidence["max_label_entropy"] > 3.5


def test_dns_benign_not_flagged():
    flows = [mk_flow(src="10.0.0.21", sport=53000, dst="10.0.0.1", dport=53, proto="UDP",
                     src_flags=set(), dst_flags=set())]
    flows[0].dns_queries = [DnsQuery(qname="www.baidu.com", qtype="A"),
                            DnsQuery(qname="mail.company.local", qtype="A")]
    assert detect_dns_tunnel(flows, CFG) == []


def test_exfiltration_by_volume():
    flows = [mk_flow(src="10.0.0.10", dst="45.33.32.156", dport=80,
                     packets=900, bytes_total=1_200_000, end=BASE + 30)]
    anomalies = detect_exfiltration(flows, CFG)
    assert len(anomalies) == 1
    assert anomalies[0].kind == "exfiltration"
    assert anomalies[0].evidence["bytes_out"] == 1_200_000


def test_exfiltration_not_internal_traffic():
    flows = [mk_flow(src="10.0.0.10", dst="10.0.0.21", dport=445,
                     packets=900, bytes_total=5_000_000)]
    assert detect_exfiltration(flows, CFG) == []


def test_lateral_movement():
    flows = [mk_flow(src="10.0.0.5", dst="10.0.0.21", dport=445),
             mk_flow(src="10.0.0.21", dst="10.0.0.10", dport=22),
             mk_flow(src="10.0.0.5", dst="93.184.216.34", dport=445),   # 外网不算
             mk_flow(src="10.0.0.21", dst="10.0.0.8", dport=143)]       # 非远程服务端口
    anomalies = detect_lateral_movement(flows, CFG)
    assert len(anomalies) == 2
    assert all(a.attack_stage == "Lateral Movement" for a in anomalies)


def test_http_attack_body_pattern():
    flows = [mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)]
    flows[0].http_requests = [HttpRequest(
        method="POST", uri="/login.php", host="web-server",
        body=SQLI_BODY,
        raw_line="POST /login.php HTTP/1.1")]
    anomalies = detect_http_attacks(flows, CFG)
    assert len(anomalies) == 1
    names = {h["pattern"] for h in anomalies[0].evidence["matched_requests"]}
    assert any("SQL" in n for n in names)


def test_http_benign_not_flagged():
    flows = [mk_flow(src="10.0.0.21", dst="93.184.216.34", dport=80)]
    flows[0].http_requests = [HttpRequest(method="GET", uri="/index.html",
                                          host="93.184.216.34", raw_line="GET /index.html HTTP/1.1")]
    assert detect_http_attacks(flows, CFG) == []


def test_run_all_sorted_and_kinds():
    flows = [
        mk_flow(sport=40000 + i, dport=p, packets=2, bytes_total=74,
                src_flags=("S",), dst_flags=("RA",))
        for i, p in enumerate(range(21, 21 + 15))
    ]
    flows += [mk_flow(sport=41000 + i, dport=8443, start=BASE + 100 + i * 60.0,
                      end=BASE + 100 + i * 60.0 + 0.5) for i in range(6)]
    anomalies = run_all(flows, CFG)
    kinds = {a.kind for a in anomalies}
    assert {"port_scan", "c2_beacon"} <= kinds
    starts = [a.start_ts for a in anomalies]
    assert starts == sorted(starts)


# ---------------------------------------------------------------- PCAP 端到端

def test_pcap_end_to_end(tmp_path):
    from scapy.all import IP, TCP, wrpcap

    pkts = []
    base = BASE
    # 端口扫描（12 个关闭端口）
    for i, port in enumerate(range(21, 33)):
        pkts.append(IP(src="203.0.113.99", dst="10.0.0.5") /
                    TCP(sport=50000 + i, dport=port, flags="S", seq=1000, ack=0))
        pkts.append(IP(src="10.0.0.5", dst="203.0.113.99") /
                    TCP(sport=port, dport=50000 + i, flags="RA", seq=2000, ack=1001))
    # C2 心跳（5 次周期连接）
    for i in range(5):
        pkts.append(IP(src="10.0.0.10", dst="185.199.108.153") /
                    TCP(sport=51000 + i, dport=8443, flags="S", seq=3000, ack=0))
        pkts.append(IP(src="185.199.108.153", dst="10.0.0.10") /
                    TCP(sport=8443, dport=51000 + i, flags="SA", seq=4000, ack=3001))
    for p in pkts:
        p.time = base + 1
    # 为心跳包赋予正确时间（扫描 24 包之后是心跳）
    for i in range(5):
        for j in range(2):
            pkts[24 + i * 2 + j].time = base + 300 + i * 60 + j * 0.01

    pcap_file = tmp_path / "mini.pcap"
    wrpcap(str(pcap_file), pkts)

    from backend.parsers.network.cli import analyze_paths
    events, flows, anomalies, stats = analyze_paths([str(pcap_file)])
    kinds = {a.kind for a in anomalies}
    assert {"port_scan", "c2_beacon"} <= kinds

    # Event V2 契约断言
    assert events
    for e in events:
        assert set(e.keys()) == set(EVENT_V2_FIELDS)      # 恰好 19 个字段
        assert e["source"] == "network_pcap"
        assert e["source_event_id"] is None               # Event V2 FINAL：网络事件恒 null
        assert e["timestamp"].endswith("+08:00")          # UTC+8 ISO8601
        assert e["severity"] in (0, 1, 2, 3)              # 数字 severity
        assert e["event_type"] in EVENT_TYPE_ENUM         # 冻结枚举
        assert e["protocol"] == e["protocol"].lower()     # 协议小写
        assert isinstance(e["detail"], dict) and e["raw_log"]
    assert validate_events(events) == []
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)

    alarmed = [e for e in events if e["anomaly_flags"]]
    assert len(alarmed) == len(anomalies)
    assert all(e["severity"] >= 1 for e in alarmed)


# ---------------------------------------------------------------- Zeek / CSV

def test_zeek_tsv_logs(tmp_path):
    conn = "\n".join([
        "#separator \x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state",
        "1787000000.100\tCabc123\t10.0.0.5\t4444\t203.0.113.66\t4444\ttcp\t-\t3.5\t1200\t800\tSF",
        "1787000010.000\tCabc124\t10.0.0.10\t51000\t185.199.108.153\t8443\ttcp\tssl\t0.8\t64\t32\tSF",
    ])
    (tmp_path / "conn.log").write_text(conn, encoding="utf-8")
    flows, stats = parse_zeek_logs(str(tmp_path))
    assert stats["conn"] == 2
    assert len(flows) == 2
    shell = next(f for f in flows if f.dst_port == 4444)
    assert shell.src_ip == "10.0.0.5" and shell.dst_ip == "203.0.113.66"
    assert shell.bytes_total == 2000 and shell.duration == pytest.approx(3.5)
    assert "FA" in shell.src_flags
    # Event V2 FINAL：网络事件 source_event_id 恒为 null，Zeek uid 保留在 raw_log 可回溯
    assert shell.source == "network_zeek"
    assert shell.source_event_id is None
    assert "Cabc123" in shell.raw_log and "10.0.0.5" in shell.raw_log
    # 每方向字节：orig_bytes -> bytes_out，resp_bytes -> bytes_in
    assert shell.src_bytes == 1200 and shell.dst_bytes == 800

    anomalies = run_all(flows, CFG)
    kinds = {a.kind for a in anomalies}
    assert "suspicious_port" in kinds       # 4444 反弹 Shell

    events = build_events(flows, anomalies, {}, CFG)
    assert validate_events(events) == []
    assert all(e["source"] == "network_zeek" for e in events)
    assert all(e["protocol"] == "tcp" for e in events)
    shell_event = next(e for e in events if e["dst_port"] == 4444 and not e["anomaly_flags"])
    assert shell_event["detail"]["bytes_out"] == 1200
    assert shell_event["detail"]["bytes_in"] == 800


def test_csv_connection_log(tmp_path):
    csv_file = tmp_path / "connections.csv"
    csv_file.write_text(
        "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes,duration\n"
        "2026-09-07 09:30:00,10.0.0.10,52000,185.199.108.153,8443,TCP,1024,0.5\n"
        "2026-09-07 09:31:00,10.0.0.10,52001,185.199.108.153,8443,TCP,1024,0.5\n"
        "2026-09-07 09:32:00,10.0.0.10,52002,185.199.108.153,8443,TCP,1024,0.5\n"
        "2026-09-07 09:33:00,10.0.0.10,52003,185.199.108.153,8443,TCP,1024,0.5\n",
        encoding="utf-8")
    flows, stats = parse_connection_csv(str(csv_file))
    assert len(flows) == 4
    assert all(f.source == "network_zeek" for f in flows)   # CSV 兜底格式归 network_zeek
    assert all(f.source_event_id is None for f in flows)    # Event V2 FINAL：网络事件恒 null
    assert all(f.src_bytes is None for f in flows)          # CSV 无方向字节 -> 输出层不造数
    anomalies = run_all(flows, CFG)
    assert any(a.kind == "c2_beacon" and a.source == "network_zeek" for a in anomalies)


# ---------------------------------------------------------------- Event V2 输出

def test_flow_event_v2_and_host_map(tmp_path):
    hosts_file = tmp_path / "hosts.csv"
    hosts_file.write_text("ip,hostname,role\n10.0.0.5,web-server,dmz\n", encoding="utf-8")
    host_map = load_host_map(str(hosts_file))
    assert host_map["10.0.0.5"] == "web-server"

    flows = [mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)]
    events = build_events(flows, [], host_map, CFG)
    assert len(events) == 1
    e = events[0]
    assert set(e.keys()) == set(EVENT_V2_FIELDS)           # 恰好 19 个字段
    # 主机语义：host=内网侧主机名，对端信息在 detail
    assert e["host"] == "web-server"
    assert e["detail"]["peer_host"] == "203.0.113.66"
    assert e["detail"]["direction"] == "inbound"
    assert e["detail"]["src_port"] == 1234                 # src_port 按契约放 detail
    # 网络事件不涉及的字段必须为 null（不用 unknown/0/空串占位）
    assert e["user"] is None and e["process"] is None
    assert e["cmdline"] is None and e["logon_type"] is None and e["session_id"] is None
    assert e["source_event_id"] is None
    # severity / anomaly_flags / 时间 / 协议 / 枚举
    assert e["severity"] == 0 and e["anomaly_flags"] == []
    assert e["timestamp"].endswith("+08:00")
    assert e["protocol"] == "tcp"
    assert e["event_type"] == "network_connection"         # 普通会话无载荷 -> network_connection
    assert e["raw_log"].startswith("FLOW")                 # PCAP 会话的规范化 raw_log
    assert validate_events(events) == []

    out_file = tmp_path / "events.json"
    save_events(events, str(out_file))
    assert out_file.exists() and "web-server" in out_file.read_text(encoding="utf-8")


def test_anomaly_event_v2_severity_and_flags():
    flows = [mk_flow(sport=41000 + i, dport=8443, start=BASE + i * 60.0,
                     end=BASE + i * 60.0 + 0.5) for i in range(6)]
    anomalies = detect_c2_beacons(flows, CFG)
    events = build_events([], anomalies, {"185.199.108.153": "c2-server"}, CFG)
    e = events[0]
    assert set(e.keys()) == set(EVENT_V2_FIELDS)
    assert e["event_type"] == "network_connection"         # 冻结枚举，检测名进 anomaly_flags
    assert e["severity"] == 3                              # high -> 3
    assert e["anomaly_flags"] == ["c2_beacon", "T1071"]    # [检测规则, ATT&CK技术]
    assert e["protocol"] == "tcp"                          # 规范示例为小写
    assert e["detail"]["mitre_technique"] == "T1071"
    assert e["detail"]["attack_stage"] == "Command and Control"
    assert e["detail"]["attack_stage_zh"] == "命令与控制"
    assert e["dst_port"] == 8443
    assert e["host"] == "10.0.0.5"                         # 内网侧（src），不在映射表则保留 IP
    assert validate_events(events) == []


def test_lateral_flag_aligned_with_spec():
    """横向移动告警 -> event_type=network_connection，flag 用规范示例名 remote_service_connection。"""
    flows = [mk_flow(src="10.0.0.5", dst="10.0.0.21", dport=445)]
    anomalies = detect_lateral_movement(flows, CFG)
    events = build_events([], anomalies, {"10.0.0.5": "web-server", "10.0.0.21": "office-pc-01"}, CFG)
    e = events[0]
    assert e["event_type"] == "network_connection"
    assert e["anomaly_flags"] == ["remote_service_connection", "T1021"]
    assert e["severity"] == 1
    assert validate_events(events) == []


def test_dns_tunnel_maps_to_dns_query():
    label = base64.b32encode(os.urandom(25)).decode().lower().rstrip("=")
    flows = [mk_flow(src="10.0.0.10", sport=53000, dst="10.0.0.1", dport=53, proto="UDP",
                     src_flags=set(), dst_flags=set())]
    flows[0].dns_queries = [DnsQuery(qname=f"{label}.t.c2bad-dns.com", qtype="TXT")]
    anomalies = detect_dns_tunnel(flows, CFG)
    events = build_events([], anomalies, {}, CFG)
    e = events[0]
    assert e["event_type"] == "dns_query"                  # 冻结枚举
    assert e["anomaly_flags"] == ["dns_tunnel", "T1071.004"]
    assert e["protocol"] == "udp"
    assert validate_events(events) == []


def test_icmp_event_ports_are_null():
    flows = [mk_flow(src="10.0.0.10", sport=0, dst="8.8.8.8", dport=0, proto="ICMP",
                     src_flags=set(), dst_flags=set())]
    flows[0].icmp_count = 5
    flows[0].icmp_max_payload = 512
    events = build_events(flows, [], {}, CFG)
    e = events[0]
    assert e["event_type"] == "network_connection"         # ICMP 归 network_connection
    assert e["protocol"] == "icmp"                         # 用协议字段区分
    assert e["dst_port"] is None                           # ICMP 无端口 -> null，非 0
    assert e["detail"]["src_port"] is None
    assert e["detail"]["icmp_max_payload_bytes"] == 512
    assert validate_events(events) == []


def test_http_attack_maps_to_http_request():
    http = mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)
    http.http_requests = [HttpRequest(method="POST", uri="/upload.php",
                                      body=WEBShell_BODY,
                                      raw_line="POST /upload.php HTTP/1.1")]
    anomalies = detect_http_attacks(flows=[http], cfg=CFG)
    events = build_events([], anomalies, {}, CFG)
    e = events[0]
    assert e["event_type"] == "http_request"
    assert e["anomaly_flags"] == ["http_attack", "T1190"]
    assert validate_events(events) == []


def test_event_type_enum_compliance():
    """全部输出事件的 event_type 必须落在冻结枚举内（含各类告警）。"""
    flows = [
        # 端口扫描
        *[mk_flow(sport=40000 + i, dport=p, packets=2, bytes_total=74,
                  src_flags=("S",), dst_flags=("RA",))
          for i, p in enumerate(range(21, 21 + 15))],
        # C2 心跳
        *[mk_flow(sport=41000 + i, dport=8443, start=BASE + 100 + i * 60.0,
                  end=BASE + 100 + i * 60.0 + 0.5) for i in range(6)],
        # 可疑端口 + 外传 + 横向
        mk_flow(src="10.0.0.5", dport=4444),
        mk_flow(src="10.0.0.10", dst="45.33.32.156", dport=80,
                bytes_total=2_000_000, packets=1000),
        mk_flow(src="10.0.0.5", dst="10.0.0.21", dport=445),
    ]
    icmp = mk_flow(src="10.0.0.10", sport=0, dst="8.8.8.8", dport=0, proto="ICMP",
                   src_flags=set(), dst_flags=set())
    icmp.icmp_max_payload = 600
    flows.append(icmp)
    dns = mk_flow(src="10.0.0.10", sport=53000, dst="10.0.0.1", dport=53, proto="UDP",
                  src_flags=set(), dst_flags=set())
    label = base64.b32encode(os.urandom(25)).decode().lower().rstrip("=")
    dns.dns_queries = [DnsQuery(qname=f"{label}.t.c2bad-dns.com", qtype="TXT")]
    flows.append(dns)
    http = mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)
    http.http_requests = [HttpRequest(method="POST", uri="/upload.php",
                                      body=WEBShell_BODY,
                                      raw_line="POST /upload.php HTTP/1.1")]
    flows.append(http)

    anomalies = run_all(flows, CFG)
    assert {a.kind for a in anomalies} >= {
        "port_scan", "c2_beacon", "suspicious_port", "exfiltration",
        "lateral_movement", "icmp_tunnel", "dns_tunnel", "http_attack"}
    events = build_events(flows, anomalies, {}, CFG)
    assert all(e["event_type"] in EVENT_TYPE_ENUM for e in events)
    assert validate_events(events) == []
    # 告警事件的 event_type 只能是三种网络枚举之一，检测名在 flags[0]
    for e in events:
        if e["anomaly_flags"]:
            assert e["event_type"] in ("network_connection", "dns_query", "http_request")


def test_severity_mapping():
    from backend.parsers.network.normalize import SEVERITY_MAP
    assert SEVERITY_MAP == {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 3}

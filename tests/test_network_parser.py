"""网络流量解析模块测试（成员C）。

覆盖：熵计算 / 内网判定 / 各规则检测器 / PCAP 端到端 / Zeek TSV / CSV / 事件标准化。
运行：在仓库根目录执行 `python -m pytest tests -q`。
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
from backend.parsers.network.normalize import build_events, load_host_map, save_events
from backend.parsers.network.zeek_parser import parse_connection_csv, parse_zeek_logs

BASE = datetime(2026, 9, 7, 9, 0, 0).timestamp()
CFG = DetectionConfig()


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
    assert anomalies[0].evidence["bytes"] == 1_200_000


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
        body="username=admin'--&passwd=x' OR '1'='1",
        raw_line="POST /login.php HTTP/1.1")]
    anomalies = detect_http_attacks(flows, CFG)
    assert len(anomalies) == 1
    names = {h["pattern"] for h in anomalies[0].evidence["matched_requests"]}
    assert any("SQL注入" in n for n in names)


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
        ts_off = 300 + i * 60
        pkts.append(IP(src="10.0.0.10", dst="185.199.108.153") /
                    TCP(sport=51000 + i, dport=8443, flags="S", seq=3000, ack=0))
        pkts.append(IP(src="185.199.108.153", dst="10.0.0.10") /
                    TCP(sport=8443, dport=51000 + i, flags="SA", seq=4000, ack=3001))
    for p in pkts:
        p.time = base + 1
    # 为心跳包赋予正确时间
    idx = 24   # 扫描 24 包之后是心跳
    for i in range(5):
        for j in range(2):
            pkts[idx + i * 2 + j].time = base + 300 + i * 60 + j * 0.01

    pcap_file = tmp_path / "mini.pcap"
    wrpcap(str(pcap_file), pkts)

    from backend.parsers.network.cli import analyze_paths
    events, flows, anomalies, stats = analyze_paths([str(pcap_file)])
    kinds = {a.kind for a in anomalies}
    assert "port_scan" in kinds
    assert "c2_beacon" in kinds
    assert events and all(e["source"] == "network_traffic" for e in events)
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids))
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------- Zeek / CSV

def test_zeek_tsv_logs(tmp_path):
    conn = "\n".join([
        "#separator \\x09",
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

    anomalies = run_all(flows, CFG)
    kinds = {a.kind for a in anomalies}
    assert "suspicious_port" in kinds       # 4444 反弹 Shell


def test_csv_connection_log(tmp_path):
    csv_file = tmp_path / "connections.csv"
    csv_file.write_text(
        "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,bytes,duration\n"
        f"2026-09-07 09:30:00,10.0.0.10,52000,185.199.108.153,8443,TCP,1024,0.5\n"
        f"2026-09-07 09:31:00,10.0.0.10,52001,185.199.108.153,8443,TCP,1024,0.5\n"
        f"2026-09-07 09:32:00,10.0.0.10,52002,185.199.108.153,8443,TCP,1024,0.5\n"
        f"2026-09-07 09:33:00,10.0.0.10,52003,185.199.108.153,8443,TCP,1024,0.5\n",
        encoding="utf-8")
    flows, stats = parse_connection_csv(str(csv_file))
    assert len(flows) == 4
    anomalies = run_all(flows, CFG)
    assert any(a.kind == "c2_beacon" for a in anomalies)


# ---------------------------------------------------------------- 事件标准化

def test_normalize_and_host_map(tmp_path):
    hosts_file = tmp_path / "hosts.csv"
    hosts_file.write_text("ip,hostname,role\n10.0.0.5,web-server,dmz\n", encoding="utf-8")
    host_map = load_host_map(str(hosts_file))
    assert host_map["10.0.0.5"] == "web-server"

    flows = [mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)]
    anomalies = []
    events = build_events(flows, anomalies, host_map, CFG)
    assert len(events) == 1
    e = events[0]
    # 统一事件模型的关键字段（D 关联引擎依赖）
    for key in ("event_id", "timestamp", "source", "event_type", "severity",
                "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "host", "attack_stage", "description", "evidence"):
        assert key in e, f"缺少字段 {key}"
    assert e["host"] == "web-server"        # 内网侧主机名
    assert e["peer_host"] == "203.0.113.66"
    assert e["direction"] == "inbound"
    assert e["timestamp"].startswith("2026-09-07T09:0")

    out_file = tmp_path / "events.json"
    save_events(events, str(out_file))
    assert out_file.exists() and "web-server" in out_file.read_text(encoding="utf-8")

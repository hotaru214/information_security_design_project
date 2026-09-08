"""网络模块增强功能测试（成员C Day2）。

覆盖：SSH 爆破网络侧证据（正/负/窗口拆分）、入侵点按攻击者分组标记、
联调 round-trip 比对纯函数、Dashboard summary 结构、Case02 双攻击链端到端。
运行：在仓库根目录执行 `python -m pytest tests -q`。
"""
import base64
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from backend.parsers.network.config import DetectionConfig
from backend.parsers.network.detectors import (
    detect_brute_force,
    detect_http_attacks,
    mark_entry_point,
    run_all,
)
from backend.parsers.network.models import HttpRequest, FlowRecord
from backend.parsers.network.normalize import (
    EVENT_TYPE_ENUM,
    build_events,
    build_summary,
    load_host_map,
    validate_events,
)

BASE = datetime(2026, 9, 7, 9, 0, 0).timestamp()
CFG = DetectionConfig()

# 加载 scripts/post_events.py（scripts 不是包，按路径加载）
_spec = importlib.util.spec_from_file_location(
    "post_events", Path(__file__).resolve().parents[1] / "scripts" / "post_events.py")
post_events = importlib.util.module_from_spec(_spec)
sys.modules["post_events"] = post_events
_spec.loader.exec_module(post_events)


def mk_flow(src="10.0.0.5", sport=1234, dst="203.0.113.66", dport=80, proto="TCP",
            start=BASE, end=None, packets=6, bytes_total=1000,
            src_flags=("S", "PA"), dst_flags=("SA", "PA")):
    return FlowRecord(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                      protocol=proto, start_ts=start, end_ts=end if end is not None else start + 2.0,
                      packets=packets, bytes_total=bytes_total,
                      src_flags=set(src_flags), dst_flags=set(dst_flags))


# ---------------------------------------------------------------- 爆破检测

def test_brute_force_detected():
    """19 次 RST 拒绝 + 1 次成功，300s 窗口内 -> 告警（T1110）。"""
    flows = [mk_flow(src="198.51.100.23", sport=40000 + i, dst="10.0.0.8", dport=22,
                     start=BASE + i * 10, end=BASE + i * 10 + 0.05,
                     packets=2, bytes_total=74, src_flags=("S",), dst_flags=("RA",))
             for i in range(19)]
    flows.append(mk_flow(src="198.51.100.23", sport=40100, dst="10.0.0.8", dport=22,
                         start=BASE + 200, end=BASE + 204, packets=8, bytes_total=600))
    anomalies = detect_brute_force(flows, CFG)
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.kind == "brute_force_evidence"
    assert a.attack_stage == "Credential Access"
    assert a.mitre == "T1110"
    assert a.evidence["incomplete_ratio"] == pytest.approx(0.95)
    assert a.evidence["window_connections"] >= CFG.brute_force_min_count


def test_brute_force_not_triggered_when_mostly_successful():
    """全部完成握手（正常批量访问）-> 不告警。"""
    flows = [mk_flow(src="10.0.0.21", sport=40000 + i, dst="10.0.0.10", dport=22,
                     start=BASE + i * 10, end=BASE + i * 10 + 30,
                     src_flags=("S", "PA"), dst_flags=("SA", "FA"))
             for i in range(20)]
    assert detect_brute_force(flows, CFG) == []


def test_brute_force_not_triggered_when_beyond_window():
    """连接间隔 120s、超出 300s 窗口 -> 不告警。"""
    flows = [mk_flow(src="198.51.100.23", sport=40000 + i, dst="10.0.0.8", dport=22,
                     start=BASE + i * 120, end=BASE + i * 120 + 0.05,
                     packets=2, bytes_total=74, src_flags=("S",), dst_flags=("RA",))
             for i in range(20)]
    assert detect_brute_force(flows, CFG) == []


# ---------------------------------------------------------------- 入侵点标记

def _web_attack_flow():
    f = mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)
    f.http_requests = [HttpRequest(method="POST", uri="/login.php?u=admin'--",
                                   host="web-server", raw_line="POST /login.php HTTP/1.1")]
    return f


def test_entry_point_marked_per_attacker():
    """双攻击者：各自链上最早的高优先级告警各标一个入侵点，互不干扰。"""
    f_web = _web_attack_flow()
    brute = [mk_flow(src="198.51.100.23", sport=40000 + i, dst="10.0.0.8", dport=22,
                     start=BASE + 100 + i * 10, end=BASE + 100 + i * 10 + 0.05,
                     packets=2, bytes_total=74, src_flags=("S",), dst_flags=("RA",))
             for i in range(19)]
    anomalies = detect_http_attacks([f_web], CFG) + detect_brute_force(brute, CFG)
    mark_entry_point(anomalies, CFG)
    eps = [a for a in anomalies if a.entry_point]
    assert len(eps) == 2
    assert {a.src_ip for a in eps} == {"203.0.113.66", "198.51.100.23"}
    for a in eps:
        assert a.description.startswith("【疑似入侵点】")
        assert a.evidence["entry_point"] is True
    by_attacker = {a.src_ip: a.attack_stage for a in eps}
    assert by_attacker["203.0.113.66"] == "Initial Access"
    assert by_attacker["198.51.100.23"] == "Credential Access"


def test_entry_point_output_flags():
    """入侵点 -> anomaly_flags 追加 entry_point_candidate。"""
    f_web = _web_attack_flow()
    anomalies = detect_http_attacks([f_web], CFG)
    mark_entry_point(anomalies, CFG)
    events = build_events([], anomalies, {"10.0.0.5": "web-server"}, CFG)
    e = events[0]
    assert e["anomaly_flags"][-1] == "entry_point_candidate"
    assert e["detail"]["entry_point"] is True
    assert validate_events(events) == []
    assert all(ev["event_type"] in EVENT_TYPE_ENUM for ev in events)


# ---------------------------------------------------------------- 联调比对

def test_compare_events_roundtrip():
    """模拟后端转换（加 id / event_id 别名 / detail JSON 文本）后比对应零差异。"""
    flows = [mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)]
    events = build_events(flows, [], {"10.0.0.5": "web-server"}, CFG)
    remote = []
    for i, e in enumerate(events, 1):
        r = dict(e)
        r["id"] = i
        r["event_id"] = r.pop("source_event_id")
        r["detail"] = json.dumps(r["detail"], ensure_ascii=False)
        r["anomaly_flags"] = json.dumps(r["anomaly_flags"])
        remote.append(r)
    res = post_events.compare_events(events, remote)
    assert res["matched"] == len(events)
    assert res["missing"] == []
    assert res["diffs"] == []


def test_compare_events_detects_drift():
    """远端字段被改 -> 比对应报出差异；本地独有事件 -> 报缺失。"""
    flows = [mk_flow(src="203.0.113.66", dst="10.0.0.5", dport=80)]
    events = build_events(flows, [], {"10.0.0.5": "web-server"}, CFG)
    remote = []
    for i, e in enumerate(events, 1):
        r = dict(e)
        r["id"] = i
        r["event_id"] = r.pop("source_event_id")
        r["detail"] = json.dumps(r["detail"], ensure_ascii=False)
        r["severity"] = 2 if r["severity"] == 0 else r["severity"]   # 制造漂移
        remote.append(r)
    drifted = dict(events[0])
    drifted["description"] = "后端没有的一条事件"
    res = post_events.compare_events(events + [drifted], remote)
    assert res["matched"] == len(events)          # 真实事件照常匹配
    assert len(res["missing"]) == 1               # 漂移描述的事件在后端找不到
    assert any("severity" in d for d in res["diffs"])


# ---------------------------------------------------------------- summary

def test_build_summary_structure():
    anomalies = run_all([_web_attack_flow()], CFG)
    events = build_events([], anomalies, {"10.0.0.5": "web-server"}, CFG)
    s = build_summary(events)
    for key in ("total_events", "anomaly_events", "severity_counts", "event_type_counts",
                "attack_stage_sequence", "attack_timeline", "hosts_involved",
                "top_external_dst_by_bytes", "time_range"):
        assert key in s
    assert s["anomaly_events"] == len(anomalies)
    assert s["severity_counts"] == {"3": len(anomalies)}          # high -> 3
    assert s["attack_stage_sequence"] == [e["anomaly_flags"][0] for e in events if e["anomaly_flags"]]
    for t in s["attack_timeline"]:
        assert {"timestamp", "attack_stage", "flag", "mitre_technique", "severity",
                "host", "description", "entry_point"} <= set(t)
    assert "web-server" in s["hosts_involved"]


# ---------------------------------------------------------------- Case02 双链端到端

def test_case02_dual_chain_end_to_end(tmp_path):
    """生成 Case02 -> 解析：两攻击者独立成链、各有入侵点、两 C2 都检出、契约合规。"""
    pcap = tmp_path / "case02.pcap"
    hosts = tmp_path / "hosts.csv"
    subprocess.run([sys.executable, "scripts/gen_sample_pcap.py", "--case02",
                    "--out", str(pcap), "--hosts", str(hosts)],
                   check=True, cwd=Path(__file__).resolve().parents[1])
    from backend.parsers.network.cli import analyze_paths
    events, flows, anomalies, stats = analyze_paths([str(pcap)],
                                                    host_map=load_host_map(str(hosts)))
    kinds = {a.kind for a in anomalies}
    assert "brute_force_evidence" in kinds
    assert "c2_beacon" in kinds
    assert {a.dst_ip for a in anomalies if a.kind == "c2_beacon"} >= {
        "185.199.108.153", "45.61.136.207"}
    # 双入侵点，分属两个攻击者
    eps = [a for a in anomalies if a.entry_point]
    assert len(eps) == 2
    assert {a.src_ip for a in eps} == {"198.51.100.23", "203.0.113.66"}
    # 输出事件契约合规
    assert events
    assert validate_events(events) == []
    flagged = [e for e in events if e["anomaly_flags"]]
    assert len(flagged) == len(anomalies)
    assert sum(1 for e in flagged if "entry_point_candidate" in e["anomaly_flags"]) == 2

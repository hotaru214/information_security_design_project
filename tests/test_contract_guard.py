"""契约守卫测试（成员C）：确保任何来源的数据在进入系统前后都符合 Event V2 / EventOut 契约。

validate_events = 解析器输出（19 字段）阻断级校验
validate_eventout = D 的输入（19 字段 + 数据库 id）阻断级校验
collect_warnings = 非阻断警告（如 host 为 IP 字符串，待后端放宽 host 可空后归零）
"""
import json
from pathlib import Path

import pytest

from backend.parsers.network.normalize import (
    collect_warnings,
    validate_eventout,
    validate_events,
)

ROOT = Path(__file__).resolve().parents[1]


def base_event(**overrides):
    e = {
        "timestamp": "2026-09-08T13:10:00.000+08:00",
        "host": "web-server",
        "source": "network_pcap",
        "source_event_id": None,
        "event_type": "network_connection",
        "user": None,
        "process": None,
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.66",
        "dst_port": 4444,
        "protocol": "tcp",
        "logon_type": None,
        "session_id": None,
        "cmdline": None,
        "detail": {"src_port": 1234, "direction": "outbound"},
        "description": "test event",
        "anomaly_flags": [],
        "severity": 0,
        "raw_log": "FLOW test",
    }
    e.update(overrides)
    return e


# ---------------------------------------------------------------- 阻断级校验

def test_valid_event_passes():
    assert validate_events([base_event()]) == []
    assert validate_eventout([dict(base_event(), id=1)]) == []


def test_placeholder_host_rejected():
    for bad in ("unknown", "", "  ", "-"):
        assert any("host" in p for p in validate_events([base_event(host=bad)])), bad


def test_port_zero_placeholder_rejected():
    """dst_port 缺失必须 null，用 0 占位 -> 阻断。"""
    assert any("dst_port" in p for p in validate_events([base_event(dst_port=0)]))


def test_bad_timestamp_rejected():
    assert validate_events([base_event(timestamp="2026-09-08T13:10:00.000Z")])
    assert validate_events([base_event(timestamp="not-a-time+08:00")])


def test_network_source_event_id_must_be_null():
    e = base_event(source="network_zeek", source_event_id="Cabc123")
    assert any("source_event_id" in p for p in validate_events([e]))
    assert validate_events([base_event(source="sysmon", source_event_id=1)]) == []   # 主机侧可非空


def test_anomaly_flags_element_type():
    e = base_event(anomaly_flags=[1, 2])
    assert any("anomaly_flags" in p for p in validate_events([e]))


# ---------------------------------------------------------------- EventOut

def test_eventout_requires_unique_positive_id():
    assert any("id" in p for p in validate_eventout([dict(base_event())]))            # 缺 id
    assert any("id 重复" in p for p in validate_eventout(
        [dict(base_event(), id=5), dict(base_event(dst_ip="1.2.3.4", description="x2"), id=5)]))
    assert any("id 非法" in p for p in validate_eventout([dict(base_event(), id=-1)]))


# ---------------------------------------------------------------- 警告（非阻断）

def test_host_ip_string_is_warning_not_error():
    e = base_event(host="147.32.84.165")
    assert validate_events([e]) == []                       # 不阻断（后端 schema 现要求非空）
    assert any("host 为 IP" in w for w in collect_warnings([e]))


def test_mapped_host_no_warning():
    assert collect_warnings([base_event(host="saruman-infected")]) == []


# ---------------------------------------------------------------- 文件级守卫

def test_all_eventout_files_in_sample_events_are_compliant():
    """data/sample_events/ 下所有 *_eventout.json 必须通过 EventOut 契约校验——
    未来任何人（含 D/F）新放的导出文件都会被本测试自动检查。"""
    files = sorted(ROOT.glob("data/sample_events/*_eventout.json"))
    assert files, "未找到 EventOut 导出文件（先跑 scripts/export_for_d.py）"
    for f in files:
        events = json.loads(f.read_text(encoding="utf-8"))
        problems = validate_eventout(events)
        assert not problems, f"{f.name} 契约不合规: {problems[:3]}"
        warns = collect_warnings(events)
        # 警告不阻断，但必须处于已知受控范围（host IP 兜底），出现其他类型警告要人工审查
        unexpected = [w for w in warns if "host 为 IP" not in w]
        assert not unexpected, f"{f.name} 出现未知警告: {unexpected[:3]}"

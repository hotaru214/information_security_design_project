import pytest

from backend.analysis import build_attack_graph, correlate_events


def network_event(**changes):
    event = {
        "id": 101, "event_id": None,
        "timestamp": "2026-09-08T13:00:00+08:00",
        "host": "office-pc", "source": "network_pcap",
        "event_type": "network_connection", "user": None, "process": None,
        "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "dst_port": 4444,
        "protocol": "tcp", "logon_type": None, "session_id": None,
        "cmdline": None, "detail": {}, "description": "Network connection",
        "anomaly_flags": [], "severity": 0, "raw_log": "Network evidence",
    }
    event.update(changes)
    return event


def file_event(path):
    return network_event(
        host="Core",
        source="linux_audit",
        event_type="file_read",
        src_ip=None,
        dst_ip=None,
        dst_port=None,
        detail={"file_path": path},
    )


def test_finance_file_read_is_collection():
    steps = correlate_events([file_event("/data/finance_demo.txt")])

    collection = [
        step for step in steps
        if step["stage"] == "Collection" and step["technique_id"] == "T1005"
    ]

    assert len(collection) == 1
    assert collection[0]["evidence_event_ids"] == [101]


def test_harmless_text_file_is_not_collection():
    steps = correlate_events([file_event("/tmp/readme.txt")])

    assert not any(step["stage"] == "Collection" for step in steps)


def test_http_request_to_suspicious_external_c2_is_detected():
    event = network_event(
        event_type="http_request",
        src_ip="10.10.30.10",
        dst_ip="10.10.10.20",
        dst_port=8080,
        detail={"uri": "/test-beacon?data=CASE01_WIN10_FAKE_DATA"},
    )

    steps = correlate_events([event], internal_networks=FINAL_NETWORKS)

    assert any(
        step["stage"] == "Command and Control"
        and step["technique_id"] == "T1071"
        for step in steps
    )


def test_normal_external_http_is_not_c2():
    event = network_event(
        event_type="http_request",
        src_ip="10.10.30.10",
        dst_ip="10.10.10.20",
        dst_port=80,
        detail={"uri": "/index.html"},
    )

    steps = correlate_events([event], internal_networks=FINAL_NETWORKS)

    assert not any(step["stage"] == "Command and Control" for step in steps)


def test_waf_http_alert_is_initial_access():
    event = network_event(
        source="waf",
        event_type="http_request",
        src_ip="10.10.10.10",
        dst_ip="10.10.20.10",
        dst_port=80,
        protocol="http",
        detail={"uri": "/upload.php?cmd=whoami", "attack_type": "command_injection"},
        anomaly_flags=["web_attack", "initial_access"],
        severity=3,
    )

    steps = correlate_events([event], internal_networks=FINAL_NETWORKS)

    assert any(
        step["stage"] == "Initial Access"
        and step["technique_id"] == "T1190"
        and step["evidence_event_ids"] == [101]
        for step in steps
    )


def test_firewall_boundary_connection_is_initial_access():
    event = network_event(
        source="firewall",
        event_type="network_connection",
        src_ip="10.10.10.10",
        dst_ip="10.10.20.10",
        dst_port=80,
        protocol="tcp",
        detail={"action": "allow", "rule_name": "allow_web"},
        anomaly_flags=["initial_access"],
        severity=2,
    )

    steps = correlate_events([event], internal_networks=FINAL_NETWORKS)

    assert any(
        step["stage"] == "Initial Access"
        and step["technique_id"] == "T1190"
        and step["evidence_event_ids"] == [101]
        for step in steps
    )


@pytest.mark.parametrize("event_type", ["network_connection", "http_request"])
@pytest.mark.parametrize("detail", [{}, {"bytes_out": None}, {"bytes_out": "invalid"}, {"bytes_out": 0}])
@pytest.mark.parametrize("flagged", [False, True])
def test_bytes_out_tolerates_unknown_and_preserves_flags(event_type, detail, flagged):
    event = network_event(event_type=event_type, detail=detail,
                          anomaly_flags=["exfiltration"] if flagged else [])
    steps = correlate_events([event])
    assert isinstance(steps, list)
    exfiltration = [s for s in steps if s["stage"] == "Exfiltration"]
    assert bool(exfiltration) == flagged
    if flagged:
        assert exfiltration[0]["evidence_event_ids"] == [101]
    if event_type == "network_connection":
        assert any(s["stage"] == "Command and Control" for s in steps)


@pytest.mark.parametrize("host_map,expected", [
    ({}, (None, None)),
    ({"192.168.1.20": "office-pc"}, (None, "office-pc")),
    ({"192.168.1.10": "web-server", "192.168.1.20": "office-pc"},
     ("web-server", "office-pc")),
])
def test_lateral_hosts_only_use_endpoint_mapping(host_map, expected):
    event = network_event(dst_ip="192.168.1.20", dst_port=445)
    steps = correlate_events([event], host_map)
    step = next(s for s in steps if s["stage"] == "Lateral Movement")
    assert (step["source_host"], step["target_host"]) == expected
    assert (step["source_ip"], step["target_ip"]) == ("192.168.1.10", "192.168.1.20")
    assert step["evidence_event_ids"] == [101]


@pytest.mark.parametrize("ip,hostname,expected", [
    ("10.0.0.1", None, "host"),
    ("172.16.0.1", None, "host"),
    ("172.31.255.254", None, "host"),
    ("192.168.1.20", None, "host"),
    ("8.8.8.8", None, "external_ip"),
    ("8.8.8.8", "known-host", "host"),
    ("invalid-ip", None, "external_ip"),
    (None, None, None),
    ("", None, None),
])
def test_graph_node_type_uses_ip_for_both_endpoints(ip, hostname, expected):
    step = {
        "step_id": "S001", "stage": "Lateral Movement", "technique_id": "T1021",
        "technique_name": "Remote Services", "timestamp": "2026-09-08T13:00:00+08:00",
        "source_host": hostname, "target_host": hostname,
        "source_ip": ip, "target_ip": ip, "description": "Connection",
        "evidence_event_ids": [101],
    }
    graph = build_attack_graph([step])
    assert set(graph) == {"nodes", "edges"}
    if expected is None:
        assert graph == {"nodes": [], "edges": []}
    else:
        assert graph["nodes"] == [{"id": hostname or ip, "label": hostname or ip, "type": expected}]
        assert graph["edges"][0]["evidence_event_ids"] == [101]


FINAL_NETWORKS = ["10.10.20.0/24", "10.10.30.0/24"]
DATASET_NETWORKS = [
    "10.0.0.0/24",
    "10.10.20.0/24",
    "10.10.30.0/24",
]


@pytest.mark.parametrize("ip,internal", [
    ("10.0.0.5", True), ("10.0.0.10", True), ("10.0.0.21", True),
    ("203.0.113.66", False),
    ("10.10.10.10", False), ("10.10.10.20", False),
    ("10.10.20.10", True), ("10.10.30.10", True),
])
def test_supported_dataset_zones(ip, internal):
    from backend.analysis.correlation import is_internal_ip, is_external_ip
    assert is_internal_ip(ip, DATASET_NETWORKS) is internal
    assert is_external_ip(ip, DATASET_NETWORKS) is (not internal)


@pytest.mark.parametrize("ip,internal", [
    ("10.10.10.10", False), ("10.10.10.20", False),
    ("10.10.20.10", True), ("10.10.20.20", True),
    ("10.10.30.10", True), ("10.10.30.20", True), ("8.8.8.8", False),
])
def test_scenario_zone(ip, internal):
    from backend.analysis.correlation import is_internal_ip, is_external_ip
    assert is_internal_ip(ip, FINAL_NETWORKS) is internal
    assert is_external_ip(ip, FINAL_NETWORKS) is (not internal)


@pytest.mark.parametrize("ip", [None, "", "invalid"])
def test_unknown_zone_safe(ip):
    from backend.analysis.correlation import is_internal_ip, is_external_ip
    assert not is_internal_ip(ip, FINAL_NETWORKS)
    assert not is_external_ip(ip, FINAL_NETWORKS)


def test_empty_configuration_is_not_legacy():
    from backend.analysis.correlation import is_internal_ip, is_external_ip
    assert is_internal_ip("10.10.10.10")
    assert not is_internal_ip("10.10.10.10", [])
    assert is_external_ip("10.10.10.10", [])
    with pytest.raises(ValueError):
        correlate_events([], internal_networks=["bad-cidr"])


@pytest.mark.parametrize("stage,technique,changes", [
    ("Initial Access", "T1190", dict(event_type="http_request", src_ip="10.10.10.10",
        dst_ip="10.10.20.10", dst_port=80, detail={"uri": "/shell"})),
    ("Lateral Movement", "T1021", dict(src_ip="10.10.20.10", dst_ip="10.10.30.10", dst_port=445)),
    ("Command and Control", "T1071", dict(src_ip="10.10.30.10", dst_ip="10.10.10.20", dst_port=4444)),
    ("Exfiltration", "T1041", dict(src_ip="10.10.30.20", dst_ip="10.10.10.20",
        anomaly_flags=["exfiltration"])),
    ("Command and Control", "T1071", dict(event_type="dns_query", src_ip="10.10.30.10",
        dst_ip="10.10.10.20", detail={"domain": "example.com"}, anomaly_flags=["c2"])),
])
def test_scenario_detectors_and_wrong_direction(stage, technique, changes):
    event = network_event(**changes)
    steps = correlate_events([event], internal_networks=FINAL_NETWORKS)
    assert any(s["stage"] == stage and s["technique_id"] == technique for s in steps)
    assert all(s["evidence_event_ids"] == [101] for s in steps)
    # An unrelated hostname mapping must not change zone decisions.
    mapped = correlate_events([event], {event["src_ip"]: "arbitrary"}, FINAL_NETWORKS)
    assert [s["stage"] for s in mapped] == [s["stage"] for s in steps]
    if stage == "Initial Access":
        event["dst_ip"] = "10.10.10.20"
    else:
        event["src_ip"] = "10.10.10.10"
    assert not any(s["stage"] == stage for s in correlate_events([event], internal_networks=FINAL_NETWORKS))


def test_graph_zone_and_original_demo():
    import json
    from pathlib import Path
    from backend.analysis import find_attack_paths
    sample = json.loads((Path(__file__).resolve().parents[1] /
                         "data/sample_events/d_attack_chain_events.json").read_text(encoding="utf-8"))
    steps = correlate_events(sample["events"], sample["host_map"])
    graph = build_attack_graph(steps)
    assert (len(steps), len(graph["nodes"]), len(graph["edges"]), len(find_attack_paths(steps))) == (11, 5, 11, 1)
    step = dict(steps[0], source_host=None, source_ip="10.10.10.10",
                target_host=None, target_ip="10.10.20.10")
    graph = build_attack_graph([step], FINAL_NETWORKS)
    assert {n["id"]: n["type"] for n in graph["nodes"]} == {
        "10.10.10.10": "external_ip", "10.10.20.10": "host"}

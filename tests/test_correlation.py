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

"""Content-based HTTP detection, including the unmodified Final E capture."""
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from backend.parsers.network.pcap_parser import parse_pcap
from backend.parsers.network.normalize import build_events, validate_events


@pytest.mark.parametrize("port", [80, 8080, 8000, 8088, 9100, 18081])
def test_http_request_and_response_independent_of_port(tmp_path, port):
    path = tmp_path / "http.pcap"
    wrpcap(str(path), [
        Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/TCP(sport=45000, dport=port)/Raw(
            b"GET /reports/example.txt HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        Ether()/IP(src="192.0.2.2", dst="192.0.2.1")/TCP(sport=port, dport=45000)/Raw(
            b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nexample"),
    ])
    events = build_events(parse_pcap(str(path))[0], [])
    assert validate_events(events) == []
    event, = events
    assert event["event_type"] == "http_request"
    assert event["detail"]["method"] == "GET"
    assert event["detail"]["uri"] == "/reports/example.txt"
    assert event["detail"]["http_requests"][0]["host"] == "example.test"
    assert event["detail"]["status_code"] == 200
    assert event["anomaly_flags"] == []


@pytest.mark.parametrize("payload", [
    b"ordinary printer data\r\n", b"GET /document\r\n", b"GET /document NOTHTTP\r\n",
    b"GET /document HTTP/1.1", b"prefix GET /document HTTP/1.1\r\n",
])
def test_non_http_tcp_on_9100_stays_network_connection(tmp_path, payload):
    path = tmp_path / "tcp.pcap"
    wrpcap(str(path), [Ether()/IP()/TCP(sport=45000, dport=9100)/Raw(payload)])
    event, = build_events(parse_pcap(str(path))[0], [])
    assert event["event_type"] == "network_connection"
    assert "uri" not in event["detail"]
    assert "status_code" not in event["detail"]


def test_final_e_real_core_capture_http_semantics():
    path = Path(__file__).resolve().parents[1] / "data/network_logs/e_case01/win10-to-core.pcap"
    events = build_events(parse_pcap(str(path))[0], [])
    assert validate_events(events) == []
    requests = [e for e in events if e["dst_port"] == 9100]
    assert len(requests) == 4
    for event in requests:
        assert event["source"] == "network_pcap"
        assert event["event_type"] == "http_request"
        assert event["detail"]["method"] == "GET"
        assert event["detail"]["uri"] == "/finance_demo.txt"
        assert event["detail"]["http_requests"][0]["host"] == "10.10.30.20:9100"
        assert event["detail"]["status_code"] == 200
        assert event["anomaly_flags"] == []
        assert event["severity"] == 0
        assert "attack_stage" not in event["detail"]
        assert "mitre_technique" not in event["detail"]

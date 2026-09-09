import json
from pathlib import Path

from backend.analysis import correlate_events
from backend.routers import attack_chain as module


def step(**changes):
    result = dict(step_id="S001", stage="Lateral Movement", technique_id="T1021",
                  technique_name="Remote Services", source_host=None, target_host="server",
                  source_ip="8.8.8.8", target_ip="192.168.1.20",
                  timestamp="2026-09-08T13:00:00+08:00", description="Connection",
                  evidence_event_ids=[12, 13])
    result.update(changes)
    return result


def test_empty_events(monkeypatch):
    monkeypatch.setattr(module, "get_events", lambda: [])
    monkeypatch.setattr(module, "get_hosts", lambda: [])
    view = module.read_attack_chain()
    assert view["nodes"] == view["links"] == []
    assert view["meta"]["event_count"] == view["meta"]["step_count"] == 0


def test_mapping():
    view = module.build_chain_view([step()], 2, [])
    link = view["links"][0]
    assert link["attack_stage"] == "Lateral Movement"
    assert link["mitre_technique"] == "T1021"
    assert link["evidence_event_ids"] == [12, 13]
    assert link["source_host"] is None
    assert link["source"] == "ip:8.8.8.8"
    assert link["target"] == "host:server"


def test_null_hosts_are_distinct_and_nodes_deduplicated():
    view = module.build_chain_view([step(), step(source_ip="1.1.1.1")], 2, [])
    assert len(view["nodes"]) == 3
    assert view["links"][0]["source"] != view["links"][1]["source"]
    assert view["links"][0]["target"] == view["links"][1]["target"]


def test_private_ip_and_identity_namespace():
    view = module.build_chain_view([step(source_host="ip:192.168.1.20",
                                       target_host=None)], 1, [])
    assert len(view["nodes"]) == 2
    node = next(n for n in view["nodes"] if n["host"] is None)
    assert node["id"] == "ip:192.168.1.20"
    assert node["ip"] == "192.168.1.20"
    assert node["category"] == "host"
    assert node["role"] is None


def test_no_steps_and_asset_enrichment():
    assert module.build_chain_view([], 3, [])["meta"]["event_count"] == 3
    view = module.build_chain_view([step(target_ip=None)], 1,
                                   [dict(hostname="server", ip="192.168.1.20", role="server")])
    node = next(n for n in view["nodes"] if n["host"] == "server")
    assert node["ip"] == "192.168.1.20"
    assert node["role"] == "server"
    assert view["links"][0]["target_ip"] is None


def test_original_d_sample():
    path = Path(__file__).resolve().parents[1] / "data/sample_events/d_attack_chain_events.json"
    sample = json.loads(path.read_text(encoding="utf-8"))
    steps = correlate_events(sample["events"], sample["host_map"])
    view = module.build_chain_view(steps, len(sample["events"]), [])
    assert len(view["links"]) == len(steps) == 11
    ids = {n["id"] for n in view["nodes"]}
    for original, link in zip(steps, view["links"]):
        assert link["evidence_event_ids"] == original["evidence_event_ids"]
        assert link["source"] in ids and link["target"] in ids


def test_router_passes_final_networks(monkeypatch):
    monkeypatch.setattr(module, "get_events", lambda: [])
    monkeypatch.setattr(module, "get_hosts", lambda: [])
    seen = []
    def correlate(events, host_map, internal_networks=None):
        seen.append(internal_networks)
        return [step(source_ip="10.10.10.10", target_host=None, target_ip="10.10.20.10")]
    monkeypatch.setattr(module, "correlate_events", correlate)
    view = module.read_attack_chain()
    assert seen == [[
        "10.0.0.0/24",
        "10.10.20.0/24",
        "10.10.30.0/24",
    ]]
    assert [n["category"] for n in view["nodes"]] == ["external_ip", "host"]


def test_router_default_networks_cover_case01_and_case02(monkeypatch):
    monkeypatch.setattr(module, "get_events", lambda: [])
    monkeypatch.setattr(module, "get_hosts", lambda: [])
    monkeypatch.setattr(module, "correlate_events", lambda *args, **kwargs: [])

    module.read_attack_chain()

    from backend.analysis.correlation import is_external_ip, is_internal_ip
    networks = module.DEFAULT_INTERNAL_NETWORKS
    assert all(is_internal_ip(ip, networks) for ip in (
        "10.0.0.5", "10.0.0.10", "10.0.0.21",
        "10.10.20.10", "10.10.30.10",
    ))
    assert all(is_external_ip(ip, networks) for ip in (
        "203.0.113.66", "10.10.10.10", "10.10.10.20",
    ))

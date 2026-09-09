from fastapi import APIRouter

from backend.analysis import build_attribution_profile, correlate_events
from backend.analysis.correlation import compile_internal_networks, is_internal_ip, is_external_ip
from backend.database import get_events, get_hosts


# Supported datasets: case01 uses 10.0.0.0/24; E/case02 uses the two LAN zones.
# 10.10.10.0/24 remains outside the list and is therefore the WAN zone.
DEFAULT_INTERNAL_NETWORKS = [
    "10.0.0.0/24",
    "10.10.20.0/24",
    "10.10.30.0/24",
]

router = APIRouter(prefix="/api/attack-chain")


def build_chain_view(attack_steps, event_count, hosts, internal_networks=None):
    """Adapt domain attack steps without changing their evidence or endpoints."""
    networks = compile_internal_networks(internal_networks)
    assets = {host["hostname"]: host for host in hosts}
    nodes = {}
    links = []

    def endpoint(host, ip):
        if host is None and ip is None:
            return None
        node_id = f"host:{host}" if host is not None else f"ip:{ip}"
        asset = assets.get(host, {})
        category = "host" if host is not None else None
        if category is None and ip:
            if is_internal_ip(ip, networks):
                category = "host"
            elif is_external_ip(ip, networks):
                category = "external_ip"
        node = nodes.setdefault(node_id, {
            "id": node_id, "host": host, "ip": ip or asset.get("ip"),
            "role": asset.get("role"), "category": category,
        })
        if node["ip"] is None and ip is not None:
            node["ip"] = ip
        return node_id

    for step in attack_steps:
        link = {key: step[key] for key in (
            "step_id", "technique_name", "source_host", "target_host",
            "source_ip", "target_ip", "timestamp", "description",
            "evidence_event_ids",
        )}
        link["case_id"] = step.get("case_id")
        link["attack_stage"] = step["stage"]
        link["mitre_technique"] = step["technique_id"]
        link["source"] = endpoint(step["source_host"], step["source_ip"])
        link["target"] = endpoint(step["target_host"], step["target_ip"])
        links.append(link)

    return {
        "meta": {
            "case": "live-analysis",
            "description": "Attack chain generated from current event database",
            "generated_from": "live", "event_count": event_count,
            "step_count": len(attack_steps),
        },
        "nodes": list(nodes.values()), "links": links,
    }


@router.get("")
def read_attack_chain(case_id: str | None = None):
    events = get_events() if case_id is None else get_events(case_id=case_id)
    hosts = get_hosts()
    host_map = {host["ip"]: host["hostname"] for host in hosts}
    attack_steps = correlate_events(events, host_map, internal_networks=DEFAULT_INTERNAL_NETWORKS)
    return build_chain_view(attack_steps, len(events), hosts, DEFAULT_INTERNAL_NETWORKS)


@router.get("/attribution")
def read_attribution_profile(case_id: str | None = None):
    events = get_events() if case_id is None else get_events(case_id=case_id)
    hosts = get_hosts()
    host_map = {host["ip"]: host["hostname"] for host in hosts}
    attack_steps = correlate_events(events, host_map, internal_networks=DEFAULT_INTERNAL_NETWORKS)
    return build_attribution_profile(
        events,
        attack_steps,
        host_map,
        internal_networks=DEFAULT_INTERNAL_NETWORKS,
    )

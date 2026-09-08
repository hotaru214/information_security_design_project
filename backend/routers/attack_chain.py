from ipaddress import ip_address

from fastapi import APIRouter

from backend.analysis import correlate_events
from backend.database import get_events, get_hosts


router = APIRouter(prefix="/api/attack-chain")


def build_chain_view(attack_steps, event_count, hosts):
    """Adapt domain attack steps without changing their evidence or endpoints."""
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
            try:
                category = "host" if ip_address(ip).is_private else "external_ip"
            except ValueError:
                pass
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
def read_attack_chain():
    events = get_events()
    hosts = get_hosts()
    host_map = {host["ip"]: host["hostname"] for host in hosts}
    attack_steps = correlate_events(events, host_map)
    return build_chain_view(attack_steps, len(events), hosts)

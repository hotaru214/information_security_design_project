from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from backend.analysis.correlation import (
    ATTACK_TECHNIQUES,
    compile_internal_networks,
    get_detail,
    get_value,
    is_external_ip,
    is_internal_ip,
    parse_timestamp,
)


SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".sh", ".py", ".pl"}
CONFIG_EXTENSIONS = {".conf", ".config", ".cfg", ".ini", ".json", ".xml", ".yml", ".yaml"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
NON_DOMAIN_FILE_EXTENSIONS = {
    ".dll",
    ".exe",
    ".html",
    ".htm",
    ".jsp",
    ".php",
    ".aspx",
    ".asp",
}

TOOL_KEYWORDS = {
    "7z",
    "bash",
    "bitsadmin",
    "certutil",
    "cmd",
    "curl",
    "mshta",
    "nc",
    "net",
    "netcat",
    "nmap",
    "powershell",
    "psexec",
    "python",
    "reg",
    "rundll32",
    "scp",
    "ssh",
    "sudo",
    "tar",
    "wevtutil",
    "wget",
    "wmic",
}

C2_FLAGS = {"c2", "beacon", "dns_tunnel", "external_connection"}
EXFIL_FLAGS = {"exfiltration", "large_upload"}
SUSPICIOUS_C2_PORTS = {4444, 5555, 6666, 7777, 8080, 8443, 9001}

TOKEN_RE = re.compile(r"[a-z0-9_.:-]+")
PATH_RE = re.compile(
    r"(?:[a-zA-Z]:\\[^\s\"'<>|]+|/[^\s\"'<>]+|https?://[^\s\"'<>]+|[\w.-]+\.(?:ps1|bat|cmd|vbs|js|jse|sh|py|pl|conf|config|cfg|ini|json|xml|yml|yaml|zip|rar|7z|tar|gz))",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def build_attribution_profile(
    events: list[dict[str, Any]],
    attack_steps: list[dict[str, Any]],
    host_map: dict[str, str] | None = None,
    apt_profiles: list[dict[str, Any]] | dict[str, Any] | None = None,
    threat_intel: dict[str, Any] | None = None,
    internal_networks: list[str] | None = None,
) -> dict[str, Any]:
    """Build an attacker fingerprint and TTP-similarity profile.

    Attribution here means observable TTP similarity. It does not claim a
    real-world legal identity; every conclusion keeps database event IDs for
    evidence lookup.
    """

    host_map = host_map or {}
    networks = compile_internal_networks(internal_networks)
    profiles = normalize_profiles(apt_profiles if apt_profiles is not None else load_default_apt_profiles())
    intel = threat_intel if threat_intel is not None else load_default_threat_intel()

    normalized_events = [normalize_event(event) for event in events]
    normalized_events = [event for event in normalized_events if event is not None]

    case_ids = collect_case_ids(normalized_events, attack_steps)
    if len(case_ids) > 1:
        case_profiles = [
            build_case_profile(
                case_id,
                [event for event in normalized_events if event.get("_case_id") == case_id],
                [step for step in attack_steps if step.get("case_id") == case_id],
                host_map,
                profiles,
                intel,
                networks,
            )
            for case_id in case_ids
        ]
        return {
            "case_id": None,
            "profiles": case_profiles,
            "note": "Multiple case_id values were analyzed independently to avoid cross-case attribution mixing.",
        }

    case_id = case_ids[0] if case_ids else None
    return build_case_profile(case_id, normalized_events, attack_steps, host_map, profiles, intel, networks)


def build_case_profile(
    case_id: str | None,
    events: list[dict[str, Any]],
    attack_steps: list[dict[str, Any]],
    host_map: dict[str, str],
    apt_profiles: list[dict[str, Any]],
    threat_intel: dict[str, Any],
    internal_networks,
) -> dict[str, Any]:
    events = sorted(events, key=lambda event: event.get("_time") or parse_timestamp("9999-12-31T00:00:00+08:00"))
    steps = sorted(attack_steps, key=lambda step: step.get("timestamp") or "")

    entry_points = extract_entry_points(steps)
    fingerprints = extract_fingerprints(events, steps, internal_networks)
    c2_infrastructure = extract_c2_infrastructure(events, steps, host_map, threat_intel, internal_networks)
    behavior_sequence = compact_sequence([step.get("stage") for step in steps if step.get("stage")])

    observed_profile = {
        "techniques": fingerprints["techniques"],
        "technique_names": fingerprints["technique_names"],
        "tools": fingerprints["tools"],
        "scripts": fingerprints["scripts"],
        "config_files": fingerprints["config_files"],
        "registry_keys": fingerprints["registry_keys"],
        "domains": fingerprints["domains"],
        "external_ips": fingerprints["external_ips"],
        "behavior_sequence": behavior_sequence,
        "infrastructure_tags": infrastructure_tags(c2_infrastructure),
    }
    profile_text = build_profile_text(observed_profile, steps)
    matches = match_apt_profiles(observed_profile, profile_text, apt_profiles)
    evidence_event_ids = collect_profile_evidence_ids(steps, fingerprints, c2_infrastructure)

    return {
        "case_id": case_id,
        "entry_points": entry_points,
        "fingerprints": fingerprints,
        "c2_infrastructure": c2_infrastructure,
        "behavior_sequence": behavior_sequence,
        "apt_matches": matches,
        "evidence_event_ids": evidence_event_ids,
        "profile_text": profile_text,
        "note": "Attribution is based on observable TTP similarity and local threat-intel references; it is not a confirmed identity attribution.",
    }


def normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    parsed_time = parse_timestamp(get_value(event, "timestamp"))
    copied = dict(event)
    detail = copied.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}

    copied["_time"] = parsed_time
    copied["_detail"] = detail
    copied["_event_type"] = text(get_value(copied, "event_type")).lower()
    copied["_source"] = text(get_value(copied, "source")).lower()
    copied["_process"] = text(get_value(copied, "process")).lower()
    copied["_cmdline"] = text(get_value(copied, "cmdline")).lower()
    copied["_description"] = text(get_value(copied, "description")).lower()
    copied["_raw_log"] = text(get_value(copied, "raw_log")).lower()
    copied["_case_id"] = get_event_case_id(copied)
    copied["_flags"] = normalize_flags(copied.get("anomaly_flags"))
    return copied


def collect_case_ids(events: list[dict[str, Any]], steps: list[dict[str, Any]]) -> list[str | None]:
    case_ids = {
        item.get("_case_id")
        for item in events
        if item.get("_case_id") is not None
    }
    case_ids.update(
        step.get("case_id")
        for step in steps
        if step.get("case_id") is not None
    )
    if not case_ids:
        return [None]
    return sorted(case_ids)


def extract_entry_points(steps: list[dict[str, Any]]) -> dict[str, list[str]]:
    source_ips: list[str] = []
    target_hosts: list[str] = []
    target_ips: list[str] = []
    evidence_ids: list[int] = []

    for step in steps:
        if step.get("stage") != "Initial Access":
            continue
        append_unique(source_ips, step.get("source_ip"))
        append_unique(target_hosts, step.get("target_host"))
        append_unique(target_ips, step.get("target_ip"))
        for event_id in step.get("evidence_event_ids") or []:
            append_unique(evidence_ids, event_id)

    return {
        "source_ips": source_ips,
        "target_hosts": target_hosts,
        "target_ips": target_ips,
        "evidence_event_ids": evidence_ids,
    }


def extract_fingerprints(
    events: list[dict[str, Any]],
    attack_steps: list[dict[str, Any]],
    internal_networks,
) -> dict[str, Any]:
    evidence_ids = set(collect_step_evidence_ids(attack_steps))
    tools: list[str] = []
    scripts: list[str] = []
    config_files: list[str] = []
    archives: list[str] = []
    registry_keys: list[str] = []
    file_hashes: list[str] = []
    domains: list[str] = []
    external_ips: list[str] = []
    users: list[str] = []
    commands: list[str] = []
    event_evidence: list[int] = []

    for event in events:
        event_id = event.get("id")
        detail = event.get("_detail") or {}
        relevant = event_id in evidence_ids or bool(event.get("_flags")) or int_value(event.get("severity"), 0) >= 2

        if relevant:
            append_unique(event_evidence, event_id)
            append_unique(users, get_value(event, "user"))
            cmdline = get_value(event, "cmdline")
            if cmdline:
                append_unique(commands, cmdline)

        process = basename(text(get_value(event, "process")).lower())
        if relevant and process:
            append_unique(tools, normalize_tool_name(process))

        scan_for_tools(f"{event.get('_process')} {event.get('_cmdline')}", tools)

        for source_text in event_text_sources(event):
            for path in extract_paths(source_text):
                suffix = path_suffix(path)
                if suffix in SCRIPT_EXTENSIONS:
                    append_unique(scripts, path)
                elif suffix in CONFIG_EXTENSIONS:
                    append_unique(config_files, path)
                elif suffix in ARCHIVE_EXTENSIONS:
                    append_unique(archives, path)

            for domain in extract_domains(source_text):
                append_unique(domains, domain)

            for ip in IP_RE.findall(source_text):
                if is_external_ip(ip, internal_networks):
                    append_unique(external_ips, ip)

        registry_key = get_detail(event, "registry_key")
        if registry_key:
            append_unique(registry_keys, registry_key)

        for hash_value in flatten_hashes(detail.get("hashes")):
            append_unique(file_hashes, hash_value)

        for ip_key in ("src_ip", "dst_ip"):
            ip_value = get_value(event, ip_key)
            if is_external_ip(ip_value, internal_networks):
                append_unique(external_ips, ip_value)

        direct_domain = first_present(detail, ["domain", "query", "hostname", "host", "server_name"])
        if direct_domain:
            append_unique(domains, strip_domain(direct_domain))

    techniques = sorted({step.get("technique_id") for step in attack_steps if step.get("technique_id")})
    technique_names = {
        technique_id: ATTACK_TECHNIQUES.get(technique_id, step.get("technique_name"))
        for technique_id in techniques
        for step in attack_steps
        if step.get("technique_id") == technique_id
    }

    return {
        "tools": sorted(tools),
        "scripts": sorted(scripts),
        "config_files": sorted(config_files),
        "archives": sorted(archives),
        "registry_keys": sorted(registry_keys),
        "file_hashes": sorted(file_hashes),
        "domains": sorted(domains),
        "external_ips": sorted(external_ips),
        "users": sorted(users),
        "commands": commands[:20],
        "techniques": techniques,
        "technique_names": technique_names,
        "evidence_event_ids": event_evidence,
    }


def extract_c2_infrastructure(
    events: list[dict[str, Any]],
    attack_steps: list[dict[str, Any]],
    host_map: dict[str, str],
    threat_intel: dict[str, Any],
    internal_networks,
) -> list[dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}

    def ensure_endpoint(key: str) -> dict[str, Any]:
        return endpoints.setdefault(
            key,
            {
                "id": key,
                "ip": key if looks_like_ip(key) else None,
                "domains": [],
                "ports": [],
                "protocols": [],
                "first_seen": None,
                "last_seen": None,
                "source_hosts": [],
                "source_ips": [],
                "evidence_event_ids": [],
                "intel": {},
            },
        )

    for step in attack_steps:
        if step.get("stage") not in {"Command and Control", "Exfiltration"}:
            continue
        endpoint_key = step.get("target_ip") or step.get("target_host")
        if not endpoint_key:
            continue
        item = ensure_endpoint(str(endpoint_key))
        update_time_window(item, step.get("timestamp"))
        append_unique(item["source_hosts"], step.get("source_host"))
        append_unique(item["source_ips"], step.get("source_ip"))
        for event_id in step.get("evidence_event_ids") or []:
            append_unique(item["evidence_event_ids"], event_id)

    connection_groups: dict[tuple[str | None, str | None, int | None], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("_event_type") in {"network_connection", "http_request"}:
            connection_groups[(get_value(event, "src_ip"), get_value(event, "dst_ip"), int_value(get_value(event, "dst_port")))].append(event)

    repeated_keys = {
        key
        for key, group in connection_groups.items()
        if len(group) >= 3 and minutes_between_events(group[0], group[-1]) <= 30
    }

    for event in events:
        event_type = event.get("_event_type")
        if event_type not in {"network_connection", "http_request", "dns_query", "file_transfer"}:
            continue

        flags = event.get("_flags") or set()
        src_ip = get_value(event, "src_ip")
        dst_ip = get_value(event, "dst_ip")
        dst_port = int_value(get_value(event, "dst_port"))
        outbound_external = is_internal_ip(src_ip, internal_networks) and is_external_ip(dst_ip, internal_networks)
        flagged_c2 = bool(flags & (C2_FLAGS | EXFIL_FLAGS))
        suspicious_port = dst_port in SUSPICIOUS_C2_PORTS
        repeated = (src_ip, dst_ip, dst_port) in repeated_keys

        if event_type == "dns_query":
            domain = first_present(event.get("_detail") or {}, ["domain", "query", "hostname"])
            if not domain or not flagged_c2:
                continue
            endpoint_key = strip_domain(domain)
        else:
            if not outbound_external and not flagged_c2:
                continue
            if not flagged_c2 and not suspicious_port and not repeated:
                continue
            endpoint_key = dst_ip or first_present(event.get("_detail") or {}, ["domain", "host", "hostname"])
            if not endpoint_key:
                continue

        item = ensure_endpoint(str(endpoint_key))
        if looks_like_ip(endpoint_key):
            item["ip"] = str(endpoint_key)
        else:
            append_unique(item["domains"], strip_domain(endpoint_key))

        for domain in extract_domains(" ".join(event_text_sources(event))):
            append_unique(item["domains"], domain)
        append_unique(item["ports"], dst_port)
        append_unique(item["protocols"], get_value(event, "protocol"))
        append_unique(item["source_ips"], src_ip)
        append_unique(item["source_hosts"], host_map.get(str(src_ip)) or get_value(event, "host"))
        append_unique(item["evidence_event_ids"], event.get("id"))
        update_time_window(item, get_value(event, "timestamp"))

    for item in endpoints.values():
        item["ports"] = sorted(item["ports"])
        item["protocols"] = sorted(item["protocols"])
        item["domains"] = sorted(item["domains"])
        item["source_hosts"] = sorted(item["source_hosts"])
        item["source_ips"] = sorted(item["source_ips"])
        item["evidence_event_ids"] = sorted(item["evidence_event_ids"])
        item["intel"] = lookup_intel(item, threat_intel)

    return sorted(endpoints.values(), key=lambda item: item.get("first_seen") or "")


def match_apt_profiles(
    observed: dict[str, Any],
    profile_text: str,
    apt_profiles: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matches = []

    for profile in apt_profiles:
        rule_score, detail = rule_similarity(observed, profile)
        semantic_score = token_cosine(profile_text, profile_to_text(profile))
        final_score = round(0.7 * rule_score + 0.3 * semantic_score, 4)
        matches.append(
            {
                "group_id": profile.get("group_id"),
                "name": profile.get("name"),
                "aliases": profile.get("aliases", []),
                "final_score": final_score,
                "rule_score": round(rule_score, 4),
                "semantic_score": round(semantic_score, 4),
                "matched_techniques": detail["matched_techniques"],
                "matched_tools": detail["matched_tools"],
                "matched_infrastructure_tags": detail["matched_infrastructure_tags"],
                "matched_sequence": detail["matched_sequence"],
                "source_refs": profile.get("source_refs", []),
                "note": "TTP similarity match only, not confirmed attribution.",
            }
        )

    matches.sort(key=lambda item: item["final_score"], reverse=True)
    return matches[:3]


def rule_similarity(observed: dict[str, Any], profile: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    observed_techniques = set(observed.get("techniques") or [])
    profile_techniques = set(profile.get("techniques") or [])
    matched_techniques = sorted(observed_techniques & profile_techniques)
    technique_score = coverage_score(matched_techniques, profile_techniques)

    observed_tools = {normalize_tool_name(tool) for tool in observed.get("tools") or []}
    profile_tools = {normalize_tool_name(tool) for tool in profile.get("tools") or []}
    matched_tools = sorted(
        profile_tool
        for profile_tool in profile_tools
        if any(tools_match(profile_tool, observed_tool) for observed_tool in observed_tools)
    )
    tool_score = coverage_score(matched_tools, profile_tools)

    observed_tags = set(observed.get("infrastructure_tags") or [])
    profile_tags = set(profile.get("infrastructure_tags") or [])
    matched_tags = sorted(observed_tags & profile_tags)
    infra_score = coverage_score(matched_tags, profile_tags)

    observed_sequence = observed.get("behavior_sequence") or []
    profile_sequence = profile.get("behavior_sequence") or []
    matched_sequence = longest_common_subsequence(observed_sequence, profile_sequence)
    sequence_score = coverage_score(matched_sequence, profile_sequence)

    score = (
        0.55 * technique_score
        + 0.20 * tool_score
        + 0.15 * sequence_score
        + 0.10 * infra_score
    )
    return score, {
        "matched_techniques": matched_techniques,
        "matched_tools": matched_tools,
        "matched_infrastructure_tags": matched_tags,
        "matched_sequence": matched_sequence,
    }


def load_default_apt_profiles() -> list[dict[str, Any]]:
    path = project_root() / "data" / "threat_intel" / "apt_profiles.json"
    if not path.exists():
        return []
    return normalize_profiles(json.loads(path.read_text(encoding="utf-8")))


def load_default_threat_intel() -> dict[str, Any]:
    path = project_root() / "data" / "threat_intel" / "c2_intel.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_profiles(raw: list[dict[str, Any]] | dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        raw = raw.get("profiles", [])
    if not isinstance(raw, list):
        return []
    return [profile for profile in raw if isinstance(profile, dict)]


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_profile_text(observed: dict[str, Any], steps: list[dict[str, Any]]) -> str:
    parts = [
        " ".join(observed.get("behavior_sequence") or []),
        " ".join(observed.get("techniques") or []),
        " ".join(observed.get("technique_names", {}).values()),
        " ".join(observed.get("tools") or []),
        " ".join(observed.get("scripts") or []),
        " ".join(observed.get("config_files") or []),
        " ".join(observed.get("registry_keys") or []),
        " ".join(observed.get("domains") or []),
        " ".join(observed.get("external_ips") or []),
        " ".join(observed.get("infrastructure_tags") or []),
        " ".join(step.get("description", "") for step in steps),
    ]
    return " ".join(part for part in parts if part)


def profile_to_text(profile: dict[str, Any]) -> str:
    fields = [
        profile.get("name"),
        " ".join(profile.get("aliases") or []),
        " ".join(profile.get("techniques") or []),
        " ".join(profile.get("technique_names") or []),
        " ".join(profile.get("tools") or []),
        " ".join(profile.get("behavior_sequence") or []),
        " ".join(profile.get("infrastructure_tags") or []),
        profile.get("description"),
    ]
    return " ".join(text(field) for field in fields if field)


def infrastructure_tags(items: list[dict[str, Any]]) -> list[str]:
    tags: list[str] = []
    for item in items:
        intel = item.get("intel") or {}
        for tag in intel.get("tags") or []:
            append_unique(tags, text(tag).lower())
        if item.get("ip"):
            append_unique(tags, "external-ip")
        if item.get("domains"):
            append_unique(tags, "domain")
        if any(port in SUSPICIOUS_C2_PORTS for port in item.get("ports", [])):
            append_unique(tags, "non-standard-port")
    return sorted(tags)


def lookup_intel(endpoint: dict[str, Any], threat_intel: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(threat_intel, dict):
        return {}
    store = threat_intel.get("infrastructure", threat_intel)
    if not isinstance(store, dict):
        return {}

    keys = []
    if endpoint.get("ip"):
        keys.append(endpoint["ip"])
    keys.extend(endpoint.get("domains") or [])

    merged: dict[str, Any] = {}
    for key in keys:
        value = store.get(key)
        if isinstance(value, dict):
            merged.update(value)
    return merged


def event_text_sources(event: dict[str, Any]) -> list[str]:
    detail = event.get("_detail") or {}
    values: list[str] = [
        text(get_value(event, "cmdline")),
        text(get_value(event, "description")),
        text(get_value(event, "raw_log")),
        text(get_detail(event, "file_path")),
        text(get_detail(event, "registry_value_data")),
    ]
    for key in ("uri", "url", "domain", "query", "host", "hostname", "user_agent"):
        values.append(text(detail.get(key)))
    return [value for value in values if value]


def extract_paths(value: str) -> list[str]:
    return [clean_artifact(match.group(0)) for match in PATH_RE.finditer(value or "")]


def extract_domains(value: str) -> list[str]:
    domains: list[str] = []
    for match in URL_RE.finditer(value or ""):
        parsed = urlparse(match.group(0))
        if parsed.hostname and is_domain_like(parsed.hostname):
            append_unique(domains, parsed.hostname.lower())

    for token in TOKEN_RE.findall(value or ""):
        if not is_domain_like(token):
            continue
        append_unique(domains, strip_domain(token))
    return domains


def is_domain_like(value: str) -> bool:
    token = strip_domain(value)
    if "." not in token or ":" in token or "/" in token or "\\" in token:
        return False
    if looks_like_ip(token):
        return False
    if any(
        token.endswith(ext)
        for ext in SCRIPT_EXTENSIONS | CONFIG_EXTENSIONS | ARCHIVE_EXTENSIONS | NON_DOMAIN_FILE_EXTENSIONS
    ):
        return False
    labels = token.split(".")
    return len(labels[-1]) >= 2 and labels[-1].isalpha()


def flatten_hashes(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,;\s]+", value) if part.strip()]
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(flatten_hashes(item))
        return result
    if isinstance(value, dict):
        result = []
        for hash_value in value.values():
            result.extend(flatten_hashes(hash_value))
        return result
    return [str(value)]


def scan_for_tools(value: str, tools: list[str]) -> None:
    tokens = {basename(token).lower().removesuffix(".exe") for token in TOKEN_RE.findall(value or "")}
    for token in tokens:
        if token in TOOL_KEYWORDS:
            append_unique(tools, normalize_tool_name(token))


def normalize_tool_name(value: str) -> str:
    tool = basename(text(value).lower())
    if tool.endswith(".exe"):
        return tool
    if tool in TOOL_KEYWORDS and tool not in {"7z"}:
        return f"{tool}.exe" if tool in {"cmd", "reg", "wevtutil", "wmic", "rundll32", "mshta", "powershell", "certutil", "bitsadmin"} else tool
    return tool


def tools_match(left: str, right: str) -> bool:
    left_base = left.removesuffix(".exe")
    right_base = right.removesuffix(".exe")
    return left_base == right_base or left_base in right_base or right_base in left_base


def coverage_score(matches: list[Any] | set[Any], reference: list[Any] | set[Any]) -> float:
    if not reference:
        return 0.0
    return len(matches) / len(reference)


def token_cosine(left: str, right: str) -> float:
    left_counts = Counter(TOKEN_RE.findall(text(left).lower()))
    right_counts = Counter(TOKEN_RE.findall(text(right).lower()))
    if not left_counts or not right_counts:
        return 0.0
    common = set(left_counts) & set(right_counts)
    dot = sum(left_counts[token] * right_counts[token] for token in common)
    left_norm = math.sqrt(sum(value * value for value in left_counts.values()))
    right_norm = math.sqrt(sum(value * value for value in right_counts.values()))
    if not left_norm or not right_norm:
        return 0.0
    return dot / (left_norm * right_norm)


def longest_common_subsequence(left: list[str], right: list[str]) -> list[str]:
    if not left or not right:
        return []
    dp = [[[] for _ in range(len(right) + 1)] for _ in range(len(left) + 1)]
    for i, left_value in enumerate(left, start=1):
        for j, right_value in enumerate(right, start=1):
            if left_value == right_value:
                dp[i][j] = dp[i - 1][j - 1] + [left_value]
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1], key=len)
    return dp[-1][-1]


def compact_sequence(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if not value or (result and result[-1] == value):
            continue
        result.append(value)
    return result


def collect_step_evidence_ids(steps: list[dict[str, Any]]) -> list[int]:
    ids: list[int] = []
    for step in steps:
        for event_id in step.get("evidence_event_ids") or []:
            append_unique(ids, event_id)
    return ids


def collect_profile_evidence_ids(
    steps: list[dict[str, Any]],
    fingerprints: dict[str, Any],
    c2_infrastructure: list[dict[str, Any]],
) -> list[int]:
    ids = collect_step_evidence_ids(steps)
    for event_id in fingerprints.get("evidence_event_ids") or []:
        append_unique(ids, event_id)
    for item in c2_infrastructure:
        for event_id in item.get("evidence_event_ids") or []:
            append_unique(ids, event_id)
    return sorted(ids)


def append_unique(values: list[Any], value: Any) -> None:
    if value is None or value == "":
        return
    if value not in values:
        values.append(value)


def first_present(mapping: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def normalize_flags(flags: Any) -> set[str]:
    if not flags:
        return set()
    if isinstance(flags, str):
        return {flags.lower()}
    if isinstance(flags, list):
        return {text(flag).lower() for flag in flags if flag is not None}
    return set()


def get_event_case_id(event: dict[str, Any]) -> str | None:
    case_id = get_value(event, "case_id")
    if case_id:
        return str(case_id)
    detail_case_id = get_detail(event, "case_id")
    if detail_case_id:
        return str(detail_case_id)
    batch_id = get_detail(event, "batch_id")
    if batch_id:
        return str(batch_id)
    return None


def path_suffix(value: str) -> str:
    cleaned = clean_artifact(value)
    parsed = urlparse(cleaned)
    path = parsed.path if parsed.scheme else cleaned
    return Path(path.replace("\\", "/")).suffix.lower()


def clean_artifact(value: str) -> str:
    return value.strip().strip(".,;:)]}'\"")


def strip_domain(value: Any) -> str:
    domain = text(value).lower().strip().strip(".")
    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        return parsed.hostname or domain
    return domain


def basename(value: str) -> str:
    normalized = text(value).replace("\\", "/")
    return normalized.rsplit("/", 1)[-1]


def looks_like_ip(value: Any) -> bool:
    return bool(value and IP_RE.fullmatch(str(value)))


def int_value(value: Any, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def minutes_between_events(first: dict[str, Any], second: dict[str, Any]) -> float:
    if not first.get("_time") or not second.get("_time"):
        return float("inf")
    return abs((second["_time"] - first["_time"]).total_seconds() / 60)


def update_time_window(item: dict[str, Any], timestamp: Any) -> None:
    if not timestamp:
        return
    timestamp_text = str(timestamp)
    if item["first_seen"] is None or timestamp_text < item["first_seen"]:
        item["first_seen"] = timestamp_text
    if item["last_seen"] is None or timestamp_text > item["last_seen"]:
        item["last_seen"] = timestamp_text


def text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)

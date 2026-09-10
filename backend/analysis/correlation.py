from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any


ATTACK_TECHNIQUES = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1053": "Scheduled Task/Job",
    "T1543.003": "Windows Service",
    "T1548.003": "Sudo and Sudo Caching",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1005": "Data from Local System",
    "T1071": "Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1070.002": "Clear Windows Event Logs",
}

REMOTE_SERVICE_PORTS = {
    22: "SSH",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
}

SUSPICIOUS_PROCESSES = [
    "powershell",
    "cmd.exe",
    "bash",
    "sh",
    "python",
    "perl",
    "nc",
    "netcat",
    "curl",
    "wget",
    "certutil",
]

SUSPICIOUS_COMMAND_KEYWORDS = [
    "-enc",
    "encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "iex",
    "reverse",
    "base64",
    "chmod",
    "whoami",
    "net user",
    "net localgroup",
    "/bin/sh",
    "/bin/bash",
]

WEB_PARENT_PROCESSES = [
    "w3wp.exe",
    "nginx",
    "apache",
    "httpd",
    "tomcat",
    "php-fpm",
]

STARTUP_REGISTRY_KEYS = [
    "currentversion\\run",
    "currentversion\\runonce",
    "windows\\currentversion\\run",
]

SENSITIVE_FILE_KEYWORDS = [
    "password",
    "passwd",
    "shadow",
    "credential",
    "finance",
    "database",
    "backup",
    "dump",
    "id_rsa",
    ".ssh",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".zip",
    ".rar",
    ".7z",
]

STATIC_RESOURCE_SUFFIXES = [
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
]

WEB_CODE_RESOURCE_SUFFIXES = [
    ".asp",
    ".aspx",
    ".cgi",
    ".html",
    ".htm",
    ".jsp",
    ".php",
]

WEB_CONTENT_PATH_HINTS = [
    "/var/www/",
    "/usr/share/nginx/",
    "/usr/share/apache",
    "/srv/www/",
    "/wwwroot/",
    "\\inetpub\\",
    "\\wwwroot\\",
]

SYSTEM_MAINTENANCE_PROCESSES = [
    "apt",
    "apt-get",
    "dpkg",
    "mandb",
    "man-db",
    "updatedb",
    "locate",
]

SYSTEM_MAINTENANCE_PATH_HINTS = [
    "/var/lib/dpkg/info/",
    "/var/cache/",
    "/usr/share/man/",
    "/usr/share/doc/",
    "/usr/share/locale/",
    "/usr/lib/",
    "/usr/lib64/",
    "/lib/",
    "/lib64/",
]

BENIGN_CREDENTIAL_ACCESS_PROCESSES = [
    "accounts-daemon",
    "cron",
    "dpkg",
    "file",
    "gdm-session-worker",
    "gnome-control-center",
    "id",
    "ls",
    "mandb",
    "networkmanager",
    "polkit-agent-helper-1",
    "polkitd",
    "pkexec",
    "setpriv",
    "ssh",
    "stat",
    "sudo",
    "systemd-executor",
]

BENIGN_CREDENTIAL_ACCESS_PATH_HINTS = [
    "/etc/pam.d/",
    "/etc/passwd",
    "/etc/shadow",
    "/credentials",
    "/run/systemd/",
    "/known_hosts",
    "/lib/",
    "/lib64/",
]

BENIGN_DESKTOP_SCAN_PROCESSES = [
    "gnome-shell",
    "gnome-text-editor",
    "nautilus",
    "tracker-extract-3",
    "tracker-miner-fs-3",
]

LOW_SIGNAL_EXECUTION_KEYWORDS = [
    "auditctl ",
    "apt-config shell",
    "dpkg-deb --fsys-tarfile",
    "/usr/bin/lesspipe",
    "/usr/lib/update-notifier/",
    "ding@rastersoft.com",
    "gnome-terminal",
    "packagekit.service",
    "/var/lib/dpkg/info/",
    "/usr/share/man",
]

BENIGN_SERVICE_KEYWORDS = [
    "vmware",
    "vmtools",
    "vgauth",
    "vmci",
    "vmhgfs",
    "vmmouse",
    "vmmemctl",
    "vmrawdsk",
    "vsock",
    "e1i65x64",
    "print",
]

COLLECTION_FLAGS = [
    "collection",
    "collection_candidate",
    "internal_data_access",
    "sensitive_file_access",
    "t1005",
]

ARCHIVE_COMMAND_KEYWORDS = [
    "zip ",
    "rar ",
    "7z ",
    "tar ",
]

SUSPICIOUS_C2_PORTS = {4444, 5555, 6666, 7777, 8080, 9001}

INITIAL_ACCESS_URI_KEYWORDS = [
    "upload",
    "admin",
    "login",
    "shell",
    "cmd",
    "eval",
    "webshell",
    "../",
]

INITIAL_ACCESS_FLAGS = [
    "web_attack",
    "initial_access",
    "exploit",
    "rce",
    "command_injection",
    "webshell_upload",
]

INITIAL_ACCESS_ATTACK_TYPES = [
    "rce",
    "remote_code_execution",
    "command_injection",
    "webshell",
    "file_upload",
    "path_traversal",
    "sql_injection",
]


def correlate_events(
    events: list[dict[str, Any]], host_map: dict[str, str] | None = None,
    internal_networks: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert standardized EventOut records into ATT&CK attack steps.

    The evidence IDs in the returned attack steps always refer to the database
    internal ``id`` field, not the original ``source_event_id``.
    """

    host_map = host_map or {}
    compiled_internal_networks = compile_internal_networks(internal_networks)
    normalized = preprocess_events(events)
    normalized.sort(key=lambda event: event["_time"])
    grouped_events = group_events_by_case(normalized)

    steps: list[dict[str, Any]] = []
    for case_events in grouped_events.values():
        steps.extend(correlate_case_events(case_events, host_map, compiled_internal_networks))

    steps = deduplicate_steps(steps)
    steps.sort(key=lambda step: step["timestamp"])

    for index, step in enumerate(steps, start=1):
        step["step_id"] = f"S{index:03d}"

    return steps


def correlate_case_events(
    events: list[dict[str, Any]],
    host_map: dict[str, str],
    internal_networks,
) -> list[dict[str, Any]]:
    # Explicit CIDRs define the scenario boundary, independently of host names.
    context = build_context(events, host_map)
    context["internal_networks"] = internal_networks

    steps: list[dict[str, Any]] = []
    detectors = [
        detect_initial_access,
        detect_execution,
        detect_persistence,
        detect_privilege_escalation,
        detect_lateral_movement,
        detect_collection,
        detect_c2,
        detect_exfiltration,
        detect_defense_evasion,
    ]

    for detector in detectors:
        steps.extend(detector(events, context, host_map))

    return steps


def preprocess_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []

    for event in events:
        parsed_time = parse_timestamp(get_value(event, "timestamp"))
        if parsed_time is None:
            continue

        copied = dict(event)
        detail = copied.get("detail") or {}
        if not isinstance(detail, dict):
            detail = {}

        copied["_time"] = parsed_time
        copied["_detail"] = detail
        copied["_event_type"] = as_text(get_value(copied, "event_type")).lower()
        copied["_host"] = as_text(get_value(copied, "host"))
        copied["_source"] = as_text(get_value(copied, "source")).lower()
        copied["_user"] = as_text(get_value(copied, "user"))
        copied["_process"] = as_text(get_value(copied, "process")).lower()
        copied["_cmdline"] = as_text(get_value(copied, "cmdline")).lower()
        copied["_parent_process"] = as_text(
            get_detail(copied, "parent_process")
        ).lower()
        copied["_file_path"] = as_text(get_detail(copied, "file_path")).lower()
        copied["_registry_key"] = as_text(get_detail(copied, "registry_key")).lower()
        copied["_registry_value_data"] = as_text(
            get_detail(copied, "registry_value_data")
        ).lower()
        copied["_anomaly_flags"] = normalize_flags(copied.get("anomaly_flags"))
        copied["_case_id"] = get_case_id(copied)

        normalized.append(copied)

    return normalized


def group_events_by_case(
    events: list[dict[str, Any]]
) -> dict[str | None, list[dict[str, Any]]]:
    grouped: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[event.get("_case_id")].append(event)
    return dict(grouped)


def build_context(
    events: list[dict[str, Any]], host_map: dict[str, str]
) -> dict[str, Any]:
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        host = event["_host"]
        event_type = event["_event_type"]
        src_ip = get_value(event, "src_ip")
        dst_ip = get_value(event, "dst_ip")
        session_id = get_value(event, "session_id")

        if host:
            by_host[host].append(event)
        if src_ip:
            by_ip[src_ip].append(event)
        if dst_ip:
            by_ip[dst_ip].append(event)
        if event_type:
            by_type[event_type].append(event)
        if session_id:
            by_session[str(session_id)].append(event)

        mapped_src_host = resolve_host(src_ip, host_map)
        mapped_dst_host = resolve_host(dst_ip, host_map)
        if mapped_src_host:
            by_host[mapped_src_host].append(event)
        if mapped_dst_host:
            by_host[mapped_dst_host].append(event)

    return {
        "by_host": dict(by_host),
        "by_ip": dict(by_ip),
        "by_type": dict(by_type),
        "by_session": dict(by_session),
    }


def detect_initial_access(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    networks = context.get("internal_networks")
    steps = []

    for event in events:
        if event["_event_type"] not in {"http_request", "network_connection"}:
            continue

        src_ip = get_value(event, "src_ip")
        dst_ip = get_value(event, "dst_ip")
        if not is_external_ip(src_ip, networks):
            continue

        if networks is not None and not is_internal_ip(dst_ip, networks):
            continue

        uri = as_text(get_detail(event, "uri")).lower()
        suspicious_uri = any(keyword in uri for keyword in INITIAL_ACCESS_URI_KEYWORDS)
        source = event["_source"]
        attack_type = as_text(get_detail(event, "attack_type")).lower()
        firewall_action = as_text(get_detail(event, "action")).lower()
        web_port = int_value(event.get("dst_port")) in {80, 443, 8080, 8443}
        anomalous = has_any_flag(event, INITIAL_ACCESS_FLAGS)
        waf_alert = source == "waf" and (
            anomalous
            or any(keyword in attack_type for keyword in INITIAL_ACCESS_ATTACK_TYPES)
            or int_value(event.get("severity"), 0) >= 2
        )
        firewall_boundary_hit = (
            source == "firewall"
            and web_port
            and firewall_action in {"", "allow", "allowed", "accept", "accepted"}
        )
        if (
            not suspicious_uri
            and not anomalous
            and not waf_alert
            and not firewall_boundary_hit
            and int_value(event.get("severity"), 0) < 2
        ):
            continue

        if event["_event_type"] == "network_connection" and not firewall_boundary_hit:
            continue

        source_host = resolve_host(src_ip, host_map)
        target_host = resolve_host(dst_ip, host_map) or event["_host"] or None
        evidence = [event]
        if target_host:
            evidence.extend(
                find_events_in_window(
                    context["by_host"].get(target_host, []),
                    event["_time"],
                    before_minutes=0,
                    after_minutes=10,
                    event_types={"process_start"},
                    limit=1,
                )
            )

        source_note = "WAF alert" if source == "waf" else "boundary firewall event" if source == "firewall" else "HTTP request"
        steps.append(
            make_step(
                stage="Initial Access",
                technique_id="T1190",
                timestamp=event["timestamp"],
                source_host=source_host,
                target_host=target_host,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"External {source_note} reached {target_host or dst_ip} as a suspicious boundary access",
                evidence_events=evidence,
            )
        )

    return steps


def detect_execution(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    steps = []

    for event in events:
        if event["_event_type"] != "process_start":
            continue
        if is_low_signal_execution_noise(event):
            continue
        if not is_suspicious_execution(event):
            continue

        evidence = [event]
        host = event["_host"] or None
        if host:
            evidence.extend(
                find_events_in_window(
                    context["by_host"].get(host, []),
                    event["_time"],
                    before_minutes=10,
                    after_minutes=0,
                    event_types={"http_request", "login_success"},
                    limit=2,
                )
            )

        parent = event["_parent_process"]
        parent_note = " by a web service process" if is_web_parent(parent) else ""
        steps.append(
            make_step(
                stage="Execution",
                technique_id="T1059",
                timestamp=event["timestamp"],
                source_host=host,
                target_host=host,
                source_ip=None,
                target_ip=None,
                description=f"Suspicious command execution was detected on {host}{parent_note}",
                evidence_events=evidence,
            )
        )

    return steps


def detect_persistence(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    steps = []

    for event in events:
        event_type = event["_event_type"]
        host = event["_host"] or None

        if event_type in {"registry_set", "registry_create"}:
            registry_key = event["_registry_key"]
            if not any(key in registry_key for key in STARTUP_REGISTRY_KEYS):
                continue
            target = event["_registry_value_data"] or event["_file_path"] or "a startup program"
            steps.append(
                make_step(
                    stage="Persistence",
                    technique_id="T1547.001",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"Startup registry key was modified to execute {target}",
                    evidence_events=[event],
                )
            )
            continue

        if event_type == "scheduled_task_created":
            steps.append(
                make_step(
                    stage="Persistence",
                    technique_id="T1053",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"Scheduled task was created on {host}",
                    evidence_events=[event],
                )
            )
            continue

        if event_type == "service_created":
            if is_benign_service_creation(event):
                continue
            steps.append(
                make_step(
                    stage="Persistence",
                    technique_id="T1543.003",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"System service was created on {host}",
                    evidence_events=[event],
                )
            )

    return steps


def detect_privilege_escalation(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    steps = []

    for event in events:
        event_type = event["_event_type"]
        host = event["_host"] or None

        if event_type == "privilege_change":
            steps.append(
                make_step(
                    stage="Privilege Escalation",
                    technique_id="T1078",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"Privilege change was detected on {host}",
                    evidence_events=[event],
                )
            )
            continue

        if event_type == "group_member_added":
            group_name = as_text(get_detail(event, "group_name")).lower()
            if "admin" not in group_name and "sudo" not in group_name:
                continue
            steps.append(
                make_step(
                    stage="Privilege Escalation",
                    technique_id="T1078",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"User was added to a privileged group on {host}",
                    evidence_events=[event],
                )
            )
            continue

        if event_type == "process_start" and is_sudo_execution(event):
            if is_low_signal_execution_noise(event):
                continue
            steps.append(
                make_step(
                    stage="Privilege Escalation",
                    technique_id="T1548.003",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"Sudo or privileged command execution was detected on {host}",
                    evidence_events=[event],
                )
            )

    return steps


def detect_lateral_movement(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    networks = context.get("internal_networks")
    steps = []

    for event in events:
        if event["_event_type"] != "network_connection":
            continue

        dst_port = int_value(get_value(event, "dst_port"))
        if dst_port not in REMOTE_SERVICE_PORTS:
            continue

        src_ip = get_value(event, "src_ip")
        dst_ip = get_value(event, "dst_ip")
        if not is_internal_ip(src_ip, networks) or not is_internal_ip(dst_ip, networks):
            continue

        source_host = resolve_host(src_ip, host_map)
        target_host = resolve_host(dst_ip, host_map)
        if source_host and target_host and source_host == target_host:
            continue

        evidence = [event]
        source_host_events = context["by_host"].get(source_host, []) if source_host else []
        target_host_events = context["by_host"].get(target_host, []) if target_host else []

        evidence.extend(
            [
                prior
                for prior in find_events_in_window(
                    source_host_events,
                    event["_time"],
                    before_minutes=10,
                    after_minutes=0,
                    event_types={"process_start"},
                    limit=3,
                )
                if is_suspicious_execution(prior)
            ][:1]
        )
        evidence.extend(
            find_events_in_window(
                target_host_events,
                event["_time"],
                before_minutes=0,
                after_minutes=10,
                event_types={"login_success", "process_start", "service_created"},
                limit=1,
            )
        )

        steps.append(
            make_step(
                stage="Lateral Movement",
                technique_id="T1021",
                timestamp=event["timestamp"],
                source_host=source_host,
                target_host=target_host,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"{source_host or src_ip} connected to {target_host or dst_ip} through {REMOTE_SERVICE_PORTS[dst_port]} remote service",
                evidence_events=evidence,
            )
        )

    return steps


def detect_collection(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    networks = context.get("internal_networks")
    steps = []
    file_groups: dict[tuple[str | None, str], list[dict[str, Any]]] = defaultdict(list)
    file_events_used_by_http: set[int] = set()

    for event in events:
        event_type = event["_event_type"]
        host = event["_host"] or None

        if event_type in {"file_read", "file_write", "file_create"}:
            if not is_sensitive_file_event(event):
                continue
            file_groups[(host, collection_file_key(event))].append(event)
            continue

        if event_type == "process_start":
            command_text = f"{event['_process']} {event['_cmdline']}"
            if not any(keyword in command_text for keyword in ARCHIVE_COMMAND_KEYWORDS):
                continue
            steps.append(
                make_step(
                    stage="Collection",
                    technique_id="T1005",
                    timestamp=event["timestamp"],
                    source_host=host,
                    target_host=host,
                    source_ip=None,
                    target_ip=None,
                    description=f"Archive command may indicate data collection on {host}",
                    evidence_events=[event],
                )
            )
            continue

        if event_type == "http_request" and is_internal_http_resource_request(event, networks):
            src_ip = get_value(event, "src_ip")
            dst_ip = get_value(event, "dst_ip")
            source_host = resolve_host(src_ip, host_map)
            target_host = resolve_host(dst_ip, host_map) or host
            if source_host and target_host and source_host == target_host:
                continue

            target_events = context["by_host"].get(target_host, []) if target_host else []
            target_evidence = [
                candidate
                for candidate in find_events_in_window(
                    target_events,
                    event["_time"],
                    before_minutes=1,
                    after_minutes=5,
                    event_types={"file_read", "file_write", "file_create", "process_start"},
                    limit=10,
                )
                if is_collection_context_event(candidate)
            ][:3]
            sensitive_resource = is_sensitive_http_resource(event)
            if not target_evidence and not sensitive_resource:
                continue

            uri = http_uri(event) or "an internal resource"
            evidence = [event] + target_evidence
            file_events_used_by_http.update(
                int_value(get_value(candidate, "id"))
                for candidate in target_evidence
                if candidate["_event_type"] in {"file_read", "file_write", "file_create"}
            )
            steps.append(
                make_step(
                    stage="Collection",
                    technique_id="T1005",
                    timestamp=event["timestamp"],
                    source_host=source_host,
                    target_host=target_host,
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    description=f"{source_host or src_ip} retrieved sensitive internal resource {uri} from {target_host or dst_ip}",
                    evidence_events=evidence,
                )
            )

    for (host, _file_key), group in file_groups.items():
        group = [
            event
            for event in group
            if int_value(get_value(event, "id")) not in file_events_used_by_http
        ]
        if not group:
            continue
        group.sort(key=lambda event: event["_time"])
        first = group[0]
        steps.append(
            make_step(
                stage="Collection",
                technique_id="T1005",
                timestamp=first["timestamp"],
                source_host=host,
                target_host=host,
                source_ip=None,
                target_ip=None,
                description=f"Sensitive file access was detected on {host}",
                evidence_events=group[:5],
            )
        )

    return steps


def detect_c2(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    networks = context.get("internal_networks")
    steps = []
    grouped_connections: dict[tuple[str | None, str | None, int | None], list[dict[str, Any]]] = defaultdict(list)
    entry_source_ips = collect_initial_access_source_ips(events, networks)
    entry_time = earliest_initial_access_time(events, networks)

    for event in events:
        if event["_event_type"] not in {"network_connection", "http_request"}:
            continue

        src_ip = get_value(event, "src_ip")
        dst_ip = get_value(event, "dst_ip")
        dst_port = int_value(get_value(event, "dst_port"))
        if not is_internal_ip(src_ip, networks) or not is_external_ip(dst_ip, networks):
            continue

        source_host = resolve_host(src_ip, host_map) or event["_host"] or None
        grouped_connections[(source_host, dst_ip, dst_port)].append(event)

    for (source_host, dst_ip, dst_port), group in grouped_connections.items():
        group.sort(key=lambda event: event["_time"])
        flagged = any(has_any_flag(event, ["c2", "beacon", "external_connection"]) for event in group)
        if entry_time is not None and not flagged:
            post_entry = [event for event in group if event["_time"] >= entry_time]
            if post_entry:
                group = post_entry
            else:
                continue
        repeated = len(group) >= 3 and minutes_between(group[0], group[-1]) <= 30
        suspicious_port = dst_port in SUSPICIOUS_C2_PORTS
        if dst_ip in entry_source_ips and not suspicious_port and not flagged:
            continue
        if not repeated and not suspicious_port and not flagged:
            continue

        first = group[0]
        evidence = group[:5]
        reason = "repeated outbound connection" if repeated else "suspicious outbound port"
        steps.append(
            make_step(
                stage="Command and Control",
                technique_id="T1071",
                timestamp=first["timestamp"],
                source_host=source_host,
                target_host=resolve_host(dst_ip, host_map),
                source_ip=get_value(first, "src_ip"),
                target_ip=dst_ip,
                description=f"{source_host or get_value(first, 'src_ip')} made {reason} to external infrastructure",
                evidence_events=evidence,
            )
        )

    for event in events:
        if event["_event_type"] != "dns_query":
            continue
        domain = as_text(get_detail(event, "domain")).lower()
        if not domain or not (len(domain) >= 50 or has_any_flag(event, ["dns_tunnel", "c2"])):
            continue

        src_ip = get_value(event, "src_ip")
        if networks is not None and (
            not is_internal_ip(src_ip, networks)
            or not is_external_ip(get_value(event, "dst_ip"), networks)
        ):
            continue
        source_host = resolve_host(src_ip, host_map) or event["_host"] or None
        steps.append(
            make_step(
                stage="Command and Control",
                technique_id="T1071",
                timestamp=event["timestamp"],
                source_host=source_host,
                target_host=None,
                source_ip=src_ip,
                target_ip=get_value(event, "dst_ip"),
                description=f"Suspicious DNS query may indicate C2 communication from {source_host or src_ip}",
                evidence_events=[event],
            )
        )

    return steps


def collect_initial_access_source_ips(events: list[dict[str, Any]], networks) -> set[str]:
    sources: set[str] = set()
    for event in events:
        if is_initial_access_source_event(event, networks):
            sources.add(str(get_value(event, "src_ip")))
    return sources


def earliest_initial_access_time(events: list[dict[str, Any]], networks):
    times = [event["_time"] for event in events if is_initial_access_source_event(event, networks)]
    return min(times) if times else None


def is_initial_access_source_event(event: dict[str, Any], networks) -> bool:
    if event["_event_type"] not in {"http_request", "network_connection"}:
        return False

    src_ip = get_value(event, "src_ip")
    dst_ip = get_value(event, "dst_ip")
    if not is_external_ip(src_ip, networks):
        return False
    if networks is not None and not is_internal_ip(dst_ip, networks):
        return False

    uri = as_text(get_detail(event, "uri")).lower()
    attack_type = as_text(get_detail(event, "attack_type")).lower()
    suspicious_uri = any(keyword in uri for keyword in INITIAL_ACCESS_URI_KEYWORDS)
    anomalous = has_any_flag(event, INITIAL_ACCESS_FLAGS)
    waf_alert = event["_source"] == "waf" and (
        anomalous
        or any(keyword in attack_type for keyword in INITIAL_ACCESS_ATTACK_TYPES)
        or int_value(event.get("severity"), 0) >= 2
    )
    return suspicious_uri or anomalous or waf_alert or int_value(event.get("severity"), 0) >= 2


def detect_exfiltration(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    networks = context.get("internal_networks")
    steps = []

    for event in events:
        if event["_event_type"] not in {"network_connection", "http_request"}:
            continue

        src_ip = get_value(event, "src_ip")
        dst_ip = get_value(event, "dst_ip")
        if not is_internal_ip(src_ip, networks) or not is_external_ip(dst_ip, networks):
            continue

        bytes_out = int_value(get_detail(event, "bytes_out"))
        large_transfer = bytes_out is not None and bytes_out >= 5 * 1024 * 1024
        if not large_transfer and not has_any_flag(event, ["exfiltration", "large_upload"]):
            continue

        source_host = resolve_host(src_ip, host_map) or event["_host"] or None
        source_events = context["by_host"].get(source_host, []) if source_host else []
        collection_evidence = [
            candidate
            for candidate in find_events_in_window(
                source_events,
                event["_time"],
                before_minutes=30,
                after_minutes=0,
                event_types={"file_read", "file_write", "file_create", "process_start"},
                limit=10,
            )
            if is_sensitive_file_event(candidate) or is_archive_command(candidate)
        ][:3]

        if not collection_evidence and not has_any_flag(event, ["exfiltration"]):
            continue

        steps.append(
            make_step(
                stage="Exfiltration",
                technique_id="T1041",
                timestamp=event["timestamp"],
                source_host=source_host,
                target_host=resolve_host(dst_ip, host_map),
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"Large outbound transfer after data collection was detected from {source_host or src_ip}",
                evidence_events=collection_evidence + [event],
            )
        )

    return steps


def detect_defense_evasion(
    events: list[dict[str, Any]], context: dict[str, Any], host_map: dict[str, str]
) -> list[dict[str, Any]]:
    steps = []

    for event in events:
        if event["_event_type"] != "log_cleared":
            continue

        host = event["_host"] or None
        log_name = as_text(get_detail(event, "log_name")) or "event log"
        steps.append(
            make_step(
                stage="Defense Evasion",
                technique_id="T1070.002",
                timestamp=event["timestamp"],
                source_host=host,
                target_host=host,
                source_ip=None,
                target_ip=None,
                description=f"{log_name} was cleared on {host}",
                evidence_events=[event],
            )
        )

    return steps


def make_step(
    *,
    stage: str,
    technique_id: str,
    timestamp: str,
    source_host: str | None,
    target_host: str | None,
    source_ip: str | None,
    target_ip: str | None,
    description: str,
    evidence_events: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "step_id": None,
        "case_id": infer_case_id(evidence_events),
        "stage": stage,
        "technique_id": technique_id,
        "technique_name": ATTACK_TECHNIQUES[technique_id],
        "timestamp": timestamp,
        "source_host": source_host,
        "target_host": target_host,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "description": description,
        "evidence_event_ids": event_ids(evidence_events),
    }


def build_attack_graph(attack_steps: list[dict[str, Any]], internal_networks=None) -> dict[str, Any]:
    networks = compile_internal_networks(internal_networks)
    nodes: dict[str, dict[str, Any]] = {}
    edges = []

    for step in attack_steps:
        source_id = step.get("source_host") or step.get("source_ip")
        target_id = step.get("target_host") or step.get("target_ip")

        if source_id:
            nodes.setdefault(
                source_id,
                {
                    "id": source_id,
                    "label": source_id,
                    "type": "host" if (step.get("source_host") or is_internal_ip(step.get("source_ip"), networks)) else "external_ip",
                },
            )
        if target_id:
            nodes.setdefault(
                target_id,
                {
                    "id": target_id,
                    "label": target_id,
                    "type": "host" if (step.get("target_host") or is_internal_ip(step.get("target_ip"), networks)) else "external_ip",
                },
            )
        if source_id and target_id:
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "step_id": step.get("step_id"),
                    "case_id": step.get("case_id"),
                    "stage": step.get("stage"),
                    "technique_id": step.get("technique_id"),
                    "timestamp": step.get("timestamp"),
                    "evidence_event_ids": step.get("evidence_event_ids", []),
                }
            )

    return {"nodes": list(nodes.values()), "edges": edges}


def find_attack_paths(attack_steps: list[dict[str, Any]], max_depth: int = 8, internal_networks=None) -> list[list[str]]:
    graph = build_attack_graph(attack_steps, internal_networks)
    adjacency: dict[str, list[str]] = defaultdict(list)
    incoming: set[str] = set()
    nodes = {node["id"] for node in graph["nodes"]}

    for edge in graph["edges"]:
        adjacency[edge["source"]].append(edge["target"])
        incoming.add(edge["target"])

    entries = sorted(nodes - incoming)
    if not entries:
        entries = sorted(nodes)

    paths: list[list[str]] = []
    seen_paths: set[tuple[str, ...]] = set()
    for entry in entries:
        queue = deque([(entry, [entry])])
        while queue:
            current, path = queue.popleft()
            next_nodes = [node for node in adjacency.get(current, []) if node not in path]
            if not next_nodes or len(path) >= max_depth:
                path_key = tuple(path)
                if len(path) > 1 and path_key not in seen_paths:
                    seen_paths.add(path_key)
                    paths.append(path)
                continue
            for next_node in next_nodes:
                queue.append((next_node, path + [next_node]))

    paths.sort(key=len, reverse=True)
    return paths


def deduplicate_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []

    for step in steps:
        key = (
            step["stage"],
            step.get("case_id"),
            step["technique_id"],
            step.get("source_host"),
            step.get("target_host"),
            step.get("source_ip"),
            step.get("target_ip"),
            tuple(step.get("evidence_event_ids", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(step)

    return unique


def find_events_in_window(
    events: list[dict[str, Any]],
    center_time: datetime,
    *,
    before_minutes: int,
    after_minutes: int,
    event_types: set[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    matches = []

    for event in events:
        delta_minutes = (event["_time"] - center_time).total_seconds() / 60
        if delta_minutes < -before_minutes or delta_minutes > after_minutes:
            continue
        if event_types is not None and event["_event_type"] not in event_types:
            continue
        matches.append(event)
        if limit is not None and len(matches) >= limit:
            break

    return matches


def is_suspicious_execution(event: dict[str, Any]) -> bool:
    command_text = f"{event['_process']} {event['_cmdline']}"
    if any(keyword in command_text for keyword in SUSPICIOUS_PROCESSES):
        return True
    if any(keyword in command_text for keyword in SUSPICIOUS_COMMAND_KEYWORDS):
        return True
    if is_web_parent(event["_parent_process"]):
        return True
    return has_any_flag(event, ["suspicious_process", "webshell_execution", "command_execution"])


def is_low_signal_execution_noise(event: dict[str, Any]) -> bool:
    if int_value(get_value(event, "severity")) not in (None, 0):
        return False
    if event.get("anomaly_flags"):
        return False

    command_text = f"{event['_process']} {event['_cmdline']}".lower()
    return any(keyword in command_text for keyword in LOW_SIGNAL_EXECUTION_KEYWORDS)


def is_benign_service_creation(event: dict[str, Any]) -> bool:
    if int_value(get_value(event, "severity")) not in (None, 0):
        return False
    if event.get("anomaly_flags"):
        return False

    detail_text = " ".join(as_text(value) for value in (event.get("_detail") or {}).values())
    service_text = " ".join(
        [
            event["_process"],
            event["_cmdline"],
            as_text(get_value(event, "description")),
            detail_text,
        ]
    ).lower()
    return any(keyword in service_text for keyword in BENIGN_SERVICE_KEYWORDS)


def is_sudo_execution(event: dict[str, Any]) -> bool:
    command_text = f"{event['_process']} {event['_cmdline']}"
    detail = event.get("_detail") or {}
    if detail.get("sudo_command") or detail.get("sudo_user"):
        return True
    return "sudo " in command_text or "runas" in command_text or "net localgroup administrators" in command_text


def is_sensitive_file_event(event: dict[str, Any]) -> bool:
    if event["_event_type"] not in {"file_read", "file_write", "file_create"}:
        return False
    if has_explicit_collection_marker(event):
        return True
    if is_low_signal_local_file_noise(event):
        return False
    if is_system_maintenance_noise_file(event):
        return False
    if is_web_application_noise_file(event):
        return False
    return is_sensitive_path(event["_file_path"])


def is_sensitive_path(path: str) -> bool:
    return any(keyword in path for keyword in SENSITIVE_FILE_KEYWORDS)


def has_explicit_collection_marker(event: dict[str, Any]) -> bool:
    attack_stage = as_text(get_detail(event, "attack_stage")).lower()
    technique = as_text(get_detail(event, "mitre_technique")).lower()
    if "collection" in attack_stage or technique == "t1005":
        return True
    return has_any_flag(event, COLLECTION_FLAGS)


def is_web_application_noise_file(event: dict[str, Any]) -> bool:
    path = event["_file_path"].replace("\\", "/")
    if not path:
        return False

    suffix = path_suffix(path)
    if suffix not in set(STATIC_RESOURCE_SUFFIXES + WEB_CODE_RESOURCE_SUFFIXES):
        return False

    process_text = f"{event['_process']} {event['_parent_process']}"
    web_process = is_web_parent(process_text)
    web_path = any(hint.replace("\\", "/") in path for hint in WEB_CONTENT_PATH_HINTS)
    return web_process or web_path


def is_system_maintenance_noise_file(event: dict[str, Any]) -> bool:
    path = event["_file_path"].replace("\\", "/")
    if not path:
        return False

    process_text = f"{event['_process']} {event['_parent_process']}"
    maintenance_process = any(
        process in process_text.split() or process_text.endswith("/" + process)
        for process in SYSTEM_MAINTENANCE_PROCESSES
    )
    maintenance_path = any(hint in path for hint in SYSTEM_MAINTENANCE_PATH_HINTS)

    # Package/index maintenance can read files whose names contain words like
    # passwd, credential, backup or dump without representing attacker collection.
    return maintenance_process and maintenance_path


def is_low_signal_local_file_noise(event: dict[str, Any]) -> bool:
    if int_value(get_value(event, "severity")) not in (None, 0):
        return False
    if event.get("anomaly_flags"):
        return False

    path = event["_file_path"].replace("\\", "/")
    process = event["_process"].rsplit("/", 1)[-1]
    parent = event["_parent_process"].rsplit("/", 1)[-1]
    process_names = {process, parent}

    if process_names & set(BENIGN_CREDENTIAL_ACCESS_PROCESSES):
        return any(hint in path for hint in BENIGN_CREDENTIAL_ACCESS_PATH_HINTS)
    if process_names & set(BENIGN_DESKTOP_SCAN_PROCESSES):
        return any(hint in path for hint in ["/.ssh", "/etc/passwd", "/var/backups"])
    return False


def is_archive_command(event: dict[str, Any]) -> bool:
    if event["_event_type"] != "process_start":
        return False
    command_text = f"{event['_process']} {event['_cmdline']}"
    return any(keyword in command_text for keyword in ARCHIVE_COMMAND_KEYWORDS)


def is_internal_http_resource_request(event: dict[str, Any], internal_networks=None) -> bool:
    if event["_event_type"] != "http_request":
        return False
    if http_method(event) != "get":
        return False
    uri = http_uri(event)
    if not uri or uri == "/" or uri.startswith("/?"):
        return False
    if any(uri.lower().split("?", 1)[0].endswith(suffix) for suffix in STATIC_RESOURCE_SUFFIXES):
        return False
    status = int_value(get_detail(event, "status_code"))
    if status is not None and not 200 <= status < 300:
        return False
    src_ip = get_value(event, "src_ip")
    dst_ip = get_value(event, "dst_ip")
    return is_internal_ip(src_ip, internal_networks) and is_internal_ip(dst_ip, internal_networks)


def is_sensitive_http_resource(event: dict[str, Any]) -> bool:
    resource_text = " ".join(
        [
            http_uri(event),
            as_text(get_detail(event, "file_path")),
            as_text(get_detail(event, "resource")),
            as_text(get_detail(event, "path")),
        ]
    ).lower()
    return any(keyword in resource_text for keyword in SENSITIVE_FILE_KEYWORDS)


def is_collection_context_event(event: dict[str, Any]) -> bool:
    if has_explicit_collection_marker(event):
        return True
    return is_sensitive_file_event(event) or is_archive_command(event)


def collection_file_key(event: dict[str, Any]) -> str:
    return event["_file_path"].replace("\\", "/").lower()


def path_suffix(path: str) -> str:
    cleaned = path.split("?", 1)[0].split("#", 1)[0]
    if "." not in cleaned.rsplit("/", 1)[-1]:
        return ""
    return "." + cleaned.rsplit(".", 1)[-1].lower()


def http_method(event: dict[str, Any]) -> str:
    method = as_text(get_detail(event, "method")).lower()
    if method:
        return method
    first_request = first_http_request(event)
    if first_request:
        return as_text(first_request.get("method")).lower()
    return ""


def http_uri(event: dict[str, Any]) -> str:
    uri = as_text(get_detail(event, "uri"))
    if uri:
        return uri
    first_request = first_http_request(event)
    if first_request:
        return as_text(first_request.get("uri"))
    return ""


def first_http_request(event: dict[str, Any]) -> dict[str, Any] | None:
    requests = get_detail(event, "http_requests")
    if isinstance(requests, list) and requests and isinstance(requests[0], dict):
        return requests[0]
    return None


def is_web_parent(parent_process: str) -> bool:
    return any(parent in parent_process for parent in WEB_PARENT_PROCESSES)


def has_any_flag(event: dict[str, Any], expected_flags: list[str]) -> bool:
    flags = event.get("_anomaly_flags") or normalize_flags(event.get("anomaly_flags"))
    return any(flag in flags for flag in expected_flags)


def normalize_flags(flags: Any) -> set[str]:
    if not flags:
        return set()
    if isinstance(flags, str):
        return {flags.lower()}
    if isinstance(flags, list):
        return {as_text(flag).lower() for flag in flags if flag is not None}
    return set()


def event_ids(events: list[dict[str, Any]]) -> list[int]:
    ids = []
    seen = set()
    for event in events:
        event_id = event.get("id")
        if event_id is None or event_id in seen:
            continue
        seen.add(event_id)
        ids.append(event_id)
    return ids


def infer_case_id(events: list[dict[str, Any]]) -> str | None:
    case_ids = [event.get("_case_id") for event in events if event.get("_case_id")]
    if not case_ids:
        return None
    return case_ids[0]


def get_case_id(event: dict[str, Any]) -> str | None:
    # Preferred Event field. detail.case_id and detail.batch_id are accepted only
    # for compatibility with earlier sample data and parser drafts.
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


def resolve_host(ip: Any, host_map: dict[str, str]) -> str | None:
    if ip is None:
        return None
    return host_map.get(str(ip))


def get_value(event: dict[str, Any], key: str, default: Any = None) -> Any:
    value = event.get(key, default)
    return default if value is None else value


def get_detail(event: dict[str, Any], key: str, default: Any = None) -> Any:
    detail = event.get("_detail")
    if detail is None:
        detail = event.get("detail") or {}
    if not isinstance(detail, dict):
        return default
    value = detail.get(key, default)
    return default if value is None else value


def as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def int_value(value: Any, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def compile_internal_networks(networks):
    """Parse CIDRs once per analysis; None preserves legacy classification."""
    if networks is None:
        return None
    return tuple(n if isinstance(n, (IPv4Network, IPv6Network)) else ip_network(n)
                 for n in networks)


def is_internal_ip(value: Any, internal_networks=None) -> bool:
    if not value:
        return False
    try:
        parsed = ip_address(str(value))
    except ValueError:
        return False
    if internal_networks is not None:
        return any(parsed in (n if isinstance(n, (IPv4Network, IPv6Network)) else ip_network(n))
                   for n in internal_networks)
    return parsed.is_private


def is_external_ip(value: Any, internal_networks=None) -> bool:
    if not value:
        return False
    try:
        parsed = ip_address(str(value))
    except ValueError:
        return False
    if internal_networks is not None:
        return not is_internal_ip(value, internal_networks)
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
    )


def minutes_between(first: dict[str, Any], second: dict[str, Any]) -> float:
    return abs((second["_time"] - first["_time"]).total_seconds() / 60)

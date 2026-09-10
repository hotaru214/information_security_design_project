"""命令行入口。

用法（在仓库根目录）：
    python -m backend.parsers.network <pcap|pcapng|zeek目录|csv> [更多输入...]
        [--hosts data/hosts.csv] [--out out/network_events.json]
        [--anomalies-only] [--internal 10.0.0.0/8,192.168.0.0/16]
        [--config detection.json]

输出：
  - 终端打印解析摘要 + 攻击阶段时间线
  - --out 指定路径时写统一事件 JSON（数组，可直接 POST /api/events/import）
"""
import argparse
import os
import sys
from collections import Counter
from datetime import datetime

from .config import PROFILES, DetectionConfig
from .firewall_parser import _is_filterlog, parse_firewall_log
from .detectors import STAGE_ZH, run_all
from .normalize import build_events, build_summary, load_host_map, save_events, validate_events
from .pcap_parser import parse_pcap
from .zeek_parser import parse_connection_csv, parse_zeek_logs

SEVERITY_ZH = {"info": "信息", "low": "低危", "medium": "中危", "high": "高危", "critical": "严重"}
KIND_ZH = {
    "port_scan": "端口扫描", "c2_beacon": "C2心跳", "suspicious_port": "可疑端口",
    "dns_tunnel": "DNS隧道", "exfiltration": "数据外传", "icmp_tunnel": "ICMP隧道",
    "lateral_movement": "横向连接", "http_attack": "Web攻击",
    "brute_force_evidence": "登录爆破", "cc_rotation": "CC列表轮询",
}


def analyze_paths(paths: list, host_map: dict = None, cfg: DetectionConfig = None,
                  include_flows: bool = True):
    """解析一个或多个输入（pcap/zeek目录/csv），跑检测，返回 (events, flows, anomalies, stats)。"""
    if cfg is None:
        cfg = DetectionConfig()
    if host_map is None:
        host_map = {}

    flows, stats = [], []
    for path in paths:
        path = str(path)
        if _is_dir_zeek(path):
            f, s = parse_zeek_logs(path)
        elif path.lower().endswith(".log") and _is_filterlog(path):
            f, s = parse_firewall_log(path, cfg)   # OPNsense/pfSense filterlog（source=firewall）
        elif path.lower().endswith(".log"):
            f, s = parse_zeek_logs(path)   # 单个 .log（含 APT29 combined_zeek.log 合并流）
        elif path.lower().endswith(".json"):
            f, s = parse_zeek_logs(path)   # Zeek JSON / 合并流（按内容嗅探，非 Zeek 则 0 会话）
        elif path.lower().endswith((".pcap", ".pcapng", ".cap")):
            f, s = parse_pcap(path, cfg)
        elif path.lower().endswith(".csv"):
            f, s = parse_connection_csv(path)
        else:
            raise ValueError(f"不支持的输入类型: {path}（支持 .pcap/.pcapng/.cap/.csv 或 Zeek 日志目录）")
        flows.extend(f)
        stats.append(s)

    anomalies = run_detectors(flows, cfg)
    events = build_events(flows, anomalies, host_map, cfg, include_flows=include_flows)
    return events, flows, anomalies, stats


def run_detectors(flows, cfg):
    return run_all(flows, cfg)


def _is_dir_zeek(path: str) -> bool:
    import os
    return os.path.isdir(path)


def _print_summary(events, flows, anomalies, stats):
    total_packets = sum(s.get("packets", 0) for s in stats)
    print("=" * 62)
    print("网络流量解析与异常检测摘要（成员C模块）")
    print("=" * 62)
    for s in stats:
        print(f"  输入: {s.get('file')} -> {s.get('flows', 0)} 会话"
              + (f" / {s.get('packets', 0)} 包" if s.get("packets") else ""))
    kinds = Counter(a.kind for a in anomalies)
    type_counter = Counter(e["event_type"] for e in events)
    print(f"  会话总数: {len(flows)} | 事件总数: {len(events)}")
    detail = ", ".join(f"{k} {v}" for k, v in sorted(type_counter.items()))
    print(f"  事件构成: {detail}")
    print(f"  异常告警: {len(anomalies)} 条"
          + ("（" + "、".join(f"{KIND_ZH.get(k, k)}×{v}" for k, v in kinds.items() if v) + "）"
             if kinds else "（未检出）"))
    problems = validate_events(events)
    print(f"  Event V2 契约自检: {'通过' if not problems else '不合规 x' + str(len(problems))}")
    for p in problems[:5]:
        print(f"    ! {p}")

    if anomalies:
        print("-" * 62)
        print("攻击阶段时间线（网络侧证据）:")
        for a in anomalies:
            ts = datetime.fromtimestamp(a.start_ts).strftime("%H:%M:%S")
            print(f"  {ts}  [{SEVERITY_ZH[a.severity]}] {STAGE_ZH.get(a.attack_stage, a.attack_stage):<6}"
                  f" {KIND_ZH.get(a.kind, a.kind):<5} {a.description}")
    print("=" * 62)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m backend.parsers.network",
        description="网络流量解析与异常检测（恶意攻击行为溯源分析系统 - 网络流量模块）")
    parser.add_argument("inputs", nargs="+", help="pcap/pcapng/cap 文件、Zeek 日志目录或 CSV 连接日志")
    parser.add_argument("--hosts", default="", help="IP->主机名映射 CSV（列: ip,hostname,role）")
    parser.add_argument("--out", default="", help="统一事件 JSON 输出路径")
    parser.add_argument("--summary-json", default="", metavar="PATH",
                        help="Dashboard 汇总 JSON 输出路径（阶段时间线/severity分布/外传top，给F直接消费）")
    parser.add_argument("--anomalies-only", action="store_true", help="只输出告警事件，不含普通会话")
    parser.add_argument("--internal", default="", help="内网网段，逗号分隔（默认 RFC1918）")
    parser.add_argument("--config", default="", help="检测阈值 JSON 配置文件")
    parser.add_argument("--profile", default="", choices=[""] + sorted(PROFILES),
                        help="批次网络配置预设：固定 internal 网段与默认 hosts 映射（E case01 用 e_case01）")
    args = parser.parse_args(argv)

    profile = PROFILES.get(args.profile, {})
    if args.config:
        cfg = DetectionConfig.from_json(args.config)
    else:
        cfg = DetectionConfig()
    # profile 提供 internal 默认值；显式 --internal 仍可覆盖
    if args.internal:
        cfg.internal_networks = [n.strip() for n in args.internal.split(",") if n.strip()]
    elif profile.get("internal_networks"):
        cfg.internal_networks = list(profile["internal_networks"])
    cfg.__post_init__()

    # profile 提供默认 hosts；显式 --hosts 覆盖
    if not args.hosts and profile.get("hosts"):
        args.hosts = profile["hosts"]

    host_map = load_host_map(args.hosts)
    events, flows, anomalies, stats = analyze_paths(
        args.inputs, host_map=host_map, cfg=cfg, include_flows=not args.anomalies_only)

    _print_summary(events, flows, anomalies, stats)

    if args.out:
        save_events(events, args.out)
        print(f"事件已写入: {args.out}（可直接 POST /api/events/import）")
    if args.summary_json:
        summary = build_summary(events)
        out_path = args.summary_json
        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, ensure_ascii=False, indent=2)
        print(f"汇总已写入: {out_path}（告警 {summary['anomaly_events']} 条 / "
              f"阶段 {len(summary['attack_timeline'])} 步 / 主机 {len(summary['hosts_involved'])} 台）")
    return 0

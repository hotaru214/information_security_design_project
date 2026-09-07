"""网络流量解析模块（成员C）。

输入 PCAP / Zeek 日志 / 通用 CSV 连接日志，
输出统一格式安全事件，供后端（A）导入与关联分析引擎（D）使用。

用法：
    python -m backend.parsers.network data/network_logs/case01_enterprise_attack.pcap --hosts data/hosts.csv
"""
from .config import DetectionConfig
from .models import Anomaly, FlowRecord
from .normalize import build_events, load_host_map, save_events
from .pcap_parser import parse_pcap
from .zeek_parser import parse_connection_csv, parse_zeek_logs
from .cli import analyze_paths, main

__all__ = [
    "Anomaly",
    "DetectionConfig",
    "FlowRecord",
    "analyze_paths",
    "build_events",
    "load_host_map",
    "main",
    "parse_connection_csv",
    "parse_pcap",
    "parse_zeek_logs",
    "save_events",
]

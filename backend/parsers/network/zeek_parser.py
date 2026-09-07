"""Zeek 日志与通用 CSV 连接日志解析 → FlowRecord。

支持两种 Zeek 输出格式：
  - TSV 格式（zeek 默认，带 #separator/#fields 头部），支持 .log.gz
  - JSON 格式（json-streaming-logs 插件），键为 id.orig_h 或嵌套 id.orig_h

如果队友（E）在 Linux 靶场上用 Zeek 产出了 conn.log / dns.log / http.log，
把整个日志目录传给本模块即可；没有 Zeek 时也可以用通用 CSV 格式（见 parse_connection_csv）。
"""
import csv
import gzip
import json
import logging
import os

from .models import DnsQuery, FlowRecord, HttpRequest

logger = logging.getLogger(__name__)

PROTO_MAP = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "ip": "TCP"}


def _open_text(path: str):
    """打开文本文件，自动处理 .gz。"""
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _nested_get(record: dict, key: str):
    """Zeek JSON 日志的键可能是 id.orig_h（扁平）或嵌套 {"id": {"orig_h": ...}}。"""
    if key in record:
        return record[key]
    if "." in key:
        cur = record
        for part in key.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    return None


def _parse_conn_line_fields(fields: list, values: list) -> dict:
    return dict(zip(fields, values))


class _ConnBuilder:
    """从 conn.log 建 FlowRecord，并允许 dns.log/http.log 按 (src,dst,dport) 富化。"""

    def __init__(self):
        self.flows: list[FlowRecord] = []
        self._idx: dict[tuple, list[FlowRecord]] = {}

    def add(self, rec: FlowRecord):
        self.flows.append(rec)
        key = (rec.src_ip, rec.dst_ip, rec.dst_port)
        self._idx.setdefault(key, []).append(rec)

    def match(self, src: str, dst: str, dport: int, ts: float, window: float = 1.0):
        for rec in self._idx.get((src, dst, dport), []):
            if rec.start_ts - window <= ts <= rec.end_ts + window:
                return rec
        return None

    def synth(self, src, sport, dst, dport, proto, ts, source_file):
        rec = FlowRecord(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                         protocol=proto, start_ts=ts, end_ts=ts, source_file=source_file)
        self.add(rec)
        return rec


def parse_zeek_logs(path: str):
    """解析 Zeek 日志目录或单个 conn.log 文件。

    返回 (flows, stats)。
    """
    files = _collect_zeek_files(path)
    if not files:
        raise FileNotFoundError(f"目录/路径中未找到 Zeek 日志(conn.log 等): {path}")

    builder = _ConnBuilder()
    stats = {"file": path, "conn": 0, "dns": 0, "http": 0}

    conn_file = next((f for f in files if os.path.basename(f).replace(".gz", "") == "conn.log"), None)
    if conn_file:
        for row in _iter_zeek_rows(conn_file):
            rec = _conn_row_to_flow(row, conn_file)
            if rec:
                builder.add(rec)
                stats["conn"] += 1

    dns_file = next((f for f in files if os.path.basename(f).replace(".gz", "") == "dns.log"), None)
    if dns_file:
        for row in _iter_zeek_rows(dns_file):
            src = str(_nested_get(row, "id.orig_h") or "")
            dst = str(_nested_get(row, "id.resp_h") or "")
            dport = int(_nested_get(row, "id.resp_p") or 53)
            try:
                ts = float(row.get("ts", 0))
            except (TypeError, ValueError):
                continue
            qname = str(row.get("query") or "").rstrip(".")
            if not qname:
                continue
            rec = builder.match(src, dst, dport, ts) or builder.synth(src, 0, dst, dport, "UDP", ts, dns_file)
            rec.dns_queries.append(DnsQuery(qname=qname, qtype=str(row.get("qtype_name") or "")))
            stats["dns"] += 1

    http_file = next((f for f in files if os.path.basename(f).replace(".gz", "") == "http.log"), None)
    if http_file:
        for row in _iter_zeek_rows(http_file):
            src = str(_nested_get(row, "id.orig_h") or "")
            dst = str(_nested_get(row, "id.resp_h") or "")
            dport = int(_nested_get(row, "id.resp_p") or 80)
            try:
                ts = float(row.get("ts", 0))
            except (TypeError, ValueError):
                continue
            method = str(row.get("method") or "")
            uri = str(row.get("uri") or "")
            if not method or not uri:
                continue
            rec = builder.match(src, dst, dport, ts) or builder.synth(src, 0, dst, dport, "TCP", ts, http_file)
            rec.http_requests.append(HttpRequest(
                method=method, host=str(row.get("host") or ""), uri=uri,
                user_agent=str(row.get("user_agent") or "")[:200],
                raw_line=f"{method} {uri}",
            ))
            stats["http"] += 1

    stats["flows"] = len(builder.flows)
    logger.info("Zeek 日志解析完成: %s -> %d 会话", path, stats["flows"])
    return builder.flows, stats


def _collect_zeek_files(path: str) -> list:
    files = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            base = name.lower().replace(".gz", "")
            if base.endswith(".log") and base.split(".")[0] in ("conn", "dns", "http"):
                files.append(os.path.join(path, name))
    elif os.path.isfile(path):
        files.append(path)
    return files


def _iter_zeek_rows(path: str):
    """逐行产出 Zeek 日志记录（dict）。自动识别 TSV 与 JSON。"""
    with _open_text(path) as fh:
        tsv_fields = None
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    tsv_fields = line.split("\t")[1:]
                continue
            if line.lstrip().startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
            elif tsv_fields:
                values = line.split("\t")
                if len(values) == len(tsv_fields):
                    yield _parse_conn_line_fields(tsv_fields, values)


def _conn_row_to_flow(row: dict, source_file: str):
    src = str(_nested_get(row, "id.orig_h") or "")
    dst = str(_nested_get(row, "id.resp_h") or "")
    try:
        sport = int(_nested_get(row, "id.orig_p") or 0)
        dport = int(_nested_get(row, "id.resp_p") or 0)
        ts = float(row.get("ts", 0))
    except (TypeError, ValueError):
        return None
    proto = PROTO_MAP.get(str(row.get("proto") or "tcp").lower(), "TCP")

    def _num(key):
        v = row.get(key)
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    duration = max(0.0, _num("duration"))
    bytes_total = int(max(0.0, _num("orig_bytes")) + max(0.0, _num("resp_bytes")))
    rec = FlowRecord(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                     protocol=proto, start_ts=ts, end_ts=ts + duration,
                     packets=max(1, int(_num("orig_pkts") + _num("resp_pkts"))),
                     bytes_total=bytes_total, source_file=source_file)
    state = str(row.get("conn_state") or "")
    # Zeek conn_state: S0/REJ -> 只发了 SYN 未完成；S1/SF/... -> 见过 SYN+SYNACK
    if proto == "TCP":
        rec.src_flags.add("S")
        if state in ("S1", "SF", "S2", "S3", "RSTR", "RSTO", "SH", "SS0"):
            rec.dst_flags.add("SA")
        if state == "SF":
            rec.src_flags.add("FA")
            rec.dst_flags.add("FA")
        if state.startswith("R") or state == "REJ":
            rec.dst_flags.add("R")
    return rec


def parse_connection_csv(path: str):
    """通用 CSV 连接日志 → FlowRecord（E 靶场没有 Zeek 时的兜底格式）。

    列名不区分大小写，支持：timestamp/src_ip/src_port/dst_ip/dst_port/protocol
    可选：bytes/duration/packets。timestamp 兼容 unix 秒与 "YYYY-MM-DD HH:MM:SS"。
    """
    flows = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        has_header = csv.Sniffer().has_header(sample)
        reader = csv.reader(fh)
        rows = list(reader)
    if not rows:
        return [], {"file": path, "flows": 0}

    header = [c.strip().lower() for c in rows[0]] if has_header else \
        ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol"]
    data_rows = rows[1:] if has_header else rows

    def col(row, name, default=None):
        if name in header:
            return row[header.index(name)]
        return default

    for row in data_rows:
        if not row or all(not c.strip() for c in row) or row[0].strip().startswith("#"):
            continue
        try:
            ts_raw = str(col(row, "timestamp", "")).strip()
            ts = _parse_ts(ts_raw)
            src = str(col(row, "src_ip", "")).strip()
            dst = str(col(row, "dst_ip", "")).strip()
            sport = int(float(col(row, "src_port", 0)))
            dport = int(float(col(row, "dst_port", 0)))
        except (TypeError, ValueError):
            continue
        proto = PROTO_MAP.get(str(col(row, "protocol", "tcp")).strip().lower(), "TCP")
        duration = _to_float(col(row, "duration", 0))
        bytes_total = int(_to_float(col(row, "bytes", 0)))
        packets = max(1, int(_to_float(col(row, "packets", 0))))
        rec = FlowRecord(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                         protocol=proto, start_ts=ts, end_ts=ts + max(0.0, duration),
                         packets=packets, bytes_total=bytes_total, source_file=path)
        if proto == "TCP":
            rec.src_flags.add("S")
        flows.append(rec)

    logger.info("CSV 连接日志解析完成: %s -> %d 会话", path, len(flows))
    return flows, {"file": path, "flows": len(flows)}


def _to_float(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _parse_ts(text: str) -> float:
    """时间戳兼容 unix 秒与常见文本格式。"""
    text = text.strip()
    try:
        return float(text)
    except ValueError:
        pass
    from datetime import datetime
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    raise ValueError(f"无法解析时间戳: {text!r}")

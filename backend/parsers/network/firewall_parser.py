"""防火墙/边界设备访问日志解析（source=firewall，2026-09-09 契约同步新增）。

当前支持 OPNsense/pfSense filterlog（pf 防火墙行格式，E 靶场交付）：
  <ISO时间>\t<级别>\tfilterlog\t<rulenum>,,,<rule_id>,<iface>,match,<action>,<dir>,
  <ipver>,...,<proto>,...,<src>,<dst>,<sport>,<dport>,...

产出 Event V2 事件：source=firewall、event_type=network_connection、
来源专有字段放 detail（action/rule_id/rule_number/interface/direction/ip_version）。
action=pass/block 是防火墙自身的判定结果，本模块不额外做攻击检测（severity 恒 0）。
"""
import logging
from datetime import datetime, timedelta, timezone

from .config import DetectionConfig
from .models import FlowRecord

logger = logging.getLogger(__name__)

TZ_CN = timezone(timedelta(hours=8))
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _is_filterlog(path: str) -> bool:
    """嗅探是否为 filterlog 行格式（前 5 行内出现 filterlog 关键字）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if "filterlog" in line:
                    return True
                if i >= 5:
                    break
    except OSError:
        pass
    return False


def _parse_ts(text: str) -> float:
    """filterlog 时间戳为本地无时区 ISO（E 的 VM 为 UTC+8），补 +08:00。"""
    dt = datetime.fromisoformat(text.strip())
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ_CN)
    return dt.timestamp()


def _split_pf_fields(payload: str) -> list:
    """filterlog 第 4 段为逗号分隔的 pf 字段串。"""
    return payload.split(",")


def parse_firewall_log(path: str, config: DetectionConfig = None):
    """filterlog -> list[FlowRecord]（复用会话模型，source=firewall）。

    每行一条事件级记录（不聚合），动作/规则号等来源专有信息在 record.detail_extra。
    返回 (records, stats)。
    """
    if config is None:
        config = DetectionConfig()
    records = []
    stats = {"file": path, "lines": 0, "events": 0, "skipped": 0,
             "pass": 0, "block": 0}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or "filterlog" not in line:
                stats["skipped"] += 1
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                stats["skipped"] += 1
                continue
            try:
                ts = _parse_ts(parts[0])
            except (ValueError, TypeError):
                stats["skipped"] += 1
                continue
            fields = _split_pf_fields(parts[3].strip())
            if len(fields) < 9:
                stats["skipped"] += 1
                continue
            action = fields[6]                       # pass / block
            direction = fields[7]                    # in / out
            ipver = fields[8]
            if action not in ("pass", "block") or ipver not in ("4", "6"):
                stats["skipped"] += 1
                continue

            proto_name, src, dst, sport, dport = "", "", "", None, None
            if ipver == "4" and len(fields) >= 20:
                protoid = fields[15]
                proto_name = _PROTO_NAMES.get(int(protoid)) if protoid.isdigit() else fields[16]
                src, dst = fields[18], fields[19]
                if proto_name in ("TCP", "UDP") and len(fields) >= 22:
                    sport = int(fields[20]) if fields[20].isdigit() else None
                    dport = int(fields[21]) if fields[21].isdigit() else None
            elif ipver == "6" and len(fields) >= 17:
                # pf v6 字段布局与 v4 不同：proto 名[12]/号[13]/长度[14]/src[15]/dst[16]/sport[17]/dport[18]
                proto_name = fields[12] if not fields[12].isdigit() else "IPv6"
                src, dst = fields[15], fields[16]
                if proto_name.lower() in ("tcp", "udp") and len(fields) >= 19:
                    proto_name = proto_name.upper()
                    sport = int(fields[17]) if fields[17].isdigit() else None
                    dport = int(fields[18]) if fields[18].isdigit() else None
                else:
                    proto_name = proto_name.upper() if proto_name else "IPv6"

            detail_extra = {
                "action": action,                    # 防火墙动作（pass/block）
                "rule_number": fields[0],
                "rule_id": fields[3] if len(fields) > 3 else "",
                "interface": fields[4] if len(fields) > 4 else "",
                "direction": direction,              # 防火墙视角的 in/out
                "ip_version": ipver,
                "device": "opnsense-firewall",
            }

            rec = FlowRecord(
                src_ip=src, src_port=sport or 0, dst_ip=dst, dst_port=dport or 0,
                protocol=proto_name or ("IPv6" if ipver == "6" else "IPv4"),
                start_ts=ts, end_ts=ts, packets=1, bytes_total=0,
                source="firewall", source_event_id=None,
                raw_log=line[:1000], dataset_label=f"fw-{action}",
            )
            rec.detail_extra = detail_extra          # 输出层读取（见 normalize）
            records.append(rec)
            stats["events"] += 1
            stats[action] = stats.get(action, 0) + 1
    logger.info("filterlog 解析完成: %s -> %d 事件（pass %d / block %d）",
                path, stats["events"], stats["pass"], stats.get("block", 0))
    return records, stats

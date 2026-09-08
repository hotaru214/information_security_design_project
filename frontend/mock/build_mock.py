# -*- coding: utf-8 -*-
"""
mock 数据整理脚本（成员F）—— 重新生成 frontend/mock/ 下三个数据文件。
用法（在仓库根目录执行）:
    python frontend/mock/build_mock.py

数据来源（全部真实解析输出，非手编）——两个上游文件都在 .gitignore 里，
重新生成前需要先跑一遍解析器：
  1. C 网络解析器 → out/network_events.json：
     python -m backend.parsers.network data/network_logs/case01_enterprise_attack.pcap \
         --hosts data/hosts.csv --out out/network_events.json
  2. B 主机解析器 → data/output/*.jsonl：
     cd backend/b_host_parser && python run_parse.py ../../data/sample_logs/<样本>.evtx --out ../../data/output/<名字>.jsonl
     （脚本固定读取 sample_4624_4625 / sample_sysmon_1_3_11 / sample_sysmon_12_13 / sample_wmi_4624 四份）

产出：
  frontend/mock/events.json    50条事件（契约校验0错误）
  frontend/mock/host_map.json  IP→主机名映射（来自 data/hosts.csv）
  frontend/mock/chain.json     攻击链（手工维护，不在本脚本范围）

整理规则：
  - 按最高契约《统一数据契约.txt》：B 输出的旧字段名 event_id 一律改名 source_event_id；
    mock 阶段不带 id（前端用数组下标模拟）。
  - 主机样本时间戳原为 2019/2020 年，为演示时间线连贯，仅重定基到攻击窗口
    2026-09-07（保留秒/微秒与相对顺序），其余字段值一字不改。
  - 异常标记：网络侧 11 条来自 C 检测器真实输出；主机侧 3 条按真实内容套用
    全组规则名（remote_download / encoded_exec / registry_persistence）。
"""
import json
from pathlib import Path

# 本脚本位于 frontend/mock/ 下，向上一层是 frontend/，再向上一层才是仓库根
ROOT = Path(__file__).resolve().parents[2]

# ---------- 1. 网络事件（C，真实输出） ----------
net = json.loads((ROOT / "out" / "network_events.json").read_text(encoding="utf-8"))
anom = [e for e in net if e["anomaly_flags"]]
norm = sorted([e for e in net if not e["anomaly_flags"]], key=lambda e: e["timestamp"])

# 均匀抽 17 条正常事件（覆盖三种 event_type 与各主机），+11 条告警 = 28 条网络事件
N_NORM = 17
idx = [round(i * len(norm) / N_NORM) for i in range(N_NORM)]
picked_norm = [norm[i] for i in dict.fromkeys(idx)]
net_events = anom + picked_norm

# ---------- 2. 主机事件（B，真实输出） ----------
HOST_FILES = [
    "sample_4624_4625", "sample_sysmon_1_3_11",
    "sample_sysmon_12_13", "sample_wmi_4624",
]
# 时间重定基映射：(原时,原分) -> (新时,新分)，秒/微秒保留；日期统一 2026-09-07
REBASE = {
    (21, 18): (9, 4),   # sample_4624_4625
    (23, 32): (9, 2),   # sample_sysmon_1_3_11
    (23, 33): (9, 3),
    (7, 6): (9, 6),     # sample_sysmon_12_13
    (6, 15): (9, 5),    # sample_wmi_4624
    (6, 16): (9, 6),
}
# 按真实内容套用全组异常规则名（键：source_event_id + process 精确定位；
# 同键重复记录只标第一条，避免同一动作反复计数）
HOST_FLAGS = {
    ("1", "cmd.exe"): (["remote_download", "encoded_exec"], 3),
    ("1", "rundll32.exe"): (["remote_download", "encoded_exec"], 3),
    ("13", "svchost.exe"): (["registry_persistence"], 2),
}

host_events = []
for name in HOST_FILES:
    for line in (ROOT / "data" / "output" / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        # 旧字段名 event_id -> source_event_id（最高契约）
        e["source_event_id"] = e.pop("event_id", None)
        # 时间重定基：2026-09-07，时分按映射，秒/微秒原样保留
        ts = e["timestamp"]  # 2019-05-21T23:32:57.286253+08:00
        date, hms = ts[:10], ts[11:]
        h, m = int(hms[0:2]), int(hms[3:5])
        nh, nm = REBASE.get((h, m), (h, m))
        e["timestamp"] = f"2026-09-07T{nh:02d}:{nm:02d}{hms[5:]}"
        flags = HOST_FLAGS.get((str(e["source_event_id"]), e.get("process")))
        if flags:
            if str(e["source_event_id"]) == "13" and any(
                str(x["source_event_id"]) == "13" and x["anomaly_flags"] for x in host_events
            ):
                flags = None  # 同一注册表动作的重复记录不重复标
        if flags:
            e["anomaly_flags"], e["severity"] = flags
        host_events.append(e)

events = sorted(net_events + host_events, key=lambda e: e["timestamp"])

out_dir = ROOT / "frontend" / "mock"
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / "events.json").write_text(
    json.dumps(events, ensure_ascii=False, indent=1), encoding="utf-8")

# ---------- 2.5 host_map.json（IP→主机名，Dashboard 主机统计展示用） ----------
# 来源 data/hosts.csv；后端 /api/hosts 就绪后前端优先走接口，此文件仅 mock 模式兜底
import csv
with open(ROOT / "data" / "hosts.csv", encoding="utf-8") as f:
    host_map = {row["ip"]: row["hostname"] for row in csv.DictReader(f)}
(out_dir / "host_map.json").write_text(
    json.dumps(host_map, ensure_ascii=False, indent=1), encoding="utf-8")

# ---------- 3. 校验 ----------
ENUM_SOURCE = {"windows_evtx", "sysmon", "linux_auth", "linux_audit",
               "network_pcap", "network_zeek"}
ENUM_TYPE = {
    "login_success", "login_failed", "logout",
    "process_start", "process_end",
    "network_connection", "dns_query", "http_request",
    "file_create", "file_read", "file_write", "file_modify", "file_delete",
    "registry_set", "registry_create", "registry_delete", "registry_query",
    "user_created", "user_deleted", "user_modified", "group_member_added",
    "group_member_removed", "privilege_change",
    "service_created", "service_started", "service_stopped", "service_deleted",
    "scheduled_task_created", "scheduled_task_run", "scheduled_task_deleted",
}
FIELDS = ["timestamp", "host", "source", "source_event_id", "event_type",
          "user", "process", "src_ip", "dst_ip", "dst_port", "protocol",
          "logon_type", "session_id", "cmdline", "detail", "description",
          "anomaly_flags", "severity", "raw_log"]
NULLABLE = {"source_event_id", "user", "process", "src_ip", "dst_ip",
            "dst_port", "protocol", "logon_type", "session_id", "cmdline"}

errors = []
for i, e in enumerate(events):
    if sorted(e.keys()) != sorted(FIELDS):
        errors.append(f"[{i}] 字段集不符: {sorted(set(e.keys()) ^ set(FIELDS))}")
        continue
    if e["source"] not in ENUM_SOURCE:
        errors.append(f"[{i}] source 非法: {e['source']}")
    if e["event_type"] not in ENUM_TYPE:
        errors.append(f"[{i}] event_type 非法: {e['event_type']}")
    if not isinstance(e["detail"], dict):
        errors.append(f"[{i}] detail 不是对象")
    if not e["description"] or not e["raw_log"]:
        errors.append(f"[{i}] description/raw_log 必填")
    if e["severity"] not in (0, 1, 2, 3):
        errors.append(f"[{i}] severity 非法: {e['severity']}")
    if not isinstance(e["anomaly_flags"], list):
        errors.append(f"[{i}] anomaly_flags 不是数组")
    if not e["timestamp"].endswith("+08:00"):
        errors.append(f"[{i}] 时间非 UTC+8")
    for k in FIELDS:
        if k not in NULLABLE and k not in ("detail", "description", "anomaly_flags",
                                           "severity", "raw_log", "timestamp", "host"):
            if e[k] is None:
                errors.append(f"[{i}] 非空字段为 null: {k}")
        if e.get(k) in ("unknown", ""):
            errors.append(f"[{i}] 占位值: {k}")

n_anom = sum(1 for e in events if e["anomaly_flags"])
types = sorted({e["event_type"] for e in events})
print(f"总数: {len(events)} | 异常: {n_anom} ({n_anom/len(events):.0%})")
print(f"event_type 覆盖: {types}")
print(f"source 分布:", {s: sum(1 for e in events if e['source'] == s) for s in ENUM_SOURCE if any(e['source'] == s for e in events)})
print("校验错误:", len(errors))
for msg in errors[:20]:
    print(" ", msg)

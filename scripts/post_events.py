"""把网络模块产出的 Event V2 JSON 导入 A 的后端，并做 round-trip 校验（成员C联调工具）。

用法（先启动后端：python -m uvicorn backend.main:app --reload）：

    python scripts/post_events.py out/network_events.json
    python scripts/post_events.py out/network_events.json --base http://127.0.0.1:8000 --sync-hosts data/hosts.csv

流程：
  1. 本地契约自检（validate_events，不合规直接退出）
  2. --sync-hosts：把 hosts.csv 同步到后端 /api/hosts（已存在的跳过，容忍 409）
  3. POST /api/events/import 批量导入（A 无逐条容错，422 时打印 Pydantic 错误明细）
  4. GET /api/events 拉回，与本地事件逐字段 round-trip 比对
  5. 打印报告：导入数 / 匹配数 / 缺失数 / 字段差异明细

仅用标准库，无额外依赖。
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime

sys.path.insert(0, ".")

from backend.parsers.network.normalize import validate_events  # noqa: E402


# ---------------------------------------------------------------- HTTP 基础

def _request(method: str, url: str, payload=None, timeout: float = 30.0):
    """发请求，返回 (status, json/None)。HTTPError 的响应体也返回（422 明细要用）。"""
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"raw": body}


def _print_422_detail(body):
    """FastAPI/Pydantic 校验错误明细：定位是第几条事件、哪个字段。"""
    detail = (body or {}).get("detail") if isinstance(body, dict) else None
    if not isinstance(detail, list):
        print(f"    响应体: {body}")
        return
    shown = 0
    for err in detail:
        loc = "->".join(str(x) for x in err.get("loc", []))
        print(f"    ! {loc}: {err.get('msg')} (input={err.get('input')!r:.80})")
        shown += 1
        if shown >= 10:
            print(f"    ... 共 {len(detail)} 处错误")
            break


# ---------------------------------------------------------------- hosts 同步

def sync_hosts(base: str, hosts_csv: str) -> dict:
    """把 hosts.csv 同步到后端。A 的 /api/hosts/batch 遇重复整批 409，故逐条 POST。"""
    import csv
    with open(hosts_csv, "r", encoding="utf-8-sig", newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("ip") or "").strip()]
    status, existing = _request("GET", f"{base}/api/hosts")
    if status != 200:
        print(f"[hosts] GET /api/hosts 失败: {status} {existing}")
        return {"ok": False}
    have_ips = {h.get("ip") for h in (existing or [])}

    added, skipped, failed = 0, 0, 0
    for row in rows:
        ip, hostname = row["ip"].strip(), (row.get("hostname") or "").strip()
        if not hostname or ip in have_ips:
            skipped += 1
            continue
        st, body = _request("POST", f"{base}/api/hosts", {
            "hostname": hostname, "ip": ip, "role": (row.get("role") or "").strip() or None,
        })
        if st == 201:
            added += 1
        elif st == 409:
            skipped += 1
        else:
            failed += 1
            print(f"[hosts] POST {ip}/{hostname} -> {st}")
    print(f"[hosts] 同步完成: 新增 {added} / 已存在跳过 {skipped} / 失败 {failed}")
    return {"ok": failed == 0, "added": added, "skipped": skipped}


# ---------------------------------------------------------------- round-trip 比对

def _norm_ts(ts) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts))
    except ValueError:
        return None


def _norm_detail(value):
    """后端可能把 detail 存成 JSON 字符串返回，归一成 dict 再比。"""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def compare_events(local_events: list, remote_events: list) -> dict:
    """本地事件 vs 后端 EventOut：逐字段 round-trip 比对（纯函数，可单测）。

    匹配键：(timestamp, host, event_type, description)。
    字段名映射：本地 source_event_id <-> 远端 event_id。
    """
    def key(e, eid_key=None):
        return (_norm_ts(e.get("timestamp")), e.get("host"),
                e.get("event_type"), e.get("description"))

    remote_index = {}
    for r in remote_events:
        remote_index.setdefault(key(r), []).append(r)

    matched, missing, diffs = 0, [], []
    for le in local_events:
        candidates = remote_index.get(key(le), [])
        if not candidates:
            missing.append(le.get("description", "")[:80])
            continue
        rem = candidates.pop(0)
        matched += 1
        for field in ("host", "source", "event_type", "user", "process", "src_ip",
                      "dst_ip", "dst_port", "protocol", "logon_type", "session_id",
                      "cmdline", "description", "anomaly_flags", "severity"):
            lv, rv = le.get(field), rem.get(field)
            if field == "anomaly_flags" and isinstance(rv, str):
                rv = _norm_detail(rv)
            if lv != rv:
                diffs.append(f"{le.get('description', '')[:40]} :: {field}: 本地={lv!r} 远端={rv!r}")
        # source_event_id(event_id) 与 timestamp 单独比（格式可能有差）
        lv, rv = le.get("source_event_id"), rem.get("event_id")
        if lv != rv:
            diffs.append(f"{le.get('description', '')[:40]} :: event_id: 本地={lv!r} 远端={rv!r}")
        lt, rt = _norm_ts(le.get("timestamp")), _norm_ts(rem.get("timestamp"))
        if lt != rt:
            diffs.append(f"{le.get('description', '')[:40]} :: timestamp: 本地={le.get('timestamp')} 远端={rem.get('timestamp')}")
        ld, rd = _norm_detail(le.get("detail")), _norm_detail(rem.get("detail"))
        if isinstance(ld, dict) and isinstance(rd, dict):
            only_local = set(ld) - set(rd)
            only_remote = set(rd) - set(ld)
            val_diff = [k for k in set(ld) & set(rd) if ld[k] != rd[k]]
            if only_local or only_remote or val_diff:
                diffs.append(f"{le.get('description', '')[:40]} :: detail 差异: "
                             f"本地独有={sorted(only_local)} 远端独有={sorted(only_remote)} 值不同={sorted(val_diff)}")
        elif ld != rd:
            diffs.append(f"{le.get('description', '')[:40]} :: detail 类型/内容不一致")
    return {"matched": matched, "missing": missing, "diffs": diffs}


# ---------------------------------------------------------------- 主流程

def main(argv=None):
    parser = argparse.ArgumentParser(description="导入网络事件到后端并做 round-trip 校验")
    parser.add_argument("events_json", help="Event V2 事件 JSON 文件（python -m backend.parsers.network --out 产出）")
    parser.add_argument("--base", default="http://127.0.0.1:8000", help="后端地址")
    parser.add_argument("--sync-hosts", default="", metavar="HOSTS_CSV", help="同步 hosts.csv 到后端后再导入")
    parser.add_argument("--skip-import", action="store_true", help="只比对不导入（后端已有数据时）")
    args = parser.parse_args(argv)

    with open(args.events_json, "r", encoding="utf-8") as fh:
        events = json.load(fh)
    print(f"[load] 读取 {len(events)} 条事件: {args.events_json}")

    problems = validate_events(events)
    if problems:
        print(f"[check] 本地契约自检不合规 x{len(problems)}，先修复再导入：")
        for p in problems[:10]:
            print(f"    ! {p}")
        return 1
    print("[check] 本地契约自检: 通过")

    st, body = _request("GET", f"{args.base}/health")
    if st != 200:
        print(f"[abort] 后端不可达（{args.base}/health -> {st}）。先启动: python -m uvicorn backend.main:app --reload")
        return 1
    print("[health] 后端在线")

    if args.sync_hosts:
        sync_hosts(args.base, args.sync_hosts)

    if not args.skip_import:
        st, body = _request("POST", f"{args.base}/api/events/import", events)
        if st == 201:
            print(f"[import] 成功: {body}")
        else:
            print(f"[import] 失败 HTTP {st}（A 的 import 无逐条容错，任一条不合规即整批拒绝）:")
            _print_422_detail(body)
            return 1

    st, remote = _request("GET", f"{args.base}/api/events")
    if st != 200:
        print(f"[fetch] GET /api/events 失败: {st}")
        return 1
    print(f"[fetch] 后端现有 {len(remote)} 条事件")

    result = compare_events(events, remote)
    print("=" * 60)
    print("Round-trip 校验结果")
    print("=" * 60)
    print(f"  匹配: {result['matched']}/{len(events)}")
    if result["missing"]:
        print(f"  缺失: {len(result['missing'])} 条（后端未找到对应事件）")
        for m in result["missing"][:5]:
            print(f"    - {m}")
    if result["diffs"]:
        print(f"  字段差异: {len(result['diffs'])} 处")
        for d in result["diffs"][:15]:
            print(f"    ! {d}")
    if not result["missing"] and not result["diffs"]:
        print("  全部字段往返一致 ✓")
    print("=" * 60)
    return 0 if not result["missing"] and not result["diffs"] else 2


if __name__ == "__main__":
    sys.exit(main())

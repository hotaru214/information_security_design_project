"""把解析产出的 Event V2 JSON 通过真后端转换成带数据库 id 的 EventOut（给 D）。

D 的关联引擎消费 EventOut，evidence_event_ids 使用后端数据库 id；解析器原始输出没有 id。
本脚本：导入（/api/events/import）-> 回拉（/api/events）-> 按键匹配分配真实 id -> 落盘。

用法：
    python scripts/export_for_d.py out/apt29_events.json --out data/sample_events/apt29_day1_eventout.json
    python scripts/export_for_d.py out/ctu13_events.json --dataset ctu13 \
        --out data/sample_events/ctu13_s2_eventout.json
      --dataset ctu13 时自动取子集：全部告警事件 + 与感染主机相关的普通流
仅用标准库。
"""
import argparse
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, ".")
from scripts.post_events import _request, sync_hosts  # noqa: E402
from backend.parsers.network.normalize import collect_warnings, validate_eventout  # noqa: E402

INFECTED_HOSTS = {"ctu13": {"147.32.84.165"}}   # 各数据集的 ground truth 感染主机


def build_key(e):
    ts = e.get("timestamp")
    try:
        ts = datetime.fromisoformat(str(ts)).isoformat()
    except ValueError:
        pass
    return (ts, e.get("host"), e.get("event_type"), e.get("description"))


def subset_for_dataset(events: list, dataset: str) -> list:
    """大集取子集：全部告警 + ground truth 感染主机相关的普通流（D 关联的上下文）。"""
    infected = INFECTED_HOSTS.get(dataset, set())
    out, seen_infected = [], 0
    for e in events:
        if e.get("anomaly_flags"):
            out.append(e)
        elif infected and (e.get("src_ip") in infected or e.get("dst_ip") in infected):
            seen_infected += 1
            out.append(e)
    if infected:
        print(f"  [subset] 告警 + 感染主机相关流: {len(out)} 条（其中感染相关普通流 {seen_infected}）")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Event V2 -> EventOut(带数据库 id) 导出给 D")
    ap.add_argument("events_json")
    ap.add_argument("--out", required=True, help="EventOut JSON 输出路径")
    ap.add_argument("--dataset", default="", help="数据集名（ctu13 走感染主机子集逻辑）")
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--sync-hosts", default="", metavar="HOSTS_CSV",
                    help="把数据集的 IP->主机名映射同步到后端（D 的 host_map 数据源）")
    ap.add_argument("--batch-id", default="", metavar="NAME",
                    help="批次标签：写入每条事件的 detail.batch_id（默认取输出文件名去掉 _eventout）")
    ap.add_argument("--pretty", action="store_true",
                    help="输出美化缩进 JSON（默认紧凑单行，避免仓库行数膨胀）")
    args = ap.parse_args(argv)
    batch_id = args.batch_id or os.path.splitext(os.path.basename(args.out))[0].replace("_eventout", "")

    events = json.load(open(args.events_json, encoding="utf-8"))
    for e in events:
        e.setdefault("detail", {})["batch_id"] = batch_id   # 批次标签：D/前端据此区分数据批次
    print(f"[batch] batch_id={batch_id}")
    if args.dataset == "ctu13":
        events = subset_for_dataset(events, args.dataset)
    print(f"[load] 待导出 {len(events)} 条")

    st, _ = _request("GET", f"{args.base}/health")
    if st != 200:
        print(f"[abort] 后端不可达（{args.base}）。先启动: python -m uvicorn backend.main:app --reload")
        return 1
    if args.sync_hosts:
        sync_hosts(args.base, args.sync_hosts)

    st, body = _request("POST", f"{args.base}/api/events/import", events)
    if st != 201:
        print(f"[import] 失败 HTTP {st}: {str(body)[:300]}")
        return 1
    print(f"[import] {body}")

    st, remote = _request("GET", f"{args.base}/api/events")
    if st != 200:
        print(f"[fetch] 失败 HTTP {st}")
        return 1
    print(f"[fetch] 后端共 {len(remote)} 条事件")

    index = {}
    for r in remote:
        index.setdefault(build_key(r), []).append(r)

    exported, unmatched = [], 0
    for e in events:
        cands = index.get(build_key(e))
        if not cands:
            unmatched += 1
            continue
        r = cands.pop(0)
        out = dict(e)
        out["id"] = r["id"]                    # D 的 evidence_event_ids 用这个
        exported.append(out)

    problems = validate_eventout(exported)
    if problems:
        print(f"[contract] 导出内容 EventOut 契约不合规 x{len(problems)}（阻断落盘）:")
        for p in problems[:8]:
            print(f"    ! {p}")
        return 1
    for w in collect_warnings(exported)[:5]:
        print(f"[warn] {w}")
    ids = [o["id"] for o in exported]
    assert len(ids) == len(set(ids)), "分配到重复 id！"
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        if args.pretty:
            json.dump(exported, fh, ensure_ascii=False, indent=1)
        else:
            json.dump(exported, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"[done] {args.out}: {len(exported)} 条 EventOut（含真实 id，未匹配 {unmatched}）")
    return 0 if unmatched == 0 else 2


if __name__ == "__main__":
    sys.exit(main())

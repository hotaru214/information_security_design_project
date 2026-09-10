# -*- coding: utf-8 -*-
"""
B模块命令行入口：一条命令跑完"解析 → 标准事件 → 会话重建 → 异常预标记 → 落地/入库"
==================================================================================
常用命令（在 backend/b_host_parser 目录下执行）:

  1) 快速看解析效果（打印统计和第一条样例）:
     python run_parse.py "..\\..\\data\\sample_logs\\sample_4624_4625.evtx"

  2) 解析结果落地成 .jsonl（A的接口没就绪时的标准用法）:
     python run_parse.py <文件.evtx> --out "..\\..\\data\\output\\events.jsonl"

  3) 任务9·全量导入整个文件夹（E的靶场数据到了就用这个）:
     python run_parse.py --dir "..\\..\\data\\sample_logs"
     按文件打印 成功/失败/跳过 统计——数字直接抄进《测试分析报告》。

  4) 联调：直接发给A的后端（A启动FastAPI后）:
     python run_parse.py <文件.evtx> --post http://127.0.0.1:8000/api/events/import

  5) 只解析前N条（快速冒烟测试）:
     python run_parse.py <文件.evtx> --limit 20

  6) JSON行格式的Windows主机日志（APT29 day1 manual 数据集，NXLog导出的扁平JSON）:
     python run_parse.py "..\\..\\data\\datasets\\apt29\\day1\\apt29_evals_day1_manual_2020-05-01225525.json"
     由 sysmon_json.py 处理（.evtx走不了python-evtx的替代输入格式）
"""
import argparse
import json
import sys
from pathlib import Path

# 保证直接运行本文件时也能 import 到同目录的模块
sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_evtx import parse_windows_evtx, NS   # noqa: E402
from sysmon import parse_sysmon_evtx              # noqa: E402
from sysmon_json import parse_sysmon_json         # noqa: E402
from linux_log import parse_linux_auth, parse_linux_audit, detect_linux_parser  # noqa: E402
from sessions import rebuild_sessions, print_session_summary  # noqa: E402
from anomaly import apply_anomaly_rules                       # noqa: E402
from import_client import save_jsonl, post_to_backend         # noqa: E402

# 解析器名 → 解析函数（detect_parser_for返回的键）
PARSE_FNS = {
    "windows": parse_windows_evtx,
    "sysmon": parse_sysmon_evtx,
    "sysmon_json": parse_sysmon_json,   # JSON行格式的Windows事件（APT29 manual数据集）
    "linux_auth": parse_linux_auth,
    "linux_audit": parse_linux_audit,
}
LOG_SUFFIXES = (".evtx", ".log", ".out", ".txt", ".json")

# 项目根目录 = backend/b_host_parser 的上两级（2026-09-08起本模块移入backend/下，
# 所有默认路径都相对仓库根，避免写死盘符）
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def detect_parser(path) -> str:
    """看第一条记录的Provider名判断日志类型：Sysmon日志交给sysmon.py，其余交给windows_evtx.py"""
    import Evtx.Evtx as evtx_mod
    import xml.etree.ElementTree as ET
    with evtx_mod.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                provider = root.find(f"{NS}System/{NS}Provider")
                name = (provider.get("Name") or "") if provider is not None else ""
                return "sysmon" if "Sysmon" in name else "windows"
            except Exception:
                continue  # 第一条坏了看下一条
    return "windows"


def dedupe_linux_audit(events: list):
    """auditd事件跨文件去重。

    E的证据包里，同一个auditd事件（同审计序号）会同时出现在原始audit.log和
    ausearch按规则提取的.txt里——全量导入时不去重的话D看到的是双份时间线。
    以 (event_type, detail.audit_serial, timestamp) 为键；非auditd事件不动。
    返回 (去重后列表, 移除条数)。
    """
    seen = set()
    out = []
    removed = 0
    for ev in events:
        serial = (ev.get("detail") or {}).get("audit_serial")
        if serial is None:
            out.append(ev)
            continue
        key = (ev["event_type"], serial, ev["timestamp"])
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        out.append(ev)
    return out, removed


def _is_windows_json_lines(path) -> bool:
    """看首行是否像 NXLog 导出的 Windows 事件 JSON 行（有 EventID/Channel 顶层键）。

    .json 也可能是一般的JSON数组/别的数据，不能只看扩展名就硬认。"""
    import json as _json
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                first = _json.loads(line)
                return isinstance(first, dict) and "EventID" in first and "Channel" in first
    except Exception:
        return False
    return False


def detect_parser_for(path) -> str:
    """统一格式探测：.evtx按Provider识别（windows/sysmon）；
    .json行文件按首行键识别（sysmon_json）；文本日志（.log等）按首行内容
    识别Linux类型（linux_auth/linux_audit）。认不出返回None（调用方跳过并提示，不硬猜）。"""
    if path.suffix.lower() == ".evtx":
        return detect_parser(path)
    if path.suffix.lower() == ".json":
        return "sysmon_json" if _is_windows_json_lines(path) else None
    if path.suffix.lower() in LOG_SUFFIXES:
        return detect_linux_parser(path)
    return None


def enrich(events: list):
    """会话重建 + 异常预标记。必须在合并后的整批事件上跑（跨文件才能算出爆破/会话配对）。
    返回 (events, sessions, anomaly_stats)。"""
    events, sessions = rebuild_sessions(events)
    anomaly_stats = apply_anomaly_rules(events)
    return events, sessions, anomaly_stats


def print_enrich_stats(sessions: list, anomaly_stats: dict):
    print(f"      异常预标记: {anomaly_stats['flagged']}条被标记 "
          f"{anomaly_stats['by_rule']}")
    print_session_summary(sessions)


def post(args, events):
    """第3步可选：发给A的后端。连不上不算失败——jsonl已落地，不阻塞。"""
    import requests  # 仅--post联调时需要；纯解析/落地不装requests也能跑
    print(f"[3/3] 发送给A的后端 {args.post} ...")
    try:
        n = post_to_backend(events, args.post)
        print(f"      完成：A的接口已接收 {n} 条")
    except requests.exceptions.ConnectionError:
        print("      [连不上] A的后端大概率没启动。别等他——"
              "jsonl已经落好地了，先继续开发，A就绪后再发一次。")
    except Exception as e:
        print(f"      [发送失败] {e}")


def parse_file(path: Path, kind: str, linux_host=None):
    """按解析器名解析一个文件，返回 (events, stats)。Linux解析器多带一个host参数。"""
    st = {}
    if kind in ("linux_auth", "linux_audit"):
        return PARSE_FNS[kind](str(path), st, host=linux_host), st
    return PARSE_FNS[kind](str(path), st), st


def run_single(args, in_path: Path):
    """单文件模式：解析 → enrich → 落地 → 可选POST → 打印样例。"""
    kind = detect_parser_for(in_path)
    if kind is None:
        print(f"[错误] 无法识别 {in_path.name} 的日志格式"
              f"（.evtx 或 .log/.out/.txt 文本日志才支持）")
        sys.exit(1)
    events, stats = parse_file(in_path, kind, linux_host=args.linux_host)
    print(f"[1/3] 解析 {in_path.name}（解析器: {kind}）...")
    if args.limit:
        events = events[:args.limit]
    print(f"      成功 {stats['parsed']} 条 | 其他事件(暂不处理) "
          f"{stats['skipped_other']} 条 | 解析失败 {stats['failed']} 条")
    print(f"      事件ID分布: {stats['by_event_id']}")

    print("[2/3] 会话重建 + 异常预标记 ...")
    events, sessions, anomaly_stats = enrich(events)
    print_enrich_stats(sessions, anomaly_stats)

    out_path = Path(args.out) if args.out else PROJECT_ROOT / "data" / "output" / "events.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_jsonl(events, str(out_path))
    print(f"      已落地 {len(events)} 条 → {out_path}")

    if args.post:
        post(args, events)
    else:
        print("[3/3] 未指定 --post，跳过入库（联调时加上即可）")

    if events:
        print("\n===== 标准事件样例（第1条）=====")
        print(json.dumps(events[0], ensure_ascii=False, indent=2))


def run_dir(args, dir_path: Path):
    """任务9：全量导入文件夹。双层保险——
    第1层：每个解析器内部按"条"try-except（一条坏记录不废整个文件）；
    第2层：本函数按"文件"try-except（一个文件损坏/不是evtx，不废整批）。"""
    files = sorted(p for p in dir_path.rglob("*")
                   if p.is_file() and p.suffix.lower() in LOG_SUFFIXES)
    if not files:
        print(f"[错误] {dir_path} 下（含子目录）没有找到 "
              f"{','.join(LOG_SUFFIXES)} 日志文件")
        sys.exit(1)

    print(f"[1/3] 发现 {len(files)} 个日志文件，开始全量解析...")
    all_events = []
    total = {"parsed": 0, "skipped_other": 0, "failed": 0}
    broken_files = []
    no_record_files = []  # 打开成功但一条记录都没读到的文件（截断/空日志）——报告里要看得见
    unrecognized = []     # 扩展名/内容都认不出的文件
    for f in files:
        try:
            kind = detect_parser_for(f)
            if kind is None:
                print(f"  [跳过] {f.name}: 无法识别的日志格式"
                      f"（既不是evtx，首行也不像auth/audit日志）")
                unrecognized.append(f.name)
                continue
            events, st = parse_file(f, kind, linux_host=args.linux_host)
        except Exception as e:
            broken_files.append(f.name)
            print(f"  [损坏文件，跳过] {f.name}: {type(e).__name__}: {e}")
            continue
        all_events.extend(events)
        total["parsed"] += st["parsed"]
        total["skipped_other"] += st["skipped_other"]
        total["failed"] += st["failed"]
        if st["parsed"] == 0 and st["failed"] == 0 and st["skipped_other"] == 0:
            no_record_files.append(f.name)
            print(f"  [⚠️无可疑事件也无记录] {f.name}: 0条记录——文件可能被截断/清空，请人工确认")
            continue
        print(f"  {f.name}: 成功 {st['parsed']} 条 / 解析失败 {st['failed']} 条 / "
              f"跳过其他事件 {st['skipped_other']} 条  事件ID分布: {st['by_event_id']}")

    print(f"\n[2/3] 去重 + 会话重建 + 异常预标记（合并{len(all_events)}条后统一跑）...")
    all_events, dedup_removed = dedupe_linux_audit(all_events)
    if dedup_removed:
        print(f"      跨文件去重: 移除 {dedup_removed} 条"
              f"（同一auditd事件在原始log和ausearch提取的txt里重复）")
    all_events, sessions, anomaly_stats = enrich(all_events)
    print_enrich_stats(sessions, anomaly_stats)

    out_path = Path(args.out) if args.out else PROJECT_ROOT / "data" / "output" / "all_events.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_jsonl(all_events, str(out_path))
    sessions_path = out_path.with_name("all_sessions.json")
    sessions_path.write_text(json.dumps(sessions, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    print(f"\n[3/3] 已落地 {len(all_events)} 条 → {out_path}")
    print(f"      会话汇总 → {sessions_path.name}")

    # ===== 末尾统计：数字直接抄进《测试分析报告》 =====
    print("\n===== 全量导入统计 =====")
    print(f"  文件总数: {len(files)}（损坏跳过 {len(broken_files)} 个, "
          f"无记录 {len(no_record_files)} 个, 无法识别 {len(unrecognized)} 个）")
    print(f"  事件总计: 成功 {total['parsed']} 条 / 解析失败 {total['failed']} 条 / "
          f"跳过其他事件 {total['skipped_other']} 条"
          + (f" / 跨文件去重 {dedup_removed} 条" if dedup_removed else ""))
    print(f"  会话: {len(sessions)} 个 | 异常标记: {anomaly_stats['flagged']} 条 "
          f"{anomaly_stats['by_rule']}")

    if args.post:
        post(args, all_events)

    return {"files": len(files), "broken_files": broken_files,
            "no_record_files": no_record_files, "unrecognized": unrecognized,
            "parsed": total["parsed"], "failed": total["failed"],
            "skipped_other": total["skipped_other"], "dedup_removed": dedup_removed,
            "events": len(all_events), "sessions": len(sessions),
            "anomaly": anomaly_stats}


def main():
    ap = argparse.ArgumentParser(description="主机日志解析器（B模块）")
    ap.add_argument("file", nargs="?", default=None,
                    help=".evtx 文件路径（单文件模式）")
    ap.add_argument("--dir", default=None,
                    help="文件夹路径：递归解析其中全部 .evtx（任务9全量导入）")
    ap.add_argument("--out", default=None,
                    help="输出 .jsonl 路径（默认 单文件=events.jsonl / 目录模式=all_events.jsonl）")
    ap.add_argument("--post", default=None,
                    help="A的导入接口地址，如 http://127.0.0.1:8000/api/events/import")
    ap.add_argument("--limit", type=int, default=None,
                    help="单文件模式：只解析前N条记录（冒烟测试用）")
    ap.add_argument("--parser", choices=["auto", "windows", "sysmon"], default="auto",
                    help="解析器选择：auto=按日志Provider自动识别（默认）")
    ap.add_argument("--linux-host", default=None,
                    help="Linux日志的主机名覆盖（auditd行内没有主机名，"
                         "建议传E提供的靶机主机名，如 --linux-host ubuntu-vm）")
    args = ap.parse_args()

    if args.dir:
        dir_path = Path(args.dir)
        if not dir_path.is_dir():
            print(f"[错误] 文件夹不存在: {dir_path}")
            sys.exit(1)
        run_dir(args, dir_path)
        return

    if not args.file:
        ap.error("请给出一个 .evtx 文件路径，或用 --dir 指定文件夹（任务9全量导入）")
    in_path = Path(args.file)
    if not in_path.exists():
        print(f"[错误] 文件不存在: {in_path}")
        sys.exit(1)
    run_single(args, in_path)


if __name__ == "__main__":
    main()

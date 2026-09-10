# -*- coding: utf-8 -*-
"""
build_e_final_batch.py：E 最终靶场数据 → 单批 Event V2 JSON 数组（B 侧导出原料）
================================================================================
A 封箱合并流程的 B 侧一环。一条命令从 E 的最终原始主机日志复现整批标准事件：
  1. 逐个解析 E-work/raw 下 B 侧的日志（core/web 的 auth+auditd、office-win 两个 evtx）
  2. auditd 跨文件去重（同一审计序号会同时出现在按规则提取的多个 txt 里）
  3. 合并后整批跑 会话重建 + 异常预标记（时间窗规则必须整批跑，跨文件才能算出爆破）
  4. Windows 主机名对齐：evtx 的 Computer 是装机默认名（E 没改机名），
     映射成 data/hosts_e_case01.csv 里的靶机名 win10-jump——D 的关联引擎、
     /api/hosts/map 全靠 host 字段 join，机名对不上时间线就断
  5. 过 C 侧 validate_events 契约守卫预检（只 import 复用，不改 C 的代码）
  6. 落地 JSON 数组，交给 A 的"一批一库"脚本导出 EventOut：
     python scripts/reset_import_export.py --name e_final_host \
         --events data/output/e_final_host_events.json --hosts data/hosts_e_case01.csv

用法（任意目录均可）:
    python backend/b_host_parser/build_e_final_batch.py \
        [--out data/output/e_final_host_events.json] [--no-windows] [--limit N]

--no-windows 是降级开关（Windows 两个 evtx 解析失败时先保 Linux 批次出门）；
--limit 每文件只取前 N 条，用于冒烟验证脚本本身。
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent        # backend/b_host_parser/
PROJECT = HERE.parent.parent                  # 仓库根目录
sys.path.insert(0, str(HERE))                 # b_host_parser 内部模块
sys.path.insert(0, str(PROJECT))              # backend 包（C 的契约守卫，只复用不改）

from linux_log import parse_linux_auth, parse_linux_audit          # noqa: E402
from windows_evtx import parse_windows_evtx                        # noqa: E402
from sysmon import parse_sysmon_evtx                               # noqa: E402
from run_parse import enrich, dedupe_linux_audit, detect_parser    # noqa: E402
from backend.parsers.network.normalize import (                    # noqa: E402
    collect_warnings, validate_events,
)

# E 最终数据清单：(仓库根相对路径, 解析器, Linux主机名覆盖)
# 覆盖值与 data/hosts_e_case01.csv 对齐（web-server 10.10.20.10 / core-server 10.10.30.20）；
# core-auth.log 行内主机名是 E 虚拟机的默认名（mxy-VMware-Virtual-Platform），必须覆盖。
E_FINAL_FILES = [
    ("E-work/raw/core-server/core-auth.log", "linux_auth", "core-server"),
    ("E-work/raw/core-server/core-process-audit.txt", "linux_audit", "core-server"),
    ("E-work/raw/core-server/core-file-audit.txt", "linux_audit", "core-server"),
    ("E-work/raw/core-server/core-network-audit.txt", "linux_audit", "core-server"),
    ("E-work/raw/web/web-process-audit.txt", "linux_audit", "web-server"),
    ("E-work/raw/web/web-file-audit.txt", "linux_audit", "web-server"),
    ("E-work/raw/web/web-network-audit.txt", "linux_audit", "web-server"),
    ("E-work/raw/office-win/security-final.evtx", "evtx", None),
    ("E-work/raw/office-win/system-final.evtx", "evtx", None),
]

# evtx 的 Computer 字段 → hosts_e_case01.csv 的靶机名。
# DESKTOP-88HQCN9 是 E 的 office-win 虚拟机现机名，WIN-UL7KE8FN5I6 是 System 日志里
# 留存的改名前旧机名——两台名指同一台靶机（win10-jump 10.10.30.10）。
HOST_ALIASES = {
    "DESKTOP-88HQCN9": "win10-jump",
    "WIN-UL7KE8FN5I6": "win10-jump",
}


def parse_one(rel_path: str, kind: str, linux_host):
    """按清单里指定的解析器解析一个文件，返回 (events, stats)。"""
    path = PROJECT / rel_path
    st = {}
    if kind == "linux_auth":
        events = parse_linux_auth(str(path), st, host=linux_host)
    elif kind == "linux_audit":
        events = parse_linux_audit(str(path), st, host=linux_host)
    else:  # evtx：按 Provider 路由（Security/System→windows，Sysmon→sysmon）
        fn = parse_sysmon_evtx if detect_parser(path) == "sysmon" else parse_windows_evtx
        events = fn(str(path), st)
    return events, st


def main(argv=None):
    ap = argparse.ArgumentParser(description="E最终靶场数据 → Event V2 JSON数组（B侧批次原料）")
    ap.add_argument("--out", default="data/output/e_final_host_events.json",
                    help="输出 JSON 数组路径（仓库根相对，默认 data/output/e_final_host_events.json）")
    ap.add_argument("--no-windows", action="store_true",
                    help="跳过两个 evtx（Windows 解析失败时的降级开关）")
    ap.add_argument("--limit", type=int, default=None,
                    help="每个文件只取前 N 条事件（冒烟验证脚本用）")
    args = ap.parse_args(argv)

    print("===== 1/5 逐文件解析 E 最终主机日志 =====")
    all_events = []
    for rel, kind, host in E_FINAL_FILES:
        if args.no_windows and kind == "evtx":
            print(f"  [跳过] {Path(rel).name}（--no-windows）")
            continue
        try:
            events, st = parse_one(rel, kind, host)
        except Exception as e:
            print(f"  [失败] {rel}: {type(e).__name__}: {e}")
            return 1
        if args.limit:
            events = events[:args.limit]
        all_events.extend(events)
        print(f"  {Path(rel).name}: 成功 {st['parsed']} / 解析失败 {st['failed']} / "
              f"跳过其他 {st['skipped_other']}")

    print(f"===== 2/5 去重 + 会话重建 + 异常预标记（合并 {len(all_events)} 条后整批跑）=====")
    all_events, dedup_removed = dedupe_linux_audit(all_events)
    all_events, sessions, anomaly_stats = enrich(all_events)
    print(f"  auditd跨文件去重: -{dedup_removed} 条 | 会话 {len(sessions)} 个 | "
          f"异常标记 {anomaly_stats['flagged']} 条 {anomaly_stats['by_rule']}")

    print("===== 3/5 Windows 主机名对齐（evtx Computer → 靶机名）=====")
    aligned = {}
    for ev in all_events:
        alias = HOST_ALIASES.get(ev["host"])
        if alias:
            aligned[ev["host"]] = aligned.get(ev["host"], 0) + 1
            ev["host"] = alias
    for old, n in sorted(aligned.items()):
        print(f"  {old} → {HOST_ALIASES[old]}（{n} 条）")
    if not aligned:
        print("  （无需对齐）")

    print("===== 4/5 C侧契约守卫预检（validate_events）=====")
    problems = validate_events(all_events)
    warnings = collect_warnings(all_events)
    if problems:
        for p in problems[:10]:
            print(f"  [阻断] {p}")
        print(f"  共 {len(problems)} 条契约问题——已阻断导出，先修数据再跑")
        return 1
    print(f"  {len(all_events)} 条全部通过阻断级校验"
          f"（非阻断警告 {len(warnings)} 条：host为IP的过渡期标注）")

    out = PROJECT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(all_events, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"===== 5/5 已落地 {len(all_events)} 条 → {out}")
    print("下一步（A的一批一库导出）: python scripts/reset_import_export.py "
          f"--name e_final_host --events {args.out} --hosts data/hosts_e_case01.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())

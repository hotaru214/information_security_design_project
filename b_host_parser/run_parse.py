# -*- coding: utf-8 -*-
"""
B模块命令行入口：一条命令跑完"解析 → 标准事件 → 落地/入库"
=============================================================
常用命令（在 b_host_parser 目录下执行）:

  1) 快速看解析效果（打印统计和第一条样例）:
     python run_parse.py "..\data\sample_logs\sample_4624_4625.evtx"

  2) 解析结果落地成 .jsonl（A的接口没就绪时的标准用法）:
     python run_parse.py "..\data\sample_logs\sample_4624_4625.evtx" --out "..\data\output\events.jsonl"

  3) 直接发给A的后端（联调用，A启动FastAPI后）:
     python run_parse.py <文件.evtx> --post http://127.0.0.1:8000/api/events/import

  4) 只解析前N条（快速冒烟测试）:
     python run_parse.py <文件.evtx> --limit 20
"""
import argparse
import json
import sys
from pathlib import Path

# 保证直接运行本文件时也能 import 到同目录的模块
sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_evtx import parse_windows_evtx, NS   # noqa: E402
from sysmon import parse_sysmon_evtx              # noqa: E402
from import_client import save_jsonl, post_to_backend  # noqa: E402

# 项目根目录 = b_host_parser 的上一级（所有默认路径都相对它，避免写死盘符）
PROJECT_ROOT = Path(__file__).resolve().parent.parent


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


def main():
    ap = argparse.ArgumentParser(description="主机日志解析器（B模块）")
    ap.add_argument("file", help=".evtx 文件路径")
    ap.add_argument("--out", default=None,
                    help="输出 .jsonl 路径（默认 data/output/events.jsonl）")
    ap.add_argument("--post", default=None,
                    help="A的导入接口地址，如 http://127.0.0.1:8000/api/events/import")
    ap.add_argument("--limit", type=int, default=None,
                    help="只解析前N条记录（冒烟测试用）")
    ap.add_argument("--parser", choices=["auto", "windows", "sysmon"], default="auto",
                    help="解析器选择：auto=按日志Provider自动识别（默认）")
    args = ap.parse_args()

    in_path = Path(args.file)
    if not in_path.exists():
        print(f"[错误] 文件不存在: {in_path}")
        sys.exit(1)

    # ---------- 第1步：解析 ----------
    if args.parser == "auto":
        args.parser = detect_parser(in_path)
    parse_fn = parse_sysmon_evtx if args.parser == "sysmon" else parse_windows_evtx
    print(f"[1/3] 解析 {in_path.name}（解析器: {args.parser}）...")
    stats = {}
    events = parse_fn(str(in_path), stats)
    if args.limit:
        events = events[:args.limit]
    print(f"      成功 {stats['parsed']} 条 | 其他事件(暂不处理) "
          f"{stats['skipped_other']} 条 | 解析失败 {stats['failed']} 条")
    print(f"      事件ID分布: {stats['by_event_id']}")

    # ---------- 第2步：落地 .jsonl ----------
    out_path = Path(args.out) if args.out else PROJECT_ROOT / "data" / "output" / "events.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_jsonl(events, str(out_path))
    print(f"[2/3] 已落地 {len(events)} 条 → {out_path}")

    # ---------- 第3步：可选，发给A的后端 ----------
    if args.post:
        print(f"[3/3] 发送给A的后端 {args.post} ...")
        try:
            n = post_to_backend(events, args.post)
            print(f"      完成：A的接口已接收 {n} 条")
        except requests.exceptions.ConnectionError:
            print("      [连不上] A的后端大概率没启动。别等他——"
                  "jsonl已经落好地了，先继续开发，A就绪后再发一次。")
        except Exception as e:
            print(f"      [发送失败] {e}")
    else:
        print("[3/3] 未指定 --post，跳过入库（联调时加上即可）")

    # ---------- 打印第一条样例，肉眼检查格式 ----------
    if events:
        print("\n===== 标准事件样例（第1条）=====")
        print(json.dumps(events[0], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    import requests  # 放底部避免未安装时--help都跑不了
    main()

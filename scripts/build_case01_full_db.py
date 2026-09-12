# -*- coding: utf-8 -*-
"""
build_case01_full_db.py：case01 双批共库导入（网络侧 + 主机侧 → 同一个后端实例）
================================================================================
背景：reset_import_export.py 是"一批一库"（每次先删库），导致 D 的库里只剩最后
导入的一批——出现过"只有 firewall/network_pcap、没有主机侧事件"的问题。
本脚本把 case01 的两批数据连续导入同一个后端，再统一导出合并 EventOut 给 D：
  1. e_case01_eventout.json        网络侧（firewall + network_pcap，约 720 条）
  2. e_final_host_events.json      主机侧（web/core 的 audit+auth、win10 的 evtx，47,195 条）

用法（任意目录均可，端口冲突时自动换）:
    python scripts/build_case01_full_db.py
    python scripts/build_case01_full_db.py --skip-network   # 库里已有网络侧时只补主机侧

产出：
  - data/sample_events/e_case01_full_db.json  合并 EventOut（含真实 id，交给 D）
    （命名刻意不带 _eventout 后缀：data/sample_events/*_eventout.json 有"单文件单批次"的
      CI 约定（tests 里的批次隔离校验），合并文件天然双批，不走那条约定）
  - 校验报告：各 batch 条数 / 主机分布 / getshell 关键证据在库
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

NETWORK_EVENTOUT = ROOT / "data" / "sample_events" / "e_case01_eventout.json"
HOST_EVENTS = ROOT / "data" / "output" / "e_final_host_events.json"
HOSTS_CSV = ROOT / "data" / "hosts_e_case01.csv"
OUT_COMBINED = ROOT / "data" / "sample_events" / "e_case01_full_db.json"

GETSHELL_MARKERS = ("case01-stage.sh", "sshpass")   # 主机侧 getshell/横向的关键进程名


def request(method: str, url: str, payload=None, timeout=120):
    import urllib.request
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def free_port(preferred: int) -> int:
    import socket
    port = preferred
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1


def wait_health(port: int, tries: int = 30) -> bool:
    for _ in range(tries):
        try:
            st, _ = request("GET", f"http://127.0.0.1:{port}/health", timeout=3)
            if st == 200:
                return True
        except Exception:
            time.sleep(1)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="case01 网络侧+主机侧双批共库导入")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--skip-network", action="store_true",
                    help="跳过网络侧（库里已有 e_case01 时）")
    ap.add_argument("--skip-host", action="store_true",
                    help="跳过主机侧（库里已有 e_final_host 时）")
    args = ap.parse_args(argv)

    db = ROOT / "data" / "attack_trace.db"
    if db.exists():
        db.unlink()
        print("[reset] 已删除旧数据库（一批一库 → 双批共库重建）")

    port = free_port(args.port)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(port),
         "--log-level", "warning"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[start] uvicorn PID {proc.pid}（端口 {port}）")
    try:
        if not wait_health(port):
            print("[abort] 后端未就绪")
            return 1
        base = f"http://127.0.0.1:{port}"

        # 主机映射：web-server / core-server / win10-jump（D 的 host_map 数据源）
        from scripts.post_events import sync_hosts
        sync_hosts(base, str(HOSTS_CSV))

        batches = []
        if not args.skip_network:
            batches.append((NETWORK_EVENTOUT, "e_case01"))
        if not args.skip_host:
            batches.append((HOST_EVENTS, "e_final_host"))

        for path, batch_id in batches:
            print(f"===== 导入 {batch_id}（{path.name}）=====")
            events = json.loads(path.read_text(encoding="utf-8"))
            # EventOut 里多余的 id 键由 EventCreate 忽略；batch_id 统一重写，保证口径一致
            from backend.schemas.event import EventCreate
            cleaned = []
            for e in events:
                ev = EventCreate.model_validate(e).model_dump(mode="json")
                ev.setdefault("detail", {})["batch_id"] = batch_id
                cleaned.append(ev)
            st, body = request("POST", f"{base}/api/events/import", cleaned)
            print(f"[import] {batch_id}: HTTP {st} {str(body)[:120]}")
            if st != 201:
                return 1

        # 统一回拉 → 合并 EventOut 给 D（evidence_event_ids 用库内真实 id）
        st, remote = request("GET", f"{base}/api/events")
        if st != 200:
            print(f"[abort] 回拉失败 HTTP {st}")
            return 1
        OUT_COMBINED.write_text(
            json.dumps(remote, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        print(f"[done] 合并 EventOut → {OUT_COMBINED}（{len(remote)} 条）")

        # ---- 校验报告 ----
        from collections import Counter
        by_batch = Counter((e.get("detail") or {}).get("batch_id") for e in remote)
        by_host = Counter(e.get("host") for e in remote)
        print("[verify] 各批条数:", dict(by_batch))
        print("[verify] 主机分布:", {k: v for k, v in sorted(by_host.items(), key=str)})
        hits = [e for e in remote if e.get("host") == "web-server"
                and e.get("event_type") == "process_start"
                and any(m in (e.get("cmdline") or "") + (e.get("process") or "")
                        for m in GETSHELL_MARKERS)]
        print(f"[verify] getshell 关键证据在库: {len(hits)} 条")
        for e in hits[:5]:
            print(f"    {e['timestamp'][:19]} {e['process']:<10} "
                  f"cmdline={(e.get('cmdline') or '')[:90]}")
        if not hits:
            print("[warn] 未找到 getshell 证据——检查主机批是否导入完整")
            return 1
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

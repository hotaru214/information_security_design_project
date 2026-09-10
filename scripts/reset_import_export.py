"""一批一库：重置数据库 -> 启动后端 -> 导入单批数据 -> 导出 EventOut -> 停后端。

目的：避免多批数据混在同一个库里导致 D 的关联引擎跨批次串链。
每批数据独立入库（id 从 1 重新编号），EventOut 文件与库内 id 严格一致。

用法：
    python scripts/reset_import_export.py --name e_case01 --events out/e_case01_events.json ^
        [--hosts data/hosts_e_case01.csv] [--dataset ctu13] [--port 8000]

流程：清理 8000 端口残留 -> 删除 data/attack_trace.db -> 启动 uvicorn -> 等 /health ->
    export_for_d（导入+打 batch_id+导出）-> 停止后端。仅用标准库。
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NETSTAT = r"C:\Windows\System32\netstat.exe"
TASKKILL = r"C:\Windows\System32\taskkill.exe"


def free_port(port: int):
    """杀掉占用端口的残留进程（此前多次出现孤儿 uvicorn）。"""
    out = subprocess.run([NETSTAT, "-ano"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    pids = {line.split()[-1] for line in out.splitlines()
            if f":{port}" in line and "LISTENING" in line.upper()}
    for pid in pids:
        subprocess.run([TASKKILL, "/F", "/PID", pid], capture_output=True,
                       encoding="utf-8", errors="replace")
        print(f"  [kill] 端口 {port} 残留进程 PID {pid}")
    if pids:
        time.sleep(1)


def wait_health(port: int, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="单批数据隔离入库 + EventOut 导出")
    ap.add_argument("--name", required=True, help="批次名（batch_id，也是输出文件名前缀）")
    ap.add_argument("--events", required=True, help="解析器 Event V2 JSON")
    ap.add_argument("--hosts", default="", help="IP->主机名映射 CSV")
    ap.add_argument("--dataset", default="", help="ctum13 等子集裁剪逻辑标记")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)

    db = ROOT / "data" / "attack_trace.db"
    if db.exists():
        db.unlink()
        print("[reset] 已删除旧数据库")

    free_port(args.port)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(args.port), "--log-level", "warning"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[start] uvicorn PID {proc.pid}（端口 {args.port}）")
    try:
        if not wait_health(args.port):
            print("[abort] 后端未就绪")
            return 1

        out_file = ROOT / "data" / "sample_events" / f"{args.name}_eventout.json"
        cmd = [sys.executable, str(ROOT / "scripts" / "export_for_d.py"),
               str(ROOT / args.events), "--out", str(out_file),
               "--batch-id", args.name, "--base", f"http://127.0.0.1:{args.port}"]
        if args.hosts:
            cmd += ["--sync-hosts", str(ROOT / args.hosts)]
        if args.dataset:
            cmd += ["--dataset", args.dataset]
        rc = subprocess.run(cmd, cwd=ROOT).returncode
        if rc != 0:
            return rc

        events = json.loads(out_file.read_text(encoding="utf-8"))
        batches = {e["detail"].get("batch_id") for e in events}
        ids = [e["id"] for e in events]
        print(f"[verify] {out_file.name}: {len(events)} 条 | batch_id={batches} | id {min(ids)}~{max(ids)}")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
            print("[stop] 后端已停止")
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

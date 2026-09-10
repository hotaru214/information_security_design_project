"""启动平台（后端 8000 同源托管前端）—— 封箱版启动脚本。

内置此前踩过的所有坑的自动处理：
  1. 端口残留孤儿进程 -> 启动前自动清理
  2. 依赖缺失 -> 明确提示安装命令
  3. 数据库为空 -> 提示先导入数据
  4. 健康检查通过后自动打开浏览器（--no-open 关闭）

用法：
  python scripts/start_platform.py                 # 默认 8000 + 自动开浏览器
  python scripts/start_platform.py --port 8001     # 批次演示库（先 reset_import_export 导入该批）
  python scripts/start_platform.py --no-open       # 不自动开浏览器
停止：本窗口 Ctrl+C（会连同 uvicorn 一起退出）。
"""
import argparse
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PORT_DEFAULT = 8000


def free_port(port: int):
    """清理端口残留（孤儿 uvicorn 是本项目的经典问题）。"""
    netstat = r"C:\Windows\System32\netstat.exe"
    taskkill = r"C:\Windows\System32\taskkill.exe"
    if not Path(netstat).exists():
        netstat, taskkill = "netstat", "taskkill"
    out = subprocess.run([netstat, "-ano"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    pids = {line.split()[-1] for line in out.splitlines()
            if f":{port}" in line and "LISTENING" in line.upper()}
    for pid in pids:
        subprocess.run([taskkill, "/F", "/PID", pid], capture_output=True)
        print(f"  [清理] 端口 {port} 残留进程 PID {pid}")
    if pids:
        time.sleep(1)


def check_deps():
    missing = []
    for mod in ("fastapi", "uvicorn", "scapy"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        print(f"[错误] 缺少依赖: {', '.join(missing)}")
        print("请先执行: python -m pip install -r requirements.txt")
        sys.exit(1)
    print("[依赖] 检查通过")


def db_overview():
    import sqlite3
    db = ROOT / "data" / "attack_trace.db"
    if not db.exists():
        print("[数据] 数据库不存在——平台可启动，但页面无数据。")
        print("       导入数据两种方式：")
        print("       1) 平台内「数据管理」页上传原始文件（推荐）")
        print("       2) 命令行: python scripts/reset_import_export.py --name <批次> --events <事件JSON>")
        return
    try:
        conn = sqlite3.connect(db)
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        rows = conn.execute(
            "SELECT COALESCE(case_id, '未分批'), COUNT(*) FROM events "
            "GROUP BY COALESCE(case_id, '未分批') ORDER BY 2 DESC").fetchall()
        hosts_n = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        conn.close()
        print(f"[数据] 事件 {total} 条 / 主机映射 {hosts_n} 台")
        for cid, n in rows[:5]:
            print(f"       - {cid}: {n} 条")
        if total == 0:
            print("       （库为空——用「数据管理」页或 reset_import_export.py 导入数据）")
    except sqlite3.Error as e:
        print(f"[数据] 数据库读取异常（不影响启动）: {e}")


def wait_health(port: int, timeout: float = 30.0) -> bool:
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
    ap = argparse.ArgumentParser(description="启动溯源分析平台（后端同源托管前端）")
    ap.add_argument("--port", type=int, default=PORT_DEFAULT)
    ap.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args(argv)

    free_port(args.port)
    check_deps()
    db_overview()

    print(f"[启动] uvicorn 端口 {args.port}（Ctrl+C 停止平台）")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--port", str(args.port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_health(args.port):
            print("[错误] 后端健康检查超时，请查看上方输出")
            proc.terminate()
            return 1
        url = f"http://127.0.0.1:{args.port}/"
        print(f"[就绪] 平台已启动: {url}")
        print(f"       接口文档: {url}docs    健康检查: {url}health")
        if not args.no_open:
            webbrowser.open(url)
            print("[浏览器] 已自动打开（--no-open 可关闭此行为）")
        print("[运行中] 按 Ctrl+C 停止平台")
        proc.wait()
    except KeyboardInterrupt:
        print("\n[停止] 正在关闭平台…")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[退出] 平台已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""公开数据集下载工具（成员C，任务书测试要求1：收集互联网企业内网攻击数据集）。

支持两个数据集：
  1. CTU-13（Stratosphere IPS，僵尸网络场景，binetflow 带标签）
     --list-ctu        列出可用场景与 binetflow 文件大小
     --ctu <目录名>    下载指定场景的 .binetflow，如 CTU-Malware-Capture-Botnet-43
  2. APT29 day1（OTRF detection-hackathon，Sysmon+Zeek JSON，带 ATT&CK 标注）
     --list-apt29      列出 day1 数据文件
     --apt29           下载 day1 的 zeek JSON（--filter 可改 sysmon/osquery）

数据保存到 data/datasets/ 下（不入 git）。仅用标准库。
示例：
    python scripts/fetch_dataset.py --list-ctu
    python scripts/fetch_dataset.py --ctu CTU-Malware-Capture-Botnet-43
    python scripts/fetch_dataset.py --list-apt29
    python scripts/fetch_dataset.py --apt29 --filter zeek
"""
import argparse
import json
import os
import re
import ssl
import sys
import urllib.request

# 部分网络环境（校园网/代理）会拦截证书链导致 CERTIFICATE_VERIFY_FAILED；
# 本脚本只下载公开数据集，验证降级风险可控。B 的踩坑笔记记录过同类问题。
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

CTU_BASE = "https://mcfp.felk.cvut.cz/publicDatasets/"
APT29_API = "https://api.github.com/repos/OTRF/detection-hackathon-apt29/contents/datasets/day1/zeek"
APT29_RAW = "https://raw.githubusercontent.com/OTRF/detection-hackathon-apt29/master/datasets/day1/zeek/"
APT29_EXTRA = {
    "day1-README.md": "https://raw.githubusercontent.com/OTRF/detection-hackathon-apt29/master/datasets/day1/README.md",
    "repo-README.md": "https://raw.githubusercontent.com/OTRF/detection-hackathon-apt29/master/README.md",
}
OUT_ROOT = os.path.join("data", "datasets")

UA = {"User-Agent": "Mozilla/5.0 (course-project; data collection)"}


def fetch(url: str, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return resp.read()


def download(url: str, dest: str, min_size: int = 0) -> str:
    """下载到 dest（跳过已存在且大小足够的文件），返回实际路径。"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest) and os.path.getsize(dest) >= min_size:
        print(f"  [skip] {dest} 已存在（{os.path.getsize(dest)/1e6:.1f} MB）")
        return dest
    print(f"  [down] {url}")
    data = fetch(url, timeout=600.0)
    with open(dest, "wb") as fh:
        fh.write(data)
    got = open(dest, "rb").read()
    if got != data:
        raise IOError(f"写入校验失败: {dest}")
    print(f"  [ok]   {dest}（{len(data)/1e6:.1f} MB）")
    return dest


def list_ctu():
    print("获取 CTU-13 场景索引（仅列 .binetflow，pcap 动辄数 GB 不自动下载）...")
    html = fetch(CTU_BASE, timeout=120.0).decode("utf-8", "replace")
    dirs = sorted(set(re.findall(r'href="(CTU-Malware-Capture-Botnet-\d+)/"', html)))
    if not dirs:
        print("未解析到场景目录，直接访问:", CTU_BASE)
        return
    for d in dirs:
        try:
            sub = fetch(CTU_BASE + d + "/", timeout=60.0).decode("utf-8", "replace")
        except Exception as e:
            print(f"  {d}: 目录获取失败 {e}")
            continue
        for name, size in re.findall(r'href="([^"]+\.binetflow)"[^<]*</a>\s*(\d[\d.]*[KMG]?)', sub):
            print(f"  {d}/{name}  {size}")
        flows = re.findall(r'href="([^"]+\.binetflow)"', sub)
        if flows and not re.findall(r"\d[\d.]*[KMG]?", " ".join(flows)):
            for name in flows:
                print(f"  {d}/{name}")


def get_ctu(capture_dir: str):
    base = CTU_BASE + capture_dir.strip("/") + "/"
    html = fetch(base, timeout=120.0).decode("utf-8", "replace")
    binetflows = sorted(set(re.findall(r'href="([^"]+\.binetflow)"', html)))
    if not binetflows:
        raise SystemExit(f"{base} 下未找到 .binetflow")
    out = []
    for name in binetflows:
        out.append(download(base + name, os.path.join(OUT_ROOT, "ctu13", capture_dir, name), min_size=100_000))
    return out


def list_apt29():
    print("获取 APT29 day1 文件清单（GitHub contents API）...")
    data = json.loads(fetch(APT29_API).decode("utf-8"))
    for item in data:
        if item["type"] == "file":
            print(f"  {item['name']}  {item['size']/1e6:.2f} MB")


def get_apt29(filt: str):
    out = []
    data = json.loads(fetch(APT29_API).decode("utf-8"))
    for item in data:
        if item["type"] != "file" or filt.lower() not in item["name"].lower():
            continue
        url = APT29_RAW + item["name"]
        dest = os.path.join(OUT_ROOT, "apt29", "day1", "zeek", item["name"])
        out.append(download(url, dest, min_size=1000))
    for name, url in APT29_EXTRA.items():   # ground truth 文档一并保存
        dest = os.path.join(OUT_ROOT, "apt29", "day1", name)
        try:
            out.append(download(url, dest, min_size=100))
        except Exception as e:
            print(f"  [warn] {name}: {e}")
    if not out:
        print(f"没有匹配 '{filt}' 的文件（用 --list-apt29 查看清单）")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="公开数据集下载（CTU-13 / APT29 day1）")
    ap.add_argument("--list-ctu", action="store_true")
    ap.add_argument("--ctu", default="", metavar="CAPTURE_DIR")
    ap.add_argument("--list-apt29", action="store_true")
    ap.add_argument("--apt29", action="store_true")
    ap.add_argument("--filter", default="zeek", help="APT29 文件名过滤（默认 zeek）")
    args = ap.parse_args(argv)

    try:
        if args.list_ctu:
            list_ctu()
        if args.ctu:
            get_ctu(args.ctu)
        if args.list_apt29:
            list_apt29()
        if args.apt29:
            get_apt29(args.filter)
        if not any([args.list_ctu, args.ctu, args.list_apt29, args.apt29]):
            ap.print_help()
    except Exception as e:
        print(f"[下载失败] {type(e).__name__}: {e}")
        print("网络不可达时：检查代理/VPN 后重试；APT29 也可手动从 GitHub 网页下载后放入 data/datasets/apt29/day1/apt29-stage1/")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

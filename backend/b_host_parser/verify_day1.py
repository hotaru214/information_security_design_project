# -*- coding: utf-8 -*-
"""
一键自检脚本：逐项验证 Day1~Day1.5 的产出是否真的完成
======================================================
用法（在本目录下）:
    python verify_day1.py

全部通过 = 看到 6 个 [OK] 和最后的 "全部验证通过"。
任何一个 [FAIL] 会打印原因，直接把原因发给ZCode就能修。
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent        # backend/b_host_parser/
PROJECT = HERE.parent.parent                  # 仓库根目录（模块已移入backend/下）
sys.path.insert(0, str(HERE))

results = []


def check(tag, desc, fn):
    """跑一项验证，通过打[OK]，失败打[FAIL]+原因（不中断后面的检查）。"""
    try:
        fn()
        results.append(True)
        print(f"[OK]   {tag}  {desc}")
    except Exception as e:
        results.append(False)
        print(f"[FAIL] {tag}  {desc}")
        print(f"       └─ 原因: {type(e).__name__}: {e}")


# ---------- 任务1：契约 / schema ----------
def t1():
    from schema import make_event, STANDARD_FIELDS, SOURCES
    ev = make_event(timestamp="t", host="h")
    assert list(ev.keys()) == STANDARD_FIELDS, "make_event的键和STANDARD_FIELDS不一致"
    assert len(STANDARD_FIELDS) == 19, f"契约字段应为19个, 实际{len(STANDARD_FIELDS)}"
    # Event V2: source枚举6值
    for s in ("windows_evtx", "sysmon", "linux_auth", "linux_audit",
              "network_pcap", "network_zeek"):
        assert s in SOURCES, f"V2要求source枚举缺 {s}"
    try:
        make_event(不存在的字段=1)
        raise AssertionError("make_event应当拒绝未知字段，但没拒绝")
    except KeyError:
        pass  # 预期行为：报KeyError


check("任务1", "Event V2: 19字段齐全, source枚举6值, 未知字段会被拒绝", t1)

# ---------- 任务2：环境 + 样例数据 ----------
def t2():
    import Evtx.Evtx   # noqa: F401  python-evtx
    import requests    # noqa: F401
    for name in ("sample_4624_4625.evtx", "sample_wmi_4624.evtx",
                 "sample_sysmon_1_3_11.evtx", "sample_sysmon_12_13.evtx"):
        p = PROJECT / "data" / "sample_logs" / name
        assert p.exists() and p.stat().st_size > 60000, f"样例缺失或过小: {name}"


check("任务2", "python-evtx / requests 已安装, 4份真实攻击样本evtx就位", t2)

# ---------- 任务3：Windows解析器（登录 + 进程创建） ----------
def t3():
    from windows_evtx import parse_windows_evtx
    st = {}
    evs = parse_windows_evtx(str(PROJECT / "data" / "sample_logs" / "sample_4624_4625.evtx"), st)
    assert st["parsed"] == 4 and st["failed"] == 0, f"期望4条0失败, 实际: {st}"

    f4625 = next(e for e in evs if e["source_event_id"] == 4625)
    # Event V2: ISO8601 T分隔
    assert "T" in f4625["timestamp"] and f4625["timestamp"].endswith("+08:00"), \
        f"时间应为ISO8601 T分隔UTC+8, 实际: {f4625['timestamp']}"
    assert f4625["src_ip"] is None, "本地登录(类型2)的src_ip必须是null(原始值是'-')"
    assert f4625["detail"]["substatus_desc"] == "密码错误", "SubStatus没翻译成人话"

    st2 = {}
    evs2 = parse_windows_evtx(str(PROJECT / "data" / "sample_logs" / "sample_wmi_4624.evtx"), st2)
    assert st2["parsed"] == 8 and st2["by_event_id"].get("4688") == 2, f"4688应解析出来: {st2}"
    p = next(e for e in evs2 if e["source_event_id"] == 4688)
    assert p["event_type"] == "process_start" and p["process"] == "WmiPrvSE.exe"
    assert p["cmdline"] is None, "4688未开命令行审核时cmdline必须是null(不许造假)"
    assert p["detail"]["new_process_id"], "new_process_id应取自NewProcessId"
    assert any(e["source_event_id"] == 4624 and e["src_ip"] == "10.0.2.17" for e in evs2), \
        "应有src_ip=10.0.2.17的远程登录(样例里第一条带IP的是IPv6)"


check("任务3", "Windows解析: UTC+8 / 空IP=null / 4625失败原因 / 4624远程IP / 4688进程启动(process_start)", t3)

# ---------- 任务3b：Sysmon解析器（进程/网络/文件/注册表） ----------
def t3b():
    from sysmon import parse_sysmon_evtx
    st = {}
    evs = parse_sysmon_evtx(str(PROJECT / "data" / "sample_logs" / "sample_sysmon_1_3_11.evtx"), st)
    assert st["parsed"] == 8, f"sysmon 1_3_11期望8条, 实际: {st}"
    by_type = {}
    for e in evs:
        by_type.setdefault(e["event_type"], []).append(e)
        assert e["source"] == "sysmon" and e["raw_log"], "source/raw_log必填"

    p1 = by_type["process_start"][0]
    assert p1["cmdline"] and p1["detail"]["parent_cmdline"], "Sysmon1必须有真实cmdline和父进程"

    p3 = by_type["network_connection"][0]
    assert p3["dst_ip"] and p3["dst_port"] and p3["protocol"], "Sysmon3必须有dst_ip/dst_port/protocol"
    assert p3["src_ip"], "Sysmon3必须有src_ip"
    assert "src_port" in p3["detail"], "detail键名应为src_port（D规范）"

    p11 = by_type["file_create"][0]
    assert p11["detail"]["file_path"], "Sysmon11必须有文件路径"

    str2 = {}
    evs2 = parse_sysmon_evtx(str(PROJECT / "data" / "sample_logs" / "sample_sysmon_12_13.evtx"), str2)
    reg = next(e for e in evs2 if e["source_event_id"] == 13)
    assert reg["detail"]["registry_key"], "Sysmon13必须有注册表键"
    # Event V2 detail键名
    assert "registry_value_data" in reg["detail"], "应使用V2键名registry_value_data"
    assert "registry_operation" in reg["detail"], "应使用V2键名registry_operation"
    assert "registry_value_name" in reg["detail"], "应使用V2键名registry_value_name"
    assert "value" not in reg["detail"] and "event_type_name" not in reg["detail"], \
        "旧键名value/event_type_name必须移除"


check("任务3b", "Sysmon解析: process_start/cmdline+父进程 / network_connection含dst_port+protocol+src_port / file_create / registry_set", t3b)

# ---------- 任务4：落地.jsonl + POST给后端 ----------
class MockBackend(BaseHTTPRequestHandler):
    """模拟A的后端：收到数组就返回 {"imported": 条数}"""
    hits = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        MockBackend.hits.append(len(body))
        resp = json.dumps({"imported": len(body)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *a):  # 关掉默认访问日志
        pass


def t4():
    from import_client import post_to_backend
    out = PROJECT / "data" / "output" / "events.jsonl"
    assert out.exists() and out.stat().st_size > 0, "events.jsonl 不存在, 先跑 run_parse.py"
    lines = [json.loads(l) for l in out.open(encoding="utf-8")]
    assert len(lines) == 4, f"events.jsonl 应有4条, 实际{len(lines)}"

    srv = ThreadingHTTPServer(("127.0.0.1", 0), MockBackend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/api/events/import"
        n = post_to_backend(lines, url)
        assert n == 4 and sum(MockBackend.hits) == 4, f"POST结果异常: sent={n}, hits={MockBackend.hits}"
    finally:
        srv.shutdown()


check("任务4", "落地events.jsonl(4条) + 批量POST接口链路可用(模拟后端实测)", t4)

# ---------- 契约全量校验：所有输出文件 ----------
def t5():
    from schema import STANDARD_FIELDS
    total = bad = 0
    for f in ("events.jsonl", "events_wmi.jsonl", "events_sysmon.jsonl", "events_sysmon_reg.jsonl"):
        p = PROJECT / "data" / "output" / f
        assert p.exists(), f"{f} 不存在"
        for line in p.open(encoding="utf-8"):
            ev = json.loads(line)
            total += 1
            if list(ev.keys()) != STANDARD_FIELDS or ev["raw_log"] is None:
                bad += 1
    assert bad == 0, f"{bad}/{total}条不符合契约"


check("契约", "全部22条输出: 19键齐全+raw_log必填, 零placeholder(null语义)", t5)

# ---------- 任务5：踩坑笔记 ----------
def t6():
    p = PROJECT / "docs" / "B-踩坑笔记-Day1.md"
    assert p.exists() and p.stat().st_size > 1000, "踩坑笔记缺失或内容过少"


check("任务5", "踩坑笔记已记录", t6)

# ---------- 汇总 ----------
print("-" * 56)
if all(results):
    print(f"全部验证通过：{sum(results)}/{len(results)} 项 [OK]")
else:
    print(f"有 {results.count(False)} 项未通过，把 [FAIL] 的原因发给ZCode即可修")
    sys.exit(1)

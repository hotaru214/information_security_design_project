"""LLM 分析模块测试（成员F）——重点覆盖验收要求的"降级路径"。

形态说明（与 test_attack_chain.py 同约定）：
    单元测试直接调函数 + monkeypatch，不依赖真实 SQLite；
    接口测试用 TestClient 挂 analysis 路由，get_events/get_hosts 打桩。

覆盖场景：
    1. 没配 API key → source="fallback" 的完整报告（验收①）；
    2. LLM 请求超时（mock httpx.post 抛 TimeoutException）→ 自动降级，
       且确认重试了一次共两次调用（验收③）；
    3. 第一次解析失败、第二次成功 → source="llm"（重试路径）；
    4. LLM 编造 event_id → validate_report 过滤，只留真实数据库 id；
    5. POST /api/analysis 无 key → 200 + fallback 报告（接口层验收①）；
    6. 空事件库 → 空报告结构完整。
"""

import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import llm_analysis
from backend.llm_analysis import (
    build_attack_path,
    extract_json,
    generate_report,
    validate_report,
)
from backend.routers import analysis as analysis_module
from backend.routers.analysis import router as analysis_router


# ---------------------------------------------------------------------------
# 测试数据：3 条事件（数据库 id 1/2/3）+ 2 个关联步骤
# ---------------------------------------------------------------------------
def make_events():
    return [
        {
            "id": 1, "timestamp": "2026-09-07T09:02:08+08:00", "host": "web-server",
            "source": "network_pcap", "source_event_id": None, "event_type": "http_request",
            "user": None, "process": None, "src_ip": "203.0.113.66", "dst_ip": "10.10.20.10",
            "dst_port": 80, "protocol": "tcp", "logon_type": None, "session_id": None,
            "cmdline": None, "detail": {}, "description": "Web 攻击载荷命中",
            "anomaly_flags": ["http_attack"], "severity": 3, "raw_log": "raw-1",
        },
        {
            "id": 2, "timestamp": "2026-09-07T09:02:57+08:00", "host": "web-server",
            "source": "sysmon", "source_event_id": 1, "event_type": "process_start",
            "user": "SYSTEM", "process": "cmd.exe", "src_ip": None, "dst_ip": None,
            "dst_port": None, "protocol": None, "logon_type": None, "session_id": None,
            "cmdline": "cmd.exe /c powershell -enc AAAA", "detail": {},
            "description": "可疑进程创建", "anomaly_flags": ["suspicious_process"],
            "severity": 3, "raw_log": "raw-2",
        },
        {
            "id": 3, "timestamp": "2026-09-07T09:03:20+08:00", "host": "web-server",
            "source": "network_pcap", "source_event_id": None, "event_type": "network_connection",
            "user": None, "process": None, "src_ip": "10.10.20.10", "dst_ip": "10.10.30.10",
            "dst_port": 445, "protocol": "tcp", "logon_type": None, "session_id": None,
            "cmdline": None, "detail": {}, "description": "SMB 横向连接",
            "anomaly_flags": ["remote_service_connection"], "severity": 1, "raw_log": "raw-3",
        },
    ]


def make_steps():
    return [
        {
            "step_id": "S001", "stage": "Initial Access", "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "timestamp": "2026-09-07T09:02:08+08:00",
            "source_host": None, "target_host": "web-server",
            "source_ip": "203.0.113.66", "target_ip": "10.10.20.10",
            "description": "External HTTP request reached web-server",
            "evidence_event_ids": [1],
        },
        {
            "step_id": "S002", "stage": "Execution", "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "timestamp": "2026-09-07T09:02:57+08:00",
            "source_host": "web-server", "target_host": "web-server",
            "source_ip": None, "target_ip": None,
            "description": "Suspicious command execution on web-server",
            "evidence_event_ids": [2],
        },
        {
            "step_id": "S003", "stage": "Lateral Movement", "technique_id": "T1021",
            "technique_name": "Remote Services",
            "timestamp": "2026-09-07T09:03:20+08:00",
            "source_host": "web-server", "target_host": None,
            "source_ip": "10.10.20.10", "target_ip": "10.10.30.10",
            "description": "SMB connection to office host",
            "evidence_event_ids": [3],
        },
    ]


def force_llm_disabled(monkeypatch):
    """清掉两项 LLM 配置 → is_llm_configured() 为 False。"""
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)


# ---------------------------------------------------------------------------
# 场景①：没配 key → 降级
# ---------------------------------------------------------------------------
def test_fallback_without_api_key(monkeypatch):
    force_llm_disabled(monkeypatch)
    report = generate_report(make_steps(), make_events())

    assert report["source"] == "fallback"
    # 契约字段一个不能少（前端 report.js 按字段名渲染）；agent_trace 是
    # 多智能体编排新增的轨迹字段，降级场景也必须存在（前端如实渲染）
    assert set(report) == {
        "attack_path", "summary", "key_evidences", "mitre_mapping",
        "risk_level", "recommendations", "source", "agent_trace",
    }
    assert all(a["status"] == "degraded" for a in report["agent_trace"])
    # attack_path 来自 build_attack_graph 推导：外部攻击IP → web-server → 内网
    assert "web-server" in report["attack_path"]
    # 证据 id 必须是数据库真实 id
    assert all(e["event_id"] in {1, 2, 3} for e in report["key_evidences"])
    # 最高 severity=3 → 高危
    assert report["risk_level"] == "高危"
    # mitre_mapping 直接取 step 事实，不编造
    pairs = {(m["stage"], m["technique"]) for m in report["mitre_mapping"]}
    assert ("Initial Access", "T1190") in pairs
    assert ("Lateral Movement", "T1021") in pairs


def test_attack_path_keeps_internal_collection_branch_before_c2():
    steps = [
        {
            "stage": "Command and Control",
            "timestamp": "2026-09-08T16:55:27+08:00",
            "source_host": "win10-jump",
            "target_host": "c2-server",
            "source_ip": "10.10.30.10",
            "target_ip": "10.10.10.20",
        },
        {
            "stage": "Initial Access",
            "timestamp": "2026-09-09T10:48:43+08:00",
            "source_host": "attacker",
            "target_host": "web-server",
            "source_ip": "10.10.10.10",
            "target_ip": "10.10.20.10",
        },
        {
            "stage": "Lateral Movement",
            "timestamp": "2026-09-09T10:58:57+08:00",
            "source_host": "web-server",
            "target_host": "win10-jump",
            "source_ip": "10.10.20.10",
            "target_ip": "10.10.30.10",
        },
        {
            "stage": "Collection",
            "timestamp": "2026-09-09T12:10:54+08:00",
            "source_host": "win10-jump",
            "target_host": "core-server",
            "source_ip": "10.10.30.10",
            "target_ip": "10.10.30.20",
        },
    ]

    assert build_attack_path(steps) == [
        "attacker",
        "web-server",
        "win10-jump",
        "core-server",
        "c2-server",
    ]


# ---------------------------------------------------------------------------
# 场景②：LLM 超时（mock httpx.post 抛 TimeoutException）→ 重试一次后降级
# ---------------------------------------------------------------------------
def test_fallback_on_llm_timeout(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_MODEL", "deepseek-chat")

    calls = {"count": 0}

    def fake_post(*_args, **_kwargs):
        calls["count"] += 1
        raise httpx.TimeoutException("simulated LLM timeout")

    monkeypatch.setattr(llm_analysis.httpx, "post", fake_post)

    report = generate_report(make_steps(), make_events())

    assert report["source"] == "fallback"
    # 多智能体编排：host/network 两个领域智能体各 1 次 + 协调智能体重试
    # 一次共 2 次 = 4 次 LLM 调用，全部失败后整体降级
    assert calls["count"] == 4
    assert all(a["status"] == "degraded" for a in report["agent_trace"])


# ---------------------------------------------------------------------------
# 场景③：第一次解析失败、第二次成功 → source="llm"（重试路径）
# ---------------------------------------------------------------------------
def test_retry_after_parse_failure_then_llm_success(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")

    good_json = json.dumps({
        "attack_path": ["203.0.113.66", "web-server", "10.10.30.10"],
        "summary": "攻击者经 Web 漏洞入侵 web-server 并横向移动。",
        "key_evidences": [{"event_id": 1, "reason": "Web 攻击载荷命中"}],
        "mitre_mapping": [{"stage": "Initial Access", "technique": "T1190",
                           "evidence_event_ids": [1]}],
        "risk_level": "高危",
        "recommendations": ["修复 Web 输入校验"],
    }, ensure_ascii=False)

    responses = iter(["这不是 JSON，模型夹带了解释文字", f"```json\n{good_json}\n```"])

    def fake_call_llm(messages, _config=None):
        # 多智能体编排：领域智能体的 prompt 含 findings schema → 返回领域发现；
        # 协调智能体 → 依次返回"坏输出、好输出"，验证协调层重试一次后成功
        if '"findings"' in messages[1]["content"]:
            return json.dumps(
                {"findings": ["203.0.113.66 高频请求 web-server 80 端口"]},
                ensure_ascii=False)
        return next(responses)

    monkeypatch.setattr(llm_analysis, "call_llm", fake_call_llm)

    report = generate_report(make_steps(), make_events())

    assert report["source"] == "llm"
    assert report["key_evidences"][0]["event_id"] == 1
    assert "web-server" in report["attack_path"]


# ---------------------------------------------------------------------------
# 场景④：LLM 编造 id → validate_report 过滤
# ---------------------------------------------------------------------------
def test_validate_report_filters_fabricated_ids():
    data = {
        "attack_path": ["A", "B"],
        "summary": "s",
        "key_evidences": [
            {"event_id": 1, "reason": "real"},
            {"event_id": 99999, "reason": "fabricated"},
            {"event_id": "not-a-number", "reason": "garbage"},
        ],
        "mitre_mapping": [
            {"stage": "Execution", "technique": "T1059", "evidence_event_ids": [1, 99999]},
        ],
        "risk_level": "严重",          # 非法等级 → 保守映射为高危
        "recommendations": ["do X"],
    }
    report = validate_report(data, valid_event_ids={1, 2, 3})

    assert [e["event_id"] for e in report["key_evidences"]] == [1]
    assert report["mitre_mapping"][0]["evidence_event_ids"] == [1]
    assert report["risk_level"] == "高危"
    assert report["source"] == "llm"


def test_extract_json_tolerates_code_fence_and_prose():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('分析如下：{"a": 1} 以上。') == {"a": 1}
    with pytest.raises(ValueError):
        extract_json("完全没有 JSON")
    with pytest.raises(ValueError):
        extract_json("")


# ---------------------------------------------------------------------------
# 场景⑤：POST /api/analysis 无 key → 200 + fallback（接口层）
# ---------------------------------------------------------------------------
def test_api_endpoint_fallback_without_key(monkeypatch):
    force_llm_disabled(monkeypatch)
    monkeypatch.setattr(analysis_module, "get_events", make_events)
    monkeypatch.setattr(analysis_module, "get_hosts",
                        lambda: [{"hostname": "web-server", "ip": "10.10.20.10", "role": "web"}])

    app = FastAPI()
    app.include_router(analysis_router)
    client = TestClient(app)

    # 无请求体 = 全库分析
    response = client.post("/api/analysis")
    assert response.status_code == 200
    report = response.json()
    assert report["source"] == "fallback"
    assert "attack_path" in report and "mitre_mapping" in report

    # 带主机过滤：事件按 host 过滤后仍能出报告
    response = client.post("/api/analysis", json={"host": "web-server"})
    assert response.status_code == 200
    assert response.json()["source"] == "fallback"


# ---------------------------------------------------------------------------
# 场景⑥：空事件库 → 结构完整的空报告
# ---------------------------------------------------------------------------
def test_empty_database_report(monkeypatch):
    force_llm_disabled(monkeypatch)
    report = generate_report([], [])
    assert report["source"] == "fallback"
    assert report["attack_path"] == []
    assert report["key_evidences"] == []
    assert "未关联出攻击行为" in report["summary"]

# ---------------------------------------------------------------------------
# 场景⑦/⑧：多智能体编排（题面"大模型多智能体协调技术"）
# ---------------------------------------------------------------------------
def test_orchestration_emits_agent_trace(monkeypatch):
    """三个智能体全部成功 → agent_trace 三条、状态 ok、轨迹随报告返回。"""
    monkeypatch.setenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")

    good_report = json.dumps({
        "attack_path": ["203.0.113.66", "web-server"],
        "summary": "攻击者经 Web 漏洞入侵 web-server。",
        "key_evidences": [{"event_id": 1, "reason": "Web 攻击载荷命中"}],
        "mitre_mapping": [{"stage": "Initial Access", "technique": "T1190",
                           "evidence_event_ids": [1]}],
        "risk_level": "高危",
        "recommendations": ["修复 Web 输入校验"],
    }, ensure_ascii=False)

    def fake_call_llm(messages, _config=None):
        if '"findings"' in messages[1]["content"]:
            return json.dumps({"findings": ["领域智能体的事实发现"]}, ensure_ascii=False)
        return good_report

    monkeypatch.setattr(llm_analysis, "call_llm", fake_call_llm)
    report = generate_report(make_steps(), make_events())

    assert report["source"] == "llm"
    trace = report["agent_trace"]
    assert [a["agent"] for a in trace] == [
        "HostAnalysisAgent", "NetworkAnalysisAgent", "CorrelationAgent"]
    assert all(a["status"] == "ok" for a in trace)
    assert all("elapsed_ms" in a and "input_events" in a for a in trace)


def test_single_agent_failure_degrades_without_breaking_report(monkeypatch):
    """一个领域智能体失败 → 该智能体 degraded，报告仍由协调智能体产出。"""
    monkeypatch.setenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")

    good_report = json.dumps({
        "attack_path": ["203.0.113.66", "web-server"],
        "summary": "攻击者经 Web 漏洞入侵 web-server。",
        "key_evidences": [{"event_id": 1, "reason": "Web 攻击载荷命中"}],
        "mitre_mapping": [{"stage": "Initial Access", "technique": "T1190",
                           "evidence_event_ids": [1]}],
        "risk_level": "高危",
        "recommendations": ["修复 Web 输入校验"],
    }, ensure_ascii=False)

    def fake_call_llm(messages, _config=None):
        if '"findings"' in messages[1]["content"]:
            # 领域智能体输出畸形 JSON → 该智能体 degraded（不传染）
            return "这不是 JSON"
        return good_report

    monkeypatch.setattr(llm_analysis, "call_llm", fake_call_llm)
    report = generate_report(make_steps(), make_events())

    assert report["source"] == "llm"
    trace = report["agent_trace"]
    assert trace[0]["status"] == "degraded" or trace[1]["status"] == "degraded"
    assert trace[2]["status"] == "ok"
    assert report["key_evidences"][0]["event_id"] == 1

"""LLM 分析服务（成员F）——POST /api/analysis 的业务层。

职责边界：
    1. 输入准备：把 D 的关联结果（attack_steps）+ 证据事件摘要拼成
       精简 LLM 上下文（只取需要字段，控制 token 量，绝不整条塞 raw_log）；
    2. LLM 调用：OpenAI 兼容协议 POST {LLM_BASE_URL}/chat/completions
       （DeepSeek/千问/GLM/Kimi 均兼容，换厂商只改 .env 的 LLM_BASE_URL）；
    3. 结果解析：严格 JSON，解析失败重试一次，再失败走降级；
    4. 降级（答辩保命）：没配 key / 请求失败 / 解析失败时，用规则模板
       生成同结构报告，接口永远 200。

输出契约（前端 report.js 已按此渲染，字段名不许改）：
    attack_path      list[str]                       攻击路径节点序列
    summary          str                             攻击路径文字摘要
    key_evidences    list[{event_id, reason}]        event_id=数据库 events.id
    mitre_mapping    list[{stage, technique, evidence_event_ids}]
    risk_level       str                             低危/中危/高危
    recommendations  list[str]                       处置建议
    source           str                             "llm" | "fallback"
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

# python-dotenv 是软依赖：没装也能跑（此时只认进程环境变量）
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - 仅缺依赖时触发
    def load_dotenv(*_args: Any, **_kwargs: Any) -> bool:
        return False

# .env 放项目根（backend/ 的上一级），import 时加载进 os.environ
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

# ---------------------------------------------------------------------------
# 配置：每次调用时从环境变量读取（而不是 import 时固化），
# 这样 pytest 用 monkeypatch.setenv 就能切换"配了 key / 没配 key"两种形态。
# ---------------------------------------------------------------------------


def get_llm_config() -> dict[str, str]:
    """读取 LLM 三项配置；未配置项返回空字符串。"""
    return {
        "base_url": os.getenv("LLM_BASE_URL", "").rstrip("/"),
        "api_key": os.getenv("LLM_API_KEY", ""),
        "model": os.getenv("LLM_MODEL", "deepseek-chat"),
    }


def get_llm_timeout() -> float:
    """请求超时秒数（.env 可配 LLM_TIMEOUT_SECONDS，默认 30）。"""
    try:
        return float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
    except ValueError:
        return 30.0


def is_llm_configured() -> bool:
    """key 和 base_url 都非空才算已配置——缺一个就走降级。"""
    config = get_llm_config()
    return bool(config["base_url"]) and bool(config["api_key"])


# token 控制：证据事件超过上限时，优先保留异常事件（severity 高的排前面）。
MAX_CONTEXT_EVENTS = 120

# 固定建议清单（降级用），按出现的攻击阶段追加对应条目。
BASE_RECOMMENDATIONS = [
    "隔离受影响主机并阻断其对外通信，保存现场证据",
    "全域重置凭据并审计登录日志，确认横向移动波及范围",
]
STAGE_RECOMMENDATIONS = {
    "Initial Access": "修复对外服务的输入校验与已知漏洞（初始访问入口），排查 Web 日志中的其他入侵痕迹",
    "Execution": "排查可疑进程与计划任务，限制脚本解释器（PowerShell/cmd）的滥用",
    "Persistence": "清理注册表 Run 键、可疑服务与计划任务等持久化项",
    "Privilege Escalation": "回收异常提权账户权限，审计管理员组成员变更",
    "Lateral Movement": "加固远程服务（SMB/RDP/SSH）凭据策略，开启最小权限与访问审计",
    "Collection": "评估敏感文件访问范围，确认数据是否已被收集打包",
    "Command and Control": "封禁 C2 域名/IP，部署 DNS 与外联行为监控",
    "Exfiltration": "评估数据泄露范围并按预案上报，阻断外传通道",
    "Defense Evasion": "检查日志清除行为，接入了 SIEM 的主机恢复审计策略",
}


# ---------------------------------------------------------------------------
# 输入准备：精简事件上下文
# ---------------------------------------------------------------------------
def build_event_context(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把完整事件压缩成 LLM 需要的最小字段集（契约列出的 12 项）。

    控制策略：按 severity 降序（高危证据优先保留）+ 时间升序做次级排序，
    超过 MAX_CONTEXT_EVENTS 截断——分析主要靠异常事件，正常事件截掉不损失精度。
    """
    compact = []
    for event in events:
        detail = event.get("detail") or {}
        if not isinstance(detail, dict):
            detail = {}
        compact.append({
            "id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "host": event.get("host"),
            "event_type": event.get("event_type"),
            "user": event.get("user"),
            "process": event.get("process"),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "description": event.get("description"),
            "anomaly_flags": event.get("anomaly_flags") or [],
            "severity": event.get("severity"),
            "attack_stage": detail.get("attack_stage"),
            "mitre_technique": detail.get("mitre_technique"),
        })

    compact.sort(
        key=lambda e: (-(e["severity"] if isinstance(e["severity"], int) else 0),
                       str(e["timestamp"] or ""))
    )
    return compact[:MAX_CONTEXT_EVENTS]


def build_attack_path(attack_steps: list[dict[str, Any]],
                      internal_networks: list[str] | None = None) -> list[str]:
    """从 D 的 attack_steps 推导路径节点序列。

    攻击图里常见分支：同一跳板主机可能一边访问内网核心资产，一边回连
    C2。单纯取 BFS 的第一条最长路径会在等长分支里丢掉另一条关键边。
    因此报告用生命周期叙事路径：入口 -> 横向移动 -> 数据访问目标 ->
    C2/外传目标；拿不到叙事路径时再退回图路径。
    """
    from backend.analysis.correlation import build_attack_graph, find_attack_paths

    narrative = build_narrative_attack_path(attack_steps)
    if len(narrative) > 1:
        return narrative

    paths = find_attack_paths(attack_steps, internal_networks=internal_networks)
    if paths:
        return paths[0]
    graph = build_attack_graph(attack_steps, internal_networks)
    return [node["id"] for node in graph["nodes"]]


def build_narrative_attack_path(attack_steps: list[dict[str, Any]]) -> list[str]:
    ordered = sorted(attack_steps, key=lambda step: str(step.get("timestamp") or ""))
    path: list[str] = []

    def endpoint(step: dict[str, Any], side: str) -> str | None:
        value = step.get(f"{side}_host") or step.get(f"{side}_ip")
        return str(value) if value not in (None, "") else None

    def append_node(value: str | None) -> None:
        if value is None:
            return
        if value not in path:
            path.append(value)

    def append_edges(stage_names: set[str], *, include_source: bool = False) -> None:
        for step in ordered:
            if step.get("stage") not in stage_names:
                continue
            source = endpoint(step, "source")
            target = endpoint(step, "target")
            if source and target and source == target:
                append_node(source)
                continue
            if include_source:
                append_node(source)
            append_node(target)

    append_edges({"Initial Access"}, include_source=True)
    append_edges({"Lateral Movement"}, include_source=not path)
    append_edges({"Collection"}, include_source=not path)
    append_edges({"Exfiltration", "Command and Control"}, include_source=not path)

    return path


# ---------------------------------------------------------------------------
# Prompt 构造
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "你是一名企业安全溯源分析专家（SOC analysts / threat hunting）。"
    "你会收到一次入侵事件的关联攻击步骤（attack steps）与证据事件摘要。"
    "你的任务：还原攻击路径、引用关键证据、映射 ATT&CK 技术、评估风险并给出处置建议。"
    "必须遵守：1) 只输出一个 JSON 对象，不要输出任何解释文字或 markdown 代码块；"
    "2) key_evidences 的 event_id 与 mitre_mapping 的 evidence_event_ids 只能使用"
    "输入里出现过的数据库事件 id，禁止编造；"
    "3) mitre_mapping 的 technique 只使用证据事实支持的 ATT&CK 编号，不许臆测。"
)

RESPONSE_SCHEMA_EXAMPLE = """{
  "attack_path": ["攻击者IP或主机", "第一台受害主机", "...", "C2/外传目标"],
  "summary": "150字以内的攻击路径中文摘要，说明入侵入口、执行方式、横向路径、最终动作",
  "key_evidences": [
    {"event_id": 12, "reason": "中文说明该事件为何是关键证据"}
  ],
  "mitre_mapping": [
    {"stage": "Execution", "technique": "T1059", "evidence_event_ids": [12, 15]}
  ],
  "risk_level": "高危",
  "recommendations": ["中文处置建议1", "中文处置建议2"]
}"""


def build_user_prompt(attack_steps: list[dict[str, Any]],
                      context_events: list[dict[str, Any]],
                      attack_path_hint: list[str]) -> str:
    """组装用户消息：关联结果 + 事件摘要 + 输出 schema。"""
    steps_digest = [
        {
            "stage": step.get("stage"),
            "technique": step.get("technique_id"),
            "timestamp": step.get("timestamp"),
            "source": step.get("source_host") or step.get("source_ip"),
            "target": step.get("target_host") or step.get("target_ip"),
            "description": step.get("description"),
            "evidence_event_ids": step.get("evidence_event_ids", []),
        }
        for step in attack_steps
    ]
    return (
        "【攻击路径参考（由规则关联引擎推导，可修正）】\n"
        f"{json.dumps(attack_path_hint, ensure_ascii=False)}\n\n"
        "【关联攻击步骤】\n"
        f"{json.dumps(steps_digest, ensure_ascii=False)}\n\n"
        "【证据事件摘要（event_id 为数据库唯一 id）】\n"
        f"{json.dumps(context_events, ensure_ascii=False)}\n\n"
        "请严格按以下 JSON schema 输出（不要输出多余文字）：\n"
        f"{RESPONSE_SCHEMA_EXAMPLE}"
    )


# ---------------------------------------------------------------------------
# LLM 调用与 JSON 解析
# ---------------------------------------------------------------------------
def call_llm(messages: list[dict[str, str]], config: dict[str, str] | None = None) -> str:
    """OpenAI 兼容协议调用。网络错误/超时/非 200 一律抛 LLMRequestError。"""
    config = config or get_llm_config()
    url = f"{config['base_url']}/chat/completions"
    try:
        response = httpx.post(
            url,
            headers={"Authorization": f"Bearer {config['api_key']}"},
            json={
                "model": config["model"],
                "messages": messages,
                "temperature": 0.2,   # 溯源分析要克制，别让模型自由发挥
            },
            timeout=get_llm_timeout(),
        )
        response.raise_for_status()
        payload = response.json()
        return payload["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMRequestError(f"LLM request failed: {exc}") from exc


class LLMRequestError(Exception):
    """LLM 请求失败（超时/网络/HTTP错误/响应结构异常）——由调用方决定重试或降级。"""


def extract_json(text: str) -> dict[str, Any]:
    """从 LLM 回复中提取 JSON 对象。

    容忍三种脏输出：```json 围栏、前后夹杂的解释文字、首尾空白。
    提取不到合法 JSON 抛 ValueError（触发重试/降级）。
    """
    if not text:
        raise ValueError("empty LLM response")
    cleaned = text.strip()
    if cleaned.startswith("```"):
        # 去掉 ```json ... ``` 围栏
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object found in LLM response")
    return json.loads(cleaned[start:end + 1])


# ---------------------------------------------------------------------------
# 结果校验与修复（LLM 输出不可信，逐字段强校验）
# ---------------------------------------------------------------------------
def validate_report(data: Any, valid_event_ids: set[int]) -> dict[str, Any]:
    """把 LLM 返回的任意结构修剪成输出契约；结构性缺失直接抛 ValueError。"""
    if not isinstance(data, dict):
        raise ValueError("LLM report is not a JSON object")

    attack_path = data.get("attack_path")
    if not isinstance(attack_path, list) or not attack_path:
        raise ValueError("attack_path missing or empty")
    attack_path = [str(node) for node in attack_path if node is not None]
    if not attack_path:
        raise ValueError("attack_path has no valid nodes")

    key_evidences = []
    for item in data.get("key_evidences") or []:
        if not isinstance(item, dict):
            continue
        event_id = item.get("event_id")
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            continue
        if event_id not in valid_event_ids:
            continue    # 编造的 id 直接丢弃（答辩抽查点）
        key_evidences.append({
            "event_id": event_id,
            "reason": str(item.get("reason") or "")[:200],
        })

    mitre_mapping = []
    for item in data.get("mitre_mapping") or []:
        if not isinstance(item, dict):
            continue
        stage = str(item.get("stage") or "").strip()
        technique = str(item.get("technique") or "").strip()
        if not stage or not technique:
            continue
        raw_ids = item.get("evidence_event_ids") or []
        if not isinstance(raw_ids, list):
            raw_ids = []
        evidence_ids = []
        for raw_id in raw_ids:
            try:
                numeric = int(raw_id)
            except (TypeError, ValueError):
                continue
            if numeric in valid_event_ids and numeric not in evidence_ids:
                evidence_ids.append(numeric)
        mitre_mapping.append({
            "stage": stage,
            "technique": technique,
            "evidence_event_ids": evidence_ids,
        })

    recommendations_raw = data.get("recommendations") or []
    if not isinstance(recommendations_raw, list):
        recommendations_raw = []
    recommendations = [str(item) for item in recommendations_raw if item is not None]
    if not recommendations:
        raise ValueError("recommendations missing")

    risk_level = str(data.get("risk_level") or "").strip()
    if risk_level not in {"低危", "中危", "高危"}:
        # LLM 给了不认识的等级（如"严重"）→ 保守映射为高危
        risk_level = "高危" if risk_level else "中危"

    return {
        "attack_path": attack_path,
        "summary": str(data.get("summary") or "").strip(),
        "key_evidences": key_evidences,
        "mitre_mapping": mitre_mapping,
        "risk_level": risk_level,
        "recommendations": recommendations,
        "source": "llm",
    }


# ---------------------------------------------------------------------------
# 降级报告（规则模板，结构同契约）
# ---------------------------------------------------------------------------
def generate_fallback_report(attack_steps: list[dict[str, Any]],
                             events_by_id: dict[int, dict[str, Any]],
                             attack_path: list[str] | None = None) -> dict[str, Any]:
    """无 key / LLM 失败时的规则模板报告。

    attack_path：调用方传入（build_attack_graph 推导）；
    summary：按阶段顺序拼模板句；
    key_evidences：每个 attack_step 取 severity 最高的证据事件；
    mitre_mapping：直接取 step 已有的 stage/technique（不编造）；
    risk_level：证据事件最高 severity 映射（3→高危/2→中危/其余→低危）；
    recommendations：按出现阶段从固定清单取。
    """
    if not attack_path:
        attack_path = []

    stages_in_order: list[str] = []
    for step in attack_steps:
        stage = step.get("stage")
        if stage and stage not in stages_in_order:
            stages_in_order.append(stage)

    summary = _build_summary(attack_steps, attack_path)

    key_evidences = []
    for step in attack_steps:
        candidates = [events_by_id[eid] for eid in step.get("evidence_event_ids", [])
                      if eid in events_by_id]
        if not candidates:
            continue
        top = max(candidates, key=lambda e: e.get("severity") if isinstance(e.get("severity"), int) else -1)
        key_evidences.append({
            "event_id": top.get("id"),
            "reason": f"{step.get('stage')}阶段（{step.get('technique_id')}）：{step.get('description')}",
        })

    mitre_mapping = []
    seen_pairs: set[tuple[str, str]] = set()
    for step in attack_steps:
        pair = (step.get("stage"), step.get("technique_id"))
        if pair in seen_pairs or not all(pair):
            continue
        seen_pairs.add(pair)
        mitre_mapping.append({
            "stage": pair[0],
            "technique": pair[1],
            "evidence_event_ids": list(step.get("evidence_event_ids", [])),
        })

    severities = [
        e.get("severity") for e in events_by_id.values()
        if isinstance(e.get("severity"), int)
    ]
    max_severity = max(severities) if severities else 0
    risk_level = {3: "高危", 2: "中危"}.get(max_severity, "低危")

    recommendations = list(BASE_RECOMMENDATIONS)
    recommendations += [STAGE_RECOMMENDATIONS[s] for s in stages_in_order
                        if s in STAGE_RECOMMENDATIONS]

    return {
        "attack_path": attack_path,
        "summary": summary,
        "key_evidences": key_evidences,
        "mitre_mapping": mitre_mapping,
        "risk_level": risk_level,
        "recommendations": recommendations,
        "source": "fallback",
    }


def _build_summary(attack_steps: list[dict[str, Any]], attack_path: list[str]) -> str:
    """按攻击生命周期顺序把每个阶段拼成一句模板话，节点用 host ?? ip。"""
    if not attack_steps:
        return "当前事件库中未关联出攻击行为。"

    def node_text(step: dict[str, Any], side: str) -> str:
        host = step.get(f"{side}_host")
        ip = step.get(f"{side}_ip")
        return str(host or ip or "?")

    lifecycle_order = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Defense Evasion",
    ]
    first_by_stage = {}
    for step in sorted(attack_steps, key=lambda item: str(item.get("timestamp") or "")):
        stage = step.get("stage") or ""
        if stage and stage not in first_by_stage:
            first_by_stage[stage] = step

    stage_phrases: list[str] = []
    for stage in lifecycle_order:
        step = first_by_stage.get(stage)
        if not step:
            continue
        phrase = {
            "Initial Access": f"经 {node_text(step, 'source')} 入侵 {node_text(step, 'target')}",
            "Execution": f"在 {node_text(step, 'source')} 执行异常进程",
            "Persistence": f"在 {node_text(step, 'source')} 建立持久化",
            "Privilege Escalation": f"在 {node_text(step, 'source')} 提升权限",
            "Lateral Movement": f"横向移动至 {node_text(step, 'target')}",
            "Collection": f"在 {node_text(step, 'source')} 收集敏感数据",
            "Command and Control": f"连接外部 C2（{node_text(step, 'target')}）",
            "Exfiltration": f"向 {node_text(step, 'target')} 外传数据",
            "Defense Evasion": f"在 {node_text(step, 'source')} 清除日志反取证",
        }.get(stage)
        if phrase:
            stage_phrases.append(phrase)

    summary = "攻击者" + " → ".join(stage_phrases) + "。"
    if attack_path:
        summary += f"完整攻击路径：{' → '.join(str(n) for n in attack_path)}。"
    return summary


# ---------------------------------------------------------------------------
# 编排入口：LLM 优先，失败降级（接口永远能拿到完整报告）
# ---------------------------------------------------------------------------
def generate_report(attack_steps: list[dict[str, Any]],
                    events: list[dict[str, Any]],
                    internal_networks: list[str] | None = None) -> dict[str, Any]:
    """生成溯源分析报告：LLM 优先 → 解析失败重试一次 → 规则模板降级。

    所有分支的返回值都是同一结构（含 source 标记来源），路由层不做二次处理。
    """
    events_by_id: dict[int, dict[str, Any]] = {
        event["id"]: event for event in events if event.get("id") is not None
    }
    attack_path = build_attack_path(attack_steps, internal_networks)

    if not attack_steps:
        # 没有关联出任何攻击行为：直接给空报告（不浪费 LLM 调用）
        return {
            "attack_path": attack_path,
            "summary": "当前事件库中未关联出攻击行为。",
            "key_evidences": [],
            "mitre_mapping": [],
            "risk_level": "低危",
            "recommendations": ["继续保持日志与流量采集，扩大部分覆盖以积累分析素材"],
            "source": "fallback",
        }

    if not is_llm_configured():
        return generate_fallback_report(attack_steps, events_by_id, attack_path)

    context_events = build_event_context(events)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt(attack_steps, context_events, attack_path)},
    ]

    # 最多两次尝试：首次失败（请求/解析）重试一次，再失败降级
    last_error: Exception | None = None
    for _attempt in range(2):
        try:
            raw = call_llm(messages)
            report = validate_report(extract_json(raw), set(events_by_id))
            if not report["summary"]:
                report["summary"] = _build_summary(attack_steps, attack_path)
            return report
        except (LLMRequestError, ValueError, json.JSONDecodeError) as exc:
            last_error = exc

    # 降级时在日志层面留痕（答辩时说明"LLM 不可用自动降级"就是这条）
    print(f"[llm_analysis] LLM analysis failed after retry, fallback used: {last_error}")
    return generate_fallback_report(attack_steps, events_by_id, attack_path)

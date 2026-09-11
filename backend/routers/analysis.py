"""POST /api/analysis —— LLM 溯源分析报告（成员F）。

流程：取事件（可按主机/时间范围过滤）→ D 的关联引擎产 attack_steps →
llm_analysis.generate_report（LLM 优先，失败降级规则模板）→ 固定 JSON 契约。
接口永远 200：LLM 不可用不影响前端拿到 source="fallback" 的完整报告。
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.analysis import build_attribution_profile, correlate_events
from backend.database import get_events, get_hosts
from backend.llm_analysis import generate_report
from backend.routers.attack_chain import DEFAULT_INTERNAL_NETWORKS

router = APIRouter(prefix="/api/analysis")


class AnalysisRequest(BaseModel):
    """可选过滤条件：不传或全空 = 全库分析（前端默认就是全量）。"""

    case_id: str | None = None   # 仅分析某个批次（events.case_id / detail.batch_id）
    host: str | None = None      # 仅分析某台主机相关的事件
    start: str | None = None     # ISO8601（UTC+8），如 2026-09-07T09:00:00+08:00
    end: str | None = None


def filter_events(events: list[dict], request: AnalysisRequest | None) -> list[dict]:
    """按主机/时间范围过滤事件。时间用字符串比较即可——Event V2 契约保证
    所有 timestamp 都是同一格式（ISO8601 统一 +08:00），同格式字符串的
    字典序 == 时间序，无需解析成 datetime。"""
    if request is None:
        return events

    def event_in_range(timestamp: str | None) -> bool:
        if not isinstance(timestamp, str) or len(timestamp) < 19:
            return False    # 无有效时间的事件不落在任何区间内
        if request.start and timestamp < request.start:
            return False
        if request.end and timestamp > request.end:
            return False
        return True

    filtered = events
    if request.host:
        filtered = [e for e in filtered if e.get("host") == request.host]
    if request.start or request.end:
        filtered = [e for e in filtered if event_in_range(e.get("timestamp"))]
    return filtered


@router.post("")
def analyze(request: AnalysisRequest | None = None):
    events = get_events(case_id=request.case_id) if (request and request.case_id) else get_events()
    events = filter_events(events, request)
    host_map = {host["ip"]: host["hostname"] for host in get_hosts()}
    attack_steps = correlate_events(
        events, host_map, internal_networks=DEFAULT_INTERNAL_NETWORKS
    )
    # 多智能体溯源：把 D 的攻击者画像 / APT TTP 相似性匹配一并交给协调智能体。
    # 画像不可用（数据缺失/异常）时传 None——协调智能体没有画像照常工作，
    # 失败只影响报告的归因区块，绝不影响"永远 200"。
    try:
        attribution = build_attribution_profile(
            events, attack_steps, host_map=host_map,
            internal_networks=DEFAULT_INTERNAL_NETWORKS,
        )
    except Exception as exc:
        print(f"[analysis] attribution unavailable, correlation agent runs without profile: {exc}")
        attribution = None
    return generate_report(
        attack_steps, events, internal_networks=DEFAULT_INTERNAL_NETWORKS,
        attribution=attribution,
    )

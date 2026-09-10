"""数据导入与批次管理路由（2026-09-10 平台化需求）。

GET  /api/batches   批次清单（case_id/事件数/告警数/时间范围/来源分布）
POST /api/ingest    上传原始数据文件 -> 服务端自动嗅探解析 -> 打 case_id 入库

支持的数据类型（自动按扩展名/内容分发）：
  网络侧（C 模块）：.pcap/.pcapng/.cap、Zeek 日志（.log/.json，含合并 JSON 流）、
                   OPNsense filterlog、通用连接 CSV
  主机侧（B 模块）：.evtx（Windows）、auditd/auth 日志（.log/.txt）——
                   依赖 python-evtx，未安装时该文件返回错误不中断
解析完成后统一打 case_id 入库（EventCreate 校验，无效行跳过计数）。
"""
import shutil
import sys
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from backend.analysis.correlation import get_case_id
from backend.database import get_events, insert_events
from backend.parsers.network import analyze_paths
from backend.schemas.event import EventCreate

router = APIRouter(prefix="/api")

INGEST_ROOT = Path(__file__).resolve().parent.parent / "data" / "ingest"
B_PARSER_DIR = Path(__file__).resolve().parent.parent / "b_host_parser"

_NETWORK_EXTS = {".pcap", ".pcapng", ".cap", ".csv", ".json"}
_LOG_EXTS = {".log", ".txt", ".out"}


def _classify(path: Path) -> str:
    """按扩展名+内容把上传文件分派给 C 网络解析 / B 主机解析。"""
    suffix = path.suffix.lower()
    if suffix in _NETWORK_EXTS:
        return "network"
    if suffix == ".evtx":
        return "host_windows"
    if suffix in _LOG_EXTS:
        content = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if "filterlog" in content:
            return "network"           # filterlog 也是 C 的输入
        host_markers = ("audit(", "type=SYSCALL", "sshd", "sudo")
        if any(m in content for m in host_markers):
            return "host_linux"
        return "unknown"
    return "unknown"


def _parse_with_b(path: Path, kind_hint: str) -> list:
    """调用 B 模块解析主机日志（扁平导入需注入 b_host_parser 目录到 sys.path）。"""
    if str(B_PARSER_DIR) not in sys.path:
        sys.path.insert(0, str(B_PARSER_DIR))
    import run_parse  # noqa: E402  （B 模块统一入口：detect_parser_for/parse_file/enrich）

    kind = kind_hint or run_parse.detect_parser_for(path) or ""
    events, _stats = run_parse.parse_file(Path(path), kind)
    return run_parse.enrich(events)


def _events_to_ingested(events: list, case_id: str) -> tuple[list, list]:
    """dict 事件 -> (合法 EventCreate 列表, 错误列表)，并打顶层 case_id。"""
    valid, errors = [], []
    for i, e in enumerate(events):
        e["case_id"] = case_id
        try:
            valid.append(EventCreate(**e))
        except Exception as exc:
            errors.append(f"第{i + 1}条不合规: {str(exc)[:120]}")
    return valid, errors


@router.get("/batches")
def list_batches():
    """批次清单：按 get_case_id 归组，含事件数/告警数/时间范围/来源分布。"""
    from collections import Counter

    events = get_events()
    groups = {}
    for e in events:
        cid = get_case_id(e) or "default"
        g = groups.setdefault(cid, {"case_id": cid, "count": 0, "alerts": 0,
                                    "sources": Counter(), "timestamps": []})
        g["count"] += 1
        if e.get("anomaly_flags"):
            g["alerts"] += 1
        g["sources"][e.get("source") or "?"] += 1
        ts = e.get("timestamp")
        if isinstance(ts, str):
            g["timestamps"].append(ts)
    out = []
    for cid, g in sorted(groups.items()):
        ts_list = sorted(g["timestamps"])
        out.append({
            "case_id": cid,
            "count": g["count"],
            "alert_count": g["alerts"],
            "sources": dict(g["sources"]),
            "first_ts": ts_list[0] if ts_list else None,
            "last_ts": ts_list[-1] if ts_list else None,
        })
    return {"batches": out, "total": len(events)}


@router.post("/ingest")
async def ingest(case_id: str = Form(...), files: list[UploadFile] = File(...)):
    """上传原始数据 -> 自动解析 -> 打 case_id 入库。

    case_id 即批次名（如 case03/incident-2026）；同名批次会追加事件。
    """
    case_id = case_id.strip()
    if not case_id or any(ch in case_id for ch in ("/", chr(92), " ")):
        raise HTTPException(status_code=422, detail="case_id 不能为空且不含斜杠/空格")

    ingest_dir = INGEST_ROOT / case_id
    ingest_dir.mkdir(parents=True, exist_ok=True)

    all_events, per_file = [], []
    total_imported, total_failed = 0, 0
    for uf in files:
        dest = ingest_dir / Path(uf.filename or "upload.bin").name
        with open(dest, "wb") as fh:
            fh.write(await uf.read())
        kind = _classify(dest)
        entry = {"file": dest.name, "parser": kind, "events": 0, "error": None}
        try:
            if kind == "network":
                events, _flows, _anoms, _stats = analyze_paths([str(dest)])
            elif kind == "host_windows":
                events = _parse_with_b(dest, "windows")
            elif kind == "host_linux":
                events = _parse_with_b(dest, "linux")
            else:
                events = _parse_with_b(dest, "")
            valid, errors = _events_to_ingested(events, case_id)
            if valid:
                insert_events(valid)
            entry["events"] = len(valid)
            total_imported += len(valid)
            total_failed += len(events) - len(valid)
            if errors:
                entry["errors"] = errors[:5]
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        per_file.append(entry)

    return {"case_id": case_id, "imported": total_imported,
            "failed": total_failed, "per_file": per_file,
            "hint": f"切换/查看该批次: 页眉下拉选 {case_id}；攻击链: GET /api/attack-chain?case_id={case_id}"}


from __future__ import annotations

import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .agent_client import AgentCallError, call_agent
from .config import get_settings
from .ip_geo import lookup_ip_geo
from .storage import (
    add_blocked_ip,
    bulk_update_log_status,
    cache_ip_geo,
    get_cached_ip_geo,
    get_log_detail,
    get_overview,
    get_screen_data,
    init_db,
    list_blocked_ips,
    list_logs,
    remove_blocked_ip,
    update_log_status,
)


settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="magualine-admin")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _to_compact_json(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _truncate_text(value: object, limit: int = 600) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...(已截断)"


def _prepare_overview_for_agent(overview: dict) -> dict:
    compact = dict(overview)
    compact["latest_high_risk_alerts"] = (overview.get("latest_high_risk_alerts") or [])[:5]
    compact["recent_alert_stream"] = (overview.get("recent_alert_stream") or [])[:8]
    compact["top_source_ips"] = (overview.get("top_source_ips") or [])[:8]
    compact["top_attack_types"] = (overview.get("top_attack_types") or [])[:8]
    compact["top_paths"] = (overview.get("top_paths") or [])[:8]
    compact["geo_buckets"] = (overview.get("geo_buckets") or [])[:8]
    compact["hourly_trend"] = (overview.get("hourly_trend") or [])[-12:]
    return compact


def _prepare_log_detail_for_agent(log_detail: dict) -> dict:
    headers = log_detail.get("request_headers")
    if isinstance(headers, dict):
        compact_headers = {}
        for key in (
            "host",
            "user-agent",
            "content-type",
            "referer",
            "origin",
            "x-forwarded-for",
            "authorization",
            "cookie",
        ):
            value = headers.get(key)
            if value is not None:
                compact_headers[key] = _truncate_text(value, 180)
        headers = compact_headers

    return {
        "id": log_detail.get("id"),
        "created_at": log_detail.get("created_at"),
        "client_ip": log_detail.get("client_ip"),
        "destination_host": log_detail.get("destination_host"),
        "destination_ip": log_detail.get("destination_ip"),
        "ip_geo": log_detail.get("ip_geo", {}),
        "method": log_detail.get("method"),
        "path": log_detail.get("path"),
        "query_string": _truncate_text(log_detail.get("query_string"), 300),
        "action": log_detail.get("action"),
        "attack_type": log_detail.get("attack_type"),
        "attack_detail": _truncate_text(log_detail.get("attack_detail"), 500),
        "cve_id": log_detail.get("cve_id"),
        "severity": log_detail.get("severity"),
        "alert_status": log_detail.get("alert_status"),
        "handled_status": log_detail.get("handled_status"),
        "status_code": log_detail.get("status_code"),
        "upstream_status": log_detail.get("upstream_status"),
        "duration_ms": log_detail.get("duration_ms"),
        "request_headers": headers or {},
        "body_preview": _truncate_text(log_detail.get("body_preview"), 1200),
    }


def _build_overview_prompt(overview: dict, alert_samples: list[dict], blocked_ips: list[dict]) -> str:
    return (
        "任务模式：overview_24h\n"
        "请你基于输入的数据完成过去 24 小时安全态势分析，输出 JSON。\n"
        "必须包含：summary、attack_top_ips、severity_top_ips、key_findings、actions_now、actions_today、watch_list、rule_improvement_directions、false_positive_risks、confidence。\n"
        "分类标准：real_attack/customer_business/pending_business/notified_event。\n\n"
        f"overview={_to_compact_json(_prepare_overview_for_agent(overview))}\n"
        f"alert_samples={_to_compact_json(alert_samples)}\n"
        f"blocked_ips={_to_compact_json(blocked_ips)}\n"
    )


def _build_single_log_prompt(log_detail: dict) -> str:
    return (
        "任务模式：single_flow_triage\n"
        "请对单条流量进行研判，输出 JSON。\n"
        "必须包含：disposition、risk_level、confidence、attack_analysis、evidence、uncertainties、suggested_actions、ip_block_suggestion、rule_patch_suggestion。\n"
        "分类值只能是：real_attack/customer_business/pending_business/notified_event。\n\n"
        f"log_detail={_to_compact_json(_prepare_log_detail_for_agent(log_detail))}\n"
    )


def _normalize_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _build_overview_display(parsed: dict, raw_text: str) -> dict:
    if not parsed:
        return {
            "title": "AI 态势分析",
            "summary": raw_text or "模型未返回结构化结果",
            "key_findings": [],
            "actions_now": [],
            "actions_today": [],
            "watch_list": [],
        }

    return {
        "title": str(parsed.get("title") or "AI 态势分析"),
        "summary": str(parsed.get("summary") or parsed.get("overall_summary") or ""),
        "key_findings": _normalize_list(parsed.get("key_findings")),
        "actions_now": _normalize_list(parsed.get("actions_now")),
        "actions_today": _normalize_list(parsed.get("actions_today")),
        "watch_list": _normalize_list(parsed.get("watch_list")),
        "rule_improvement_directions": _normalize_list(parsed.get("rule_improvement_directions")),
        "false_positive_risks": _normalize_list(parsed.get("false_positive_risks")),
        "confidence": parsed.get("confidence", ""),
    }


def _build_log_display(parsed: dict, raw_text: str) -> dict:
    if not parsed:
        return {
            "title": "AI 单条流量研判",
            "summary": raw_text or "模型未返回结构化结果",
            "disposition": "pending_business",
            "risk_level": "medium",
            "confidence": "",
            "evidence": [],
            "suggested_actions": [],
        }

    disposition = str(parsed.get("disposition") or "pending_business")
    risk_level = str(parsed.get("risk_level") or "medium")
    title = str(parsed.get("title") or f"AI 研判：{disposition} / {risk_level}")
    summary = str(parsed.get("attack_analysis") or parsed.get("summary") or "")

    return {
        "title": title,
        "summary": summary,
        "disposition": disposition,
        "risk_level": risk_level,
        "confidence": parsed.get("confidence", ""),
        "evidence": _normalize_list(parsed.get("evidence")),
        "uncertainties": _normalize_list(parsed.get("uncertainties")),
        "suggested_actions": _normalize_list(parsed.get("suggested_actions")),
        "rule_patch_suggestion": parsed.get("rule_patch_suggestion", []),
    }


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def require_api_auth(request: Request) -> None:
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="请先登录")


@app.on_event("startup")
async def startup() -> None:
    init_db()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"app_name": "magualine"},
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"app_name": "magualine", "active_page": "dashboard"},
    )


@app.get("/screen", response_class=HTMLResponse)
async def screen_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="screen.html",
        context={"app_name": "magualine", "active_page": "screen"},
    )


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={"app_name": "magualine", "active_page": "logs"},
    )


@app.get("/block", response_class=HTMLResponse)
async def block_page(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="block.html",
        context={"app_name": "magualine", "active_page": "block"},
    )


@app.post("/api/login")
async def login(request: Request):
    payload = await request.json()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if username != settings.admin_username or password != settings.admin_password:
        return JSONResponse(status_code=401, content={"message": "用户名或密码错误"})

    request.session["authenticated"] = True
    request.session["username"] = username
    return {"message": "ok"}


@app.post("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "ok"}


@app.get("/api/runtime")
async def runtime(request: Request):
    require_api_auth(request)
    return {"app_name": "magualine", "username": request.session.get("username", "admin")}


@app.get("/api/overview")
async def overview(request: Request):
    require_api_auth(request)
    return get_overview(hours=24)


@app.get("/api/screen")
async def screen_data(request: Request):
    require_api_auth(request)
    return get_screen_data(hours=24)


@app.post("/api/agent/overview-24h")
async def agent_overview(request: Request):
    require_api_auth(request)
    payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    session_id = str(payload.get("session_id", "")).strip() or None

    overview_data = get_overview(hours=24)
    alert_samples = list_logs(page=1, page_size=12, alerts_only=True).get("items", [])
    blocked_ips_payload = list_blocked_ips(page=1, page_size=12)
    blocked_ips = blocked_ips_payload.get("items", [])
    prompt = _build_overview_prompt(overview_data, alert_samples, blocked_ips)

    try:
        result = call_agent(prompt, session_id=session_id)
    except AgentCallError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}
    return {
        "display": _build_overview_display(parsed, str(result.get("raw_text", ""))),
        "raw": parsed or {"raw_text": result.get("raw_text", "")},
        "usage": result.get("usage", {}),
        "session_id": result.get("session_id", ""),
        "request_id": result.get("request_id", ""),
    }


@app.get("/api/logs")
async def logs(
    request: Request,
    alerts_only: bool = False,
    action: str | None = None,
    keyword: str | None = None,
    severity: str | None = None,
    alert_status: str | None = None,
    handled_status: str | None = None,
    page: int = 1,
    page_size: int = 20,
):
    require_api_auth(request)
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    return list_logs(
        page=page,
        page_size=page_size,
        alerts_only=alerts_only,
        action=action or None,
        keyword=keyword or None,
        severity=severity or None,
        alert_status=alert_status or None,
        handled_status=handled_status or None,
    )


@app.get("/api/logs/{log_id}")
async def log_detail(log_id: int, request: Request):
    require_api_auth(request)
    detail = get_log_detail(log_id)
    if not detail:
        raise HTTPException(status_code=404, detail="日志不存在")

    ip = detail.get("client_ip", "")
    geo = get_cached_ip_geo(ip)
    if not geo:
        geo = lookup_ip_geo(ip)
        cache_ip_geo(ip, geo)

    detail["ip_geo"] = geo
    return detail


@app.post("/api/agent/log/{log_id}/analyze")
async def agent_log_analyze(log_id: int, request: Request):
    require_api_auth(request)
    payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    session_id = str(payload.get("session_id", "")).strip() or None

    detail = get_log_detail(log_id)
    if not detail:
        raise HTTPException(status_code=404, detail="日志不存在")

    ip = detail.get("client_ip", "")
    geo = get_cached_ip_geo(ip)
    if not geo:
        geo = lookup_ip_geo(ip)
        cache_ip_geo(ip, geo)
    detail["ip_geo"] = geo

    prompt = _build_single_log_prompt(detail)
    try:
        result = call_agent(prompt, session_id=session_id)
    except AgentCallError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}
    return {
        "display": _build_log_display(parsed, str(result.get("raw_text", ""))),
        "raw": parsed or {"raw_text": result.get("raw_text", "")},
        "usage": result.get("usage", {}),
        "session_id": result.get("session_id", ""),
        "request_id": result.get("request_id", ""),
    }


@app.patch("/api/logs/{log_id}/status")
async def patch_log_status(log_id: int, request: Request):
    require_api_auth(request)
    payload = await request.json()
    alert_status = str(payload.get("alert_status", "")).strip()

    if alert_status not in {"real_attack", "customer_business", "pending_business", "notified_event"}:
        raise HTTPException(status_code=400, detail="处置分类不合法")

    update_log_status(log_id, alert_status)
    return {"message": "ok"}


@app.post("/api/logs/disposition/bulk")
async def bulk_patch_log_status(request: Request):
    require_api_auth(request)
    payload = await request.json()
    alert_status = str(payload.get("alert_status", "")).strip()
    log_ids = payload.get("log_ids", [])

    if alert_status not in {"real_attack", "customer_business", "pending_business", "notified_event"}:
        raise HTTPException(status_code=400, detail="处置分类不合法")
    if not isinstance(log_ids, list) or not log_ids:
        raise HTTPException(status_code=400, detail="请选择需要处置的流量记录")

    bulk_update_log_status(log_ids, alert_status)
    return {"message": "ok"}


@app.get("/api/blocked-ips")
async def blocked_ips(request: Request, page: int = 1, page_size: int = 20):
    require_api_auth(request)
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    return list_blocked_ips(page=page, page_size=page_size)


@app.post("/api/blocked-ips")
async def create_blocked_ip(request: Request):
    require_api_auth(request)
    payload = await request.json()
    ip = str(payload.get("ip", "")).strip()
    reason = str(payload.get("reason", "")).strip()

    if not ip:
        raise HTTPException(status_code=400, detail="IP 地址不能为空")

    add_blocked_ip(ip, reason or "手动封禁", created_by=request.session.get("username", "admin"))
    return {"message": "ok"}


@app.delete("/api/blocked-ips/{record_id}")
async def delete_blocked_ip(record_id: int, request: Request):
    require_api_auth(request)
    remove_blocked_ip(record_id)
    return {"message": "ok"}


if __name__ == "__main__":
    uvicorn.run("app.admin:app", host="0.0.0.0", port=9443)

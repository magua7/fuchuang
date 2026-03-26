from __future__ import annotations

from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
from .ip_geo import lookup_ip_geo
from .storage import (
    add_blocked_ip,
    bulk_update_log_status,
    cache_ip_geo,
    get_cached_ip_geo,
    get_log_detail,
    get_overview,
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


@app.patch("/api/logs/{log_id}/status")
async def patch_log_status(log_id: int, request: Request):
    require_api_auth(request)
    payload = await request.json()
    alert_status = str(payload.get("alert_status", "")).strip()

    if alert_status not in {"real_attack", "customer_business", "pending_business", "notified_event"}:
        raise HTTPException(status_code=400, detail="告警状态不合法")

    update_log_status(log_id, alert_status)
    return {"message": "ok"}


@app.post("/api/logs/disposition/bulk")
async def bulk_patch_log_status(request: Request):
    require_api_auth(request)
    payload = await request.json()
    alert_status = str(payload.get("alert_status", "")).strip()
    log_ids = payload.get("log_ids", [])

    if alert_status not in {"real_attack", "customer_business", "pending_business", "notified_event"}:
        raise HTTPException(status_code=400, detail="告警状态不合法")
    if not isinstance(log_ids, list) or not log_ids:
        raise HTTPException(status_code=400, detail="请选择需要处置的告警")

    bulk_update_log_status(log_ids, alert_status)
    return {"message": "ok"}


@app.get("/api/blocked-ips")
async def blocked_ips(request: Request):
    require_api_auth(request)
    return {"items": list_blocked_ips()}


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

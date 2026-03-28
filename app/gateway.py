from __future__ import annotations

import json
import socket
import time
from functools import lru_cache
from ipaddress import ip_address
from typing import Iterable
from urllib.parse import urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, Response as FastAPIResponse

from .config import get_settings
from .detection import inspect_request, looks_like_auth_attempt
from .storage import (
    add_auth_attempt,
    add_blocked_ip,
    add_log,
    clear_recent_auth_failures,
    count_recent_auth_failures,
    get_block_reason,
    init_db,
)


HOP_BY_HOP_HEADERS = {
    "accept-encoding",
    "connection",
    "content-encoding",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


settings = get_settings()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="magualine-gateway")
BRUTE_FORCE_THRESHOLD = 8


def display_rule_name(rule_name: str | None) -> str:
    mapping = {
        "manual_block": "手动封禁",
        "sql_injection": "SQL 注入",
        "xss": "跨站脚本",
        "path_traversal": "目录穿越",
        "command_injection": "命令注入",
        "scanner_probe": "扫描探测",
        "webshell_upload": "WebShell 上传",
        "brute_force": "暴力破解",
        "cve_exploit_attempt": "CVE 漏洞利用",
        "security_guard": "流量防护",
    }
    return mapping.get(rule_name or "", rule_name or "流量防护")


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def filter_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    clean_headers: dict[str, str] = {}
    for key, value in headers:
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        clean_headers[key] = value
    return clean_headers


def resolve_forwarded_port(request: Request) -> str:
    if request.url.port:
        return str(request.url.port)
    return "443" if request.url.scheme == "https" else "80"


def serialize_request_headers(headers: Iterable[tuple[str, str]]) -> str:
    captured: dict[str, str] = {}
    for key, value in headers:
        lowered = key.lower()
        if lowered in HOP_BY_HOP_HEADERS:
            continue
        if lowered in SENSITIVE_HEADERS:
            captured[key] = "[REDACTED]"
        else:
            captured[key] = value[:1000]
    return json.dumps(captured, ensure_ascii=False)


def get_destination_host(request: Request, upstream_url: str) -> str:
    host_header = (request.headers.get("host") or "").strip()
    if host_header:
        parsed = urlparse(f"//{host_header}")
        return parsed.hostname or host_header
    parsed_upstream = urlparse(upstream_url)
    return parsed_upstream.hostname or ""


@lru_cache(maxsize=512)
def resolve_destination_ip(hostname: str) -> str:
    hostname = (hostname or "").strip()
    if not hostname:
        return "-"
    try:
        return str(ip_address(hostname))
    except ValueError:
        pass
    try:
        candidates = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return "-"

    for candidate in candidates:
        sockaddr = candidate[4]
        if sockaddr and sockaddr[0]:
            return sockaddr[0]
    return "-"


def build_upstream_url(request: Request, full_path: str) -> str:
    query = request.url.query
    base = settings.upstream_url
    path = "/" + full_path.lstrip("/")
    url = f"{base}{path}"
    if query:
        url = f"{url}?{query}"
    return url


def blocked_response(reason: str, rule_name: str | None = None) -> HTMLResponse:
    label = display_rule_name(rule_name or "security_guard")
    html = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>magualine 流量防护</title>
        <style>
          body {{
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: linear-gradient(160deg, #091224, #14274a 50%, #e7eefb);
            color: #0f172a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          }}
          .card {{
            width: min(560px, calc(100vw - 32px));
            background: rgba(255,255,255,0.95);
            border-radius: 24px;
            padding: 32px;
            box-shadow: 0 30px 80px rgba(15, 23, 42, 0.28);
          }}
          h1 {{
            margin: 0 0 8px;
            font-size: 34px;
          }}
          .tag {{
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            background: #dbeafe;
            color: #1d4ed8;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }}
          p {{
            line-height: 1.7;
            color: #334155;
          }}
        </style>
      </head>
      <body>
        <div class="card">
          <span class="tag">magualine</span>
          <h1>请求已被拦截</h1>
          <p>当前请求已被流量防护策略阻断。</p>
          <p><strong>原因：</strong>{reason}</p>
          <p><strong>规则：</strong>{label}</p>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=403)


@app.on_event("startup")
async def startup() -> None:
    init_db()
    timeout = httpx.Timeout(settings.request_timeout)
    app.state.http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)


@app.on_event("shutdown")
async def shutdown() -> None:
    client: httpx.AsyncClient | None = getattr(app.state, "http_client", None)
    if client:
        await client.aclose()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, full_path: str = "") -> Response:
    started = time.perf_counter()
    client_ip = get_client_ip(request)
    query = request.url.query
    body = await request.body()
    body_preview = body[: settings.log_body_limit].decode("utf-8", errors="ignore")
    user_agent = request.headers.get("user-agent", "")
    content_type = request.headers.get("content-type", "")
    authorization = request.headers.get("authorization", "")
    method = request.method.upper()
    path = "/" + full_path.lstrip("/")
    request_headers_json = serialize_request_headers(request.headers.items())
    upstream_url = build_upstream_url(request, full_path)
    destination_host = get_destination_host(request, upstream_url)
    destination_ip = resolve_destination_ip(destination_host)

    manual_block_reason = get_block_reason(client_ip)
    if manual_block_reason:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="blocked",
            attack_type="manual_block",
            attack_detail=manual_block_reason,
            cve_id=None,
            status_code=403,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        return blocked_response(manual_block_reason, "manual_block")

    detection = inspect_request(method, path, query, body_preview, user_agent, content_type)
    if detection.blocked:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="blocked",
            attack_type=detection.rule_name,
            attack_detail=f"{detection.matched_on}: {detection.detail}",
            cve_id=detection.cve_id,
            status_code=403,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        if detection.cve_id:
            reason = f"{detection.cve_id} 利用指纹命中位置：{detection.matched_on}"
        else:
            reason = f"{display_rule_name(detection.rule_name)} 命中位置：{detection.matched_on}"
        return blocked_response(reason, detection.rule_name)

    headers = filter_headers(request.headers.items())
    original_host = request.headers.get("host", "")
    if original_host:
        headers["host"] = original_host
        headers["x-forwarded-host"] = original_host
        headers["x-forwarded-server"] = original_host.split(":", 1)[0]
    headers["x-forwarded-for"] = client_ip
    headers["x-real-ip"] = client_ip
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-port"] = resolve_forwarded_port(request)

    try:
        upstream_response = await app.state.http_client.request(
            method,
            upstream_url,
            headers=headers,
            content=body if body else None,
        )
    except httpx.HTTPError as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        add_log(
            client_ip=client_ip,
            destination_host=destination_host,
            destination_ip=destination_ip,
            method=method,
            path=path,
            query_string=query,
            user_agent=user_agent,
            request_headers=request_headers_json,
            action="error",
            attack_type=None,
            attack_detail=str(exc)[:300],
            cve_id=None,
            status_code=502,
            upstream_status=None,
            duration_ms=duration_ms,
            body_preview=body_preview,
        )
        return JSONResponse(
            status_code=502,
            content={"message": "源站请求失败", "detail": str(exc)},
        )

    auth_attempt = looks_like_auth_attempt(method, path, query, body_preview, authorization)
    if auth_attempt:
        if upstream_response.status_code in {200, 201, 204, 301, 302, 303}:
            add_auth_attempt(client_ip, path, True, upstream_response.status_code)
            clear_recent_auth_failures(client_ip)
        elif upstream_response.status_code in {401, 403, 429}:
            add_auth_attempt(client_ip, path, False, upstream_response.status_code)
            recent_failures = count_recent_auth_failures(client_ip)
            if recent_failures >= BRUTE_FORCE_THRESHOLD:
                duration_ms = int((time.perf_counter() - started) * 1000)
                reason = f"10 分钟内出现 {recent_failures} 次登录失败"
                add_blocked_ip(client_ip, f"暴力破解阈值触发：{reason}", created_by="system")
                add_log(
                    client_ip=client_ip,
                    destination_host=destination_host,
                    destination_ip=destination_ip,
                    method=method,
                    path=path,
                    query_string=query,
                    user_agent=user_agent,
                    request_headers=request_headers_json,
                    action="blocked",
                    attack_type="brute_force",
                    attack_detail=reason,
                    cve_id=None,
                    status_code=403,
                    upstream_status=upstream_response.status_code,
                    duration_ms=duration_ms,
                    body_preview=body_preview,
                )
                return blocked_response(reason, "brute_force")

    duration_ms = int((time.perf_counter() - started) * 1000)
    add_log(
        client_ip=client_ip,
        destination_host=destination_host,
        destination_ip=destination_ip,
        method=method,
        path=path,
        query_string=query,
        user_agent=user_agent,
        request_headers=request_headers_json,
        action="allowed",
        attack_type=None,
        attack_detail=None,
        cve_id=None,
        status_code=upstream_response.status_code,
        upstream_status=upstream_response.status_code,
        duration_ms=duration_ms,
        body_preview=body_preview,
    )

    response_headers = filter_headers(upstream_response.headers.items())
    return FastAPIResponse(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )


if __name__ == "__main__":
    uvicorn.run("app.gateway:app", host="0.0.0.0", port=8080)

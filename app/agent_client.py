from __future__ import annotations

import json
import re

import httpx

from .config import get_settings


class AgentCallError(RuntimeError):
    pass


def _extract_text(data: dict) -> str:
    output = data.get("output")
    if isinstance(output, dict):
        text = output.get("text")
        if isinstance(text, str):
            return text

        content = output.get("content")
        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    for key in ("text", "content"):
                        value = item.get(key)
                        if isinstance(value, str):
                            parts.append(value)
                elif isinstance(item, str):
                    parts.append(item)
            if parts:
                return "\n".join(parts)

    return ""


def _strip_markdown_json_fence(text: str) -> str:
    fenced = re.match(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    return text.strip()


def _try_parse_json(text: str) -> dict | None:
    if not text:
        return None
    cleaned = _strip_markdown_json_fence(text)
    try:
        payload = json.loads(cleaned)
        if isinstance(payload, dict):
            return payload
    except Exception:
        return None
    return None


def call_agent(prompt: str, session_id: str | None = None) -> dict:
    settings = get_settings()
    if not settings.dashscope_api_key:
        raise AgentCallError("未配置 DASHSCOPE_API_KEY")
    if not settings.bailian_app_id:
        raise AgentCallError("未配置 BAILIAN_APP_ID")

    url = f"{settings.bailian_base_url}/api/v1/apps/{settings.bailian_app_id}/completion"
    headers = {
        "Authorization": f"Bearer {settings.dashscope_api_key}",
        "Content-Type": "application/json",
    }
    if settings.bailian_workspace_id:
        headers["X-DashScope-WorkSpace"] = settings.bailian_workspace_id

    payload = {
        "input": {"prompt": prompt},
        "parameters": {},
        "debug": {},
    }
    if session_id:
        payload["input"]["session_id"] = session_id

    timeout = httpx.Timeout(
        connect=min(10.0, float(settings.bailian_timeout)),
        read=float(settings.bailian_timeout),
        write=min(20.0, float(settings.bailian_timeout)),
        pool=min(10.0, float(settings.bailian_timeout)),
    )

    last_error: Exception | None = None
    response = None
    for _ in range(2):
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=timeout)
            break
        except Exception as exc:
            last_error = exc

    if response is None:
        raise AgentCallError(f"百炼请求失败: {last_error}") from last_error

    if response.status_code >= 400:
        detail = response.text[:400]
        raise AgentCallError(f"百炼返回错误 {response.status_code}: {detail}")

    try:
        data = response.json()
    except Exception as exc:
        raise AgentCallError(f"百炼返回非 JSON: {response.text[:200]}") from exc

    text = _extract_text(data)
    parsed = _try_parse_json(text)
    output = data.get("output") if isinstance(data.get("output"), dict) else {}
    session_value = output.get("session_id") if isinstance(output, dict) else None

    return {
        "request_id": data.get("request_id", ""),
        "session_id": session_value or session_id or "",
        "usage": data.get("usage", {}),
        "raw_text": text,
        "parsed": parsed or {},
    }

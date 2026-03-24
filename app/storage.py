from __future__ import annotations

import json
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import get_settings
from .ip_geo import classify_special_ip


REGION_BUCKET_RULES = {
    "华北": ("北京", "天津", "河北", "山西", "内蒙古"),
    "华东": ("上海", "江苏", "浙江", "安徽", "福建", "江西", "山东"),
    "华南": ("广东", "广西", "海南"),
    "华中": ("河南", "湖北", "湖南"),
    "西部": ("重庆", "四川", "贵州", "云南", "西藏", "陕西", "甘肃", "青海", "宁夏", "新疆"),
    "东北": ("辽宁", "吉林", "黑龙江"),
}

SCREEN_BUCKET_ORDER = ("华北", "华东", "华南", "华中", "西部", "东北", "本地", "海外", "未知")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    db_path = get_settings().db_path
    connection = sqlite3.connect(db_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
    return connection


def ensure_column(connection: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def classify_log(action: str, attack_type: str | None) -> tuple[str, str]:
    high_rules = {"webshell_upload", "brute_force", "command_injection", "sql_injection", "cve_exploit_attempt"}
    medium_rules = {"xss", "path_traversal", "scanner_probe", "manual_block"}

    if action == "allowed":
        return "low", "not_applicable"

    if action == "error":
        return "medium", "pending"

    if attack_type in high_rules:
        return "high", "pending"

    if attack_type in medium_rules or action == "blocked":
        return "medium", "pending"

    return "low", "not_applicable"


def init_db() -> None:
    with closing(get_connection()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query_string TEXT,
                user_agent TEXT,
                request_headers TEXT,
                action TEXT NOT NULL,
                attack_type TEXT,
                attack_detail TEXT,
                cve_id TEXT,
                severity TEXT,
                alert_status TEXT,
                status_updated_at TEXT,
                status_code INTEGER,
                upstream_status INTEGER,
                duration_ms INTEGER,
                body_preview TEXT
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                path TEXT NOT NULL,
                success INTEGER NOT NULL,
                status_code INTEGER
            );

            CREATE TABLE IF NOT EXISTS ip_geo_cache (
                ip TEXT PRIMARY KEY,
                label TEXT,
                country TEXT,
                region TEXT,
                city TEXT,
                isp TEXT,
                source TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_request_logs_created_at
            ON request_logs(created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip
            ON request_logs(client_ip);

            CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_created_at
            ON auth_attempts(client_ip, created_at DESC);
            """
        )
        ensure_column(connection, "request_logs", "severity", "severity TEXT")
        ensure_column(connection, "request_logs", "alert_status", "alert_status TEXT")
        ensure_column(connection, "request_logs", "status_updated_at", "status_updated_at TEXT")
        ensure_column(connection, "request_logs", "cve_id", "cve_id TEXT")
        ensure_column(connection, "request_logs", "request_headers", "request_headers TEXT")
        connection.execute(
            """
            UPDATE request_logs
            SET severity = COALESCE(severity,
                CASE
                    WHEN action = 'allowed' THEN 'low'
                    WHEN action = 'error' THEN 'medium'
                    WHEN attack_type IN ('webshell_upload', 'brute_force', 'command_injection', 'sql_injection', 'cve_exploit_attempt') THEN 'high'
                    WHEN action = 'blocked' THEN 'medium'
                    ELSE 'low'
                END
            ),
            alert_status = COALESCE(alert_status,
                CASE
                    WHEN action IN ('blocked', 'error') THEN 'pending'
                    ELSE 'not_applicable'
                END
            ),
            status_updated_at = COALESCE(status_updated_at, created_at)
            """
        )
        connection.commit()


def add_log(
    *,
    client_ip: str,
    method: str,
    path: str,
    query_string: str,
    user_agent: str,
    request_headers: str | None,
    action: str,
    attack_type: str | None,
    attack_detail: str | None,
    cve_id: str | None,
    status_code: int | None,
    upstream_status: int | None,
    duration_ms: int | None,
    body_preview: str | None,
) -> None:
    severity, alert_status = classify_log(action, attack_type)
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO request_logs (
                created_at, client_ip, method, path, query_string, user_agent,
                request_headers, action, attack_type, attack_detail, cve_id, severity, alert_status, status_updated_at,
                status_code, upstream_status, duration_ms, body_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow_iso(),
                client_ip,
                method,
                path,
                query_string,
                user_agent,
                request_headers,
                action,
                attack_type,
                attack_detail,
                cve_id,
                severity,
                alert_status,
                utcnow_iso(),
                status_code,
                upstream_status,
                duration_ms,
                body_preview,
            ),
        )
        connection.commit()


def list_logs(
    *,
    page: int = 1,
    page_size: int = 20,
    action: str | None = None,
    keyword: str | None = None,
    severity: str | None = None,
    alert_status: str | None = None,
) -> dict:
    base_sql = """
        FROM request_logs
    """
    clauses = []
    params: list[object] = []

    if action:
        clauses.append("action = ?")
        params.append(action)

    if keyword:
        clauses.append("(client_ip LIKE ? OR path LIKE ? OR attack_type LIKE ? OR attack_detail LIKE ? OR cve_id LIKE ?)")
        like_value = f"%{keyword}%"
        params.extend([like_value, like_value, like_value, like_value, like_value])

    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    if alert_status:
        clauses.append("alert_status = ?")
        params.append(alert_status)

    where_sql = ""
    if clauses:
        where_sql = " WHERE " + " AND ".join(clauses)

    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    total_sql = "SELECT COUNT(*) AS total " + base_sql + where_sql
    data_sql = """
        SELECT id, created_at, client_ip, method, path, query_string, user_agent,
               action, attack_type, attack_detail, cve_id, severity, alert_status,
               status_code, upstream_status, duration_ms, body_preview
    """ + base_sql + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?"

    with closing(get_connection()) as connection:
        total = connection.execute(total_sql, params).fetchone()["total"] or 0
        rows = connection.execute(data_sql, [*params, page_size, offset]).fetchall()

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


def get_log_detail(log_id: int) -> dict | None:
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT id, created_at, client_ip, method, path, query_string, user_agent,
                   request_headers, action, attack_type, attack_detail, cve_id,
                   severity, alert_status, status_updated_at, status_code,
                   upstream_status, duration_ms, body_preview
            FROM request_logs
            WHERE id = ?
            """,
            (log_id,),
        ).fetchone()

    if not row:
        return None

    data = dict(row)
    raw_headers = data.get("request_headers")
    if raw_headers:
        try:
            data["request_headers"] = json.loads(raw_headers)
        except Exception:
            data["request_headers"] = {"raw": raw_headers}
    else:
        data["request_headers"] = {}
    return data


def _build_hourly_trend(rows: list[sqlite3.Row], bucket_count: int = 12) -> list[dict]:
    end_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start_hour = end_hour - timedelta(hours=bucket_count - 1)

    buckets: list[dict] = []
    index: dict[datetime, dict] = {}
    for offset in range(bucket_count):
        bucket_time = start_hour + timedelta(hours=offset)
        bucket = {
            "_time": bucket_time,
            "label": bucket_time.strftime("%H:00"),
            "total": 0,
            "blocked": 0,
            "high": 0,
        }
        buckets.append(bucket)
        index[bucket_time] = bucket

    for row in rows:
        try:
            created_at = datetime.fromisoformat(row["created_at"]).astimezone(timezone.utc)
        except Exception:
            continue

        bucket_key = created_at.replace(minute=0, second=0, microsecond=0)
        bucket = index.get(bucket_key)
        if not bucket:
            continue

        bucket["total"] += 1
        if row["action"] == "blocked":
            bucket["blocked"] += 1
        if row["severity"] == "high":
            bucket["high"] += 1

    for bucket in buckets:
        bucket.pop("_time", None)
    return buckets


def _infer_geo_bucket(ip: str, geo: dict | None) -> str:
    special = classify_special_ip(ip)
    if special is not None:
        if special.get("country") in {"本机", "内网"}:
            return "本地"
        return "未知"

    if not geo:
        return "未知"

    country = str(geo.get("country") or "")
    region = str(geo.get("region") or "")
    city = str(geo.get("city") or "")
    geo_text = f"{country}{region}{city}"

    if country and country != "中国":
        return "海外"

    for bucket, keywords in REGION_BUCKET_RULES.items():
        if any(keyword in geo_text for keyword in keywords):
            return bucket

    return "未知"


def get_overview(hours: int = 24) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    with closing(get_connection()) as connection:
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS total_requests,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_requests,
                SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) AS allowed_requests,
                COUNT(DISTINCT client_ip) AS unique_ips
            FROM request_logs
            WHERE created_at >= ?
            """,
            (since,),
        ).fetchone()

        top_attack_types = connection.execute(
            """
            SELECT COALESCE(attack_type, 'manual_block') AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND action = 'blocked'
            GROUP BY COALESCE(attack_type, 'manual_block')
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        top_source_ips = connection.execute(
            """
            SELECT client_ip AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        top_paths = connection.execute(
            """
            SELECT path AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY path
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        blocked_ip_count = connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"]

        alert_totals = connection.execute(
            """
            SELECT
                SUM(CASE WHEN action IN ('blocked', 'error') THEN 1 ELSE 0 END) AS total_alerts,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_risk_alerts,
                SUM(CASE WHEN alert_status = 'pending' THEN 1 ELSE 0 END) AS pending_alerts,
                SUM(CASE WHEN alert_status = 'resolved' THEN 1 ELSE 0 END) AS resolved_alerts
            FROM request_logs
            WHERE created_at >= ?
            """,
            (since,),
        ).fetchone()

        brute_force_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'brute_force'
            """,
            (since,),
        ).fetchone()["count"]

        webshell_upload_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'webshell_upload'
            """,
            (since,),
        ).fetchone()["count"]

        cve_alert_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND attack_type = 'cve_exploit_attempt'
            """,
            (since,),
        ).fetchone()["count"]

        latest_high_risk_alerts = connection.execute(
            """
            SELECT id, created_at, client_ip, path, attack_type, attack_detail, cve_id, alert_status
            FROM request_logs
            WHERE created_at >= ? AND severity = 'high'
            ORDER BY id DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        recent_alert_stream = connection.execute(
            """
            SELECT id, created_at, client_ip, path, attack_type, attack_detail,
                   cve_id, alert_status, severity, action
            FROM request_logs
            WHERE created_at >= ? AND action IN ('blocked', 'error')
            ORDER BY id DESC
            LIMIT 8
            """,
            (since,),
        ).fetchall()

        top_cve_ids = connection.execute(
            """
            SELECT cve_id AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ? AND cve_id IS NOT NULL AND cve_id <> ''
            GROUP BY cve_id
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        trend_rows = connection.execute(
            """
            SELECT created_at, action, severity
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            ((datetime.now(timezone.utc) - timedelta(hours=12)).isoformat(),),
        ).fetchall()

        geo_cache_rows = connection.execute(
            """
            SELECT ip, label, country, region, city, isp, source
            FROM ip_geo_cache
            """
        ).fetchall()
        geo_cache = {row["ip"]: dict(row) for row in geo_cache_rows}

        ip_rows = connection.execute(
            """
            SELECT client_ip, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY client_ip
            """,
            (since,),
        ).fetchall()

    total_requests = totals["total_requests"] or 0
    blocked_requests = totals["blocked_requests"] or 0
    allowed_requests = totals["allowed_requests"] or 0
    blocked_rate = round((blocked_requests / total_requests) * 100, 1) if total_requests else 0.0
    hourly_trend = _build_hourly_trend(list(trend_rows))

    geo_counter: Counter[str] = Counter()
    for row in ip_rows:
        ip = row["client_ip"]
        count = row["count"] or 0
        bucket = _infer_geo_bucket(ip, geo_cache.get(ip))
        geo_counter[bucket] += count

    geo_buckets = [{"name": bucket, "count": geo_counter.get(bucket, 0)} for bucket in SCREEN_BUCKET_ORDER]
    active_geo_buckets = sorted(
        (item for item in geo_buckets if item["count"] > 0),
        key=lambda item: item["count"],
        reverse=True,
    )

    return {
        "window_hours": hours,
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "allowed_requests": allowed_requests,
        "unique_ips": totals["unique_ips"] or 0,
        "blocked_rate": blocked_rate,
        "blocked_ip_count": blocked_ip_count,
        "total_alerts": alert_totals["total_alerts"] or 0,
        "high_risk_alerts": alert_totals["high_risk_alerts"] or 0,
        "pending_alerts": alert_totals["pending_alerts"] or 0,
        "resolved_alerts": alert_totals["resolved_alerts"] or 0,
        "brute_force_events": brute_force_events or 0,
        "webshell_upload_events": webshell_upload_events or 0,
        "cve_alert_events": cve_alert_events or 0,
        "top_attack_types": [dict(row) for row in top_attack_types],
        "top_source_ips": [dict(row) for row in top_source_ips],
        "top_paths": [dict(row) for row in top_paths],
        "latest_high_risk_alerts": [dict(row) for row in latest_high_risk_alerts],
        "recent_alert_stream": [dict(row) for row in recent_alert_stream],
        "top_cve_ids": [dict(row) for row in top_cve_ids],
        "hourly_trend": hourly_trend,
        "geo_buckets": geo_buckets,
        "active_geo_buckets": active_geo_buckets[:6],
    }


def list_blocked_ips() -> list[dict]:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, ip, reason, created_at, created_by FROM blocked_ips ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def add_blocked_ip(ip: str, reason: str | None, created_by: str = "admin") -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO blocked_ips (ip, reason, created_at, created_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, created_by=excluded.created_by
            """,
            (ip.strip(), reason or "", utcnow_iso(), created_by),
        )
        connection.commit()


def get_cached_ip_geo(ip: str, max_age_hours: int = 72) -> dict | None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT ip, label, country, region, city, isp, source, updated_at
            FROM ip_geo_cache
            WHERE ip = ? AND updated_at >= ?
            """,
            (ip, cutoff),
        ).fetchone()
    return dict(row) if row else None


def cache_ip_geo(ip: str, geo: dict) -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO ip_geo_cache (ip, label, country, region, city, isp, source, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                label=excluded.label,
                country=excluded.country,
                region=excluded.region,
                city=excluded.city,
                isp=excluded.isp,
                source=excluded.source,
                updated_at=excluded.updated_at
            """,
            (
                ip,
                geo.get("label", ""),
                geo.get("country", ""),
                geo.get("region", ""),
                geo.get("city", ""),
                geo.get("isp", ""),
                geo.get("source", ""),
                utcnow_iso(),
            ),
        )
        connection.commit()


def update_log_status(log_id: int, alert_status: str) -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            UPDATE request_logs
            SET alert_status = ?, status_updated_at = ?
            WHERE id = ?
            """,
            (alert_status, utcnow_iso(), log_id),
        )
        connection.commit()


def add_auth_attempt(client_ip: str, path: str, success: bool, status_code: int | None) -> None:
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO auth_attempts (created_at, client_ip, path, success, status_code)
            VALUES (?, ?, ?, ?, ?)
            """,
            (utcnow_iso(), client_ip, path, 1 if success else 0, status_code),
        )
        connection.commit()


def count_recent_auth_failures(client_ip: str, window_minutes: int = 10) -> int:
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM auth_attempts
            WHERE client_ip = ? AND success = 0 AND created_at >= ?
            """,
            (client_ip, since),
        ).fetchone()
    return int(row["count"] or 0)


def clear_recent_auth_failures(client_ip: str) -> None:
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM auth_attempts WHERE client_ip = ?", (client_ip,))
        connection.commit()


def remove_blocked_ip(record_id: int) -> None:
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM blocked_ips WHERE id = ?", (record_id,))
        connection.commit()


def get_block_reason(ip: str) -> str | None:
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT reason FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return None
    return row["reason"] or "手动封禁"

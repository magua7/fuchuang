from __future__ import annotations

import json
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import get_settings
from .ip_geo import classify_special_ip, lookup_ip_geo


REGION_BUCKET_RULES = {
    "华北": ("北京", "天津", "河北", "山西", "内蒙古"),
    "华东": ("上海", "江苏", "浙江", "安徽", "福建", "江西", "山东"),
    "华南": ("广东", "广西", "海南"),
    "华中": ("河南", "湖北", "湖南"),
    "西部": ("重庆", "四川", "贵州", "云南", "西藏", "陕西", "甘肃", "青海", "宁夏", "新疆"),
    "东北": ("辽宁", "吉林", "黑龙江"),
}

SCREEN_BUCKET_ORDER = ("华北", "华东", "华南", "华中", "西部", "东北", "本地", "海外", "未知")

SCREEN_TARGET = {
    "name": "防护主站",
    "label": "中国 · 业务区",
    "lng": 112.9389,
    "lat": 28.2282,
}

REGION_COORDINATES = {
    "华北": {"lng": 116.4074, "lat": 39.9042},
    "华东": {"lng": 121.4737, "lat": 31.2304},
    "华南": {"lng": 113.2644, "lat": 23.1291},
    "华中": {"lng": 114.3055, "lat": 30.5928},
    "西部": {"lng": 104.0665, "lat": 30.5728},
    "东北": {"lng": 126.6424, "lat": 45.7567},
    "本地": {"lng": 112.9389, "lat": 28.2282},
    "海外": {"lng": 12.4964, "lat": 41.9028},
    "未知": {"lng": 12.4964, "lat": 41.9028},
}

COUNTRY_COORDINATES = {
    "中国": {"lng": 104.1954, "lat": 35.8617},
    "美国": {"lng": -98.5795, "lat": 39.8283},
    "英国": {"lng": -2.2426, "lat": 53.4808},
    "荷兰": {"lng": 5.2913, "lat": 52.1326},
    "德国": {"lng": 10.4515, "lat": 51.1657},
    "俄罗斯": {"lng": 105.3188, "lat": 61.5240},
    "日本": {"lng": 138.2529, "lat": 36.2048},
    "韩国": {"lng": 127.7669, "lat": 35.9078},
    "新加坡": {"lng": 103.8198, "lat": 1.3521},
    "加拿大": {"lng": -106.3468, "lat": 56.1304},
    "法国": {"lng": 2.2137, "lat": 46.2276},
    "澳大利亚": {"lng": 133.7751, "lat": -25.2744},
    "印度": {"lng": 78.9629, "lat": 20.5937},
    "巴西": {"lng": -51.9253, "lat": -14.2350},
    "中国香港": {"lng": 114.1694, "lat": 22.3193},
    "中国台湾": {"lng": 121.5654, "lat": 23.6978},
    "香港": {"lng": 114.1694, "lat": 22.3193},
    "台湾": {"lng": 121.5654, "lat": 23.6978},
}

PROVINCE_COORDINATES = {
    "北京": {"lng": 116.4074, "lat": 39.9042},
    "天津": {"lng": 117.2000, "lat": 39.1333},
    "上海": {"lng": 121.4737, "lat": 31.2304},
    "江苏": {"lng": 118.7632, "lat": 32.0617},
    "浙江": {"lng": 120.1551, "lat": 30.2741},
    "广东": {"lng": 113.2644, "lat": 23.1291},
    "湖北": {"lng": 114.3055, "lat": 30.5928},
    "湖南": {"lng": 112.9389, "lat": 28.2282},
    "四川": {"lng": 104.0665, "lat": 30.5728},
    "重庆": {"lng": 106.5516, "lat": 29.5630},
    "山东": {"lng": 117.1201, "lat": 36.6512},
    "福建": {"lng": 119.2965, "lat": 26.0745},
    "河南": {"lng": 113.6254, "lat": 34.7466},
    "海南": {"lng": 110.3312, "lat": 20.0319},
    "辽宁": {"lng": 123.4315, "lat": 41.8057},
    "吉林": {"lng": 125.3235, "lat": 43.8171},
    "黑龙江": {"lng": 126.6424, "lat": 45.7567},
    "陕西": {"lng": 108.9398, "lat": 34.3416},
    "广西": {"lng": 108.3200, "lat": 22.8240},
    "云南": {"lng": 102.7123, "lat": 25.0406},
}


def _normalize_geo_name(value: str) -> str:
    text = str(value or "").strip()
    for token in ("省", "市", "特别行政区", "自治区", "壮族", "回族", "维吾尔"):
        text = text.replace(token, "")
    return text.strip()


def _geo_coordinates(country: str, region: str, city: str, bucket: str) -> dict:
    for candidate in (
        city,
        _normalize_geo_name(city),
        region,
        _normalize_geo_name(region),
        country,
        _normalize_geo_name(country),
        bucket,
    ):
        if candidate in PROVINCE_COORDINATES:
            return PROVINCE_COORDINATES[candidate]
        if candidate in COUNTRY_COORDINATES:
            return COUNTRY_COORDINATES[candidate]
        if candidate in REGION_COORDINATES:
            return REGION_COORDINATES[candidate]
    return REGION_COORDINATES["未知"]


def _build_location_label(country: str, region: str, city: str, bucket: str) -> str:
    country = str(country or "").strip()
    region = _normalize_geo_name(region)
    city = _normalize_geo_name(city)

    if country and country != "中国":
        return country
    if city:
        return city
    if region:
        return region
    if bucket in REGION_COORDINATES:
        return bucket
    return "未知"


def _build_screen_flow_name(country: str, region: str, city: str, bucket: str, label: str) -> str:
    country = str(country or "").strip()
    region = _normalize_geo_name(region)
    city = _normalize_geo_name(city)
    label = str(label or "").strip()

    if country and country != "中国":
        return _normalize_geo_name(country) or "未知"

    if region:
        return region

    if label:
        parts = [
            _normalize_geo_name(part)
            for part in label.replace("|", "/").replace("·", "/").split("/")
            if _normalize_geo_name(part)
        ]
        if len(parts) >= 2:
            return parts[1]
        if parts:
            return parts[0]

    if city:
        return city

    if bucket in REGION_COORDINATES:
        return bucket

    return "未知"


def _ensure_geo(ip: str, geo_cache: dict[str, dict]) -> dict:
    cached = geo_cache.get(ip)
    if cached:
        return cached

    cached = get_cached_ip_geo(ip)
    if not cached:
        cached = lookup_ip_geo(ip)
        cache_ip_geo(ip, cached)

    geo_cache[ip] = cached
    return cached


ALERT_STATUS_ACTIVE = (
    "real_attack",
    "customer_business",
    "pending_business",
    "notified_event",
)


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
        return "medium", "pending_business"

    if attack_type in high_rules:
        return "high", "real_attack"

    if attack_type in medium_rules or action == "blocked":
        return "medium", "pending_business"

    return "low", "not_applicable"


def init_db() -> None:
    with closing(get_connection()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                destination_host TEXT,
                destination_ip TEXT,
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
        ensure_column(connection, "request_logs", "destination_host", "destination_host TEXT")
        ensure_column(connection, "request_logs", "destination_ip", "destination_ip TEXT")
        ensure_column(connection, "request_logs", "severity", "severity TEXT")
        ensure_column(connection, "request_logs", "alert_status", "alert_status TEXT")
        ensure_column(connection, "request_logs", "handled_status", "handled_status TEXT")
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
            alert_status = CASE
                WHEN alert_status = 'pending' THEN
                    CASE
                        WHEN attack_type IN ('webshell_upload', 'brute_force', 'command_injection', 'sql_injection', 'cve_exploit_attempt') THEN 'real_attack'
                        WHEN action IN ('blocked', 'error') THEN 'pending_business'
                        ELSE 'not_applicable'
                    END
                WHEN alert_status IN ('resolved', 'resolved_event') THEN 'notified_event'
                WHEN alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event', 'not_applicable') THEN alert_status
                WHEN alert_status IS NULL THEN
                    CASE
                        WHEN attack_type IN ('webshell_upload', 'brute_force', 'command_injection', 'sql_injection', 'cve_exploit_attempt') THEN 'real_attack'
                        WHEN action IN ('blocked', 'error') THEN 'pending_business'
                        ELSE 'not_applicable'
                    END
                ELSE alert_status
            END,
            handled_status = CASE
                WHEN handled_status IN ('handled', 'unhandled') THEN handled_status
                WHEN alert_status IN ('resolved', 'resolved_event', 'notified_event') THEN 'handled'
                ELSE 'unhandled'
            END,
            status_updated_at = COALESCE(status_updated_at, created_at)
            """
        )
        connection.commit()


def add_log(
    *,
    client_ip: str,
    destination_host: str | None,
    destination_ip: str | None,
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
    handled_status = "unhandled"
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO request_logs (
                created_at, client_ip, destination_host, destination_ip, method, path, query_string, user_agent,
                request_headers, action, attack_type, attack_detail, cve_id, severity, alert_status, handled_status, status_updated_at,
                status_code, upstream_status, duration_ms, body_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow_iso(),
                client_ip,
                destination_host,
                destination_ip,
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
                handled_status,
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
    alerts_only: bool = False,
    action: str | None = None,
    keyword: str | None = None,
    severity: str | None = None,
    alert_status: str | None = None,
    handled_status: str | None = None,
) -> dict:
    base_sql = """
        FROM request_logs
    """
    clauses = []
    params: list[object] = []

    if alerts_only:
        placeholders = ", ".join("?" for _ in ALERT_STATUS_ACTIVE)
        clauses.append(f"alert_status IN ({placeholders})")
        params.extend(ALERT_STATUS_ACTIVE)

    if action:
        clauses.append("action = ?")
        params.append(action)

    if keyword:
        clauses.append("(client_ip LIKE ? OR destination_host LIKE ? OR destination_ip LIKE ? OR path LIKE ? OR attack_type LIKE ? OR attack_detail LIKE ? OR cve_id LIKE ?)")
        like_value = f"%{keyword}%"
        params.extend([like_value, like_value, like_value, like_value, like_value, like_value, like_value])

    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    if alert_status:
        clauses.append("alert_status = ?")
        params.append(alert_status)

    if handled_status:
        clauses.append("handled_status = ?")
        params.append(handled_status)

    where_sql = ""
    if clauses:
        where_sql = " WHERE " + " AND ".join(clauses)

    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    total_sql = "SELECT COUNT(*) AS total " + base_sql + where_sql
    data_sql = """
        SELECT id, created_at, client_ip, destination_host, destination_ip, method, path, query_string, user_agent,
               action, attack_type, attack_detail, cve_id, severity, alert_status, handled_status,
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
            SELECT id, created_at, client_ip, destination_host, destination_ip, method, path, query_string, user_agent,
                   request_headers, action, attack_type, attack_detail, cve_id,
                   severity, alert_status, handled_status, status_updated_at, status_code,
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
                SUM(CASE WHEN alert_status IN ('real_attack', 'customer_business', 'pending_business', 'notified_event') THEN 1 ELSE 0 END) AS total_alerts,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_risk_alerts,
                SUM(CASE WHEN alert_status = 'real_attack' THEN 1 ELSE 0 END) AS real_attack_alerts,
                SUM(CASE WHEN alert_status = 'customer_business' THEN 1 ELSE 0 END) AS customer_business_alerts,
                SUM(CASE WHEN alert_status = 'pending_business' THEN 1 ELSE 0 END) AS pending_business_alerts,
                SUM(CASE WHEN alert_status = 'notified_event' THEN 1 ELSE 0 END) AS notified_event_alerts,
                SUM(CASE WHEN handled_status = 'unhandled' THEN 1 ELSE 0 END) AS unhandled_alerts,
                SUM(CASE WHEN handled_status = 'handled' THEN 1 ELSE 0 END) AS handled_alerts
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
        "real_attack_alerts": alert_totals["real_attack_alerts"] or 0,
        "customer_business_alerts": alert_totals["customer_business_alerts"] or 0,
        "pending_business_alerts": alert_totals["pending_business_alerts"] or 0,
        "notified_event_alerts": alert_totals["notified_event_alerts"] or 0,
        "resolved_event_alerts": alert_totals["notified_event_alerts"] or 0,
        "unhandled_alerts": alert_totals["unhandled_alerts"] or 0,
        "handled_alerts": alert_totals["handled_alerts"] or 0,
        "pending_alerts": alert_totals["unhandled_alerts"] or 0,
        "resolved_alerts": alert_totals["handled_alerts"] or 0,
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


def get_screen_data(hours: int = 24) -> dict:
    overview = get_overview(hours=hours)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    with closing(get_connection()) as connection:
        recent_rows = connection.execute(
            """
            SELECT id, created_at, client_ip, destination_host, destination_ip, path, action,
                   attack_type, attack_detail, cve_id, severity, alert_status, handled_status
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY id DESC
            LIMIT 240
            """,
            (since,),
        ).fetchall()

        timeline_rows = connection.execute(
            """
            SELECT created_at, action, severity
            FROM request_logs
            WHERE created_at >= ?
            ORDER BY created_at ASC
            """,
            (since,),
        ).fetchall()

        attack_ip_rows = connection.execute(
            """
            SELECT client_ip AS ip, COUNT(*) AS count,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_count
            FROM request_logs
            WHERE created_at >= ? AND action IN ('blocked', 'error')
            GROUP BY client_ip
            ORDER BY count DESC
            LIMIT 5
            """,
            (since,),
        ).fetchall()

        victim_rows = connection.execute(
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

        destination_row = connection.execute(
            """
            SELECT COALESCE(NULLIF(destination_host, ''), '防护主站') AS name, COUNT(*) AS count
            FROM request_logs
            WHERE created_at >= ?
            GROUP BY COALESCE(NULLIF(destination_host, ''), '防护主站')
            ORDER BY count DESC
            LIMIT 1
            """,
            (since,),
        ).fetchone()

        geo_cache_rows = connection.execute(
            """
            SELECT ip, label, country, region, city, isp, source
            FROM ip_geo_cache
            """
        ).fetchall()

    geo_cache = {row["ip"]: dict(row) for row in geo_cache_rows}

    flow_seed = [dict(row) for row in recent_rows if row["action"] in ("blocked", "error")]
    if not flow_seed:
        flow_seed = [dict(row) for row in recent_rows]

    flow_counter: dict[str, dict] = {}
    origin_counter: Counter[str] = Counter()
    attack_ip_items: list[dict] = []
    attack_ip_lookup = {row["ip"]: row for row in attack_ip_rows}

    for ip in {row["client_ip"] for row in recent_rows}:
        _ensure_geo(ip, geo_cache)

    for row in flow_seed:
        ip = row["client_ip"]
        geo = geo_cache.get(ip) or {}
        bucket = _infer_geo_bucket(ip, geo)
        source_name = _build_screen_flow_name(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
            geo.get("label", ""),
        )
        coords = _geo_coordinates(
            geo.get("country", ""),
            geo.get("region", ""),
            geo.get("city", ""),
            bucket,
        )
        key = f"{source_name}:{bucket}"
        item = flow_counter.setdefault(
            key,
            {
                "source_name": source_name,
                "source_bucket": bucket,
                "source_country": str(geo.get("country", "") or ""),
                "source_region": str(geo.get("region", "") or ""),
                "source_city": str(geo.get("city", "") or ""),
                "source_label": str(geo.get("label", "") or source_name),
                "source_lng": coords["lng"],
                "source_lat": coords["lat"],
                "count": 0,
                "blocked_count": 0,
                "high_count": 0,
                "top_rule": row["attack_type"] or "manual_block",
                "top_cve": row["cve_id"] or "",
            },
        )
        item["count"] += 1
        if row["action"] == "blocked":
            item["blocked_count"] += 1
        if row["severity"] == "high":
            item["high_count"] += 1
        origin_counter[source_name] += 1

    globe_flows = sorted(flow_counter.values(), key=lambda item: (item["high_count"], item["count"]), reverse=True)[:8]
    for item in globe_flows:
        item["severity"] = "high" if item["high_count"] else ("medium" if item["blocked_count"] else "low")
        item["target_name"] = destination_row["name"] if destination_row else SCREEN_TARGET["name"]
        item["target_label"] = SCREEN_TARGET["label"]
        item["target_lng"] = SCREEN_TARGET["lng"]
        item["target_lat"] = SCREEN_TARGET["lat"]

    attack_source_top = [
        {"name": name, "count": count}
        for name, count in origin_counter.most_common(5)
    ]

    for row in attack_ip_rows:
        ip = row["ip"]
        geo = geo_cache.get(ip) or {}
        bucket = _infer_geo_bucket(ip, geo)
        attack_ip_items.append(
            {
                "ip": ip,
                "count": row["count"],
                "high_count": row["high_count"],
                "label": _build_location_label(
                    geo.get("country", ""),
                    geo.get("region", ""),
                    geo.get("city", ""),
                    bucket,
                ),
                "geo_label": str(geo.get("label", "") or ""),
                "bucket": bucket,
            }
        )

    critical_count = sum(
        1
        for row in recent_rows
        if row["attack_type"] in {"webshell_upload", "cve_exploit_attempt", "command_injection"}
    )
    severity_distribution = [
        {"name": "危急", "count": critical_count},
        {"name": "高危", "count": overview["high_risk_alerts"]},
        {"name": "中危", "count": max(overview["blocked_requests"] - overview["high_risk_alerts"], 0)},
        {"name": "低危", "count": max(overview["total_requests"] - overview["blocked_requests"], 0)},
    ]

    recent_alerts = []
    for row in recent_rows[:6]:
        geo = geo_cache.get(row["client_ip"]) or {}
        recent_alerts.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "client_ip": row["client_ip"],
                "path": row["path"],
                "attack_type": row["attack_type"],
                "attack_detail": row["attack_detail"],
                "cve_id": row["cve_id"],
                "severity": row["severity"],
                "action": row["action"],
                "location": str(geo.get("label", "") or "未知位置"),
            }
        )

    timeline_24h = _build_hourly_trend([dict(row) for row in timeline_rows], bucket_count=24)
    top_paths = [dict(row) for row in victim_rows]

    return {
        "window_hours": hours,
        "target": {
            "name": destination_row["name"] if destination_row else SCREEN_TARGET["name"],
            "label": SCREEN_TARGET["label"],
            "lng": SCREEN_TARGET["lng"],
            "lat": SCREEN_TARGET["lat"],
        },
        "overview": overview,
        "globe_flows": globe_flows,
        "attack_ip_top5": attack_ip_items,
        "attack_source_top5": attack_source_top,
        "victim_targets_top5": top_paths,
        "timeline_24h": timeline_24h,
        "severity_distribution": severity_distribution,
        "recent_alerts": recent_alerts,
        "top_attack_types": overview["top_attack_types"],
        "top_cve_ids": overview["top_cve_ids"],
    }


def list_blocked_ips(page: int = 1, page_size: int = 20) -> dict:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    with closing(get_connection()) as connection:
        total = connection.execute("SELECT COUNT(*) AS count FROM blocked_ips").fetchone()["count"]
        rows = connection.execute(
            """
            SELECT id, ip, reason, created_at, created_by
            FROM blocked_ips
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (page_size, offset),
        ).fetchall()

    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


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
            SET alert_status = ?, handled_status = 'handled', status_updated_at = ?
            WHERE id = ?
            """,
            (alert_status, utcnow_iso(), log_id),
        )
        connection.commit()


def bulk_update_log_status(log_ids: list[int], alert_status: str) -> None:
    clean_ids = [int(log_id) for log_id in log_ids if str(log_id).strip()]
    if not clean_ids:
        return

    placeholders = ", ".join("?" for _ in clean_ids)
    with closing(get_connection()) as connection:
        connection.execute(
            f"""
            UPDATE request_logs
            SET alert_status = ?, handled_status = 'handled', status_updated_at = ?
            WHERE id IN ({placeholders})
            """,
            (alert_status, utcnow_iso(), *clean_ids),
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

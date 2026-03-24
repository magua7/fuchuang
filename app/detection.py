from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class DetectionResult:
    blocked: bool
    rule_name: str | None = None
    matched_on: str | None = None
    detail: str | None = None
    cve_id: str | None = None


LOGIN_PATH_PATTERN = re.compile(
    r"(/login|/signin|/sign-in|/auth|/session|/oauth|/token|/admin|/console|/manager)",
    re.IGNORECASE,
)
LOGIN_FIELD_PATTERN = re.compile(
    r"(username=|user=|account=|password=|passwd=|pwd=)",
    re.IGNORECASE,
)
UPLOAD_PATH_PATTERN = re.compile(
    r"(/upload|/file|/import|/attachment|/media|/editor|/api/.+upload)",
    re.IGNORECASE,
)
WEBSHELL_FILENAME_PATTERN = re.compile(
    r"filename\s*=\s*['\"]?[^'\"]+\.(php\d*|phtml|jsp|jspx|asp|aspx|cer|asa|py|sh|pl|cgi)['\"]?",
    re.IGNORECASE,
)
WEBSHELL_PAYLOAD_PATTERN = re.compile(
    r"(<\?php|<%@\s*page|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|cmd\.exe|powershell\.exe|eval\s*\(|assert\s*\(|base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|system\s*\(|exec\s*\(|request\.getParameter)",
    re.IGNORECASE,
)

CVE_SIGNATURES = [
    {
        "cve_id": "CVE-2021-44228",
        "name": "Log4Shell",
        "pattern": re.compile(r"(\$\{jndi:(ldap|ldaps|rmi|dns|iiop)|%24%7Bjndi:(ldap|ldaps|rmi|dns|iiop))", re.IGNORECASE),
    },
    {
        "cve_id": "CVE-2022-22965",
        "name": "Spring4Shell",
        "pattern": re.compile(
            r"(class\.module\.classLoader|class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first)",
            re.IGNORECASE,
        ),
    },
    {
        "cve_id": "CVE-2017-5638",
        "name": "Apache Struts 2 OGNL",
        "pattern": re.compile(
            r"(%\{\(#_memberAccess|#context\[['\"]com\.opensymphony\.xwork2\.dispatcher\.HttpServletResponse['\"]\]|multipart/form-data.{0,120}%\{)",
            re.IGNORECASE,
        ),
    },
    {
        "cve_id": "CVE-2022-26134",
        "name": "Confluence OGNL RCE",
        "pattern": re.compile(
            r"(\$\{.*@java\.lang\.Runtime@getRuntime\(\)\.exec|%24%7B.*@java\.lang\.Runtime@getRuntime\(\)\.exec)",
            re.IGNORECASE,
        ),
    },
    {
        "cve_id": "CVE-2019-19781",
        "name": "Citrix ADC Path Traversal",
        "pattern": re.compile(r"(/vpn/../vpns/|/vpn/%2e%2e/vpns/)", re.IGNORECASE),
    },
    {
        "cve_id": "CVE-2021-41773",
        "name": "Apache Path Traversal",
        "pattern": re.compile(r"(/\.\%2e/|\.\%2e/\.\%2e/|\.\./\.\./etc/passwd)", re.IGNORECASE),
    },
    {
        "cve_id": "CVE-2017-9841",
        "name": "PHPUnit eval-stdin",
        "pattern": re.compile(r"(phpunit/.+eval-stdin\.php|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php)", re.IGNORECASE),
    },
    {
        "cve_id": "CVE-2018-20062",
        "name": "ThinkPHP RCE",
        "pattern": re.compile(r"(think\\app/invokefunction|/index\.php\?s=/Index/\\think\\app/invokefunction)", re.IGNORECASE),
    },
]


RULES = [
    (
        "sql_injection",
        re.compile(
            r"(\bunion\b.{0,24}\bselect\b|\bselect\b.{0,24}\bfrom\b|\bor\b\s+1=1|\bdrop\s+table\b|\binformation_schema\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "xss",
        re.compile(r"(<script\b|javascript:|onerror=|onload=|alert\s*\(|document\.cookie)", re.IGNORECASE),
    ),
    (
        "path_traversal",
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini)", re.IGNORECASE),
    ),
    (
        "command_injection",
        re.compile(r"(\|\||&&|;\s*(cat|curl|wget|bash|sh)\b|`.+`|\$\(.*\))", re.IGNORECASE),
    ),
    (
        "scanner_probe",
        re.compile(r"(sqlmap|nmap|nikto|acunetix|dirbuster|gobuster|masscan)", re.IGNORECASE),
    ),
]


def looks_like_auth_attempt(method: str, path: str, query: str, body_text: str, authorization: str = "") -> bool:
    joined = f"{path}?{query}"
    if authorization.lower().startswith("basic "):
        return True
    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return False
    if LOGIN_PATH_PATTERN.search(joined):
        return True
    if LOGIN_FIELD_PATTERN.search(body_text):
        return True
    return False


def detect_webshell_upload(method: str, path: str, content_type: str, body_text: str) -> DetectionResult:
    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return DetectionResult(blocked=False)

    route_hit = UPLOAD_PATH_PATTERN.search(path) is not None
    multipart_hit = "multipart/form-data" in (content_type or "").lower()
    filename_hit = WEBSHELL_FILENAME_PATTERN.search(body_text)
    payload_hit = WEBSHELL_PAYLOAD_PATTERN.search(body_text)

    if filename_hit and payload_hit:
        return DetectionResult(
            blocked=True,
            rule_name="webshell_upload",
            matched_on="body",
            detail=f"{filename_hit.group(1)} + {payload_hit.group(0)[:120]}",
        )

    if route_hit and filename_hit:
        return DetectionResult(
            blocked=True,
            rule_name="webshell_upload",
            matched_on="body",
            detail=f"可疑脚本扩展名: {filename_hit.group(1)}",
        )

    if multipart_hit and filename_hit and payload_hit:
        return DetectionResult(
            blocked=True,
            rule_name="webshell_upload",
            matched_on="body",
            detail=f"可疑上传内容: {filename_hit.group(1)}",
        )

    return DetectionResult(blocked=False)


def detect_cve_exploit(method: str, path: str, query: str, body_text: str, user_agent: str) -> DetectionResult:
    candidates = {
        "path": f"{method} {path}",
        "query": query or "",
        "body": body_text or "",
        "user_agent": user_agent or "",
    }

    for signature in CVE_SIGNATURES:
        for field, value in candidates.items():
            match = signature["pattern"].search(value)
            if match:
                return DetectionResult(
                    blocked=True,
                    rule_name="cve_exploit_attempt",
                    matched_on=field,
                    detail=f"{signature['name']} / {match.group(0)[:140]}",
                    cve_id=signature["cve_id"],
                )

    return DetectionResult(blocked=False)


def inspect_request(
    method: str,
    path: str,
    query: str,
    body_text: str,
    user_agent: str,
    content_type: str = "",
) -> DetectionResult:
    webshell_detection = detect_webshell_upload(method, path, content_type, body_text)
    if webshell_detection.blocked:
        return webshell_detection

    cve_detection = detect_cve_exploit(method, path, query, body_text, user_agent)
    if cve_detection.blocked:
        return cve_detection

    candidates = {
        "path": f"{method} {path}",
        "query": query or "",
        "body": body_text or "",
        "user_agent": user_agent or "",
    }

    for rule_name, pattern in RULES:
        for field, value in candidates.items():
            match = pattern.search(value)
            if match:
                return DetectionResult(
                    blocked=True,
                    rule_name=rule_name,
                    matched_on=field,
                    detail=match.group(0)[:200],
                )

    return DetectionResult(blocked=False)

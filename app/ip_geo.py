from __future__ import annotations

import ipaddress

import httpx


def classify_special_ip(ip: str) -> dict | None:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "label": "无效 IP",
            "country": "",
            "region": "",
            "city": "",
            "isp": "",
            "source": "local",
        }

    if parsed.is_loopback:
        return {
            "label": "本机回环地址",
            "country": "本机",
            "region": "",
            "city": "",
            "isp": "",
            "source": "local",
        }

    if parsed.is_private:
        return {
            "label": "内网地址",
            "country": "内网",
            "region": "",
            "city": "",
            "isp": "",
            "source": "local",
        }

    if parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return {
            "label": "保留地址",
            "country": "保留地址",
            "region": "",
            "city": "",
            "isp": "",
            "source": "local",
        }

    return None


def lookup_ip_geo(ip: str) -> dict:
    special = classify_special_ip(ip)
    if special is not None:
        return special

    try:
        response = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "lang": "zh-CN",
                "fields": "status,message,country,regionName,city,isp,query",
            },
            timeout=5.0,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return {
            "label": "定位失败",
            "country": "",
            "region": "",
            "city": "",
            "isp": "",
            "source": "remote",
        }

    if payload.get("status") != "success":
        return {
            "label": "未知位置",
            "country": "",
            "region": "",
            "city": "",
            "isp": "",
            "source": "remote",
        }

    country = payload.get("country") or ""
    region = payload.get("regionName") or ""
    city = payload.get("city") or ""
    isp = payload.get("isp") or ""
    label = " / ".join([part for part in [country, region, city] if part]) or "未知位置"

    return {
        "label": label,
        "country": country,
        "region": region,
        "city": city,
        "isp": isp,
        "source": "remote",
    }

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

DEFAULT_HEADERS = {
    "User-Agent": "GDPR-Wizard/1.0 (+https://localhost)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
MAX_HTML_SCAN = 8000


@dataclass
class InspectionResult:
    url: Optional[str]
    reachable: bool
    status_code: Optional[int]
    cookies: Dict[str, Any]
    banner_detected: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "cookies": self.cookies,
            "banner_detected": self.banner_detected,
        }


def _no_site(reason: str) -> InspectionResult:
    return InspectionResult(
        url=None,
        reachable=False,
        status_code=None,
        cookies={"enabled": False, "details": [], "reason": reason},
        banner_detected=False,
    )


def _normalize_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        return f"https://{raw_url}".rstrip("/")
    return raw_url


def inspect_website(raw_url: Optional[str]) -> Dict[str, Any]:
    if not raw_url:
        return _no_site("no_website").as_dict()
    url = _normalize_url(raw_url)
    if not url:
        return _no_site("no_website").as_dict()
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=6)
    except requests.RequestException:
        return InspectionResult(
            url=url,
            reachable=False,
            status_code=None,
            cookies={"enabled": False, "details": [], "reason": "unreachable"},
            banner_detected=False,
        ).as_dict()
    cookie_details = []
    for cookie in response.cookies:
        rest = getattr(cookie, "_rest", {}) or {}
        cookie_details.append(
            {
                "name": cookie.name,
                "domain": cookie.domain,
                "secure": cookie.secure,
                "http_only": bool(rest.get("HttpOnly")),
                "expires": cookie.expires,
            }
        )
    enabled = bool(cookie_details)
    snippet = (response.text or "")[:MAX_HTML_SCAN]
    banner_detected = bool(re.search(r"cookie", snippet, re.IGNORECASE))
    cookies_payload = {
        "enabled": enabled,
        "details": cookie_details,
        "reason": "detected" if enabled else "not_detected",
        "banner_detected": banner_detected,
    }
    if not enabled and not banner_detected:
        cookies_payload["reason"] = "no_evidence"
    return InspectionResult(
        url=response.url or url,
        reachable=True,
        status_code=response.status_code,
        cookies=cookies_payload,
        banner_detected=banner_detected,
    ).as_dict()

"""
EL: Deep cookie compliance scanner με τεχνικό και κανονιστικό scoring.
EN: Deep cookie compliance scanner with technical and regulatory scoring.

EL: Το module συλλέγει evidence από headers, cookies, banner copy, policy links,
και resource hosts ώστε να παράγει actionable findings και remediation gaps.

EN: This module collects evidence from headers, cookies, banner copy, policy links,
and resource hosts to produce actionable findings and remediation gaps.
"""

from __future__ import annotations

import re
import socket
import ssl
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Pattern, Tuple
from urllib.parse import urljoin, urlparse

import requests

DEFAULT_HEADERS = {
    "User-Agent": "GDPR-Wizard/1.0 (+https://localhost)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
MAX_HTML_BYTES = 60000
POLICY_HTML_BYTES = 90000
REQUEST_TIMEOUT = 10
SECURITY_HEADER_NAMES = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
RECOMMENDED_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "origin",
    "origin-when-cross-origin",
}
TRACKER_SIGNATURES: List[Tuple[str, Pattern[str]]] = [
    ("Google Analytics", re.compile(r"www\.google-analytics\.com|gtag/js|analytics\.js", re.IGNORECASE)),
    ("Google Tag Manager", re.compile(r"googletagmanager\.com", re.IGNORECASE)),
    ("Meta Pixel", re.compile(r"connect\.facebook\.net|fbq\(", re.IGNORECASE)),
    ("Hotjar", re.compile(r"static\.hotjar\.com|script\.hotjar\.com|hotjar\.com", re.IGNORECASE)),
    ("LinkedIn Insight", re.compile(r"snap\.licdn\.com", re.IGNORECASE)),
    ("Matomo", re.compile(r"piwik\.js|matomo\.js", re.IGNORECASE)),
    ("HubSpot Tracking", re.compile(r"js\.hs-analytics\.net", re.IGNORECASE)),
]
CONSENT_TOOL_SIGNATURES: List[Tuple[str, Pattern[str]]] = [
    ("Cookiebot", re.compile(r"Cookiebot|consent\.cookiebot\.com", re.IGNORECASE)),
    ("OneTrust", re.compile(r"onetrust|optanon", re.IGNORECASE)),
    ("IAB TCF", re.compile(r"__tcfapi", re.IGNORECASE)),
    ("Didomi", re.compile(r"didomi|consent\.didomi\.io", re.IGNORECASE)),
    ("Quantcast Consent", re.compile(r"quantcast-choice", re.IGNORECASE)),
]
COOKIE_CATEGORY_HINTS: Dict[str, List[Pattern[str]]] = {
    "strictly_necessary": [re.compile(r"session", re.IGNORECASE), re.compile(r"csrftoken", re.IGNORECASE), re.compile(r"auth", re.IGNORECASE)],
    "analytics": [
        re.compile(r"^_ga", re.IGNORECASE),
        re.compile(r"^_gid", re.IGNORECASE),
        re.compile(r"^_gat", re.IGNORECASE),
        re.compile(r"_hj", re.IGNORECASE),
        re.compile(r"matomo", re.IGNORECASE),
        re.compile(r"piwik", re.IGNORECASE),
    ],
    "advertising": [
        re.compile(r"^_fbp", re.IGNORECASE),
        re.compile(r"^_gcl", re.IGNORECASE),
        re.compile(r"^_uet", re.IGNORECASE),
        re.compile(r"^_scid", re.IGNORECASE),
        re.compile(r"adroll", re.IGNORECASE),
        re.compile(r"doubleclick", re.IGNORECASE),
    ],
    "preferences": [
        re.compile(r"consent", re.IGNORECASE),
        re.compile(r"remember", re.IGNORECASE),
        re.compile(r"lang", re.IGNORECASE),
    ],
}
BANNER_CONTEXT_RE = re.compile(r"(.{0,80}cookie.{0,120}(accept|consent|settings).{0,80})", re.IGNORECASE | re.DOTALL)
POLICY_TEXT_KEYWORDS = ["policy", "notice", "statement", "information", "settings", "preferences", "details", "declaration"]
POLICY_CANDIDATE_KEYWORDS = ["cookie", "privacy", "gdpr", "data protection", "policy", "notice", "legal", "preferences"]
SKIPPED_POLICY_LINK_PREFIXES = ("#", "javascript:", "mailto:", "tel:")
CONSENT_ACCEPT_RE = re.compile(r"(accept all|allow all|agree|i agree|consent)", re.IGNORECASE)
CONSENT_REJECT_RE = re.compile(r"(reject all|decline|deny|refuse|necessary only)", re.IGNORECASE)
CONSENT_SETTINGS_RE = re.compile(r"(manage preferences|cookie settings|manage consent|privacy settings|customi[sz]e)", re.IGNORECASE)
RESOURCE_TAG_PATTERNS: Dict[str, Pattern[str]] = {
    "script": re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
    "img": re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
    "iframe": re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
    "link": re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
}
POLICY_DISCLOSURE_PATTERNS: Dict[str, Pattern[str]] = {
    "categories": re.compile(r"(strictly necessary|analytics|advertising|marketing|preferences|statistics)", re.IGNORECASE),
    "retention": re.compile(r"(retention|expire|storage period|how long)", re.IGNORECASE),
    "withdrawal": re.compile(r"(withdraw consent|change consent|opt[- ]out|revoke consent)", re.IGNORECASE),
    "contact": re.compile(r"(contact|dpo|data protection|privacy@|email)", re.IGNORECASE),
}
COOKIE_MENTION_RE = re.compile(r"\bcookies?\b", re.IGNORECASE)


def _normalize_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        return f"https://{raw_url}".rstrip("/")
    return raw_url


def parse_hostname(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    return parsed.hostname or ""


def summarize_cookie_audit(audit: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    EL: Παράγει concise executive σύνοψη του πλήρους cookie audit payload.
    EN: Produces a concise executive summary from the full cookie audit payload.
    """

    if not audit:
        return None
    summary: Dict[str, Any] = {
        "url": audit.get("url"),
        "checked_at": audit.get("checked_at"),
        "score": audit.get("score"),
        "features": [],
    }
    features: List[str] = []
    technical = audit.get("technical") or {}
    if audit.get("banner_detected"):
        features.append("Consent banner present on initial page load.")
    consent_tools = audit.get("consent_signals") or []
    if consent_tools:
        features.append("Consent platform integrated: " + ", ".join(consent_tools))
        summary["consent_platforms"] = consent_tools
    consent_ui = audit.get("consent_ui") or {}
    if consent_ui.get("banner_detected"):
        if consent_ui.get("granular_choices"):
            features.append("Consent UI includes accept and reject/manage actions.")
        else:
            features.append("Consent UI detected but reject/manage action is unclear.")
    policy_links = audit.get("policy_links") or []
    if policy_links:
        features.append("Cookie policy link(s) exposed to users.")
        summary["policy_links"] = policy_links
    policy_page_analysis = audit.get("policy_page_analysis") or {}
    if policy_page_analysis.get("checked"):
        coverage = policy_page_analysis.get("coverage") or {}
        covered = [key for key, present in coverage.items() if present]
        if covered:
            features.append("Policy page disclosures found: " + ", ".join(covered))
        if policy_page_analysis.get("cookie_mentions"):
            features.append(f"Policy page references cookies ({policy_page_analysis.get('cookie_mentions')} mention(s)).")
        summary["policy_page"] = {
            "url": policy_page_analysis.get("url"),
            "status_code": policy_page_analysis.get("status_code"),
            "coverage": coverage,
            "cookie_mentions": policy_page_analysis.get("cookie_mentions"),
        }
    sec_headers = technical.get("security_headers") or {}
    strong_headers = [name for name, meta in sec_headers.items() if (meta or {}).get("present")]
    if strong_headers:
        features.append("Security headers configured: " + ", ".join(strong_headers))
    tls = technical.get("tls") or {}
    if tls.get("ok"):
        issuer = tls.get("issuer")
        detail = "Valid TLS certificate"
        if issuer:
            detail += f" issued by {issuer}"
        features.append(detail + ".")
        summary["tls"] = {key: tls.get(key) for key in ("issuer", "days_left", "ok")}
    if technical.get("https"):
        features.append("HTTPS enforced on the landing page.")
    cookies = audit.get("cookies") or []
    if isinstance(cookies, list) and cookies:
        categories = Counter((cookie.get("category") or "unclassified" for cookie in cookies))
        formatted = [f"{count} {label.replace('_', ' ')}" for label, count in categories.items()]
        features.append("Observed cookie categories: " + ", ".join(formatted))
        summary["cookie_categories"] = {label: count for label, count in categories.items()}
    storage_signals = audit.get("storage_signals") or {}
    if any(storage_signals.values()):
        observed = [name for name, value in storage_signals.items() if value]
        features.append("Client storage signals: " + ", ".join(observed))
        summary["storage_signals"] = observed
    resources = audit.get("resource_inventory") or {}
    third_party_hosts = resources.get("third_party_hosts") or []
    if third_party_hosts:
        features.append(f"{len(third_party_hosts)} third-party resource host(s) referenced.")
        summary["third_party_hosts"] = third_party_hosts[:10]
    summary["features"] = features
    summary["url"] = audit.get("url")
    summary["checked_at"] = audit.get("checked_at")
    summary["score"] = audit.get("score")
    return summary


def _empty_technical() -> Dict[str, Any]:
    return {
        "https": False,
        "security_headers": {
            name: {"present": False, "value": None, "status": "missing", "detail": "Header not returned"}
            for name in SECURITY_HEADER_NAMES
        },
        "tls": {"ok": False, "days_left": None, "issuer": None},
        "headers": {"server": None, "powered_by": None},
        "metrics": {"response_time_ms": None, "content_length": None, "status_code": None},
    }


class _AnchorCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self._anchor_depth = 0
        self._current_href: Optional[str] = None
        self._current_texts: List[str] = []
        self._current_attr_text: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        tag_lower = tag.lower()
        attr_map = {name.lower(): (value or "") for name, value in attrs}
        if tag_lower == "a":
            if self._anchor_depth > 0:
                self._anchor_depth += 1
                return
            href = attr_map.get("href")
            if not href:
                return
            self._anchor_depth = 1
            self._current_href = href
            self._current_texts = []
            self._current_attr_text = [attr_map.get(key, "") for key in ("title", "aria-label", "data-label") if attr_map.get(key)]
        elif self._anchor_depth > 0:
            self._anchor_depth += 1
            if tag_lower == "img":
                alt_text = attr_map.get("alt") or attr_map.get("title")
                if alt_text:
                    self._current_texts.append(alt_text)

    def handle_endtag(self, tag: str):
        if self._anchor_depth == 0:
            return
        self._anchor_depth -= 1
        if self._anchor_depth == 0 and self._current_href is not None:
            combined_text = " ".join(part.strip() for part in (" ".join(self._current_texts), " ".join(self._current_attr_text)) if part).strip()
            self.links.append((self._current_href, combined_text))
            self._current_href = None
            self._current_texts = []
            self._current_attr_text = []

    def handle_data(self, data: str):
        if self._anchor_depth > 0 and data:
            self._current_texts.append(data)

    def handle_startendtag(self, tag: str, attrs):
        # EL: Πιάνει self-closing tags (π.χ. <img/>) που βρίσκονται σε anchor.
        # EN: Captures self-closing tags (e.g. <img/>) inside an anchor.
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def error(self, message: str):
        # EL: Το HTMLParser απαιτεί override του error handler.
        # EN: HTMLParser requires overriding the error handler.
        pass


def _detect_signals(html: str, signatures: List[Tuple[str, Pattern[str]]]) -> List[str]:
    if not html:
        return []
    signals: List[str] = []
    for name, pattern in signatures:
        if pattern.search(html):
            signals.append(name)
    return signals


def _extract_banner_context(html: str) -> Optional[str]:
    if not html:
        return None
    match = BANNER_CONTEXT_RE.search(html)
    if not match:
        return None
    snippet = re.sub(r"\s+", " ", match.group(1))
    return snippet.strip()


def _cookie_duration_days(expires: Optional[int]) -> Optional[int]:
    if not expires:
        return None
    try:
        expiry = datetime.fromtimestamp(expires, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return None
    delta = expiry - datetime.now(UTC)
    return max(0, delta.days)


def _cookie_expiry_iso(expires: Optional[int]) -> Optional[str]:
    if not expires:
        return None
    try:
        return datetime.fromtimestamp(expires, tz=UTC).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _classify_cookie(name: Optional[str]) -> str:
    name = (name or "").lower()
    if not name:
        return "unclassified"
    for category, patterns in COOKIE_CATEGORY_HINTS.items():
        for pattern in patterns:
            if pattern.search(name):
                return category
    return "unclassified"


def _is_third_party_cookie(cookie_domain: Optional[str], hostname: str) -> bool:
    if not cookie_domain or not hostname:
        return False
    cookie_host = cookie_domain.lstrip(".").lower()
    host = hostname.lower()
    return not (host.endswith(cookie_host) or cookie_host.endswith(host))


def _cookie_requires_http_only(name: Optional[str]) -> bool:
    lowered = (name or "").lower()
    if not lowered:
        return False
    return any(token in lowered for token in ("session", "auth", "token", "secure"))


def _html_metadata(html: str) -> Dict[str, Any]:
    title = None
    lang = None
    if html:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = re.sub(r"\s+", " ", title_match.group(1)).strip()
        lang_match = re.search(r"<html[^>]+lang=[\"']?([a-zA-Z-]+)", html, re.IGNORECASE)
        if lang_match:
            lang = lang_match.group(1)
    scripts = len(re.findall(r"<script\b", html, re.IGNORECASE)) if html else 0
    forms = len(re.findall(r"<form\b", html, re.IGNORECASE)) if html else 0
    links = len(re.findall(r"<a\b", html, re.IGNORECASE)) if html else 0
    return {"title": title, "language": lang, "script_count": scripts, "form_count": forms, "link_count": links}


def _is_same_party_host(hostname: str, candidate_host: str) -> bool:
    host = (hostname or "").lower()
    candidate = (candidate_host or "").lower()
    if not host or not candidate:
        return False
    return host.endswith(candidate) or candidate.endswith(host)


def _extract_resource_hosts(html: str, final_url: str, hostname: str) -> Dict[str, Any]:
    if not html:
        return {
            "all_hosts": [],
            "third_party_hosts": [],
            "third_party_by_tag": {},
            "resource_counts": {},
        }
    all_hosts: List[str] = []
    third_party_hosts: List[str] = []
    third_party_by_tag: Dict[str, List[str]] = {}
    resource_counts: Dict[str, int] = {}
    for tag, pattern in RESOURCE_TAG_PATTERNS.items():
        tag_hosts: List[str] = []
        matches = pattern.findall(html)
        resource_counts[tag] = len(matches)
        for raw_src in matches:
            resolved = urljoin(final_url, raw_src)
            parsed = urlparse(resolved)
            resource_host = (parsed.hostname or "").lower()
            if not resource_host:
                continue
            if resource_host not in all_hosts:
                all_hosts.append(resource_host)
            if _is_same_party_host(hostname, resource_host):
                continue
            if resource_host not in third_party_hosts:
                third_party_hosts.append(resource_host)
            if resource_host not in tag_hosts:
                tag_hosts.append(resource_host)
        if tag_hosts:
            third_party_by_tag[tag] = tag_hosts[:10]
    return {
        "all_hosts": all_hosts[:30],
        "third_party_hosts": third_party_hosts[:20],
        "third_party_by_tag": third_party_by_tag,
        "resource_counts": resource_counts,
    }


def _detect_storage_and_cookie_access(html: str) -> Dict[str, bool]:
    if not html:
        return {
            "document_cookie_read": False,
            "document_cookie_write": False,
            "local_storage": False,
            "session_storage": False,
            "indexed_db": False,
        }
    document_cookie_read = bool(re.search(r"document\.cookie", html, re.IGNORECASE))
    document_cookie_write = bool(re.search(r"document\.cookie\s*=", html, re.IGNORECASE))
    local_storage = bool(re.search(r"localStorage\.(setItem|getItem|removeItem)|window\.localStorage", html, re.IGNORECASE))
    session_storage = bool(re.search(r"sessionStorage\.(setItem|getItem|removeItem)|window\.sessionStorage", html, re.IGNORECASE))
    indexed_db = bool(re.search(r"indexedDB\.", html, re.IGNORECASE))
    return {
        "document_cookie_read": document_cookie_read,
        "document_cookie_write": document_cookie_write,
        "local_storage": local_storage,
        "session_storage": session_storage,
        "indexed_db": indexed_db,
    }


def _consent_ui_signals(html: str) -> Dict[str, Any]:
    if not html:
        return {
            "banner_detected": False,
            "accept_action": False,
            "reject_action": False,
            "settings_action": False,
            "granular_choices": False,
            "cookie_mentions": 0,
        }
    cookie_mentions = len(re.findall(r"\bcookie\b", html, re.IGNORECASE))
    accept_action = bool(CONSENT_ACCEPT_RE.search(html))
    reject_action = bool(CONSENT_REJECT_RE.search(html))
    settings_action = bool(CONSENT_SETTINGS_RE.search(html))
    banner_detected = bool(cookie_mentions and (accept_action or reject_action or settings_action))
    return {
        "banner_detected": banner_detected,
        "accept_action": accept_action,
        "reject_action": reject_action,
        "settings_action": settings_action,
        "granular_choices": bool((reject_action or settings_action) and accept_action),
        "cookie_mentions": cookie_mentions,
    }


def _set_cookie_headers(response: requests.Response) -> List[str]:
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = [value for value in raw_headers.getlist("Set-Cookie") if value]
        if values:
            return values
    combined = response.headers.get("Set-Cookie")
    if not combined:
        return []
    # EL: Fallback για clients που επιστρέφουν merged Set-Cookie header.
    # EN: Fallback for clients exposing a single merged Set-Cookie header.
    return [combined]


def _parse_set_cookie_names(set_cookie_headers: List[str]) -> List[str]:
    names: List[str] = []
    for header_value in set_cookie_headers:
        simple = SimpleCookie()
        try:
            simple.load(header_value)
        except Exception:
            continue
        for morsel_name in simple.keys():
            if morsel_name not in names:
                names.append(morsel_name)
    return names


def _analyze_policy_page(session_client: requests.Session, policy_links: List[str], final_url: str) -> Dict[str, Any]:
    if not policy_links:
        return {"checked": False, "url": None, "status_code": None, "coverage": {}, "cookie_mentions": 0}
    best_match: Optional[Dict[str, Any]] = None
    for link in policy_links:
        resolved = urljoin(final_url, link)
        parsed = urlparse(resolved)
        if parsed.scheme not in {"http", "https"}:
            continue
        try:
            policy_response = session_client.get(resolved, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        text = (policy_response.text or "")[:POLICY_HTML_BYTES]
        coverage = {
            key: bool(pattern.search(text))
            for key, pattern in POLICY_DISCLOSURE_PATTERNS.items()
        }
        coverage_hits = sum(1 for present in coverage.values() if present)
        cookie_mentions = len(COOKIE_MENTION_RE.findall(text))
        score = min(cookie_mentions, 8) + (coverage_hits * 3)
        if "privacy" in (resolved.lower() + (policy_response.url or "").lower()):
            score += 1
        candidate = {
            "checked": True,
            "url": policy_response.url or resolved,
            "status_code": policy_response.status_code,
            "coverage": coverage,
            "cookie_mentions": cookie_mentions,
            "coverage_hits": coverage_hits,
            "score": score,
        }
        if best_match is None or candidate["score"] > best_match["score"]:
            best_match = candidate
    if best_match:
        return best_match
    return {"checked": False, "url": None, "status_code": None, "coverage": {}, "cookie_mentions": 0}


@dataclass
class CookieAuditResult:
    """
    EL: Canonical runtime model για serialized αποτελέσματα cookie audit.
    EN: Canonical runtime model for serialized cookie audit results.
    """

    url: Optional[str]
    reachable: bool
    status_code: Optional[int]
    cookies: List[Dict[str, Any]]
    banner_detected: bool
    banner_context: Optional[str]
    policy_links: List[str]
    score: int
    summary: str
    findings: List[str]
    recommendations: List[str]
    checked_at: str
    technical: Dict[str, Any]
    tracker_signals: List[str]
    consent_signals: List[str]
    consent_ui: Dict[str, Any]
    storage_signals: Dict[str, bool]
    resource_inventory: Dict[str, Any]
    set_cookie_headers: List[str]
    policy_page_analysis: Dict[str, Any]
    page_metadata: Dict[str, Any]
    compliance_gaps: List[Dict[str, Any]]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "reachable": self.reachable,
            "status_code": self.status_code,
            "cookies": self.cookies,
            "banner_detected": self.banner_detected,
            "banner_context": self.banner_context,
            "policy_links": self.policy_links,
            "score": self.score,
            "summary": self.summary,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "checked_at": self.checked_at,
            "technical": self.technical,
            "tracker_signals": self.tracker_signals,
            "consent_signals": self.consent_signals,
            "consent_ui": self.consent_ui,
            "storage_signals": self.storage_signals,
            "resource_inventory": self.resource_inventory,
            "set_cookie_headers": self.set_cookie_headers,
            "policy_page_analysis": self.policy_page_analysis,
            "page_metadata": self.page_metadata,
            "compliance_gaps": self.compliance_gaps,
        }


def _extract_policy_links(html: str) -> List[str]:
    if not html:
        return []
    parser = _AnchorCollector()
    try:
        parser.feed(html)
    except Exception:
        # EL: Αγνοούμε malformed HTML χωρίς να τερματίζουμε το audit.
        # EN: Gracefully ignore malformed HTML without aborting the audit.
        pass
    results: List[str] = []
    for href, label in parser.links:
        normalized_label = (label or "").lower()
        normalized_href = (href or "").lower()
        if _is_cookie_policy_reference(normalized_label, normalized_href):
            if href not in results:
                results.append(href)
        if len(results) >= 5:
            break
    return results


def _is_policy_candidate_reference(label_text: str, href: str) -> bool:
    if not href:
        return False
    lowered_href = href.lower().strip()
    if lowered_href.startswith(SKIPPED_POLICY_LINK_PREFIXES):
        return False
    combined = f"{label_text} {lowered_href}"
    return any(keyword in combined for keyword in POLICY_CANDIDATE_KEYWORDS)


def _candidate_policy_score(label_text: str, href: str) -> int:
    score = 0
    combined = f"{label_text} {href}".lower()
    if "cookie" in combined:
        score += 8
    if "privacy" in combined:
        score += 5
    if "gdpr" in combined or "data protection" in combined:
        score += 4
    if "policy" in combined or "notice" in combined:
        score += 2
    if "legal" in combined:
        score += 1
    return score


def _extract_candidate_policy_links(html: str) -> List[str]:
    if not html:
        return []
    parser = _AnchorCollector()
    try:
        parser.feed(html)
    except Exception:
        pass
    scored: List[Tuple[int, str]] = []
    seen: set[str] = set()
    for href, label in parser.links:
        normalized_label = (label or "").lower()
        normalized_href = (href or "").strip()
        if not _is_policy_candidate_reference(normalized_label, normalized_href):
            continue
        if normalized_href in seen:
            continue
        seen.add(normalized_href)
        score = _candidate_policy_score(normalized_label, normalized_href)
        scored.append((score, normalized_href))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [href for _, href in scored[:12]]


def _is_cookie_policy_reference(label_text: str, href: str) -> bool:
    if "cookie" in label_text:
        if any(keyword in label_text for keyword in POLICY_TEXT_KEYWORDS) or label_text.count("cookie") > 1:
            return True
    if "cookie" in href:
        if any(keyword in href for keyword in POLICY_TEXT_KEYWORDS) or href.endswith("cookie") or "cookies" in href:
            return True
    return False


def _assess_hsts(value: str) -> Tuple[str, str]:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return ("warn", "Missing max-age directive.")
    max_age = int(match.group(1))
    if max_age < 10886400:  # EL: 18 εβδομάδες / EN: 18 weeks
        return ("warn", f"max-age {max_age} is below best practice (>=10886400).")
    detail = "Includes subdomains." if "includesubdomains" in value.lower() else "Does not cover subdomains."
    return ("good", detail)


def _assess_csp(value: str) -> Tuple[str, str]:
    lowered = value.lower()
    if not lowered.strip():
        return ("fail", "Empty Content-Security-Policy value.")
    if "default-src" not in lowered:
        return ("warn", "Missing default-src directive.")
    default_match = re.search(r"default-src\s+([^;]+)", lowered)
    if default_match:
        directive = default_match.group(1)
        if "*" in directive:
            return ("warn", "default-src wildcard allows any origin.")
    if "'unsafe-inline'" in lowered or "'unsafe-eval'" in lowered:
        return ("warn", "Allows unsafe inline/eval scripts.")
    return ("good", "CSP present with default-src directive.")


def _assess_xfo(value: str) -> Tuple[str, str]:
    lowered = value.strip().lower()
    if lowered in {"deny", "sameorigin"}:
        return ("good", f"Set to {lowered}.")
    if lowered.startswith("allow-from"):
        return ("warn", "allow-from is deprecated; prefer SAMEORIGIN or frame-ancestors in CSP.")
    return ("warn", "Unrecognized X-Frame-Options value.")


def _assess_referrer(value: str) -> Tuple[str, str]:
    lowered = value.strip().lower()
    if not lowered:
        return ("warn", "Empty Referrer-Policy value.")
    if lowered in RECOMMENDED_REFERRER_POLICIES:
        return ("good", f"Using {lowered}.")
    return ("warn", f"{value.strip()} is less privacy-preserving than recommended values.")


def _assess_permissions(value: str) -> Tuple[str, str]:
    lowered = value.strip().lower()
    if not lowered:
        return ("warn", "Empty Permissions-Policy value.")
    if "=" not in lowered:
        return ("warn", "No feature directives detected.")
    if "interest-cohort" in lowered and "=()" not in lowered:
        return ("warn", "Does not disable FLoC/Topics (interest-cohort).")
    return ("good", "Feature directives declared.")


SECURITY_HEADER_ASSESSORS = {
    "Strict-Transport-Security": _assess_hsts,
    "Content-Security-Policy": _assess_csp,
    "X-Frame-Options": _assess_xfo,
    "Referrer-Policy": _assess_referrer,
    "Permissions-Policy": _assess_permissions,
}


def _audit_score(
    reachable: bool,
    cookies: List[Dict[str, Any]],
    banner_detected: bool,
    consent_ui: Dict[str, Any],
    policy_links: List[str],
    policy_page_analysis: Dict[str, Any],
    hostname: str,
    security_headers: Dict[str, Dict[str, Any]],
    tls_ok: bool,
    days_left: Optional[int],
    tracker_signals: List[str],
    consent_signals: List[str],
    storage_signals: Dict[str, bool],
    third_party_hosts: List[str],
    set_cookie_mismatch: bool,
    long_lived_cookies: List[Dict[str, Any]],
    http_only_gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    EL: Υπολογίζει compliance score με weighted penalties και recommendations.
    EN: Computes compliance score with weighted penalties and recommendations.
    """

    score = 100
    findings: List[str] = []
    recommendations: List[str] = []
    if not reachable:
        return {
            "score": 0,
            "findings": ["Website could not be reached."],
            "recommendations": ["Verify the URL and ensure the site responds over HTTPS before scanning."],
        }
    if cookies and not banner_detected:
        score -= 40
        findings.append("Cookies set before any evidence of a consent banner.")
        recommendations.append("Ensure a consent banner appears before setting non-essential cookies.")
    if banner_detected and not consent_ui.get("granular_choices"):
        score -= 8
        findings.append("Consent UI detected, but no clear reject/settings controls were found.")
        recommendations.append("Offer both accept and reject/manage options at the first layer of the consent banner.")
    if cookies and not policy_links:
        score -= 30
        findings.append("No cookie policy link detected on the landing page.")
        recommendations.append("Publish a dedicated cookie policy and expose a clear link in the footer or banner.")
    if policy_page_analysis.get("checked"):
        coverage = policy_page_analysis.get("coverage") or {}
        missing_disclosures = [key for key, present in coverage.items() if not present]
        if missing_disclosures:
            score -= min(12, 3 * len(missing_disclosures))
            findings.append("Cookie policy exists but key disclosure areas are missing.")
            recommendations.append("Expand cookie policy content to include categories, retention, withdrawal, and contact details.")
    if not cookies and not banner_detected:
        findings.append("No cookies detected on first load.")
    insecure = [c for c in cookies if not c.get("secure")]
    if insecure:
        score -= 10
        findings.append("Some cookies lack the Secure flag.")
        recommendations.append("Mark cookies as Secure when served over HTTPS.")
    third_party = [c for c in cookies if hostname and c.get("domain") and hostname not in (c.get("domain") or "")]
    if third_party:
        score -= 10
        findings.append("Third-party cookies detected.")
        recommendations.append("Review third-party scripts/cookies and document them in the cookie policy.")
    missing_headers = [name for name, meta in security_headers.items() if not meta.get("present")]
    weak_headers = [
        name
        for name, meta in security_headers.items()
        if meta.get("present") and meta.get("status") in {"warn", "fail"}
    ]
    if missing_headers:
        score -= min(20, 5 * len(missing_headers))
        findings.append(f"Missing recommended security headers: {', '.join(missing_headers)}")
        recommendations.append("Implement standard HTTP security headers (HSTS, CSP, Referrer-Policy, X-Frame-Options).")
    if weak_headers:
        score -= min(10, 3 * len(weak_headers))
        findings.append(f"Security headers need tightening: {', '.join(weak_headers)}")
        recommendations.append("Review header values to ensure they enforce strict browser protections.")
    if not tls_ok:
        score -= 10
        findings.append("TLS handshake failed or certificate invalid.")
        recommendations.append("Ensure the site presents a valid TLS certificate and supports HTTPS.")
    elif days_left is not None and days_left < 30:
        score -= 5
        findings.append("TLS certificate expires within 30 days.")
        recommendations.append("Renew the TLS certificate to maintain uninterrupted HTTPS coverage.")
    if long_lived_cookies:
        score -= 5
        names = ", ".join(c.get("name") for c in long_lived_cookies[:3] if c.get("name"))
        label = f": {names}" if names else ""
        findings.append(f"Cookies with >13 month lifespan detected{label}.")
        recommendations.append("Shorten cookie lifespan to align with consent renewal expectations (<13 months).")
    if http_only_gaps:
        score -= 5
        names = ", ".join(c.get("name") for c in http_only_gaps[:3] if c.get("name"))
        label = f": {names}" if names else ""
        findings.append(f"Sensitive cookies served without HttpOnly flag{label}.")
        recommendations.append("Mark session/auth cookies as HttpOnly to prevent access from client-side scripts.")
    if tracker_signals and not banner_detected:
        score -= 10
        findings.append("Tracking scripts detected before any consent banner signals.")
        recommendations.append("Block marketing/analytics scripts until consent is recorded.")
    if tracker_signals and not consent_signals:
        findings.append("Trackers detected but no consent manager signature found.")
        recommendations.append("Document and integrate a consent platform that governs tracker loading.")
    if third_party_hosts and not banner_detected:
        score -= 6
        findings.append("Third-party resources load before visible consent controls.")
        recommendations.append("Delay non-essential third-party resources until consent has been captured.")
    if storage_signals.get("document_cookie_write") and not banner_detected:
        score -= 8
        findings.append("Client-side script writes cookies without visible consent controls.")
        recommendations.append("Gate JavaScript cookie writes behind explicit consent logic.")
    if set_cookie_mismatch:
        score -= 3
        findings.append("Set-Cookie header count differs from parsed cookie jar count.")
        recommendations.append("Review all Set-Cookie responses to ensure complete inventory and classification.")
    if banner_detected:
        findings.append("Consent banner keywords visible in markup.")
    if consent_signals:
        findings.append(f"Consent platform signature detected: {', '.join(consent_signals)}")
    if tracker_signals:
        findings.append(f"Tracking vendors referenced: {', '.join(tracker_signals)}")
    if policy_links:
        findings.append("Cookie policy link detected.")
    score = max(0, min(100, score))
    summary = "Strong compliance posture." if score >= 80 else "Partial compliance; remediation recommended." if score >= 50 else "High compliance risk detected."
    return {"score": score, "findings": findings, "recommendations": recommendations, "summary": summary}


def _compliance_gaps(
    cookies: List[Dict[str, Any]],
    banner_detected: bool,
    consent_ui: Dict[str, Any],
    policy_links: List[str],
    policy_page_analysis: Dict[str, Any],
    tracker_signals: List[str],
    consent_signals: List[str],
    security_headers: Dict[str, Dict[str, Any]],
    tls_report: Dict[str, Any],
    https_enforced: bool,
    long_lived_cookies: List[Dict[str, Any]],
    http_only_gaps: List[Dict[str, Any]],
    storage_signals: Dict[str, bool],
    set_cookie_mismatch: bool,
    page_metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    EL: Μετατρέπει τα signals σε δομημένο gap register για remediation planning.
    EN: Converts signals into a structured gap register for remediation planning.
    """

    gaps: List[Dict[str, Any]] = []

    def add_gap(area: str, severity: str, detail: str, recommendation: str, evidence: Optional[str] = None) -> None:
        entry = {
            "area": area,
            "severity": severity,
            "detail": detail,
            "recommendation": recommendation,
        }
        if evidence:
            entry["evidence"] = evidence
        gaps.append(entry)

    if cookies and not banner_detected:
        add_gap(
            "Consent banner",
            "high",
            "Cookies were observed before any consent prompt in the markup.",
            "Load a consent banner immediately and defer non-essential scripts until the visitor opts in.",
        )
    if cookies and not policy_links:
        add_gap(
            "Policy disclosure",
            "medium",
            "No cookie policy link was detected on the landing page.",
            "Expose a persistent cookie policy link (footer/header) and ensure it explains all cookie categories.",
        )
    if tracker_signals and not consent_signals:
        add_gap(
            "Consent management platform",
            "medium",
            "Tracking scripts load without evidence of a consent platform signature.",
            "Integrate the site with a CMP (e.g., IAB TCF, OneTrust, Cookiebot) and gate trackers behind it.",
            ", ".join(tracker_signals),
        )
    if banner_detected and not consent_ui.get("granular_choices"):
        add_gap(
            "Consent choice symmetry",
            "medium",
            "Banner copy appears to offer acceptance but no equivalent reject/manage action was detected.",
            "Provide reject/manage controls with similar prominence to the accept action.",
        )
    insecure = [c for c in cookies if not c.get("secure")]
    if insecure:
        add_gap(
            "Secure flag",
            "high",
            "Some cookies lack the Secure attribute despite HTTPS delivery.",
            "Set the Secure flag on all cookies set when HTTPS is available.",
            ", ".join(c.get("name") for c in insecure if c.get("name")),
        )
    third_party = [c for c in cookies if c.get("third_party")]
    if third_party:
        add_gap(
            "Third-party cookies",
            "medium",
            "External domains set cookies on first load.",
            "Ensure vendor contracts and the cookie policy document each third party and purpose.",
            ", ".join(sorted({c.get("domain") for c in third_party if c.get("domain")})),
        )
    if long_lived_cookies:
        add_gap(
            "Consent renewal",
            "medium",
            ">13 month cookie expiries detected, which can outlast user consent.",
            "Shorten cookie lifetime or refresh consent before the maximum retention window.",
        )
    if http_only_gaps:
        add_gap(
            "HttpOnly flag",
            "high",
            "Session/authentication cookies are accessible to client-side scripts.",
            "Mark authentication/session identifiers as HttpOnly to protect against injection attacks.",
        )
    missing_headers = [name for name, meta in security_headers.items() if not meta.get("present")]
    weak_headers = [
        f"{name}: {meta.get('detail')}"
        for name, meta in security_headers.items()
        if meta.get("present") and meta.get("status") in {"warn", "fail"}
    ]
    if missing_headers:
        add_gap(
            "Security headers",
            "medium",
            "Recommended HTTP security headers are absent.",
            "Configure HSTS, CSP, Referrer-Policy, Permissions-Policy, and X-Frame-Options at the edge.",
            ", ".join(missing_headers),
        )
    if weak_headers:
        add_gap(
            "Security header tuning",
            "low",
            "Some security headers are present but misconfigured.",
            "Strengthen header directives based on best-practice values.",
            " | ".join(weak_headers),
        )
    if not tls_report.get("ok"):
        add_gap(
            "TLS availability",
            "high",
            "TLS handshake failed or certificate is invalid.",
            "Serve the site over HTTPS with a valid, trusted certificate.",
        )
    elif tls_report.get("days_left") is not None and tls_report.get("days_left") < 30:
        add_gap(
            "TLS renewal",
            "low",
            "TLS certificate expires in under 30 days.",
            "Plan a certificate renewal before expiry to avoid lapses.",
            f"{tls_report.get('days_left')} days remaining",
        )
    if not https_enforced:
        add_gap(
            "HTTPS enforcement",
            "high",
            "Landing page did not redirect to HTTPS or mixed protocols were observed.",
            "Force HTTPS via redirects/HSTS and avoid serving initial content over HTTP.",
        )
    if not page_metadata.get("language"):
        add_gap(
            "Accessibility",
            "low",
            "No lang attribute declared on the <html> tag.",
            "Specify the content language to support assistive technologies and legal disclosures.",
        )
    if storage_signals.get("document_cookie_write") and not banner_detected:
        add_gap(
            "Client-side cookie writes",
            "high",
            "JavaScript appears to write cookies before visible consent controls.",
            "Delay document.cookie assignments for non-essential purposes until consent state is true.",
        )
    if storage_signals.get("local_storage") and not consent_signals:
        add_gap(
            "Local storage governance",
            "medium",
            "localStorage access was detected with no CMP signature in markup.",
            "Document storage usage and align browser storage behavior with consent categories.",
        )
    if set_cookie_mismatch:
        add_gap(
            "Cookie inventory integrity",
            "low",
            "Raw Set-Cookie headers do not match parsed cookie objects.",
            "Review all response-level Set-Cookie headers to validate inventory completeness.",
        )
    third_party_hosts = page_metadata.get("third_party_script_hosts") or []
    if third_party_hosts and not consent_signals:
        add_gap(
            "Third-party scripts",
            "medium",
            "External scripts load before any consent tooling reference.",
            "Load third-party marketing tags only after the visitor grants consent.",
            ", ".join(third_party_hosts),
        )
    if policy_page_analysis.get("checked"):
        coverage = policy_page_analysis.get("coverage") or {}
        missing = [key for key, present in coverage.items() if not present]
        if missing:
            human = ", ".join(missing)
            add_gap(
                "Cookie policy completeness",
                "medium",
                "Linked cookie policy exists but does not clearly cover all core disclosure topics.",
                "Add explicit sections for categories, retention windows, consent withdrawal, and contact points.",
                human,
            )
    return gaps


def _security_headers(headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    normalized = {k.lower(): v for k, v in headers.items() if isinstance(v, str)}
    report: Dict[str, Dict[str, Any]] = {}
    for name in SECURITY_HEADER_NAMES:
        key = name.lower()
        raw_value = normalized.get(key)
        if raw_value is None:
            report[name] = {
                "present": False,
                "value": None,
                "status": "missing",
                "detail": "Header not returned",
            }
            continue
        assessor = SECURITY_HEADER_ASSESSORS.get(name)
        status = "good"
        detail = "Header returned."
        if assessor:
            status, detail = assessor(raw_value)
        report[name] = {
            "present": True,
            "value": raw_value,
            "status": status,
            "detail": detail,
        }
    return report


def _tls_report(hostname: str) -> Dict[str, Any]:
    if not hostname:
        return {"ok": False, "days_left": None, "issuer": None}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError):
        return {"ok": False, "days_left": None, "issuer": None}
    not_after = cert.get("notAfter")
    issuer = ", ".join("=".join(part) for rdn in cert.get("issuer", []) for part in rdn)
    days_left = None
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        delta = expiry - datetime.now(UTC)
        days_left = max(0, delta.days)
    return {"ok": True, "days_left": days_left, "issuer": issuer}


def run_cookie_audit(raw_url: str) -> Dict[str, Any]:
    """
    EL: End-to-end εκτέλεση cookie audit (fetch -> inspect -> score -> gaps).
    EN: End-to-end cookie audit execution (fetch -> inspect -> score -> gaps).
    """

    url = _normalize_url(raw_url)
    checked_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if not url:
        return CookieAuditResult(
            url=None,
            reachable=False,
            status_code=None,
            cookies=[],
            banner_detected=False,
            banner_context=None,
            policy_links=[],
            score=0,
            summary="No URL provided.",
            findings=["Provide a website URL to run the audit."],
            recommendations=["Enter a publicly reachable HTTPS URL and rerun the audit."],
            checked_at=checked_at,
            technical=_empty_technical(),
            tracker_signals=[],
            consent_signals=[],
            consent_ui={},
            storage_signals={},
            resource_inventory={},
            set_cookie_headers=[],
            policy_page_analysis={"checked": False, "url": None, "status_code": None, "coverage": {}},
            page_metadata={},
            compliance_gaps=[],
        ).as_dict()
    session_client = requests.Session()
    try:
        response = session_client.get(url, headers=DEFAULT_HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        reachable = True
    except requests.RequestException:
        return CookieAuditResult(
            url=url,
            reachable=False,
            status_code=None,
            cookies=[],
            banner_detected=False,
            banner_context=None,
            policy_links=[],
            score=0,
            summary="Unable to reach the site.",
            findings=["The website did not respond over HTTPS during the audit window."],
            recommendations=["Confirm the site is online and accessible, then rerun the audit."],
            checked_at=checked_at,
            technical=_empty_technical(),
            tracker_signals=[],
            consent_signals=[],
            consent_ui={},
            storage_signals={},
            resource_inventory={},
            set_cookie_headers=[],
            policy_page_analysis={"checked": False, "url": None, "status_code": None, "coverage": {}},
            page_metadata={},
            compliance_gaps=[],
        ).as_dict()

    html = (response.text or "")[:MAX_HTML_BYTES]
    final_url = response.url or url
    hostname = (urlparse(final_url).hostname or "").lower()
    policy_links = _extract_policy_links(html)
    candidate_policy_links = _extract_candidate_policy_links(html)
    consent_ui = _consent_ui_signals(html)
    banner_detected = bool(consent_ui.get("banner_detected"))
    banner_context = _extract_banner_context(html) if banner_detected else None

    resource_inventory = _extract_resource_hosts(html, final_url, hostname)
    resource_signal_text = " ".join(resource_inventory.get("all_hosts") or [])
    tracker_signals = sorted(set(_detect_signals(html, TRACKER_SIGNATURES) + _detect_signals(resource_signal_text, TRACKER_SIGNATURES)))
    consent_signals = sorted(set(_detect_signals(html, CONSENT_TOOL_SIGNATURES) + _detect_signals(resource_signal_text, CONSENT_TOOL_SIGNATURES)))
    storage_signals = _detect_storage_and_cookie_access(html)
    links_to_check = list(policy_links)
    for candidate_link in candidate_policy_links:
        if candidate_link not in links_to_check:
            links_to_check.append(candidate_link)
    policy_page_analysis = _analyze_policy_page(session_client, links_to_check, final_url)
    if not policy_links and policy_page_analysis.get("checked"):
        coverage = policy_page_analysis.get("coverage") or {}
        if policy_page_analysis.get("cookie_mentions", 0) > 0 or any(coverage.values()):
            discovered_url = policy_page_analysis.get("url")
            if isinstance(discovered_url, str) and discovered_url:
                policy_links = [discovered_url]

    page_metadata = _html_metadata(html)
    page_metadata["third_party_script_hosts"] = list(resource_inventory.get("third_party_hosts") or [])[:10]
    page_metadata["banner_context"] = banner_context
    page_metadata["resource_counts"] = resource_inventory.get("resource_counts") or {}

    security_headers = _security_headers(response.headers)
    tls_host = hostname if final_url.startswith("https") else parse_hostname(url)
    tls_report = _tls_report(tls_host)
    # EL: Αν το HTTPS request πέτυχε αλλά το raw socket TLS probe απέτυχε
    # (συχνό σε ορισμένα CDNs), θεωρούμε TLS διαθέσιμο βάσει του επιτυχημένου request.
    # EN: If HTTPS request succeeded but raw socket TLS probe failed (common on
    # some CDNs), treat TLS as available based on the successful request.
    if final_url.startswith("https") and not tls_report["ok"]:
        tls_report = {"ok": True, "days_left": tls_report.get("days_left"), "issuer": tls_report.get("issuer")}
    set_cookie_headers = _set_cookie_headers(response)
    set_cookie_names = _parse_set_cookie_names(set_cookie_headers)
    cookies: List[Dict[str, Any]] = []
    long_lived: List[Dict[str, Any]] = []
    http_only_gaps: List[Dict[str, Any]] = []
    for cookie in response.cookies:
        rest = getattr(cookie, "_rest", {}) or {}
        rest_lookup = {str(key).lower(): value for key, value in rest.items()}
        same_site = rest_lookup.get("samesite")
        duration_days = _cookie_duration_days(cookie.expires)
        entry = {
            "name": cookie.name,
            "domain": cookie.domain or hostname,
            "secure": cookie.secure,
            "http_only": bool(rest_lookup.get("httponly")) or ("httponly" in rest_lookup),
            "same_site": str(same_site).upper() if same_site else None,
            "path": cookie.path,
            "expires": cookie.expires,
            "expires_at": _cookie_expiry_iso(cookie.expires),
            "category": _classify_cookie(cookie.name),
            "third_party": _is_third_party_cookie(cookie.domain, hostname),
            "duration_days": duration_days,
            "persistent": duration_days is not None and duration_days > 0,
            "size": len(cookie.value or ""),
        }
        if duration_days is not None and duration_days > 395:
            long_lived.append(entry)
        if _cookie_requires_http_only(cookie.name) and not entry["http_only"]:
            http_only_gaps.append(entry)
        cookies.append(entry)
    cookie_names = [cookie.get("name") for cookie in cookies if cookie.get("name")]
    set_cookie_name_set = set(set_cookie_names)
    cookie_name_set = set(cookie_names)
    set_cookie_mismatch = bool(
        set_cookie_headers
        and (
            (set_cookie_name_set and set_cookie_name_set != cookie_name_set)
            or (not set_cookie_name_set and len(set_cookie_headers) != len(cookies))
        )
    )
    scoring = _audit_score(
        reachable,
        cookies,
        banner_detected,
        consent_ui,
        policy_links,
        policy_page_analysis,
        hostname,
        security_headers,
        tls_report["ok"],
        tls_report["days_left"],
        tracker_signals,
        consent_signals,
        storage_signals,
        list(resource_inventory.get("third_party_hosts") or []),
        set_cookie_mismatch,
        long_lived,
        http_only_gaps,
    )
    response_time_ms = int(response.elapsed.total_seconds() * 1000) if response.elapsed else None
    content_length = len(response.content) if response.content is not None else None
    https_enforced = final_url.startswith("https")
    technical = {
        "https": https_enforced,
        "security_headers": security_headers,
        "tls": tls_report,
        "headers": {"server": response.headers.get("Server"), "powered_by": response.headers.get("X-Powered-By")},
        "metrics": {
            "response_time_ms": response_time_ms,
            "content_length": content_length,
            "status_code": response.status_code,
        },
    }
    compliance_gaps = _compliance_gaps(
        cookies,
        banner_detected,
        consent_ui,
        policy_links,
        policy_page_analysis,
        tracker_signals,
        consent_signals,
        security_headers,
        tls_report,
        https_enforced,
        long_lived,
        http_only_gaps,
        storage_signals,
        set_cookie_mismatch,
        page_metadata,
    )
    return CookieAuditResult(
        url=final_url,
        reachable=reachable,
        status_code=response.status_code,
        cookies=cookies,
        banner_detected=banner_detected,
        banner_context=banner_context,
        policy_links=policy_links,
        score=scoring["score"],
        summary=scoring["summary"],
        findings=scoring["findings"],
        recommendations=scoring["recommendations"],
        checked_at=checked_at,
        technical=technical,
        tracker_signals=tracker_signals,
        consent_signals=consent_signals,
        consent_ui=consent_ui,
        storage_signals=storage_signals,
        resource_inventory={
            **resource_inventory,
            "set_cookie_header_count": len(set_cookie_headers),
            "set_cookie_names": set_cookie_names,
            "cookie_jar_count": len(cookies),
            "set_cookie_mismatch": set_cookie_mismatch,
        },
        set_cookie_headers=set_cookie_headers,
        policy_page_analysis=policy_page_analysis,
        page_metadata=page_metadata,
        compliance_gaps=compliance_gaps,
    ).as_dict()

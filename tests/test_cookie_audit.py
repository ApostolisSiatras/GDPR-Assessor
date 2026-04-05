# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

from cookie_audit import (
    _consent_ui_signals,
    _extract_candidate_policy_links,
    _extract_resource_hosts,
    _analyze_policy_page,
    _parse_set_cookie_names,
    summarize_cookie_audit,
)


def test_consent_ui_signals_detects_granular_choices():
    html = """
    <div id="cookie-banner">
      We use cookies.
      <button>Accept all</button>
      <button>Reject all</button>
      <a href="/cookie-settings">Cookie settings</a>
    </div>
    """
    signals = _consent_ui_signals(html)
    assert signals["banner_detected"] is True
    assert signals["accept_action"] is True
    assert signals["reject_action"] is True
    assert signals["settings_action"] is True
    assert signals["granular_choices"] is True


def test_extract_resource_hosts_tracks_third_party_hosts():
    html = """
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://www.googletagmanager.com/gtag/js?id=GA"></script>
    <img src="https://connect.facebook.net/pixel.gif" />
    """
    inventory = _extract_resource_hosts(html, "https://www.example.com", "www.example.com")
    hosts = inventory["third_party_hosts"]
    assert "www.googletagmanager.com" in hosts
    assert "connect.facebook.net" in hosts


def test_parse_set_cookie_names_handles_multiple_headers():
    headers = [
        "sessionid=abc; Path=/; Secure; HttpOnly",
        "_ga=123; Path=/; Secure; SameSite=None",
    ]
    names = _parse_set_cookie_names(headers)
    assert "sessionid" in names
    assert "_ga" in names


def test_extract_candidate_policy_links_finds_privacy_policy_links():
    html = """
    <footer>
      <a href="/privacy-policy">Privacy Policy</a>
      <a href="/terms">Terms</a>
    </footer>
    """
    links = _extract_candidate_policy_links(html)
    assert "/privacy-policy" in links


def test_analyze_policy_page_prefers_cookie_relevant_candidate():
    class FakeResponse:
        def __init__(self, url: str, text: str):
            self.url = url
            self.text = text
            self.status_code = 200

    class FakeSession:
        def get(self, resolved, headers=None, timeout=None, allow_redirects=True):  # noqa: ARG002
            if "privacy-policy" in resolved:
                return FakeResponse(
                    resolved,
                    "Privacy policy. We use cookies. Categories include analytics and marketing. "
                    "You can withdraw consent and contact our DPO.",
                )
            return FakeResponse(resolved, "Legal page.")

    analysis = _analyze_policy_page(
        FakeSession(),
        ["/legal", "/privacy-policy"],
        "https://example.com",
    )
    assert analysis["checked"] is True
    assert "privacy-policy" in (analysis.get("url") or "")
    assert analysis["cookie_mentions"] > 0


def test_summarize_cookie_audit_includes_deep_scan_features():
    audit = {
        "url": "https://example.com",
        "checked_at": "2026-04-03T12:00:00Z",
        "score": 75,
        "banner_detected": True,
        "consent_signals": ["OneTrust"],
        "consent_ui": {"banner_detected": True, "granular_choices": True},
        "policy_links": ["https://example.com/cookie-policy"],
        "policy_page_analysis": {
            "checked": True,
            "url": "https://example.com/cookie-policy",
            "status_code": 200,
            "coverage": {"categories": True, "retention": True, "withdrawal": False, "contact": True},
            "cookie_mentions": 3,
        },
        "technical": {"https": True, "security_headers": {}, "tls": {"ok": True, "issuer": "Test CA", "days_left": 30}},
        "cookies": [{"category": "analytics"}],
        "storage_signals": {"document_cookie_read": True, "document_cookie_write": False},
        "resource_inventory": {"third_party_hosts": ["www.googletagmanager.com"]},
    }
    summary = summarize_cookie_audit(audit)
    assert summary is not None
    assert summary["consent_platforms"] == ["OneTrust"]
    assert summary["policy_page"]["status_code"] == 200
    assert summary["policy_page"]["cookie_mentions"] == 3
    assert summary["third_party_hosts"] == ["www.googletagmanager.com"]

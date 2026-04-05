# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

from datetime import date

import policy_engine.context as ctx_mod
from policy_engine.context import build_llm_context
from policy_engine.official_policy import ensure_last_updated


def test_build_llm_context_populates_expected_keys(monkeypatch):
    inspection_payload = {
        "url": "https://example.com",
        "reachable": True,
        "status_code": 200,
        "cookies": {
            "enabled": True,
            "details": [{"name": "session"}],
            "reason": "detected",
            "banner_detected": True,
        },
        "banner_detected": True,
    }
    monkeypatch.setattr(ctx_mod, "inspect_website", lambda _url: inspection_payload)
    answers = {
        "ORG_NAME": "Acme Corp",
        "Q-DPIA-006": ["CONSENT", "CONTRACT"],
        "Q-DPIA-008": 18,
        "Q-GAP-001": "YES",
        "ORG_WEBSITE": "example.com",
    }
    assessment = {
        "processing_register": ["HR"],
        "lawful_bases": {"primary": ["Contract"]},
        "processors": ["Payroll"],
        "cookies": {"enabled": False},
        "transfers": [{"country": "US"}],
        "retention": None,
        "security_measures": ["MFA"],
        "overall_score": {"percent": 80},
        "sections": {"A": {"percent": 70}},
    }
    ctx = build_llm_context(answers, assessment)
    assert ctx["org"]["name"] == "Acme Corp"
    assert ctx["lawful_bases"]["primary"] == ["Contract"]
    assert ctx["processors"] == ["Payroll"]
    assert ctx["cookies"]["enabled"] is False
    assert ctx["transfers"][0]["country"] == "US"
    assert ctx["retention"]["months"] == 18
    assert ctx["security_measures"] == ["MFA"]
    assert ctx["risk"]["percent"] == 80
    assert ctx["org"]["website"] in ("https://example.com", "https://example.com/")
    assert "site_inspection" in ctx


def test_ensure_last_updated_overwrites_old_value():
    today = date.today().isoformat()
    text = ensure_last_updated("# Heading\nBody")
    assert f"Last updated: {today}" in text
    stale = text.replace(today, "1999-01-01")
    refreshed = ensure_last_updated(stale)
    assert f"Last updated: {today}" in refreshed


def test_cookies_irrelevant_when_no_website():
    ctx = build_llm_context({}, {})
    assert ctx["cookies"]["reason"] == "no_website"
    assert ctx["cookies"]["enabled"] is False


def test_company_profile_processors_and_transfers_fallback(monkeypatch):
    monkeypatch.setattr(ctx_mod, "inspect_website", lambda _url: {"url": None, "cookies": {"enabled": False}})
    answers = {"company_profile": {"processors": ["Vendor A"], "transfers": ["SCCs with US partner"]}}
    assessment = {"org_profile": answers["company_profile"], "sections": {}, "overall_score": {}}
    ctx = build_llm_context(answers, assessment)
    assert "Vendor A" in ctx["processors"]
    assert "SCCs with US partner" in ctx["transfers"]


def test_gap_text_questions_feed_profile(monkeypatch):
    monkeypatch.setattr(ctx_mod, "inspect_website", lambda _url: {"url": None, "cookies": {"enabled": False}})
    answers = {
        "Q-GAP-026": "Acme Corp",
        "Q-GAP-027": "privacy@acme.test",
        "Q-GAP-028": "Vendor A, Vendor B",
        "Q-GAP-029": "SCCs with US HR system",
    }
    ctx = build_llm_context(answers, {"sections": {}, "overall_score": {}})
    assert ctx["org"]["name"] == "Acme Corp"
    assert "privacy@acme.test" in ctx["org"]["contact"]
    assert "Vendor A" in ctx["processors"] and "Vendor B" in ctx["processors"]
    assert "SCCs with US HR system" in ctx["transfers"]

# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

"""
EL: Context normalization layer για prompts και policy generation.
EN: Context normalization layer for prompts and policy generation.

EL: Συγχωνεύει answers, assessment outputs και website inspection data
σε ένα ενιαίο object που καταναλώνει το LLM prompt layer.

EN: Merges answers, assessment outputs, and website inspection data
into a single object consumed by the LLM prompt layer.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from site_inspector import inspect_website


def _listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


_DEMO_TEXT_RE = re.compile(r"auto-filled for quick demo runs", re.IGNORECASE)
_QUESTION_ID_RE = re.compile(r"\bQ-[A-Z]+-\d+\b")
_BRACKET_PLACEHOLDER_RE = re.compile(r"^\[[^\]\n]{2,}\]$")


def _is_placeholder_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    return bool(
        _DEMO_TEXT_RE.search(text)
        or _QUESTION_ID_RE.search(text)
        or _BRACKET_PLACEHOLDER_RE.match(text)
    )


def _clean_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or _is_placeholder_text(text):
        return None
    return text


def _sanitize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_sanitize_value(item) for item in value)
    text = str(value).strip()
    if _is_placeholder_text(text):
        return ""
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[redacted email]", text)
    return text[:200]


def _answer_by_hint(answers: Dict[str, Any], hints: List[str]) -> Any:
    for key, value in answers.items():
        upper_key = key.upper()
        if any(hint in upper_key for hint in hints):
            if _is_placeholder_text(value):
                continue
            return value
    return None


def _humanize_token(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if "_" in text and re.fullmatch(r"[A-Z0-9_]+", text):
        text = text.replace("_", " ").title()
    elif len(text) > 3 and re.fullmatch(r"[A-Z0-9]+", text):
        text = text.replace("_", " ").title()
    return text


def _humanize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _humanize_token(value)
    if isinstance(value, list):
        return [_humanize_value(item) for item in value]
    if isinstance(value, dict):
        return {k: _humanize_value(v) for k, v in value.items()}
    return value


def _split_values(raw: Any) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        values = [str(item).strip() for item in raw if str(item).strip()]
    else:
        values = [part.strip() for part in re.split(r"[,\n]", str(raw)) if part.strip()]
    return [value for value in values if not _is_placeholder_text(value)]


def build_llm_context(answers: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    """
    EL: Χτίζει canonical context payload για module reports και official policy.
    EN: Builds canonical context payload for module reports and official policy.
    """

    answers = answers or {}
    assessment = assessment or {}
    question_context = {
        key[:-8]: _sanitize_value(value)
        for key, value in answers.items()
        if isinstance(key, str) and key.endswith("_context") and value
    }
    key_facts = assessment.get("key_facts") or {}
    website_value = _answer_by_hint(answers, ["WEBSITE", "URL", "WEB", "SITE", "DOMAIN"])
    if isinstance(website_value, list):
        website_value = website_value[0]
    inspection = inspect_website(website_value if isinstance(website_value, str) else None)

    profile = assessment.get("org_profile") or answers.get("company_profile") or {}
    q_org_name = _clean_text(answers.get("Q-GAP-026"))
    q_contact = _clean_text(answers.get("Q-GAP-027"))
    q_processors = _split_values(answers.get("Q-GAP-028"))
    q_transfers = _split_values(answers.get("Q-GAP-029"))

    org_name = (
        _clean_text(profile.get("org_name"))
        or q_org_name
        or _clean_text(_answer_by_hint(answers, ["ORG", "COMPANY", "ENTITY"]))
        or "Information available on request."
    )
    org_sector = _clean_text(profile.get("sector")) or _clean_text(_answer_by_hint(answers, ["SECTOR", "INDUSTRY"])) or "Not provided"
    org_country = _clean_text(profile.get("country")) or _clean_text(_answer_by_hint(answers, ["COUNTRY", "LOCATION"])) or "Not specified"
    dpo_name = _clean_text(profile.get("dpo_name")) or _clean_text(_answer_by_hint(answers, ["DPO", "DATA_PROTECTION_OFFICER"]))
    dpo_status = _clean_text(answers.get("Q-GAP-001"))
    if dpo_name:
        dpo_value = dpo_name
    elif isinstance(dpo_status, str) and dpo_status.upper() in {"YES", "APPOINTED", "TRUE"}:
        dpo_value = "Appointed"
    else:
        dpo_value = "Not appointed"
    contact_parts = []
    contact_email = _clean_text(profile.get("email")) or q_contact
    contact_phone = _clean_text(profile.get("phone"))
    if contact_email:
        contact_parts.append(f"Email: {contact_email}")
    if contact_phone:
        contact_parts.append(f"Phone: {contact_phone}")
    contact_value = "; ".join(contact_parts) if contact_parts else "Information available on request."
    org = {
        "name": _sanitize_value(org_name) or "Information available on request.",
        "sector": _sanitize_value(org_sector) or "Not provided",
        "establishment_country": _sanitize_value(org_country) or "Not specified",
        "dpo": _sanitize_value(dpo_value) or dpo_value,
        "contact": contact_value,
        "website": inspection.get("url") or _sanitize_value(website_value) or None,
    }

    processing_register = assessment.get("processing_register") or []
    if not isinstance(processing_register, list):
        processing_register = []

    lawful_bases = assessment.get("lawful_bases") or {}
    if not lawful_bases and "legal_basis" in key_facts:
        lawful_bases = {"declared": _listify(key_facts["legal_basis"])}
    elif not lawful_bases and answers.get("Q-DPIA-006"):
        lawful_bases = {"declared": _listify(answers.get("Q-DPIA-006"))}
    if isinstance(lawful_bases, dict):
        lawful_bases = {k: _humanize_value(_listify(v)) for k, v in lawful_bases.items()}

    profile_processors = profile.get("processors") if isinstance(profile.get("processors"), list) else []
    if not profile_processors and q_processors:
        profile_processors = q_processors
    processors = assessment.get("processors")
    if not processors:
        processors = _listify(key_facts.get("processors"))
    if not processors and profile_processors:
        processors = profile_processors
    processors = _humanize_value(processors)

    cookies = assessment.get("cookies")
    inspector_cookies = inspection.get("cookies") or {}
    if not cookies:
        cookies = dict(inspector_cookies) if inspector_cookies else {"enabled": False, "details": []}
    else:
        cookies = dict(cookies)
        if inspector_cookies.get("reason") == "no_website":
            cookies = dict(inspector_cookies)
        else:
            cookies.setdefault("details", inspector_cookies.get("details", []))
            if "enabled" not in cookies and "enabled" in inspector_cookies:
                cookies["enabled"] = inspector_cookies["enabled"]
            if inspector_cookies.get("banner_detected"):
                cookies["banner_detected"] = True
    cookies.setdefault("enabled", False)
    cookies.setdefault("details", [])
    if not cookies.get("reason"):
        cookies["reason"] = inspector_cookies.get("reason", "not_reported")

    profile_transfers = profile.get("transfers") if isinstance(profile.get("transfers"), list) else []
    if not profile_transfers and q_transfers:
        profile_transfers = q_transfers
    transfers = assessment.get("transfers")
    if not transfers:
        transfers = _listify(key_facts.get("transfers"))
    elif isinstance(transfers, dict):
        transfers = [transfers]
    elif not isinstance(transfers, list):
        transfers = []
    if not transfers and profile_transfers:
        transfers = profile_transfers
    transfers = _humanize_value(transfers)

    retention = assessment.get("retention")
    if not retention and answers.get("Q-DPIA-008") is not None:
        retention = {"months": answers.get("Q-DPIA-008")}
    elif not retention:
        retention = {}

    security_measures = assessment.get("security_measures")
    if not security_measures:
        security_measures = _listify(key_facts.get("security_controls"))

    register_controls = {
        "article30_completeness": _sanitize_value(answers.get("Q-DPIA-030")) or "Not answered",
    }
    transfer_controls = {
        "tia_coverage": _sanitize_value(answers.get("Q-GAP-030")) or "Not answered",
    }

    context = {
        "org": org,
        "processing_register": processing_register,
        "lawful_bases": lawful_bases,
        "processors": processors if processors else [],
        "cookies": cookies,
        "transfers": transfers,
        "retention": retention,
        "security_measures": security_measures if security_measures else [],
        "risk": assessment.get("overall_score") or {},
        "sections": assessment.get("sections") or {},
        "site_inspection": inspection,
        "question_context": question_context,
        "cookie_audit": assessment.get("cookie_audit"),
        "register_controls": register_controls,
        "transfer_controls": transfer_controls,
    }
    return context

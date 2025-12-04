from __future__ import annotations

import re
from typing import Any, Dict, List

from site_inspector import inspect_website


def _listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _sanitize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_sanitize_value(item) for item in value)
    text = str(value).strip()
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[redacted email]", text)
    return text[:200]


def _answer_by_hint(answers: Dict[str, Any], hints: List[str]) -> Any:
    for key, value in answers.items():
        upper_key = key.upper()
        if any(hint in upper_key for hint in hints):
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


def _humanize_list(items: List[Any]) -> List[str]:
    return [_humanize_token(item) for item in items if isinstance(item, str) and str(item).strip()]


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
        return [str(item).strip() for item in raw if str(item).strip()]
    return [part.strip() for part in re.split(r"[,\n]", str(raw)) if part.strip()]


def build_llm_context(answers: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
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
    q_org_name = answers.get("Q-GAP-026")
    q_contact = answers.get("Q-GAP-027")
    q_processors = _split_values(answers.get("Q-GAP-028"))
    q_transfers = _split_values(answers.get("Q-GAP-029"))

    org_name = profile.get("org_name") or q_org_name or _answer_by_hint(answers, ["ORG", "COMPANY", "ENTITY"]) or "Redacted Organisation"
    org_sector = profile.get("sector") or _answer_by_hint(answers, ["SECTOR", "INDUSTRY"]) or "Not provided"
    org_country = profile.get("country") or _answer_by_hint(answers, ["COUNTRY", "LOCATION"]) or "Not specified"
    dpo_raw = profile.get("dpo_name") or _answer_by_hint(answers, ["DPO", "DATA_PROTECTION_OFFICER"]) or answers.get("Q-GAP-001")
    if isinstance(dpo_raw, str):
        dpo_value = "Appointed" if dpo_raw.upper() in {"YES", "APPOINTED"} else "Not appointed"
    else:
        dpo_value = "Not appointed"
    contact_parts = []
    contact_email = profile.get("email") or q_contact
    contact_phone = profile.get("phone")
    if contact_email:
        contact_parts.append(f"Email: {contact_email}")
    if contact_phone:
        contact_parts.append(f"Phone: {contact_phone}")
    contact_value = "; ".join(contact_parts) if contact_parts else "Data protection contact available upon request."
    org = {
        "name": _sanitize_value(org_name) or "Redacted Organisation",
        "sector": _sanitize_value(org_sector) or "Not provided",
        "establishment_country": _sanitize_value(org_country) or "Not specified",
        "dpo": _sanitize_value(dpo_raw or dpo_value) or dpo_value,
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

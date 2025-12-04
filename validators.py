from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from jsonschema import Draft7Validator

EEA_COUNTRIES = {
    "AT",
    "BE",
    "BG",
    "HR",
    "CY",
    "CZ",
    "DK",
    "EE",
    "FI",
    "FR",
    "DE",
    "GR",
    "HU",
    "IS",
    "IE",
    "IT",
    "LI",
    "LT",
    "LU",
    "LV",
    "MT",
    "NL",
    "NO",
    "PL",
    "PT",
    "RO",
    "SE",
    "SI",
    "SK",
    "ES",
}


def _normalize_country(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if len(text) == 2:
        return text.upper()
    return text.title()


def _detect_non_eea_transfers(transfers: Iterable[Any]) -> List[str]:
    outside: List[str] = []
    for transfer in transfers or []:
        country = None
        if isinstance(transfer, dict):
            country = transfer.get("country") or transfer.get("destination") or transfer.get("location")
            if not country and transfer.get("eea") is False:
                country = transfer.get("country") or "NON-EEA"
        elif isinstance(transfer, str):
            country = transfer
        if not country:
            continue
        norm = _normalize_country(country)
        if len(norm) == 2 and norm in EEA_COUNTRIES:
            continue
        if norm.upper() in {c.upper() for c in EEA_COUNTRIES}:
            continue
        outside.append(norm)
    return outside


def validate_cookie_policy(ctx: Dict[str, Any], md_text: str) -> List[str]:
    """Ensure cookies-disabled statements are present when required."""
    cookies = (ctx or {}).get("cookies") or {}
    reason = cookies.get("reason")
    if reason == "no_website":
        return []
    enabled = cookies.get("enabled") if isinstance(cookies, dict) else None
    if enabled is False:
        if "we do not use cookies" not in md_text.lower():
            return ["Cookie policy must explicitly state 'we do not use cookies' when cookies are disabled."]
    return []


def validate_transfers(ctx: Dict[str, Any], md_text: str) -> List[str]:
    """If transfers go outside the EEA ensure SCC language exists."""
    transfers = (ctx or {}).get("transfers") or []
    outside = _detect_non_eea_transfers(transfers)
    if outside:
        if not re.search(r"standard contractual clauses", md_text, flags=re.IGNORECASE):
            return [
                "International transfer section must reference Standard Contractual Clauses when ctx includes non-EEA transfers."
            ]
    return []


def validate_json(schema: Dict[str, Any], payload: Dict[str, Any]) -> List[str]:
    """Validate payload against schema using jsonschema."""
    validator = Draft7Validator(schema)
    errors = [err.message for err in validator.iter_errors(payload)]
    return errors

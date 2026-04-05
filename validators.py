# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

"""
EL: Validation κανόνες για generated GDPR artefacts.
EN: Validation rules for generated GDPR artefacts.

EL: Το module προσφέρει schema validation και domain-specific ελέγχους
(π.χ. cookie disclosure και διεθνείς μεταφορές).

EN: This module provides schema validation and domain-specific checks
(e.g., cookie disclosures and international transfers).
"""

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
EEA_COUNTRIES_UPPER = {country.upper() for country in EEA_COUNTRIES}


def _normalize_country(value: Any) -> str:
    """
    EL: Κανονικοποιεί country name/code ώστε να συγκρίνεται σταθερά.
    EN: Normalizes country names/codes so comparisons stay stable.
    """

    if not value:
        return ""
    text = str(value).strip()
    if len(text) == 2:
        return text.upper()
    return text.title()


def _detect_non_eea_transfers(transfers: Iterable[Any]) -> List[str]:
    """
    EL: Επιστρέφει transfer destinations που θεωρούνται εκτός ΕΟΧ.
    EN: Returns transfer destinations considered outside the EEA.
    """

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

        normalized = _normalize_country(country)
        if len(normalized) == 2 and normalized.upper() in EEA_COUNTRIES_UPPER:
            continue
        if normalized.upper() in EEA_COUNTRIES_UPPER:
            continue
        outside.append(normalized)
    return outside


def validate_cookie_policy(ctx: Dict[str, Any], md_text: str) -> List[str]:
    """
    EL: Επιβεβαιώνει explicit δήλωση “no cookies” όταν cookies είναι disabled.
    EN: Enforces explicit “no cookies” wording when cookies are disabled.
    """

    cookies = (ctx or {}).get("cookies") or {}
    reason = cookies.get("reason")
    if reason == "no_website":
        return []

    enabled = cookies.get("enabled") if isinstance(cookies, dict) else None
    if enabled is False and "we do not use cookies" not in md_text.lower():
        return ["Cookie policy must explicitly state 'we do not use cookies' when cookies are disabled."]
    return []


def validate_transfers(ctx: Dict[str, Any], md_text: str) -> List[str]:
    """
    EL: Απαιτεί αναφορά σε SCC όταν υπάρχουν non-EEA transfers.
    EN: Requires SCC wording when non-EEA transfers are present.
    """

    transfers = (ctx or {}).get("transfers") or []
    outside = _detect_non_eea_transfers(transfers)
    if outside and not re.search(r"standard contractual clauses", md_text, flags=re.IGNORECASE):
        return [
            "International transfer section must reference Standard Contractual Clauses when ctx includes non-EEA transfers."
        ]
    return []


def validate_json(schema: Dict[str, Any], payload: Dict[str, Any]) -> List[str]:
    """
    EL: Εκτελεί Draft7 schema validation και επιστρέφει human-readable errors.
    EN: Runs Draft7 schema validation and returns human-readable errors.
    """

    validator = Draft7Validator(schema)
    return [err.message for err in validator.iter_errors(payload)]

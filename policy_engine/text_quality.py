# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

"""
EL: Quality guards για generated νομικά κείμενα GDPR.
EN: Quality guards for generated GDPR legal text.

EL: Φιλτράρει placeholder/demo artefacts και ανιχνεύει μοτίβα που δεν
πρέπει να εμφανίζονται σε επίσημα policy/report outputs.

EN: Filters placeholder/demo artefacts and detects patterns that should
not appear in official policy/report outputs.
"""

from __future__ import annotations

import re

_DEMO_MARKER_RE = re.compile(r"auto-filled for quick demo runs", re.IGNORECASE)
_QUESTION_ID_RE = re.compile(r"\bQ-[A-Z]+-\d+\b")
_BRACKET_PLACEHOLDER_RE = re.compile(r"\[[^\]\n]{2,}\](?!\()")


def has_forbidden_legal_artifacts(text: str) -> bool:
    """
    EL: Επιστρέφει True όταν το output περιέχει demo/question placeholder artefacts.
    EN: Returns True when output contains demo/question placeholder artefacts.
    """

    raw = text or ""
    return bool(
        _DEMO_MARKER_RE.search(raw)
        or _QUESTION_ID_RE.search(raw)
        or _BRACKET_PLACEHOLDER_RE.search(raw)
    )


def sanitize_generated_legal_text(text: str) -> str:
    """
    EL: Καθαρίζει artefacts ώστε το τελικό κείμενο να είναι επαγγελματικό.
    EN: Cleans artefacts so final text remains professional.
    """

    cleaned = text or ""
    cleaned = re.sub(
        r"Auto-filled for quick demo runs\.\s*\(Q-[^)]+\)",
        "Information available on request.",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = _DEMO_MARKER_RE.sub("Information available on request.", cleaned)
    cleaned = _QUESTION_ID_RE.sub("Information available on request.", cleaned)
    cleaned = _BRACKET_PLACEHOLDER_RE.sub("Information available on request.", cleaned)
    cleaned = re.sub(r"Information available on request\.\)", "Information available on request.", cleaned)
    cleaned = re.sub(
        r"(Information available on request\.)(\s*\1)+",
        r"\1",
        cleaned,
        flags=re.IGNORECASE,
    )
    return cleaned.strip()


def quality_rewrite_instruction() -> str:
    """
    EL: Επιστρέφει σταθερή οδηγία για δεύτερο pass όταν εντοπίζονται artefacts.
    EN: Returns a stable rewrite instruction for second pass when artefacts are found.
    """

    return (
        "Rewrite the full section in formal GDPR legal language. "
        "Do not include template placeholders, bracket placeholders, demo text, or internal questionnaire identifiers. "
        "If a detail is missing, write exactly: 'Information available on request.'."
    )

# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

"""
EL: Storage helpers για hash/signature και απλή αποθήκευση policy markdown.
EN: Storage helpers for hash/signature and plain policy markdown persistence.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

def hash_text(text: str) -> str:
    """
    EL: Παράγει deterministic SHA-256 hash για signatures και integrity checks.
    EN: Produces deterministic SHA-256 hash for signatures and integrity checks.
    """

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_policy_text(path: Path, text: str) -> None:
    """
    EL: Γράφει markdown text στο disk με σταθερό newline normalization.
    EN: Writes markdown text to disk with stable newline normalization.
    """

    data = text if text.endswith("\n") else f"{text}\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def read_policy_text(path: Path) -> str:
    """
    EL: Διαβάζει persisted markdown text από το disk.
    EN: Reads persisted markdown text from disk.
    """

    return path.read_text(encoding="utf-8")

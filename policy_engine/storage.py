"""
EL: Storage helpers για hash/signature και optional encryption-at-rest.
EN: Storage helpers for hash/signature and optional encryption-at-rest.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import ENCRYPTION_KEY


def hash_text(text: str) -> str:
    """
    EL: Παράγει deterministic SHA-256 hash για signatures και integrity checks.
    EN: Produces deterministic SHA-256 hash for signatures and integrity checks.
    """

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _crypt_bytes(payload: bytes) -> bytes:
    """
    EL: Ελαφρύ XOR obfuscation όταν υπάρχει encryption key (best-effort).
    EN: Lightweight XOR obfuscation when an encryption key is configured.
    """

    if not ENCRYPTION_KEY:
        return payload
    key = ENCRYPTION_KEY
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(payload))


def write_secure_text(path: Path, text: str) -> None:
    """
    EL: Γράφει text στο disk με newline normalization και optional obfuscation.
    EN: Writes text to disk with newline normalization and optional obfuscation.
    """

    data = text if text.endswith("\n") else f"{text}\n"
    payload = _crypt_bytes(data.encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def read_secure_text(path: Path) -> str:
    """
    EL: Διαβάζει secure text και κάνει reversible αποκωδικοποίηση όταν χρειάζεται.
    EN: Reads secure text and performs reversible decoding when required.
    """

    payload = path.read_bytes()
    decoded = _crypt_bytes(payload)
    return decoded.decode("utf-8")

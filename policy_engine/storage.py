from __future__ import annotations

from pathlib import Path

from .config import ENCRYPTION_KEY


def hash_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _crypt_bytes(payload: bytes) -> bytes:
    if not ENCRYPTION_KEY:
        return payload
    key = ENCRYPTION_KEY
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(payload))


def write_secure_text(path: Path, text: str) -> None:
    data = text if text.endswith("\n") else f"{text}\n"
    payload = _crypt_bytes(data.encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)

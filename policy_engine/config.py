"""
EL: Κεντρικές ρυθμίσεις για το policy generation pipeline.
EN: Central settings for the policy generation pipeline.

EL: Το module εκθέτει constants για backward compatibility, αλλά οι τιμές
προέρχονται από typed PolicyEngineConfig ώστε να είναι πιο σαφείς και testable.

EN: The module exposes constants for backward compatibility, while values
come from a typed PolicyEngineConfig for better clarity and testability.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PolicyEngineConfig:
    """
    EL: Immutable configuration object για prompts, output και encryption.
    EN: Immutable configuration object for prompts, output, and encryption.
    """

    model_name: str
    prompt_dir: Path
    official_policy_dir: Path
    pandoc_path: str | None
    last_updated_pattern: re.Pattern[str]
    encryption_key: bytes | None


def _resolve_encryption_key() -> bytes | None:
    secret = os.environ.get("POLICY_ENCRYPTION_KEY")
    if not secret:
        return None
    return hashlib.sha256(secret.encode("utf-8")).digest()


def load_policy_engine_config() -> PolicyEngineConfig:
    """
    EL: Φορτώνει policy-engine configuration και εξασφαλίζει output directories.
    EN: Loads policy-engine configuration and ensures output directories exist.
    """

    output_base_dir = Path("output")
    official_policy_dir = output_base_dir / "official"
    for directory in (output_base_dir, official_policy_dir):
        directory.mkdir(parents=True, exist_ok=True)

    return PolicyEngineConfig(
        model_name=os.environ.get("POLICY_ENGINE_MODEL", "llama3.1:8b"),
        prompt_dir=Path("prompts"),
        official_policy_dir=official_policy_dir,
        pandoc_path=shutil.which("pandoc"),
        last_updated_pattern=re.compile(r"Last updated:\s*\d{4}-\d{2}-\d{2}", re.IGNORECASE),
        encryption_key=_resolve_encryption_key(),
    )


_CONFIG = load_policy_engine_config()

# Backward-compatible exports used across the existing codebase.
MODEL_NAME = _CONFIG.model_name
PROMPT_DIR = _CONFIG.prompt_dir
OFFICIAL_POLICY_DIR = _CONFIG.official_policy_dir
PANDOC_PATH = _CONFIG.pandoc_path
LAST_UPDATED_PATTERN = _CONFIG.last_updated_pattern
ENCRYPTION_KEY = _CONFIG.encryption_key

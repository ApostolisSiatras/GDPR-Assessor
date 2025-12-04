from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path

MODEL_NAME = "llama3.1:8b"
PROMPT_DIR = Path("prompts")
OUTPUT_BASE = Path("output")
OFFICIAL_POLICY_DIR = OUTPUT_BASE / "official"
PANDOC_PATH = shutil.which("pandoc")
LAST_UPDATED_PATTERN = re.compile(r"Last updated:\s*\d{4}-\d{2}-\d{2}", re.IGNORECASE)

ENCRYPTION_SECRET = os.environ.get("POLICY_ENCRYPTION_KEY")
ENCRYPTION_KEY = hashlib.sha256(ENCRYPTION_SECRET.encode("utf-8")).digest() if ENCRYPTION_SECRET else None

for directory in (OUTPUT_BASE, OFFICIAL_POLICY_DIR):
    directory.mkdir(parents=True, exist_ok=True)

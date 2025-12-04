from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Dict

from llm import run_ollama

from .config import MODEL_NAME, PROMPT_DIR

MODULE_PROMPTS = {
    "dpia11": "dpia_report_en.txt",
    "gap": "gap_report_en.txt",
}


@lru_cache(maxsize=len(MODULE_PROMPTS))
def _load_prompt_file(filename: str) -> str:
    path = PROMPT_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Prompt template missing: {path}")
    return path.read_text(encoding="utf-8")


def generate_module_report(mode: str, context: Dict[str, Any]) -> Dict[str, Any]:
    prompt_name = MODULE_PROMPTS.get(mode)
    if not prompt_name:
        raise ValueError(f"No report prompt configured for {mode}")
    prompt_template = _load_prompt_file(prompt_name)
    context_json = json.dumps(context, indent=2, sort_keys=True)
    compiled_prompt = prompt_template.replace("{ctx}", context_json)
    body = run_ollama(compiled_prompt, model=MODEL_NAME, stream=False).strip()
    meta = {
        "mode": mode,
        "run_id": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "model": MODEL_NAME,
        "text": body,
    }
    return meta

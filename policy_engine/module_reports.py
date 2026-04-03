"""
EL: Δημιουργία LLM narrative reports ανά assessment module.
EN: LLM narrative report generation per assessment module.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Dict

from llm import run_ollama

from .config import MODEL_NAME, PROMPT_DIR
from .text_quality import has_forbidden_legal_artifacts, quality_rewrite_instruction, sanitize_generated_legal_text

MODULE_PROMPTS = {
    "dpia11": "dpia_report_en.txt",
    "gap": "gap_report_en.txt",
}


@lru_cache(maxsize=len(MODULE_PROMPTS))
def _load_prompt_file(filename: str) -> str:
    """
    EL: Κάνει cache τα prompt templates για να μειώνει disk I/O.
    EN: Caches prompt templates to reduce disk I/O.
    """

    path = PROMPT_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Prompt template missing: {path}")
    return path.read_text(encoding="utf-8")


def generate_module_report(mode: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    EL: Παράγει report markdown για το επιλεγμένο mode με deterministic metadata.
    EN: Generates report markdown for the selected mode with deterministic metadata.
    """

    prompt_name = MODULE_PROMPTS.get(mode)
    if not prompt_name:
        raise ValueError(f"No report prompt configured for {mode}")

    prompt_template = _load_prompt_file(prompt_name)
    context_json = json.dumps(context, indent=2, sort_keys=True)
    compiled_prompt = prompt_template.replace("{ctx}", context_json)
    body = run_ollama(compiled_prompt, model=MODEL_NAME, stream=False).strip()
    if has_forbidden_legal_artifacts(body):
        repair_prompt = f"{compiled_prompt}\n\nAdditional compliance rewrite requirement:\n{quality_rewrite_instruction()}"
        body = run_ollama(repair_prompt, model=MODEL_NAME, stream=False).strip()
    body = sanitize_generated_legal_text(body)

    now = datetime.now(UTC)
    return {
        "mode": mode,
        "run_id": now.strftime("%Y%m%dT%H%M%SZ"),
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "model": MODEL_NAME,
        "text": body,
    }

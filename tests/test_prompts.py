# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

from pathlib import Path
from unittest import mock

import llm

PROMPT_DIR = Path("prompts")
MARKDOWN_PROMPTS = [
    "privacy_policy_en.txt",
    "employee_notice_en.txt",
    "cookie_policy_en.txt",
    "retention_policy_en.txt",
    "dsar_procedure_en.txt",
    "breach_procedure_en.txt",
]
JSON_PROMPTS = ["ropa_json_en.txt", "dpia_json_en.txt"]


def test_prompts_include_context_placeholder_and_last_updated():
    for name in MARKDOWN_PROMPTS:
        text = (PROMPT_DIR / name).read_text(encoding="utf-8")
        assert "{ctx}" in text
        assert "Last updated:" in text


def test_json_prompts_reference_schema_structure():
    for name in JSON_PROMPTS:
        text = (PROMPT_DIR / name).read_text(encoding="utf-8")
        assert "{ctx}" in text
        assert '"activities"' in text
        assert "JSON object" in text


def test_run_ollama_sets_temperature_default():
    fake_response = mock.Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"response": "ok"}
    with mock.patch("llm.requests.post", return_value=fake_response) as patched:
        llm.run_ollama("hello")
    payload = patched.call_args.kwargs["json"]
    assert payload["options"]["temperature"] == llm.DEFAULT_TEMPERATURE

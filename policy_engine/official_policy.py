"""
EL: Official policy orchestration pipeline (LLM sections + persisted artefacts).
EN: Official policy orchestration pipeline (LLM sections + persisted artefacts).

EL: Το module συνθέτει context, καλεί prompts ανά ενότητα, αποθηκεύει
markdown/html/pdf και εκθέτει metadata για downstream downloads.

EN: This module composes context, calls per-section prompts, stores
markdown/html/pdf, and exposes metadata for downstream downloads.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Dict, List, Tuple

from llm import run_ollama

from .config import LAST_UPDATED_PATTERN, MODEL_NAME, OFFICIAL_POLICY_DIR, PANDOC_PATH, PROMPT_DIR
from .context import build_llm_context
from .rendering import convert_markdown_with_pandoc, markdown_to_html, markdown_to_pdf_bytes
from .storage import hash_text, read_policy_text, write_policy_text
from .text_quality import has_forbidden_legal_artifacts, quality_rewrite_instruction, sanitize_generated_legal_text

OFFICIAL_POLICY_PROMPTS: "OrderedDict[str, Dict[str, str]]" = OrderedDict(
    [
        ("overview", {"title": "Executive Overview", "prompt": "official_policy_overview_en.txt"}),
        ("data_processing", {"title": "Data Processing & Registers", "prompt": "official_policy_processing_en.txt"}),
        ("lawful_bases", {"title": "Lawful Bases & Transparency", "prompt": "official_policy_lawful_en.txt"}),
        ("rights", {"title": "Data Subject Rights", "prompt": "official_policy_rights_en.txt"}),
        ("security", {"title": "Security & Incident Response", "prompt": "official_policy_security_en.txt"}),
        ("governance", {"title": "Governance & Contacts", "prompt": "official_policy_governance_en.txt"}),
    ]
)


def ensure_last_updated(md_text: str) -> str:
    """
    EL: Εξασφαλίζει ότι το markdown περιέχει τρέχον Last updated line.
    EN: Ensures markdown contains a current Last updated line.
    """

    text = (md_text or "").strip()
    if not text:
        return ""

    # EL: Χρησιμοποιούμε local ημερομηνία ώστε UI/tests να συμφωνούν με system date.
    # EN: Use local calendar date so UI/tests match the system-facing date.
    today = datetime.now().date().isoformat()
    if LAST_UPDATED_PATTERN.search(text):
        text = LAST_UPDATED_PATTERN.sub(f"Last updated: {today}", text, count=1)
    else:
        lines = text.splitlines()
        inserted = False
        for idx, line in enumerate(lines):
            if line.startswith("#"):
                lines.insert(idx + 1, f"Last updated: {today}")
                inserted = True
                break
        if not inserted:
            lines.insert(0, f"Last updated: {today}")
        text = "\n".join(lines)

    if not text.endswith("\n"):
        text += "\n"
    return text


@lru_cache(maxsize=len(OFFICIAL_POLICY_PROMPTS))
def _load_prompt_text(filename: str) -> str:
    prompt_path = PROMPT_DIR / filename
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt template missing: {prompt_path}")
    return prompt_path.read_text(encoding="utf-8")


def generate_official_policy_sections(
    answers: Dict[str, Any],
    assessment: Dict[str, Any],
    overrides: Dict[str, str] | None = None,
) -> Tuple[Dict[str, Any], List[Dict[str, str]], str, str]:
    """
    EL: Δημιουργεί sections policy μέσω LLM και επιστρέφει context + markdown.
    EN: Generates policy sections via LLM and returns context + markdown.
    """

    context = build_llm_context(answers, assessment)
    ctx_json = json.dumps(context, indent=2, sort_keys=True)

    sections: List[Dict[str, str]] = []
    for slug, spec in OFFICIAL_POLICY_PROMPTS.items():
        prompt_text = _load_prompt_text(spec["prompt"]).replace("{ctx}", ctx_json)
        override_text = (overrides or {}).get(slug)
        if override_text:
            prompt_text += (
                "\n\nThe policy owner provided the following comment to incorporate verbatim where suitable:\n"
                f"{override_text}\n"
                "Blend this guidance naturally into the section without mentioning that it was a comment."
            )
        content = run_ollama(prompt_text, model=MODEL_NAME, stream=False).strip()
        if has_forbidden_legal_artifacts(content):
            repair_prompt = f"{prompt_text}\n\nAdditional compliance rewrite requirement:\n{quality_rewrite_instruction()}"
            content = run_ollama(repair_prompt, model=MODEL_NAME, stream=False).strip()
        content = sanitize_generated_legal_text(content)
        sections.append({"slug": slug, "title": spec["title"], "content": content})

    combined = _assemble_official_policy(context, sections)
    context_hash = hash_text(ctx_json)
    return context, sections, combined, context_hash


def _assemble_official_policy(context: Dict[str, Any], sections: List[Dict[str, str]]) -> str:
    org_name = context.get("org", {}).get("name", "The Organisation")
    today = datetime.now().date().isoformat()
    lines = [
        "# Official GDPR Compliance Policy",
        f"Last updated: {today}",
        "",
        f"This policy applies to **{org_name}**.",
        "",
    ]
    for section in sections:
        lines.append(section["content"].strip())
        lines.append("")
    return ensure_last_updated("\n".join(lines).strip())


def save_official_policy(markdown_text: str, sections: List[Dict[str, str]], context_hash: str) -> Dict[str, Any]:
    """
    EL: Αποθηκεύει policy artefacts σε run folder και επιστρέφει metadata.
    EN: Persists policy artefacts in a run folder and returns metadata.
    """

    now = datetime.now(UTC)
    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    run_dir = OFFICIAL_POLICY_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    policy_path = run_dir / "policy.md"
    write_policy_text(policy_path, markdown_text)

    html_path = run_dir / "policy.html"
    html_body = markdown_to_html(markdown_text)
    html_path.write_text(html_body, encoding="utf-8")

    policy_number = f"GDP-{run_id}"
    signature = hash_text(markdown_text + policy_number)

    pdf_bytes = None
    if PANDOC_PATH:
        try:
            pdf_bytes = convert_markdown_with_pandoc(markdown_text, "pdf")
        except RuntimeError:
            pdf_bytes = None
    if pdf_bytes is None:
        pdf_bytes = markdown_to_pdf_bytes(markdown_text, policy_number, signature)

    pdf_path = run_dir / "policy.pdf"
    pdf_path.write_bytes(pdf_bytes)

    metadata = {
        "run_id": run_id,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "context_hash": context_hash,
        "model": MODEL_NAME,
        "sections": sections,
        "policy_number": policy_number,
        "signature": signature,
        "paths": {
            "markdown": str(policy_path),
            "html": str(html_path),
            "pdf": str(pdf_path),
        },
    }
    (run_dir / "policy.meta.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def create_official_policy(
    answers: Dict[str, Any],
    assessment: Dict[str, Any],
    overrides: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    context, sections, markdown_text, context_hash = generate_official_policy_sections(answers, assessment, overrides)
    metadata = save_official_policy(markdown_text, sections, context_hash)
    metadata["markdown"] = markdown_text
    metadata["context"] = context
    metadata["overrides"] = overrides or {}
    return metadata


def load_official_policy(run_id: str | None) -> Dict[str, Any] | None:
    """
    EL: Φορτώνει saved policy metadata και το persisted markdown.
    EN: Loads saved policy metadata and the persisted markdown.
    """

    if not run_id:
        return None

    run_dir = OFFICIAL_POLICY_DIR / run_id
    policy_path = run_dir / "policy.md"
    meta_path = run_dir / "policy.meta.json"
    html_path = run_dir / "policy.html"
    pdf_path = run_dir / "policy.pdf"

    if not policy_path.exists() or not meta_path.exists():
        return None

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    metadata["markdown"] = read_policy_text(policy_path)
    metadata.setdefault("paths", {})
    metadata["paths"]["markdown"] = str(policy_path)
    metadata["paths"]["pdf"] = str(pdf_path) if pdf_path.exists() else metadata["paths"].get("pdf")

    if html_path.exists():
        metadata["paths"]["html"] = str(html_path)
        metadata["html"] = html_path.read_text(encoding="utf-8")
    else:
        metadata["html"] = markdown_to_html(metadata["markdown"])

    return metadata

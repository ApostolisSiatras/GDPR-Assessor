"""
EL: Κύριο web entrypoint του GDPR Assessor (Flask).
EN: Main web entrypoint for the GDPR Assessor (Flask).

EL: Το module συνδέει routing, session orchestration, scoring pipelines,
policy generation και exports. Η καθαρή ροή είναι:
request -> parse/validate -> assessment/report services -> rendered output.

EN: This module connects routing, session orchestration, scoring pipelines,
policy generation, and exports. The main flow is:
request -> parse/validate -> assessment/report services -> rendered output.
"""

from __future__ import annotations

import io
import json
import logging
import re
import zipfile
from collections import OrderedDict
from datetime import UTC, datetime
from hmac import compare_digest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for

from gdpr_wizard import AssessmentBuilder, Question, SchemaBundle, resolve_schema, render_markdown
from cookie_audit import run_cookie_audit, summarize_cookie_audit
from policy_engine import (
    OFFICIAL_POLICY_PROMPTS,
    build_llm_context,
    generate_module_report,
)
from policy_engine.config import MODEL_NAME
from policy_engine.official_policy import generate_official_policy_sections
from policy_engine.rendering import markdown_to_docx_bytes, markdown_to_html, markdown_to_pdf_bytes, markdown_to_pdf_report
from policy_engine.storage import hash_text
from platform_config import load_platform_config
from runtime_store import RuntimeSessionStore, RuntimeStoreConfig

app = Flask(__name__)
SETTINGS = load_platform_config()
app.config["SECRET_KEY"] = SETTINGS.secret_key
app.config.setdefault("PLATFORM_USERNAME", SETTINGS.platform_username)
app.config.setdefault("PLATFORM_PASSWORD", SETTINGS.platform_password)
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

logger = logging.getLogger(__name__)

SCHEMA_CHOICES: Dict[str, Dict[str, str]] = {
    "dpia11": {
        "label": "DPIA schema v1.1",
        "description": "High-risk processing impact assessment aligned to GDPR Art.35(7).",
    },
    "gap": {
        "label": "GDPR Gap Assessment",
        "description": "Organisational controls review mapped to GDPR governance requirements.",
    },
}

ASSESSMENT_MODES = ["dpia11", "gap"]
VOCAB_PATH = Path("vocabs.json")
QUESTION_CACHE: Dict[str, Dict[str, Question]] = {}
QUESTION_CACHE_STAMP: Dict[str, Optional[Tuple[float, float]]] = {}
BUNDLE_CACHE: Dict[str, SchemaBundle] = {}
BUNDLE_CACHE_STAMP: Dict[str, Tuple[float, float]] = {}
GDPR_REFERENCE_CACHE: Dict[str, Tuple[Tuple[str, str], ...]] = {}

GDPR_ARTICLE_BASE_URL = "https://www.privacy-regulation.eu/en/{article}.htm"
GDPR_RECITAL_BASE_URL = "https://www.privacy-regulation.eu/en/r{recital}.htm"
_ARTICLE_RANGE_RE = re.compile(r"^Art\.?\s*(\d+)\s*-\s*(\d+)$", re.IGNORECASE)
_PARAGRAPH_RANGE_RE = re.compile(r"^Art\.?\s*(\d+)\s*\((\d+)\)\s*-\s*\((\d+)\)$", re.IGNORECASE)
_ARTICLE_PATTERN = re.compile(r"^Art\.?\s*(\d+)(.*)$", re.IGNORECASE)
_RECITAL_PATTERN = re.compile(r"^Recital\s+(\d+)$", re.IGNORECASE)
_PAREN_PATTERN = re.compile(r"\(([^()]+)\)")

FIELD_KEYWORDS = {
    "Security & Breach": ["security", "breach", "encryption", "incident", "access control", "cyber"],
    "Governance & Oversight": ["governance", "management", "policy", "accountability", "oversight"],
    "Lawful Basis & Consent": ["lawful", "legal", "consent", "purpose", "basis", "legitimacy"],
    "Data subject rights": ["rights", "transparency", "request", "subject", "access"],
    "Data minimisation & retention": ["retention", "minimi", "storage", "deletion", "archive"],
    "Vendors & transfers": ["processor", "vendor", "transfer", "third", "supplier"],
}
GENERAL_FIELD = "General controls"
RADAR_COLORS = {
    "dpia11": ("#2563eb", "rgba(37,99,235,0.18)"),
    "gap": ("#f97316", "rgba(249,115,22,0.18)"),
}
IMPACT_KEYWORDS = {
    "High": ["security", "breach", "transfer", "monitoring", "incident", "encryption", "special category"],
    "Medium": ["consent", "transparency", "vendor", "processor", "training", "awareness"],
}
LIKELIHOOD_KEYWORDS = {
    "Likely": ["continuous", "ongoing", "automated", "daily", "realtime", "monitoring"],
    "Possible": ["periodic", "manual", "third-party", "external", "ad-hoc"],
}
IMPACT_LEVELS = ["Low", "Medium", "High"]
LIKELIHOOD_LEVELS = ["Rare", "Possible", "Likely"]
ARTICLE_REF_RE = re.compile(r"Art\.?\s*(\d+)(?:\s*\((\d+)\))?(?:\s*\(([a-zA-Z])\))?", re.IGNORECASE)
RECITAL_REF_RE = re.compile(r"Recital\s*(\d+)", re.IGNORECASE)
AUTH_EXEMPT_ENDPOINTS = {"login", "healthcheck", "static"}
RUNTIME_STORE = RuntimeSessionStore(RuntimeStoreConfig(ttl_seconds=SETTINGS.session_runtime_ttl_seconds))
REPORT_ACCESS_TOKEN = SETTINGS.report_access_token


def _login_disabled() -> bool:
    return bool(app.config.get("LOGIN_DISABLED") or app.config.get("TESTING"))


def _is_authenticated() -> bool:
    return bool(session.get("auth_user"))


def _verify_credentials(username: str, password: str) -> bool:
    """
    EL: Επαληθεύει credentials με timing-safe compare για αποφυγή leaks.
    EN: Verifies credentials with timing-safe comparisons to reduce leaks.
    """

    expected_user = app.config["PLATFORM_USERNAME"]
    expected_pass = app.config["PLATFORM_PASSWORD"]
    return compare_digest(username or "", expected_user) and compare_digest(password or "", expected_pass)


def _safe_next_path(target: Optional[str]) -> Optional[str]:
    """
    EL: Επιτρέπει redirect μόνο σε local paths για αποτροπή open redirects.
    EN: Allows redirects only to local paths to prevent open redirect issues.
    """

    if not target:
        return None
    # EL: Κανονικοποιούμε relative URLs για αποτροπή open redirects.
    # EN: Normalize relative URLs to prevent open redirect issues.
    ref_url = urlparse(request.host_url)
    next_url = urlparse(urljoin(request.host_url, target))
    if next_url.scheme in {"http", "https"} and next_url.netloc == ref_url.netloc:
        path = next_url.path or "/"
        if next_url.query:
            path = f"{path}?{next_url.query}"
        return path
    return None


def _cleanup_runtime_sessions(now: Optional[datetime] = None) -> None:
    """
    EL: Καθαρίζει ληγμένα runtime buckets από το shared in-memory store.
    EN: Cleans expired runtime buckets from the shared in-memory store.
    """

    RUNTIME_STORE.cleanup(now)


def _runtime_bucket(create: bool = True) -> Optional[Dict[str, Any]]:
    return RUNTIME_STORE.bucket(session, create=create)


def _drop_runtime_bucket() -> None:
    RUNTIME_STORE.drop_bucket(session)


def _runtime_assessments() -> Dict[str, Dict[str, Any]]:
    return RUNTIME_STORE.assessments(session)


def _runtime_module_reports() -> Dict[str, Dict[str, Any]]:
    return RUNTIME_STORE.module_reports(session)


def _runtime_official_policies() -> Dict[str, Dict[str, Any]]:
    return RUNTIME_STORE.official_policies(session)


def _get_current_official_policy_run_id() -> Optional[str]:
    return RUNTIME_STORE.current_policy_run_id(session)


def _reset_workspace_session() -> None:
    """
    EL: Καθαρίζει πλήρως runtime/session state ώστε κάθε login να ξεκινά καθαρά.
    EN: Fully clears runtime/session state so each login starts from a clean workspace.
    """

    _drop_runtime_bucket()
    session.clear()


@app.after_request
def _apply_no_store_headers(response):
    """
    EL: Αποτρέπει browser caching για HTML ώστε να μην επανεμφανίζονται φόρμες/τιμές.
    EN: Prevents browser caching for HTML responses so forms/values are not resurfaced.
    """

    content_type = response.headers.get("Content-Type", "")
    if request.method == "GET" and "text/html" in content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.before_request
def _enforce_authentication():
    _cleanup_runtime_sessions()
    if _login_disabled():
        return
    endpoint = (request.endpoint or "").split(".")[0]
    if endpoint in AUTH_EXEMPT_ENDPOINTS:
        return
    if _is_authenticated():
        g.current_user = session.get("auth_user")
        return
    next_path = request.full_path if request.query_string else request.path
    if next_path.endswith("?"):
        next_path = next_path[:-1]
    return redirect(url_for("login", next=next_path))


def field_name(q: Question) -> str:
    return f"q_{q.id}"


@app.context_processor
def inject_helpers():
    return {
        "field_name": field_name,
        "schema_choices": SCHEMA_CHOICES,
        "assessment_modes": ASSESSMENT_MODES,
        "gdpr_links": gdpr_reference_links,
        "assistant_helper": build_helper_payload(),
        "current_user": session.get("auth_user"),
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    redirect_target = request.values.get("next") or request.args.get("next")
    safe_target = _safe_next_path(redirect_target)
    if _is_authenticated():
        return redirect(safe_target or url_for("home"))
    if request.method == "GET":
        # EL: Δεν κρατάμε παλιές τιμές μεταξύ browser login sessions.
        # EN: Do not keep stale values between browser login sessions.
        _reset_workspace_session()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _verify_credentials(username, password):
            _reset_workspace_session()
            session["auth_user"] = username
            session.permanent = False
            return redirect(safe_target or url_for("home"))
        error = "Invalid username or password."
    return render_template("login.html", error=error, next=safe_target or redirect_target or "")


@app.route("/logout")
def logout():
    _reset_workspace_session()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


def build_helper_payload() -> Optional[Dict[str, Any]]:
    """
    EL: Δημιουργεί contextual βοηθητικό payload για το UI assistant panel.
    EN: Builds contextual helper payload for the UI assistant panel.
    """

    endpoint = request.endpoint or ""
    view_args = request.view_args or {}
    mode = view_args.get("mode")
    assessments = session.get("assessments", {}) or {}
    has_assessments = bool(assessments)
    dpia_url = url_for("assessment_form", mode="dpia11")
    gap_url = url_for("assessment_form", mode="gap")
    helper_map: Dict[str, Dict[str, Any]] = {
        "home": {
            "title": "Plan your next step",
            "description": "The platform can run DPIA, GAP, cookie audits, and assemble the official policy. Decide what you need today.",
            "steps": [],
            "sections": [],
            "ctas": [],
        },
        "results": {
            "title": "Interpreting analytics",
            "description": "Each visualization answers a different question about your compliance posture.",
            "steps": [
                "Readiness gauge shows average score; hover for precise values.",
                "Radar polygon compares maturity across security, governance, rights, and vendor axes.",
                "Risk matrix maps failed GDPR questions by impact vs. likelihood—start remediation in the top-right cells.",
            ],
            "sections": [
                {"title": "Correlation matrix", "text": "Cells close to 100% mean two fields move together; lower scores flag uneven coverage."},
                {"title": "AI reports", "text": "Use the Markdown/PDF exports to brief leadership or copy narrative findings."},
                {"title": "Cookie card", "text": "Shows whether the latest audit is included in the official policy and highlights gaps."},
            ],
            "ctas": [
                {"label": "Generate policy", "href": url_for("official_policy_page")},
                {"label": "Refresh cookie audit", "href": url_for("cookie_audit_view")},
            ],
        },
        "cookie_audit_view": {
            "title": "Cookie helper",
            "description": "The wizard inspects the landing page, lists trackers, and explains what the visuals mean.",
            "steps": [
                "Smart compliance gaps describe missing banners, policies, or consent platforms.",
                "The donut charts split cookies by category and first/third-party origin.",
                "Use the inventory table to update disclosures or block non-compliant tags.",
            ],
            "sections": [
                {"title": "Need to share externally?", "text": "Include the audit in the Official Policy or export the table to spreadsheets."},
                {"title": "Fixing issues", "text": "Start with high severity gaps (red badge) and ensure consent tools gate trackers."},
            ],
            "ctas": [
                {"label": "Back to analytics", "href": url_for("results")},
            ],
        },
        "official_policy_page": {
            "title": "Policy guidance",
            "description": "Compile DPIA, GAP, and cookie evidence into the official template and export ready-to-share files.",
            "steps": [
                "Confirm both assessments show as completed (workspace checkmarks).",
                "Toggle cookie audit inclusion if you want the scan embedded in the policy.",
                "Use overrides to add business context, then download PDF/Markdown copies.",
            ],
            "sections": [
                {"title": "Need only a DPIA or GAP narrative?", "text": "Use Analytics → AI reports for stand-alone summaries."},
            ],
            "ctas": [
                {"label": "Download latest", "href": url_for("official_policy_page")},
            ],
        },
    }
    if not has_assessments:
        helper_map["home"].update(
            {
                "description": "Analytics unlock after submitting at least one assessment. Start with the track that fits your goal.",
                "steps": [
                    "Need DPIA analytics? Open the DPIA module and complete each section.",
                    "Need governance insights? Complete the GAP module to populate the dashboard.",
                    "Once an assessment is submitted, revisit Analytics to see the radar, matrices, and AI summaries.",
                ],
                "sections": [
                    {"title": "First time here?", "text": "Run the DPIA for high-risk processing or the GAP for organisational controls. Both can be done separately."},
                    {"title": "Want cookie visuals?", "text": "Execute a Cookie Audit; once saved you can embed it in the official policy."},
                ],
                "ctas": [
                    {"label": "Start DPIA", "href": dpia_url},
                    {"label": "Start GAP", "href": gap_url},
                ],
            }
        )
    else:
        helper_map["home"].update(
            {
                "steps": [
                    "Choose the DPIA track for high-risk processing (Art.35) or GAP for governance controls (Art.24–32).",
                    "Use the workspace buttons to resume or restart assessments.",
                    "Visit analytics anytime to see readiness, radar visuals, and AI narratives.",
                ],
                "sections": [
                    {"title": "Just need assessments?", "text": "Open the relevant module, answer the prompts, and submit to lock results."},
                    {"title": "Need a quick cookie scan?", "text": "Head to Cookie Audit for consent banners and inventory."},
                    {"title": "Ready for a board-ready policy?", "text": "Once DPIA + GAP are saved, generate the Official Policy PDF."},
                ],
                "ctas": [
                    {"label": "Open analytics", "href": url_for("results")},
                    {"label": "Run cookie audit", "href": url_for("cookie_audit_view")},
                ],
            }
        )
    if endpoint == "assessment_form" and mode in SCHEMA_CHOICES:
        helper_map[endpoint] = {
            "title": f"Working on {SCHEMA_CHOICES[mode]['label']}",
            "description": "Move through each themed section, capture context, and submit to refresh analytics.",
            "steps": [
                "Section chips above let you jump directly to Security, Rights, Vendors, etc.",
                "Use the radio pills for Yes/No/Partially answers, then add notes describing controls.",
                "Click Submit at the bottom to save progress; you can resume later from the workspace.",
            ],
            "sections": [
                {"title": "Need GAP vs DPIA guidance?", "text": "DPIA targets high-risk processing; GAP covers organisational controls. Complete whichever you need, or both for the official policy."},
            ],
            "ctas": [
                {"label": "Return to workspace", "href": url_for("home")},
                {"label": "Open analytics", "href": url_for("results")},
            ],
        }
    helper = helper_map.get(endpoint)
    if helper:
        return helper
    return None


def _ensure_access_control() -> Dict[str, bool]:
    access = session.get("access_control")
    if not access:
        access = {mode: True for mode in ASSESSMENT_MODES}
        session["access_control"] = access
        session.modified = True
    else:
        updated = False
        for mode in ASSESSMENT_MODES:
            if mode not in access:
                access[mode] = True
                updated = True
        if updated:
            session["access_control"] = access
            session.modified = True
    return access


def _bundle_stamp(schema_path: Path) -> Optional[Tuple[float, float]]:
    try:
        return (schema_path.stat().st_mtime, VOCAB_PATH.stat().st_mtime)
    except OSError:
        logger.warning("Unable to stat schema/vocabulary paths for cache stamp.", exc_info=True)
        return None


def load_bundle(mode: str) -> SchemaBundle:
    """
    EL: Φορτώνει schema/vocabulary bundle με cache invalidation σε file change.
    EN: Loads the schema/vocabulary bundle with file-based cache invalidation.
    """

    schema_path = resolve_schema(mode, None)
    stamp = _bundle_stamp(schema_path)
    cached = BUNDLE_CACHE.get(mode)
    if cached and stamp and BUNDLE_CACHE_STAMP.get(mode) == stamp:
        return cached
    bundle = SchemaBundle(schema_path, VOCAB_PATH)
    BUNDLE_CACHE[mode] = bundle
    if stamp:
        BUNDLE_CACHE_STAMP[mode] = stamp
    else:
        BUNDLE_CACHE_STAMP.pop(mode, None)
    QUESTION_CACHE.pop(mode, None)
    QUESTION_CACHE_STAMP.pop(mode, None)
    return bundle


def group_by_section(questions: List[Question]) -> List[Tuple[str, List[Question]]]:
    sections: "OrderedDict[str, List[Question]]" = OrderedDict()
    for q in questions:
        sections.setdefault(q.section, []).append(q)
    return list(sections.items())


def question_lookup(mode: str) -> Dict[str, Question]:
    bundle = load_bundle(mode)
    stamp = BUNDLE_CACHE_STAMP.get(mode)
    cached = QUESTION_CACHE.get(mode)
    cached_stamp = QUESTION_CACHE_STAMP.get(mode)
    if cached and cached_stamp == stamp:
        return cached
    lookup = {q.id: q for q in bundle.questions}
    QUESTION_CACHE[mode] = lookup
    QUESTION_CACHE_STAMP[mode] = stamp
    return lookup


def _new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def save_assessment_files(mode: str, answers: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
    run_id = _new_run_id()
    markdown_value = render_markdown(assessment)
    _runtime_assessments()[mode] = {
        "mode": mode,
        "run_id": run_id,
        "answers": answers,
        "assessment": assessment,
        "markdown": markdown_value,
        "percent": assessment.get("overall_score", {}).get("percent"),
        "rating": assessment.get("overall_score", {}).get("rating"),
        "generated_at": assessment.get("generated_at"),
    }
    return {
        "mode": mode,
        "run_id": run_id,
        "percent": assessment.get("overall_score", {}).get("percent"),
        "rating": assessment.get("overall_score", {}).get("rating"),
        "generated_at": assessment.get("generated_at"),
    }


def load_assessment_payload(
    mode: str, entry: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[str]]:
    answers = entry.get("answers")
    assessment = entry.get("assessment")
    if assessment is None and answers:
        try:
            assessment = run_assessment(mode, load_bundle(mode), answers)
        except Exception:
            logger.exception("Failed to rebuild assessment payload for mode '%s'.", mode)
            assessment = None
    markdown = entry.get("markdown")
    if markdown is None and assessment:
        markdown = render_markdown(assessment)
    return answers, assessment, markdown


def get_session_assessment(mode: str) -> Optional[Dict[str, Any]]:
    entry = _runtime_assessments().get(mode)
    if not entry:
        completed = session.get("assessments", {}) or {}
        if mode in completed:
            completed.pop(mode, None)
            session["assessments"] = completed
            session.modified = True
        return None
    answers, assessment, markdown = load_assessment_payload(mode, entry)
    if not answers:
        return None
    enriched = dict(entry)
    enriched["answers"] = answers
    if assessment is not None:
        enriched["assessment"] = assessment
    if markdown:
        enriched.setdefault("markdown", markdown)
    return enriched


def rebuild_assessment_from_entry(mode: str, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    _, assessment, _ = load_assessment_payload(mode, entry)
    return assessment


def load_module_report_text(meta: Dict[str, Any]) -> Optional[str]:
    text = meta.get("text")
    if isinstance(text, str):
        return text
    mode = meta.get("mode")
    run_id = meta.get("run_id")
    if not mode or not run_id:
        return None
    report = _runtime_module_reports().get(mode)
    if not report:
        return None
    if report.get("run_id") != run_id:
        return None
    report_text = report.get("text")
    return report_text if isinstance(report_text, str) else None


def load_runtime_official_policy(run_id: Optional[str]) -> Optional[Dict[str, Any]]:
    target_run = run_id or _get_current_official_policy_run_id()
    if not target_run:
        return None
    policy = _runtime_official_policies().get(target_run)
    if not policy:
        return None
    return dict(policy)


def _article_anchor(article: int, paragraph: Optional[str], letter: Optional[str]) -> Optional[str]:
    if not paragraph:
        return None
    prefix = "nr" if article == 4 else "p"
    anchor = f"a{article}_{prefix}{paragraph}"
    if letter:
        anchor += letter.lower()
    return anchor


def _build_article_link(article: int, paragraph: Optional[str] = None, letter: Optional[str] = None) -> Dict[str, str]:
    url = GDPR_ARTICLE_BASE_URL.format(article=article)
    anchor = _article_anchor(article, paragraph, letter)
    if anchor:
        url = f"{url}#{anchor}"
    label = f"Art. {article}"
    if paragraph:
        label += f"({paragraph})"
    if letter:
        label += f"({letter.lower()})"
    return {"label": label, "href": url}


def _expand_article_range(start: int, end: int) -> List[Dict[str, str]]:
    if end < start:
        start, end = end, start
    return [_build_article_link(num) for num in range(start, end + 1)]


def _expand_paragraph_range(article: int, start: int, end: int) -> List[Dict[str, str]]:
    if end < start:
        start, end = end, start
    return [_build_article_link(article, str(num)) for num in range(start, end + 1)]


def _expand_gdpr_reference(ref: str) -> List[Dict[str, str]]:
    normalized = (ref or "").strip()
    if not normalized:
        return []
    cached = GDPR_REFERENCE_CACHE.get(normalized)
    if cached is not None:
        return [{"label": label, "href": href} for label, href in cached]
    recital_match = _RECITAL_PATTERN.match(normalized)
    result: List[Dict[str, str]] = []
    if recital_match:
        recital = recital_match.group(1)
        result = [
            {
                "label": f"Recital {recital}",
                "href": GDPR_RECITAL_BASE_URL.format(recital=recital),
            }
        ]
    else:
        article_range = _ARTICLE_RANGE_RE.match(normalized)
        paragraph_range = _PARAGRAPH_RANGE_RE.match(normalized)
        article_match = _ARTICLE_PATTERN.match(normalized)
        if article_range:
            start, end = map(int, article_range.groups())
            result = _expand_article_range(start, end)
        elif paragraph_range:
            article = int(paragraph_range.group(1))
            start = int(paragraph_range.group(2))
            end = int(paragraph_range.group(3))
            result = _expand_paragraph_range(article, start, end)
        elif article_match:
            article = int(article_match.group(1))
            tail = (article_match.group(2) or "").strip()
            if not tail:
                result = [_build_article_link(article)]
            else:
                tokens = _PAREN_PATTERN.findall(tail)
                if not tokens:
                    result = [_build_article_link(article)]
                else:
                    paragraph = None
                    letter = None
                    for token in tokens:
                        cleaned = token.strip()
                        if not cleaned:
                            continue
                        if cleaned.isdigit():
                            if paragraph is None:
                                paragraph = cleaned
                        else:
                            if letter is None:
                                letter = re.sub(r"[^0-9A-Za-z]", "", cleaned) or None
                    result = [_build_article_link(article, paragraph, letter)]
    GDPR_REFERENCE_CACHE[normalized] = tuple(
        (entry["label"], entry["href"]) for entry in result
    )
    return result


def gdpr_reference_links(refs: Optional[List[str]]) -> List[Dict[str, str]]:
    links: List[Dict[str, str]] = []
    for ref in refs or []:
        expanded = _expand_gdpr_reference(ref)
        if expanded:
            links.extend(expanded)
    return links


def _merge_sections(dpia_sections: Dict[str, Any], gap_sections: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for title, payload in (dpia_sections or {}).items():
        merged[f"DPIA - {title}"] = payload
    for title, payload in (gap_sections or {}).items():
        key = f"GAP - {title}"
        merged[key] = payload
    return merged


def merge_assessments(dpia: Dict[str, Any], gap: Dict[str, Any]) -> Dict[str, Any]:
    combined: Dict[str, Any] = {}
    keys = set((dpia or {}).keys()) | set((gap or {}).keys())
    for key in keys:
        if key == "sections":
            combined[key] = _merge_sections(dpia.get(key, {}), gap.get(key, {}))
        elif key in {"cookies", "processors", "transfers", "retention", "security_measures"}:
            combined[key] = gap.get(key) or dpia.get(key)
        else:
            combined[key] = gap.get(key) if gap.get(key) is not None else dpia.get(key)
    return combined


def combined_assessment_inputs() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    dpia_entry = get_session_assessment("dpia11") or {}
    gap_entry = get_session_assessment("gap") or {}
    dpia_answers, dpia_assessment, _ = load_assessment_payload("dpia11", dpia_entry)
    gap_answers, gap_assessment, _ = load_assessment_payload("gap", gap_entry)
    if not dpia_answers or not gap_answers:
        raise RuntimeError("Both DPIA and GAP assessments must be completed before generating the official policy.")
    if not dpia_assessment or not gap_assessment:
        raise RuntimeError("Unable to rebuild assessment data. Please resubmit the modules and try again.")
    answers = dict(dpia_answers)
    answers.update(gap_answers)
    assessment = merge_assessments(dpia_assessment, gap_assessment)
    profile = session.get("company_profile") or {}
    if profile:
        answers["company_profile"] = profile
        assessment.setdefault("org_profile", profile)
    return answers, assessment


def _conditionally_required(q: Question, answers: Dict[str, Any]) -> bool:
    if q.id == "Q-GAP-027":
        return answers.get("Q-GAP-001") == "YES"
    return q.required


def parse_answers(questions: List[Question], form_data: Any) -> Tuple[Dict[str, Any], Dict[str, str], Dict[str, Any]]:
    """
    EL: Κάνει parse/validation των input fields και επιστρέφει answers/errors/state.
    EN: Parses and validates input fields, returning answers/errors/state.
    """

    answers: Dict[str, Any] = {}
    errors: Dict[str, str] = {}
    state: Dict[str, Any] = {}

    for q in questions:
        name = field_name(q)
        required_flag = _conditionally_required(q, answers)
        context_field = f"context_{q.id}"
        if q.qtype == "multiselect":
            raw_values = form_data.getlist(name) if hasattr(form_data, "getlist") else form_data.get(name, [])
            state[q.id] = raw_values
            if not raw_values:
                if not required_flag:
                    continue
                errors[q.id] = "Select at least one option."
                continue
            invalid = [val for val in raw_values if val not in q.enum]
            if invalid:
                errors[q.id] = f"Invalid selections: {', '.join(invalid)}."
                continue
            answers[q.id] = raw_values
            note_value = form_data.get(context_field, "")
            state[context_field] = note_value
            note_value = note_value.strip()
            if note_value:
                answers[f"{q.id}_context"] = note_value
            continue

        raw_value = form_data.get(name, "").strip()
        state[q.id] = raw_value
        if not raw_value:
            if required_flag:
                errors[q.id] = "This field is required."
            note_value = form_data.get(context_field, "")
            state[context_field] = note_value
            note_value = note_value.strip()
            if note_value:
                answers[f"{q.id}_context"] = note_value
            continue

        try:
            if q.qtype == "boolean":
                if raw_value not in {"true", "false"}:
                    raise ValueError
                answers[q.id] = raw_value == "true"
            elif q.qtype in {"enum", "scale"}:
                if raw_value not in q.enum:
                    raise ValueError
                answers[q.id] = raw_value
            elif q.qtype == "integer":
                answers[q.id] = int(raw_value)
            else:
                answers[q.id] = raw_value
        except ValueError:
            errors[q.id] = "Invalid value supplied."
        note_value = form_data.get(context_field, "")
        state[context_field] = note_value
        note_value = note_value.strip()
        if note_value:
            answers[f"{q.id}_context"] = note_value

    return answers, errors, state


_PARTIAL_KEYWORDS = ("PARTIAL", "IN_PROGRESS", "LIMITED", "SOMETIMES")
AUTOFILL_TEXT_DEFAULT = "Information available on request."
AUTOFILL_TEXT_OVERRIDES: Dict[str, str] = {
    "Q-GAP-026": "Example Organisation Ltd",
    "Q-GAP-027": "privacy@example.org",
    "Q-GAP-028": "Example Processor Ltd",
    "Q-GAP-029": "No international transfers declared.",
    "Q-DPIA-001A": "Employees and customers.",
    "Q-DPIA-002": "Service delivery and legal compliance.",
}


def _enum_rank(q: Question) -> Dict[str, int]:
    return {value: idx for idx, value in enumerate(q.enum)}


def _select_scoring_option(q: Question, variant: str) -> Optional[str]:
    if not q.scoring:
        return None
    valid = [(opt, score) for opt, score in q.scoring.items() if score is not None]
    if not valid:
        return None
    order = _enum_rank(q)
    max_score = max(score for _, score in valid)
    if variant == "perfect":
        best = [opt for opt, score in valid if score == max_score]
        best.sort(key=lambda opt: order.get(opt, len(order)))
        return best[0]
    partials = [(opt, score) for opt, score in valid if any(token in opt for token in _PARTIAL_KEYWORDS)]
    if partials:
        partials.sort(key=lambda pair: (-pair[1], order.get(pair[0], len(order))))
        return partials[0][0]
    mid_scores = [(opt, score) for opt, score in valid if 0 < score < max_score]
    if mid_scores:
        target_value = max_score * 0.65
        mid_scores.sort(
            key=lambda pair: (
                abs(pair[1] - target_value),
                order.get(pair[0], len(order)),
            )
        )
        return mid_scores[0][0]
    high_scores = [(opt, score) for opt, score in valid if score == max_score]
    low_scores = [(opt, score) for opt, score in valid if score < max_score]
    if low_scores and abs(hash(q.id)) % 4 == 0:
        low_scores.sort(key=lambda pair: (-pair[1], order.get(pair[0], len(order))))
        return low_scores[0][0]
    high_scores.sort(key=lambda pair: order.get(pair[0], len(order)))
    return high_scores[0][0]


def _autofill_multiselect(q: Question, variant: str) -> List[str]:
    options = list(q.enum)
    if not options:
        return []
    if variant == "perfect":
        if q.coverage_policy:
            targets = [opt for opt in q.coverage_policy.get("targets", []) if opt in options]
            if targets:
                return targets
        if len(options) > 4:
            return options[:4]
        return options
    if q.coverage_policy:
        targets = [opt for opt in q.coverage_policy.get("targets", []) if opt in options]
        if targets:
            midpoint = max(1, len(targets) // 2)
            return targets[:midpoint]
    return options[: min(len(options), 2)]


def _autofill_value(q: Question, variant: str) -> Any:
    variant = variant.lower()
    if q.qtype == "boolean":
        return True
    if q.qtype == "integer":
        return 12 if variant == "perfect" else 24
    if q.qtype == "scale":
        if not q.enum:
            return "MEDIUM"
        return q.enum[0] if variant == "perfect" else q.enum[len(q.enum) // 2]
    if q.qtype == "multiselect":
        return _autofill_multiselect(q, variant)
    if q.qtype in {"enum", "scale"}:
        chosen = _select_scoring_option(q, variant)
        if chosen is not None:
            return chosen
        if q.enum:
            if variant == "perfect":
                return q.enum[0]
            if len(q.enum) > 1:
                return q.enum[1]
            return q.enum[0]
        return ""
    return AUTOFILL_TEXT_OVERRIDES.get(q.id, AUTOFILL_TEXT_DEFAULT)


def build_autofill_answers(bundle: SchemaBundle, variant: str) -> Dict[str, Any]:
    answers: Dict[str, Any] = {}
    for q in bundle.questions:
        val = _autofill_value(q, variant)
        if val is None:
            continue
        answers[q.id] = val
    return answers


def run_assessment(mode: str, bundle: SchemaBundle, answers: Dict[str, Any]) -> Dict[str, Any]:
    """
    EL: Τρέχει το scoring pipeline του επιλεγμένου module (DPIA ή GAP).
    EN: Runs the scoring pipeline for the selected module (DPIA or GAP).
    """

    builder = AssessmentBuilder(bundle, answers)
    return builder.build()


def section_chart_payload(assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not assessment:
        return {"labels": [], "values": []}
    sections = assessment.get("sections", {})
    labels = list(sections.keys())
    values = [sections[label].get("percent", 0) for label in labels]
    return {"labels": labels, "values": values}


def _normalize_article_reference(ref: str) -> Tuple[str, Tuple[int, int, int, str]]:
    ref = (ref or "").strip()
    match = ARTICLE_REF_RE.match(ref)
    if match:
        article_num = int(match.group(1))
        paragraph = match.group(2)
        letter = match.group(3)
        label = f"Art. {article_num}"
        para_val = 0
        if paragraph:
            label += f"({paragraph})"
            para_val = int(paragraph)
        letter_val = ""
        if letter:
            letter = letter.lower()
            label += f"({letter})"
            letter_val = letter
        sort_key = (0, article_num, para_val, letter_val)
        return label, sort_key
    recital = RECITAL_REF_RE.match(ref)
    if recital:
        rec_num = int(recital.group(1))
        return f"Recital {rec_num}", (1, rec_num, 0, "")
    cleaned = ref or "Other"
    return cleaned, (2, 0, 0, cleaned.lower())


def _article_scores_from_assessment(assessment: Optional[Dict[str, Any]], mode: str) -> Tuple[Dict[str, float], Dict[str, Tuple[int, int, int, str]]]:
    if not assessment:
        return {}, {}
    sections = assessment.get("sections") or {}
    if not sections:
        return {}, {}
    questions = question_lookup(mode)
    totals: Dict[str, float] = {}
    counts: Dict[str, int] = {}
    sort_keys: Dict[str, Tuple[int, int, int, str]] = {}
    for q in questions.values():
        section_payload = sections.get(q.section or "")
        if not section_payload:
            continue
        percent = section_payload.get("percent")
        if percent is None:
            continue
        refs = q.gdpr_refs or []
        for ref in refs:
            label, key = _normalize_article_reference(ref)
            totals[label] = totals.get(label, 0.0) + float(percent)
            counts[label] = counts.get(label, 0) + 1
            sort_keys.setdefault(label, key)
    scores = {label: round(totals[label] / counts[label], 1) for label in totals if counts[label]}
    return scores, sort_keys


def build_article_chart_payload(dpia: Optional[Dict[str, Any]], gap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    dpia_scores, dpia_keys = _article_scores_from_assessment(dpia, "dpia11")
    gap_scores, gap_keys = _article_scores_from_assessment(gap, "gap")
    label_keys = {**dpia_keys, **gap_keys}
    if not label_keys:
        return {"labels": [], "datasets": []}
    labels = sorted(label_keys.keys(), key=lambda label: label_keys[label])
    datasets: List[Dict[str, Any]] = []
    if dpia_scores:
        datasets.append(_radar_dataset("DPIA article coverage", RADAR_COLORS["dpia11"], labels, dpia_scores))
    if gap_scores:
        datasets.append(_radar_dataset("GAP article coverage", RADAR_COLORS["gap"], labels, gap_scores))
    return {"labels": labels, "datasets": datasets}


def build_risk_scatter_payload(dpia: Optional[Dict[str, Any]], gap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    datasets: List[Dict[str, Any]] = []
    axis_max = {"x": 1, "y": 1}
    for mode, assessment in (("dpia11", dpia), ("gap", gap)):
        if not assessment:
            continue
        high_risk = len(assessment.get("high_risk_indicators") or [])
        coverage = len(assessment.get("coverage_gaps") or [])
        score = (assessment.get("overall_score") or {}).get("percent") or 0
        axis_max["x"] = max(axis_max["x"], coverage + 1)
        axis_max["y"] = max(axis_max["y"], high_risk + 1)
        datasets.append(
            {
                "label": SCHEMA_CHOICES[mode]["label"],
                "data": [{"x": coverage, "y": high_risk, "r": max(6, score / 5)}],
                "backgroundColor": RADAR_COLORS[mode][1],
                "borderColor": RADAR_COLORS[mode][0],
                "borderWidth": 1,
            }
        )
    return {"datasets": datasets, "max": axis_max}


def build_section_risk_payload(dpia: Optional[Dict[str, Any]], gap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    points: List[Tuple[str, float]] = []
    for prefix, assessment in (("DPIA", dpia), ("GAP", gap)):
        sections = (assessment or {}).get("sections") or {}
        for section, payload in sections.items():
            percent = payload.get("percent")
            if percent is None:
                continue
            risk_value = max(0.0, 100.0 - float(percent))
            points.append((f"{prefix} • {section}", round(risk_value, 1)))
    points.sort(key=lambda item: item[1], reverse=True)
    labels = [label for label, _ in points]
    values = [value for _, value in points]
    return {"labels": labels, "values": values}


def _collect_field_scores(assessment: Optional[Dict[str, Any]]) -> Dict[str, float]:
    if not assessment:
        return {}
    sections = assessment.get("sections", {})
    buckets: Dict[str, List[float]] = {field: [] for field in FIELD_KEYWORDS}
    buckets[GENERAL_FIELD] = []
    for section_name, payload in sections.items():
        lower = (section_name or "").lower()
        matched = False
        for field, keywords in FIELD_KEYWORDS.items():
            if any(keyword in lower for keyword in keywords):
                buckets[field].append(payload.get("percent", 0))
                matched = True
        if not matched:
            buckets[GENERAL_FIELD].append(payload.get("percent", 0))
    return {
        field: round(sum(values) / len(values), 1)
        for field, values in buckets.items()
        if values
    }


def _radar_dataset(label: str, colors: Tuple[str, str], axis: List[str], scores: Dict[str, float]) -> Dict[str, Any]:
    border, background = colors
    display_values: List[float] = []
    actual_values: List[float] = []
    for axis_label in axis:
        value = scores.get(axis_label)
        if value is None:
            display_values.append(None)
            actual_values.append(None)
            continue
        numeric = float(value)
        actual_values.append(round(numeric, 1))
        display_values.append(max(0.0, min(100.0, numeric)))
    return {
        "label": label,
        "data": display_values,
        "actual": actual_values,
        "borderColor": border,
        "backgroundColor": background,
        "pointBackgroundColor": border,
        "pointHoverBackgroundColor": "#fff",
        "pointHoverBorderColor": border,
        "fill": True,
    }


def build_radar_payload(dpia: Optional[Dict[str, Any]], gap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    dpia_fields = _collect_field_scores(dpia)
    gap_fields = _collect_field_scores(gap)
    labels = sorted(set(dpia_fields.keys()) | set(gap_fields.keys()))
    datasets: List[Dict[str, Any]] = []
    if dpia_fields:
        datasets.append(_radar_dataset("DPIA readiness", RADAR_COLORS["dpia11"], labels, dpia_fields))
    if gap_fields:
        datasets.append(_radar_dataset("GAP controls", RADAR_COLORS["gap"], labels, gap_fields))
    combined: Dict[str, float] = {}
    for label in labels:
        values = []
        if label in dpia_fields:
            values.append(dpia_fields[label])
        if label in gap_fields:
            values.append(gap_fields[label])
        combined[label] = round(sum(values) / len(values), 1) if values else 0
    return {"labels": labels, "datasets": datasets, "combined": combined}


def build_correlation_matrix(labels: List[str], combined_scores: Dict[str, float]) -> Dict[str, Any]:
    matrix: List[List[float]] = []
    for label_a in labels:
        row: List[float] = []
        for label_b in labels:
            score_a = combined_scores.get(label_a, 0)
            score_b = combined_scores.get(label_b, 0)
            diff = abs(score_a - score_b)
            value = max(0.0, round(1 - (diff / 100), 2))
            row.append(value)
        matrix.append(row)
    return {"labels": labels, "matrix": matrix, "scores": combined_scores}


def _classify_by_keywords(text: str, mapping: Dict[str, List[str]], default: str) -> str:
    lowered = text.lower()
    for key, keywords in mapping.items():
        if any(keyword in lowered for keyword in keywords):
            return key
    return default


def _classify_impact(text: str) -> str:
    return _classify_by_keywords(text, IMPACT_KEYWORDS, "Low")


def _classify_likelihood(text: str) -> str:
    result = _classify_by_keywords(text, LIKELIHOOD_KEYWORDS, None)
    return result or "Rare"


def build_risk_matrix(failures: List[Dict[str, Any]]) -> Dict[str, Any]:
    grid: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
        likelihood: {impact: [] for impact in IMPACT_LEVELS}
        for likelihood in LIKELIHOOD_LEVELS
    }
    samples: List[Dict[str, Any]] = []
    for failure in failures:
        context_parts = [failure.get("section"), failure.get("text"), failure.get("question")]
        context = " ".join(part for part in context_parts if part)
        impact = _classify_impact(context)
        likelihood = _classify_likelihood(context)
        entry = {
            "question": failure.get("question"),
            "section": failure.get("section"),
            "impact": impact,
            "likelihood": likelihood,
            "mode": failure.get("mode"),
        }
        grid[likelihood][impact].append(entry)
        if len(samples) < 6:
            samples.append(entry)
    return {"grid": grid, "samples": samples}


def combined_summary(dpia: Optional[Dict[str, Any]], gap: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    dpia_percent = (dpia.get("overall_score") or {}).get("percent") if dpia else None
    gap_percent = (gap.get("overall_score") or {}).get("percent") if gap else None
    coverage_total = len(dpia.get("coverage_gaps", [])) if dpia else 0
    coverage_total += len(gap.get("coverage_gaps", [])) if gap else 0
    risks = []
    if dpia:
        risks.extend(dpia.get("high_risk_indicators") or [])
    if gap:
        risks.extend(gap.get("high_risk_indicators") or [])
    # EL: Χρησιμοποιούμε dict-fromkeys για stable order και deduplication.
    # EN: Use dict-fromkeys for stable order and deduplication.
    warnings = list(dict.fromkeys(risks))
    score_values = [value for value in (dpia_percent, gap_percent) if value is not None]
    avg_percent = round(sum(score_values) / len(score_values), 1) if score_values else 0
    return {
        "average_percent": avg_percent,
        "dpia_percent": dpia_percent,
        "gap_percent": gap_percent,
        "risk_count": len(warnings),
        "coverage_gaps": coverage_total,
        "warnings": warnings[:5],
        "tracks_available": len(score_values),
    }


def extract_failure_points(assessment: Dict[str, Any], mode: str) -> List[Dict[str, Any]]:
    meta_map = question_lookup(mode)
    failures: List[Dict[str, Any]] = []
    for gap in assessment.get("coverage_gaps", []):
        question_id = gap.get("question")
        meta = meta_map.get(question_id)
        refs = list(meta.gdpr_refs) if meta and meta.gdpr_refs else []
        failures.append(
            {
                "mode": mode,
                "question": question_id,
                "section": gap.get("section"),
                "text": gap.get("text"),
                "gdpr_refs": refs,
            }
        )
    return failures


def aggregate_annex_failures(failures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    annex_map: Dict[str, Dict[str, Any]] = {}
    for failure in failures:
        refs = failure["gdpr_refs"] or ["Unspecified annex"]
        for ref in refs:
            bucket = annex_map.setdefault(ref, {"annex": ref, "entries": []})
            bucket["entries"].append(failure)
    return sorted(annex_map.values(), key=lambda entry: len(entry["entries"]), reverse=True)


@app.template_filter("format_value")
def format_value(value: Any) -> str:
    if value is None:
        return "[not provided]"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(value) if value else "[none]"
    if isinstance(value, dict):
        return ", ".join(f"{k}: {format_value(v)}" for k, v in value.items())
    return str(value)


@app.route("/")
def home():
    if session.pop("form_state", None) is not None:
        session.modified = True
    completed = session.get("assessments", {}) or {}
    runtime_modes = set(_runtime_assessments().keys())
    stale_modes = [mode for mode in completed.keys() if mode not in runtime_modes]
    if stale_modes:
        for mode in stale_modes:
            completed.pop(mode, None)
        session["assessments"] = completed
        session.modified = True
    access = _ensure_access_control()
    accessible_modes = [mode for mode in ASSESSMENT_MODES if access.get(mode)]
    cards = []
    for mode in accessible_modes:
        entry = completed.get(mode, {})
        card = {
            "mode": mode,
            "meta": SCHEMA_CHOICES[mode],
            "done": mode in completed,
            "percent": entry.get("percent"),
            "rating": entry.get("rating"),
            "action": "Review" if mode in completed else "Start",
        }
        cards.append(card)
    remaining = [mode for mode in accessible_modes if mode not in completed]
    next_mode = remaining[0] if remaining else None
    all_done = bool(accessible_modes) and not remaining
    return render_template(
        "home.html",
        cards=cards,
        all_done=all_done,
        next_mode=next_mode,
        access_control=access,
        accessible_modes=accessible_modes,
    )


@app.route("/assessment/<mode>", methods=["GET", "POST"])
def assessment_form(mode: str):
    if mode not in SCHEMA_CHOICES:
        return redirect(url_for("home"))
    access = _ensure_access_control()
    if not access.get(mode):
        flash("You do not have access to that assessment. Update access control settings to continue.", "error")
        return redirect(url_for("home"))
    bundle = load_bundle(mode)
    sections = group_by_section(bundle.questions)
    errors: Dict[str, str] = {}
    state: Dict[str, Any] = {}

    if request.method == "POST":
        answers, errors, state = parse_answers(bundle.questions, request.form)
        if not errors:
            assessment = run_assessment(mode, bundle, answers)
            completed = session.get("assessments", {})
            completed[mode] = save_assessment_files(mode, answers, assessment)
            session["assessments"] = completed
            session.modified = True
            return redirect(url_for("results"))

    progress = {
        "current": mode,
        "completed": list(session.get("assessments", {}).keys()),
        "accessible": [name for name in ASSESSMENT_MODES if access.get(name)],
    }
    return render_template(
        "assessment_form.html",
        mode=mode,
        schema_meta=SCHEMA_CHOICES[mode],
        sections=sections,
        errors=errors,
        state=state,
        progress=progress,
    )


@app.route("/assessment/<mode>/autofill", methods=["POST"])
def autofill_assessment(mode: str):
    if mode not in SCHEMA_CHOICES:
        abort(404)
    access = _ensure_access_control()
    if not access.get(mode):
        return {"error": "You do not have access to that module."}, 403
    payload = request.get_json(silent=True) or {}
    variant = str(payload.get("variant") or "").lower()
    if variant not in {"perfect", "mediocre"}:
        return {"error": "Pick either 'perfect' or 'mediocre'."}, 400
    bundle = load_bundle(mode)
    answers = build_autofill_answers(bundle, variant)
    assessment = run_assessment(mode, bundle, answers)
    entry = save_assessment_files(mode, answers, assessment)
    entry["autofill_variant"] = variant
    completed = session.get("assessments", {})
    completed[mode] = entry
    session["assessments"] = completed
    session.modified = True
    return {
        "redirect": url_for("results"),
        "percent": assessment.get("overall_score", {}).get("percent"),
        "rating": assessment.get("overall_score", {}).get("rating"),
        "variant": variant,
    }


@app.route("/results")
def results():
    """
    EL: Κεντρικό analytics view που συνθέτει scores, charts και AI reports.
    EN: Main analytics view composing scores, charts, and AI reports.
    """

    dpia_entry = get_session_assessment("dpia11")
    gap_entry = get_session_assessment("gap")
    dpia_assessment = None
    gap_assessment = None
    if dpia_entry:
        dpia_assessment = rebuild_assessment_from_entry("dpia11", dpia_entry)
        if dpia_assessment:
            dpia_assessment["markdown"] = dpia_entry.get("markdown") or render_markdown(dpia_assessment)
    if gap_entry:
        gap_assessment = rebuild_assessment_from_entry("gap", gap_entry)
        if gap_assessment:
            gap_assessment["markdown"] = gap_entry.get("markdown") or render_markdown(gap_assessment)

    if not dpia_assessment and not gap_assessment:
        flash("Complete at least one assessment before viewing analytics.", "error")
        return redirect(url_for("home"))

    combined = combined_summary(dpia_assessment, gap_assessment)
    chart_data = {
        "dpia": section_chart_payload(dpia_assessment),
        "gap": section_chart_payload(gap_assessment),
    }
    overall_labels: List[str] = []
    overall_values: List[float] = []
    if combined["dpia_percent"] is not None:
        overall_labels.append(SCHEMA_CHOICES["dpia11"]["label"])
        overall_values.append(combined["dpia_percent"])
    if combined["gap_percent"] is not None:
        overall_labels.append(SCHEMA_CHOICES["gap"]["label"])
        overall_values.append(combined["gap_percent"])
    if not overall_labels:
        overall_labels = ["No data"]
        overall_values = [0]
    chart_data["overall"] = {"labels": overall_labels, "values": overall_values}
    radar_payload = build_radar_payload(dpia_assessment, gap_assessment)
    chart_data["radar"] = {"labels": radar_payload.get("labels", []), "datasets": radar_payload.get("datasets", [])}
    article_payload = build_article_chart_payload(dpia_assessment, gap_assessment)
    chart_data["article_radar"] = article_payload
    chart_data["risk_scatter"] = build_risk_scatter_payload(dpia_assessment, gap_assessment)
    chart_data["section_risk"] = build_section_risk_payload(dpia_assessment, gap_assessment)

    failures: List[Dict[str, Any]] = []
    if dpia_assessment:
        failures.extend(extract_failure_points(dpia_assessment, "dpia11"))
    if gap_assessment:
        failures.extend(extract_failure_points(gap_assessment, "gap"))
    annex_failures = aggregate_annex_failures(failures)
    correlation_matrix = build_correlation_matrix(radar_payload.get("labels", []), radar_payload.get("combined", {}))
    risk_matrix = build_risk_matrix(failures)
    raw_reports = _runtime_module_reports()
    prepared_reports: Dict[str, Dict[str, Any]] = {}
    for report_mode, meta in list(raw_reports.items()):
        text = load_module_report_text(meta)
        if not text:
            continue
        prepared_reports[report_mode] = {
            **meta,
            "text": text,
            "html": markdown_to_html(text),
        }
    return render_template(
        "results.html",
        dpia=dpia_assessment,
        gap=gap_assessment,
        combined=combined,
        chart_data=chart_data,
        annex_failures=annex_failures,
        module_reports=prepared_reports,
        cookie_audit=session.get("cookie_audit"),
        cookie_audit_include=session.get("cookie_audit_include", False),
        correlation_matrix=correlation_matrix,
        risk_matrix=risk_matrix,
        impact_levels=IMPACT_LEVELS,
        likelihood_levels=LIKELIHOOD_LEVELS,
    )


@app.route("/cookie-audit", methods=["GET", "POST"])
def cookie_audit_view():
    audit = session.get("cookie_audit")
    include = session.get("cookie_audit_include", False)
    error = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Enter a website URL to audit."
        else:
            audit = run_cookie_audit(url)
            session["cookie_audit"] = audit
            session.modified = True
            flash("Cookie compliance audit completed.", "info")
    return render_template(
        "cookie_audit.html",
        audit=audit,
        include_in_policy=include,
        error=error,
    )


@app.route("/cookie-audit/include", methods=["POST"])
def toggle_cookie_audit():
    include = request.form.get("include") == "true"
    if include and "cookie_audit" not in session:
        flash("Run a cookie audit before including it in the official policy.", "error")
        return redirect(url_for("cookie_audit_view"))
    session["cookie_audit_include"] = include
    session.modified = True
    message = "Cookie audit will be referenced by the official policy." if include else "Cookie audit removed from official policy scope."
    flash(message, "info")
    destination = request.form.get("next") or url_for("cookie_audit_view")
    return redirect(destination)


@app.route("/report-access", methods=["GET", "POST"])
def report_access():
    next_url = request.args.get("next") or request.form.get("next") or url_for("results")
    if not REPORT_ACCESS_TOKEN:
        session["report_access_granted"] = True
        session.modified = True
        return redirect(next_url)
    error = None
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        if token == REPORT_ACCESS_TOKEN:
            session["report_access_granted"] = True
            session.modified = True
            return redirect(next_url)
        error = "Invalid access token."
    return render_template("report_access.html", error=error, next=next_url)


@app.route("/reports/<mode>/export")
def export_assessment(mode: str):
    if mode not in ASSESSMENT_MODES:
        abort(404)
    entry = get_session_assessment(mode)
    if not entry:
        flash(f"Complete the {SCHEMA_CHOICES[mode]['label']} before downloading.", "error")
        return redirect(url_for("results"))
    if REPORT_ACCESS_TOKEN and not session.get("report_access_granted"):
        return redirect(url_for("report_access", next=url_for("export_assessment", mode=mode)))
    answers = entry.get("answers", {})
    assessment = rebuild_assessment_from_entry(mode, entry)
    if assessment is None:
        flash(f"Unable to rebuild the {SCHEMA_CHOICES[mode]['label']} assessment. Re-submit the questionnaire and try again.", "error")
        return redirect(url_for("results"))
    markdown = entry.get("markdown") or render_markdown(assessment)
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(f"{mode}_answers.json", json.dumps(answers, indent=2))
        archive.writestr(f"{mode}_assessment.json", json.dumps(assessment, indent=2))
        archive.writestr(f"{mode}_assessment.md", markdown)
    package.seek(0)
    filename = f"{mode}-assessment-package.zip"
    return send_file(package, as_attachment=True, download_name=filename, mimetype="application/zip")


@app.route("/module-report/<mode>/download.<fmt>")
def download_module_report(mode: str, fmt: str):
    if mode not in ASSESSMENT_MODES:
        abort(404)
    reports = _runtime_module_reports()
    report = reports.get(mode)
    if not report:
        flash("Generate the AI report before downloading.", "error")
        return redirect(url_for("results"))
    next_url = url_for("download_module_report", mode=mode, fmt=fmt)
    if REPORT_ACCESS_TOKEN and not session.get("report_access_granted"):
        return redirect(url_for("report_access", next=next_url))
    text = load_module_report_text(report)
    if not text:
        flash("Report data missing. Regenerate the AI report and try again.", "error")
        return redirect(url_for("results"))
    if fmt == "md":
        data = text.encode("utf-8")
        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=f"{mode}-llm-report.md",
            mimetype="text/markdown",
        )
    if fmt == "pdf":
        label = SCHEMA_CHOICES[mode]["label"]
        subtitle = f"Run {report['run_id']} · {report['generated_at']}"
        pdf_bytes = markdown_to_pdf_report(
            text,
            f"{label} compliance narrative",
            subtitle,
        )
        return send_file(
            io.BytesIO(pdf_bytes),
            as_attachment=True,
            download_name=f"{mode}-llm-report.pdf",
            mimetype="application/pdf",
        )
    if fmt == "docx":
        label = SCHEMA_CHOICES[mode]["label"]
        subtitle = f"Run {report['run_id']} · {report['generated_at']}"
        try:
            docx_bytes = markdown_to_docx_bytes(
                text,
                f"{label} compliance narrative",
                subtitle,
            )
        except RuntimeError as exc:
            flash(f"DOCX export unavailable: {exc}", "error")
            return redirect(url_for("results"))
        return send_file(
            io.BytesIO(docx_bytes),
            as_attachment=True,
            download_name=f"{mode}-llm-report.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    abort(404)


@app.route("/official-policy", methods=["GET", "POST"])
def official_policy_page():
    """
    EL: Orchestrates τη σύνθεση της official policy από DPIA/GAP/cookie inputs.
    EN: Orchestrates official policy composition from DPIA/GAP/cookie inputs.
    """

    error = None
    policy_meta = load_runtime_official_policy(session.get("official_policy_run"))
    company_profile = session.get("company_profile", {})
    policy_overrides = session.get("policy_overrides", {})
    if request.method == "POST":
        overrides = session.get("policy_overrides", {})
        try:
            answers, assessment = combined_assessment_inputs()
            if session.get("cookie_audit_include"):
                audit_summary = summarize_cookie_audit(session.get("cookie_audit"))
                if audit_summary:
                    assessment["cookie_audit"] = audit_summary
            context, sections, markdown_text, context_hash = generate_official_policy_sections(answers, assessment, overrides)
            run_id = _new_run_id()
            policy_number = f"GDP-{run_id}"
            signature = hash_text(markdown_text + policy_number)
            html_body = markdown_to_html(markdown_text)
            pdf_bytes = markdown_to_pdf_bytes(markdown_text, policy_number, signature)
            result = {
                "run_id": run_id,
                "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "context_hash": context_hash,
                "model": MODEL_NAME,
                "sections": sections,
                "policy_number": policy_number,
                "signature": signature,
                "markdown": markdown_text,
                "html": html_body,
                "pdf_bytes": pdf_bytes,
                "context": context,
                "overrides": overrides or {},
                "paths": {"pdf": "memory://pdf", "html": "memory://html", "markdown": "memory://markdown"},
            }
            bucket = _runtime_bucket(create=True)
            bucket["official_policies"][run_id] = result
            bucket["official_policy_current"] = run_id
        except (RuntimeError, ValueError, FileNotFoundError) as exc:
            logger.exception("Official policy generation failed.")
            error = str(exc)
        else:
            session["official_policy_run"] = result["run_id"]
            session.modified = True
            return redirect(url_for("official_policy_page"))
    return render_template(
        "official_policy.html",
        policy=policy_meta,
        error=error,
        assessments_ready=all(get_session_assessment(mode) for mode in ASSESSMENT_MODES),
        company_profile=company_profile,
        policy_overrides=policy_overrides,
        sections_meta=OFFICIAL_POLICY_PROMPTS,
    )


@app.route("/official-policy/download/<run_id>")
def download_official_policy(run_id: str):
    fmt = (request.args.get("fmt") or "pdf").lower()
    metadata = load_runtime_official_policy(run_id)
    if not metadata:
        abort(404)
    if fmt == "pdf":
        pdf_bytes = metadata.get("pdf_bytes")
        if not isinstance(pdf_bytes, (bytes, bytearray)):
            fmt = "md"
        else:
            return send_file(
                io.BytesIO(bytes(pdf_bytes)),
                as_attachment=True,
                download_name=f"official-gdpr-policy-{run_id}.pdf",
                mimetype="application/pdf",
            )
    if fmt == "html":
        html_text = metadata.get("html")
        if isinstance(html_text, str):
            return send_file(
                io.BytesIO(html_text.encode("utf-8")),
                as_attachment=True,
                download_name=f"official-gdpr-policy-{run_id}.html",
                mimetype="text/html",
            )
        fmt = "md"
    if fmt == "docx":
        markdown_text = metadata.get("markdown", "")
        if not isinstance(markdown_text, str) or not markdown_text.strip():
            flash("DOCX export unavailable because policy markdown is missing.", "error")
            return redirect(url_for("official_policy_page"))
        subtitle = f"Policy {metadata.get('policy_number', run_id)} · {metadata.get('generated_at', '')}"
        try:
            docx_bytes = markdown_to_docx_bytes(
                markdown_text,
                "Official GDPR Compliance Policy",
                subtitle,
            )
        except RuntimeError as exc:
            flash(f"DOCX export unavailable: {exc}", "error")
            return redirect(url_for("official_policy_page"))
        return send_file(
            io.BytesIO(docx_bytes),
            as_attachment=True,
            download_name=f"official-gdpr-policy-{run_id}.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    if fmt in {"md", "markdown"}:
        text = metadata.get("markdown", "")
        return send_file(
            io.BytesIO(text.encode("utf-8")),
            as_attachment=True,
            download_name=f"official-gdpr-policy-{run_id}.md",
            mimetype="text/markdown",
        )
    abort(400, description="Unsupported format.")


@app.route("/official-policy/comments", methods=["POST"])
def update_policy_overrides():
    overrides = session.get("policy_overrides", {})
    for slug in OFFICIAL_POLICY_PROMPTS.keys():
        overrides[slug] = request.form.get(f"override_{slug}", "").strip()
    session["policy_overrides"] = overrides
    session.modified = True
    return redirect(url_for("official_policy_page"))


@app.route("/official-policy/profile", methods=["POST"])
def update_company_profile():
    def split_lines(value: str) -> List[str]:
        return [line.strip() for line in value.splitlines() if line.strip()]

    profile = {
        "org_name": request.form.get("org_name", "").strip(),
        "sector": request.form.get("sector", "").strip(),
        "country": request.form.get("country", "").strip(),
        "dpo_name": request.form.get("dpo_name", "").strip(),
        "email": request.form.get("email", "").strip(),
        "phone": request.form.get("phone", "").strip(),
        "processors": split_lines(request.form.get("processors", "")),
        "transfers": split_lines(request.form.get("transfers", "")),
    }
    session["company_profile"] = profile
    session.modified = True
    return redirect(url_for("official_policy_page"))


@app.route("/module-report/<mode>", methods=["POST"])
def create_module_report(mode: str):
    """
    EL: Δημιουργεί LLM narrative report για το επιλεγμένο assessment mode.
    EN: Generates an LLM narrative report for the selected assessment mode.
    """

    if mode not in ASSESSMENT_MODES:
        abort(404)
    entry = get_session_assessment(mode)
    if not entry:
        flash(f"{SCHEMA_CHOICES[mode]['label']} must be completed before generating this report.", "error")
        return redirect(url_for("results"))
    answers = entry.get("answers", {})
    assessment = rebuild_assessment_from_entry(mode, entry)
    if assessment is None:
        flash(f"Unable to rebuild the {SCHEMA_CHOICES[mode]['label']} assessment. Re-submit the questionnaire and try again.", "error")
        return redirect(url_for("results"))
    if session.get("cookie_audit_include") and session.get("cookie_audit"):
        audit_summary = summarize_cookie_audit(session.get("cookie_audit"))
        if audit_summary:
            assessment["cookie_audit"] = audit_summary
    context = {
        "mode": mode,
        "label": SCHEMA_CHOICES[mode]["label"],
        "assessment": assessment,
        "org_context": build_llm_context(answers, assessment),
    }
    try:
        result = generate_module_report(mode, context)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        logger.exception("Module report generation failed for mode '%s'.", mode)
        flash(f"Failed to generate {SCHEMA_CHOICES[mode]['label']} report: {exc}", "error")
        return redirect(url_for("results"))
    reports = _runtime_module_reports()
    reports[mode] = {
        "mode": mode,
        "label": SCHEMA_CHOICES[mode]["label"],
        "run_id": result["run_id"],
        "generated_at": result["generated_at"],
        "text": result["text"],
    }
    flash(f"{SCHEMA_CHOICES[mode]['label']} report generated.", "info")
    return redirect(url_for("results") + f"#module-report-{mode}")


@app.route("/access-control", methods=["POST"])
def update_access_control():
    selected = set(request.form.getlist("allowed_modes"))
    if not selected:
        flash("Select at least one assessment to enable.", "error")
        return redirect(url_for("home"))
    access = {mode: mode in selected for mode in ASSESSMENT_MODES}
    session["access_control"] = access
    session.modified = True
    flash("Access control updated.", "info")
    return redirect(url_for("home"))


@app.route("/reset", methods=["POST"])
def reset_progress():
    _drop_runtime_bucket()
    session.clear()
    return redirect(url_for("home"))


@app.route("/healthz")
def healthcheck():
    return {"status": "ok", "schemas": list(SCHEMA_CHOICES.keys()), "completed": list(session.get("assessments", {}).keys())}


if __name__ == "__main__":
    app.run(debug=True)

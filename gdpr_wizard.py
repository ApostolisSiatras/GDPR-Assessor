#!/usr/bin/env python3
"""
EL: Core assessment engine για DPIA/GAP questionnaires και scoring.
EN: Core assessment engine for DPIA/GAP questionnaires and scoring.

EL: Το module χρησιμοποιείται τόσο από CLI όσο και από το Flask app.
Παρέχει shared data models, scoring logic και markdown rendering.

EN: This module is used by both CLI and Flask app. It provides shared
data models, scoring logic, and markdown rendering.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


# EL: Data model layer (Question/Schema).
# EN: Data model layer (Question/Schema).


@dataclass
class Question:
    """
    EL: Domain model μίας ερώτησης schema με metadata scoring/compliance.
    EN: Domain model for one schema question with scoring/compliance metadata.
    """

    id: str
    section: str
    text: str
    qtype: str
    required: bool
    gdpr_refs: List[str] = field(default_factory=list)
    enum: List[str] = field(default_factory=list)
    coverage_policy: Optional[Dict[str, Any]] = None
    scoring: Optional[Dict[str, Any]] = None
    map_values: Optional[Dict[str, Any]] = None
    max_points: float = 0.0

    @classmethod
    def from_raw(cls, raw: Dict[str, Any], vocabs: Dict[str, List[str]]) -> "Question":
        enum: List[str] = []
        if "enum" in raw and isinstance(raw["enum"], list):
            enum = list(raw["enum"])
        elif "options_ref" in raw:
            enum = list(vocabs.get(raw["options_ref"], []))
        scoring_data = raw.get("scoring")
        scoring: Optional[Dict[str, Any]] = None
        max_points = 0.0
        if isinstance(scoring_data, dict):
            scoring = dict(scoring_data)
            numeric_values = [float(val) for val in scoring.values() if isinstance(val, (int, float))]
            max_points = max(numeric_values) if numeric_values else 1.0
        return cls(
            id=raw["id"],
            section=raw.get("section", "Unsectioned"),
            text=raw["text"],
            qtype=raw["type"],
            required=raw.get("required", False),
            gdpr_refs=raw.get("gdpr_refs", []),
            enum=enum,
            coverage_policy=raw.get("coverage_policy"),
            scoring=scoring,
            map_values=raw.get("map"),
            max_points=max_points,
        )


class SchemaBundle:
    """
    EL: Φορτώνει schema + vocabularies και παράγει typed Question list.
    EN: Loads schema + vocabularies and produces typed Question list.
    """

    def __init__(self, schema_path: Path, vocabs_path: Path):
        self.schema_path = schema_path
        self.vocabs_path = vocabs_path
        with schema_path.open("r", encoding="utf-8") as fh:
            self.schema = json.load(fh)
        with vocabs_path.open("r", encoding="utf-8") as fh:
            self.vocabs = json.load(fh)
        self.questions: List[Question] = [
            Question.from_raw(raw, self.vocabs) for raw in self.schema.get("questions", [])
        ]


# EL: Wizard interface layer (interactive CLI input).
# EN: Wizard interface layer (interactive CLI input).


class TerminalWizard:
    """
    EL: Interactive CLI wizard για συλλογή απαντήσεων από χρήστη.
    EN: Interactive CLI wizard for collecting user answers.
    """

    def __init__(self, bundle: SchemaBundle):
        self.bundle = bundle

    def run(self) -> Dict[str, Any]:
        print("=" * 80)
        print("GDPR DPIA/GAP Wizard")
        print(f"Schema: {self.bundle.schema_path.name} | Generated: {self.bundle.schema.get('generated_at')}")
        print("Type 'help' for assistance, 'list' to reprint options, or 'skip' where permitted.")
        print("=" * 80)
        answers: Dict[str, Any] = {}
        for q in self.bundle.questions:
            answers[q.id] = self._ask_question(q)
        return answers

    def _parse_multiselect(self, q: Question, raw: str) -> List[str]:
        tokens = [tok.strip().upper() for tok in raw.split(",") if tok.strip()]
        valid = {opt.upper(): opt for opt in q.enum}
        out: List[str] = []
        for token in tokens:
            if token not in valid:
                raise ValueError(f"'{token}' is not one of: {', '.join(q.enum)}")
            out.append(valid[token])
        if not out and q.required:
            raise ValueError("At least one selection is required.")
        return out

    def _ask_question(self, q: Question) -> Any:
        while True:
            self._print_question(q)
            raw = input("> ").strip()
            if raw.lower() in {"help", "?"}:
                self._print_help(q)
                continue
            if raw.lower() == "list":
                self._print_options(q)
                continue
            if not raw:
                if q.required:
                    print("This question is required.")
                    continue
                return None
            if raw.lower() == "skip":
                if q.required:
                    print("Cannot skip a required question.")
                    continue
                return None
            try:
                return self._coerce_answer(q, raw)
            except ValueError as exc:
                print(f"[Invalid] {exc}")

    def _coerce_answer(self, q: Question, raw: str) -> Any:
        if q.qtype == "boolean":
            mapping = {"yes": True, "y": True, "no": False, "n": False}
            key = raw.lower()
            if key not in mapping:
                raise ValueError("Enter yes/no.")
            return mapping[key]
        if q.qtype in {"enum", "scale"}:
            opts = {opt.upper(): opt for opt in q.enum}
            key = raw.strip().upper()
            if key not in opts:
                raise ValueError(f"Pick one of: {', '.join(q.enum)}")
            return opts[key]
        if q.qtype == "multiselect":
            return self._parse_multiselect(q, raw)
        if q.qtype == "integer":
            return int(raw)
        raise ValueError(f"Unsupported question type: {q.qtype}")

    def _print_question(self, q: Question) -> None:
        print("-" * 80)
        req = "[Required]" if q.required else "[Optional]"
        refs = f" | GDPR: {', '.join(q.gdpr_refs)}" if q.gdpr_refs else ""
        print(f"{q.section} | {q.id} {req}{refs}")
        print(q.text)
        self._print_options(q)

    def _print_help(self, q: Question) -> None:
        print("Enter comma-separated codes for multi-select questions.")
        print("Commands: help/? (show this), list (reprint options), skip (if optional).")
        self._print_options(q)

    def _print_options(self, q: Question) -> None:
        if q.qtype == "boolean":
            print("Options: yes, no")
        elif q.enum:
            opts = ", ".join(q.enum)
            print(f"Options: {opts}")
        elif q.qtype == "multiselect" and q.enum:
            opts = ", ".join(q.enum)
            print(f"Select any of: {opts}")


# EL: Assessment layer (scoring, gaps, risk indicators).
# EN: Assessment layer (scoring, gaps, risk indicators).


class AssessmentBuilder:
    """
    EL: Υπολογίζει scores, gaps και traceability metadata από answers.
    EN: Computes scores, gaps, and traceability metadata from answers.
    """

    def __init__(self, bundle: SchemaBundle, answers: Dict[str, Any]):
        self.bundle = bundle
        self.answers = answers

    def build(self) -> Dict[str, Any]:
        sections = self._section_scores()
        summary = {
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "schema": self.bundle.schema_path.name,
            "sections": sections,
            "overall_score": self._overall_score(sections),
            "coverage_gaps": self._coverage_gaps(),
            "high_risk_indicators": self._high_risk_items(),
            "gdpr_articles": self._article_summary(),
            "key_facts": self._key_facts(),
        }
        return summary

    def _section_scores(self) -> Dict[str, Dict[str, float]]:
        data: Dict[str, Dict[str, float]] = {}
        for q in self.bundle.questions:
            ans = self.answers.get(q.id)
            if ans is None or not q.scoring:
                continue
            score = self._score_answer(q, ans)
            if score is None:
                continue
            sec = data.setdefault(q.section, {"earned": 0.0, "max": 0.0})
            sec["earned"] += float(score)
            max_points = q.max_points if q.max_points else 1.0
            sec["max"] += max_points
        for sec, payload in data.items():
            if payload["max"]:
                payload["percent"] = round((payload["earned"] / payload["max"]) * 100, 1)
        return data

    def _overall_score(self, sections: Dict[str, Dict[str, float]]) -> Dict[str, Any]:
        total_earned = sum(section.get("earned", 0.0) for section in sections.values())
        total_max = sum(section.get("max", 0.0) for section in sections.values())
        percent = round((total_earned / total_max) * 100, 1) if total_max else 0.0
        return {
            "earned": round(total_earned, 2),
            "max": round(total_max or 0, 2),
            "percent": percent,
            "rating": self._score_band(percent),
        }

    @staticmethod
    def _score_band(percent: float) -> str:
        if percent >= 85:
            return "Strong"
        if percent >= 70:
            return "Adequate"
        if percent >= 50:
            return "Needs Improvement"
        return "High Risk"

    def _score_answer(self, q: Question, ans: Any) -> Optional[float]:
        if not q.scoring:
            return None
        if isinstance(ans, list):
            return sum(q.scoring.get(item, 0) for item in ans if item in q.scoring)
        key = str(ans).upper()
        return q.scoring.get(key)

    def _coverage_gaps(self) -> List[Dict[str, Any]]:
        gaps: List[Dict[str, Any]] = []
        for q in self.bundle.questions:
            if not q.coverage_policy:
                continue
            if not q.required and q.id not in self.answers:
                continue
            ans = self.answers.get(q.id, [])
            if q.qtype != "multiselect":
                continue
            targets = set(q.coverage_policy.get("targets", []))
            provided = set(ans)
            mode = q.coverage_policy.get("mode")
            ok = True
            if mode == "ALL":
                ok = targets.issubset(provided)
            elif mode == "ANY":
                ok = bool(provided & targets)
            elif mode == "FRACTION":
                threshold = q.coverage_policy.get("threshold", 1.0)
                ok = len(provided & targets) >= max(1, int(len(targets) * threshold))
            if not ok:
                gaps.append(
                    {
                        "question": q.id,
                        "section": q.section,
                        "text": q.text,
                        "required_targets": sorted(targets),
                        "selected": sorted(provided),
                        "mode": mode,
                    }
                )
        return gaps

    def _high_risk_items(self) -> List[str]:
        risk_flags: List[str] = []
        special_cats = self.answers.get("Q-DPIA-004") or []
        if special_cats:
            risk_flags.append("Special-category data present (Art.9).")
        scale = self.answers.get("Q-DPIA-005")
        if scale in {"HIGH_>100K"}:
            risk_flags.append("Large-scale processing (Recital 91).")
        transfers = self.answers.get("Q-DPIA-011")
        mechanisms = self.answers.get("Q-DPIA-012")
        if transfers == "YES" and (not mechanisms or mechanisms == ["NONE"]):
            risk_flags.append("International transfers flagged without safeguards (Art.44-49).")
        adm = self.answers.get("Q-DPIA-014")
        if adm == "YES":
            risk_flags.append("Automated decision-making/profiling reported (Art.22).")
        residual_likelihood = self.answers.get("Q-DPIA-027")
        residual_impact = self.answers.get("Q-DPIA-028")
        if residual_likelihood in {"HIGH", "VERY_HIGH"} or residual_impact in {"HIGH", "VERY_HIGH"}:
            risk_flags.append("Residual risk remains high post-controls (Art.35(7)(d)).")
        return risk_flags

    def _article_summary(self) -> Dict[str, List[str]]:
        article_map: Dict[str, List[str]] = {}
        for q in self.bundle.questions:
            ans = self.answers.get(q.id)
            if ans is None:
                continue
            state = self._format_answer(ans)
            for article in q.gdpr_refs:
                bucket = article_map.setdefault(article, [])
                bucket.append(f"{q.id}: {state}")
        return article_map

    def _key_facts(self) -> Dict[str, Any]:
        facts = {
            "data_subjects": self.answers.get("Q-DPIA-001A"),
            "purposes": self.answers.get("Q-DPIA-002"),
            "data_categories": self.answers.get("Q-DPIA-003"),
            "special_categories": self.answers.get("Q-DPIA-004"),
            "legal_basis": self.answers.get("Q-DPIA-006"),
            "processors": self.answers.get("Q-DPIA-009"),
            "transfers": {
                "flag": self.answers.get("Q-DPIA-011"),
                "mechanisms": self.answers.get("Q-DPIA-012"),
            },
            "security_controls": self.answers.get("Q-DPIA-019"),
            "rights_processes": self.answers.get("Q-DPIA-025"),
        }
        return {k: v for k, v in facts.items() if v is not None}

    def _format_answer(self, ans: Any) -> str:
        if isinstance(ans, list):
            return ", ".join(ans) if ans else "[none]"
        if isinstance(ans, bool):
            return "YES" if ans else "NO"
        return str(ans)


# EL: Output helpers (JSON/Markdown export).
# EN: Output helpers (JSON/Markdown export).


def write_outputs(base: Path, mode: str, answers: Dict[str, Any], assessment: Dict[str, Any]) -> None:
    base.mkdir(parents=True, exist_ok=True)
    with (base / f"{mode}_answers.json").open("w", encoding="utf-8") as fh:
        json.dump(answers, fh, indent=2)
    with (base / f"{mode}_assessment.json").open("w", encoding="utf-8") as fh:
        json.dump(assessment, fh, indent=2)
    with (base / f"{mode}_assessment.md").open("w", encoding="utf-8") as fh:
        fh.write(render_markdown(assessment))


def render_markdown(assessment: Dict[str, Any]) -> str:
    lines = [
        f"# GDPR Assessment ({assessment.get('schema')})",
        f"- Generated: {assessment.get('generated_at')}",
        "",
        "## Overall Score",
    ]
    overall = assessment.get("overall_score") or {}
    if overall:
        lines.append(
            f"- {overall.get('percent', 0)}% ({overall.get('earned', 0)}/{overall.get('max', 0)}) — {overall.get('rating', 'N/A')}"
        )
    lines.append("")
    lines.append("## Key Facts")
    for key, value in assessment.get("key_facts", {}).items():
        pretty = value
        if isinstance(value, list):
            pretty = ", ".join(value)
        if isinstance(value, dict):
            pretty = ", ".join(f"{k}={v}" for k, v in value.items())
        lines.append(f"- **{key.replace('_', ' ').title()}**: {pretty}")
    lines.append("")
    lines.append("## Section Scores")
    for section, payload in assessment.get("sections", {}).items():
        percent = payload.get("percent", 0)
        earned = round(payload.get("earned", 0), 2)
        max_score = round(payload.get("max", 0), 2)
        lines.append(f"- **{section}**: {percent}% ({earned}/{max_score})")
    lines.append("")
    lines.append("## High-Risk Indicators")
    risks = assessment.get("high_risk_indicators") or ["None observed."]
    for item in risks:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Coverage Gaps")
    gaps = assessment.get("coverage_gaps")
    if not gaps:
        lines.append("- Coverage policies satisfied.")
    else:
        for gap in gaps:
            lines.append(
                f"- {gap['question']} ({gap['section']}): requires {gap['mode']} of {', '.join(gap['required_targets'])}; selected {', '.join(gap['selected']) or '[none]'}"
            )
    lines.append("")
    lines.append("## GDPR Article Traceability")
    for article, refs in sorted(assessment.get("gdpr_articles", {}).items()):
        lines.append(f"### {article}")
        for ref in refs:
            lines.append(f"- {ref}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


# EL: CLI entrypoint και argument parsing.
# EN: CLI entrypoint and argument parsing.


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive GDPR DPIA / Gap wizard.")
    parser.add_argument(
        "--mode",
        choices=["dpia", "dpia11", "gap"],
        default="dpia11",
        help="Shortcut for built-in schemas (dpia -> dpia.json, dpia11 -> dpia(1.1), gap -> gap.json).",
    )
    parser.add_argument("--schema", type=Path, help="Path to custom schema JSON.")
    parser.add_argument("--vocabs", type=Path, default=Path("vocabs.json"), help="Vocabulary JSON path.")
    parser.add_argument("--output", type=Path, default=Path("reports"), help="Directory for generated reports.")
    return parser.parse_args(argv)


def resolve_schema(mode: str, schema_override: Optional[Path]) -> Path:
    if schema_override:
        return schema_override
    defaults = {
        "dpia": Path("dpia.json"),
        "dpia11": Path("dpia(1.1)"),
        "gap": Path("gap.json"),
    }
    if mode not in defaults:
        raise ValueError(f"Unknown mode '{mode}'.")
    return defaults[mode]


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    schema_path = resolve_schema(args.mode, args.schema)
    if not schema_path.exists():
        print(f"Schema file {schema_path} not found.", file=sys.stderr)
        return 1
    bundle = SchemaBundle(schema_path, args.vocabs)
    wizard = TerminalWizard(bundle)
    answers = wizard.run()
    assessment = AssessmentBuilder(bundle, answers).build()
    write_outputs(args.output, args.mode, answers, assessment)
    print(f"\nAssessment saved under {args.output}/ as {args.mode}_*.json/.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

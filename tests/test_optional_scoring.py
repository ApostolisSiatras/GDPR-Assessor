# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

from pathlib import Path
from types import SimpleNamespace

from gdpr_wizard import AssessmentBuilder, Question


def _bundle(*questions):
    return SimpleNamespace(schema_path=Path("dummy.json"), questions=list(questions))


def test_optional_questions_affect_scores_only_when_answered():
    required = Question(
        id="Q-REQ",
        section="Governance",
        text="Required control",
        qtype="enum",
        required=True,
        enum=["YES", "NO"],
        scoring={"YES": 1, "NO": 0},
    )
    optional = Question(
        id="Q-OPT",
        section="Governance",
        text="Optional benefit",
        qtype="enum",
        required=False,
        enum=["YES", "NO"],
        scoring={"YES": 1, "NO": 0},
    )

    builder_without_optional = AssessmentBuilder(_bundle(required, optional), {"Q-REQ": "YES"})
    assessment_without = builder_without_optional.build()
    assert assessment_without["sections"]["Governance"]["percent"] == 100

    builder_with_optional = AssessmentBuilder(_bundle(required, optional), {"Q-REQ": "YES", "Q-OPT": "NO"})
    assessment_with = builder_with_optional.build()
    assert assessment_with["sections"]["Governance"]["percent"] == 50


def test_optional_coverage_only_checked_when_answered():
    required = Question(
        id="Q-REQ",
        section="Governance",
        text="Required control",
        qtype="enum",
        required=True,
        enum=["YES", "NO"],
        scoring={"YES": 1, "NO": 0},
    )
    optional_multi = Question(
        id="Q-OPT",
        section="Governance",
        text="Optional safeguards",
        qtype="multiselect",
        required=False,
        coverage_policy={"targets": ["A"], "mode": "ALL"},
    )

    builder_without_optional = AssessmentBuilder(_bundle(required, optional_multi), {"Q-REQ": "YES"})
    assessment_without = builder_without_optional.build()
    assert all(gap["question"] != "Q-OPT" for gap in assessment_without.get("coverage_gaps", []))

    builder_with_optional = AssessmentBuilder(
        _bundle(required, optional_multi), {"Q-REQ": "YES", "Q-OPT": ["B"]}
    )
    assessment_with = builder_with_optional.build()
    assert any(gap["question"] == "Q-OPT" for gap in assessment_with.get("coverage_gaps", []))

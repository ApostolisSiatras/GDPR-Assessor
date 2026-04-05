# Proprietary Software Notice
# This file is part of GDPR Assessor.
# Copyright (c) 2025 Apostolos Siatras.
# Unauthorized use, copying, modification, distribution, or derivative works
# is prohibited without prior written permission from the copyright holder.

import pytest

from app import app, combined_assessment_inputs


def test_combined_assessment_inputs_require_both():
    with pytest.raises(RuntimeError):
        combined_assessment_inputs()


def test_results_redirects_without_completed_assessments():
    app.config["TESTING"] = True
    client = app.test_client()
    resp = client.get("/results", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")

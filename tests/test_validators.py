from validators import validate_cookie_policy, validate_json, validate_transfers


def test_validate_cookie_policy_requires_statement_when_disabled():
    ctx = {"cookies": {"enabled": False}}
    errors = validate_cookie_policy(ctx, "# Cookie Policy\nCookies are absent")
    assert errors, "Missing disclosure should trigger error"
    ok = validate_cookie_policy(ctx, "We do not use cookies anywhere")
    assert ok == []


def test_validate_transfers_enforces_scc_language():
    ctx = {"transfers": [{"country": "US"}]}
    md = "# Policy\nInternational transfers listed here."
    errors = validate_transfers(ctx, md)
    assert errors
    md_with_scc = md + "\nStandard Contractual Clauses are applied."
    assert validate_transfers(ctx, md_with_scc) == []


def test_validate_json_reports_schema_issues():
    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    assert validate_json(schema, {"name": "ok"}) == []
    assert validate_json(schema, {})


def test_cookie_validation_skips_when_no_website():
    ctx = {"cookies": {"enabled": False, "reason": "no_website"}}
    assert validate_cookie_policy(ctx, "no statement needed") == []

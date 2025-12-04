from policy_engine import official_policy


def test_generate_official_policy_sections(monkeypatch):
    def fake_run(prompt, model, stream=False):  # noqa: ARG001
        return "## Section\nContent"

    monkeypatch.setattr(official_policy, "run_ollama", fake_run)
    answers = {"ORG_NAME": "Example Corp"}
    assessment = {"sections": {}, "overall_score": {"percent": 80}}
    context, sections, combined, ctx_hash = official_policy.generate_official_policy_sections(answers, assessment)
    assert context["org"]["name"] == "Example Corp"
    assert len(sections) == len(official_policy.OFFICIAL_POLICY_PROMPTS)
    assert "Official GDPR Compliance Policy" in combined
    assert "Last updated:" in combined
    assert ctx_hash


def test_overrides_passed_to_prompt(monkeypatch):
    captured = []

    def fake_run(prompt, model, stream=False):  # noqa: ARG001
        captured.append(prompt)
        return "## Section\nContent"

    monkeypatch.setattr(official_policy, "run_ollama", fake_run)
    overrides = {"overview": "Please emphasise sustainability mission."}
    official_policy.generate_official_policy_sections({"ORG_NAME": "Example"}, {"sections": {}, "overall_score": {}}, overrides)
    assert any("sustainability mission" in prompt for prompt in captured)


def test_save_official_policy_generates_number_and_signature(tmp_path, monkeypatch):
    monkeypatch.setattr(official_policy, "OFFICIAL_POLICY_DIR", tmp_path / "official")
    metadata = official_policy.save_official_policy("# Title\n\nBody", [], "hash")
    assert "policy_number" in metadata
    assert "signature" in metadata
    assert (tmp_path / "official" / metadata["run_id"] / "policy.pdf").exists()

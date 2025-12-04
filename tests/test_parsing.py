from gdpr_wizard import Question

import app


class FakeForm(dict):
    def get(self, key, default=""):
        return super().get(key, default)

    def getlist(self, key):
        return self.get(key, [])


def test_optional_blank_question_does_not_block_submission():
    optional_question = Question(
        id="Q-OPT",
        section="Test",
        text="Optional text",
        qtype="text",
        required=False,
    )
    answers, errors, state = app.parse_answers([optional_question], FakeForm())
    assert errors == {}
    assert answers == {}
    assert state["Q-OPT"] == ""


def test_dpo_contact_optional_when_dpo_not_appointed():
    questions = [
        Question(id="Q-GAP-001", section="A", text="Required DPO appointed?", qtype="enum", required=True, enum=["YES", "NO"]),
        Question(id="Q-GAP-027", section="A", text="DPO email", qtype="text", required=True),
    ]
    form = FakeForm({app.field_name(questions[0]): "NO", app.field_name(questions[1]): ""})
    answers, errors, _ = app.parse_answers(questions, form)
    assert "Q-GAP-027" not in errors
    assert answers["Q-GAP-001"] == "NO"


def test_dpo_contact_required_when_dpo_yes():
    questions = [
        Question(id="Q-GAP-001", section="A", text="Required DPO appointed?", qtype="enum", required=True, enum=["YES", "NO"]),
        Question(id="Q-GAP-027", section="A", text="DPO email", qtype="text", required=True),
    ]
    form = FakeForm({app.field_name(questions[0]): "YES", app.field_name(questions[1]): ""})
    _, errors, _ = app.parse_answers(questions, form)
    assert "Q-GAP-027" in errors

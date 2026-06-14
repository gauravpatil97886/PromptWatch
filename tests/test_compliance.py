from promptwatch.common import compliance as comp
from promptwatch.common.security import HIGH


def test_pii_detection():
    labels = {f["label"] for f in comp.scan("ssn 123-45-6789 email a@b.com phone (415) 555-2671")}
    assert {"US SSN", "email address", "phone number"} <= labels


def test_card_luhn():
    assert any(f["label"] == "payment card number" for f in comp.scan("4111 1111 1111 1111"))
    assert not comp.scan("4111 1111 1111 1112")  # fails Luhn → no finding


def test_aup_policies():
    keys = {v["key"] for v in comp.evaluate_policies("please SELECT * FROM prod database")}
    assert "no-prod-db-dumps" in keys


def test_model_governance():
    assert comp.check_model("claude-3-opus", deny=["claude-3-opus"])["key"] == "model-denied"
    assert comp.check_model("gpt-4", allow=["claude"])["key"] == "model-not-allowed"
    assert comp.check_model("claude-opus-4-8", allow=["claude"]) is None


def test_worst_severity():
    assert comp.worst_severity(comp.scan("ssn 123-45-6789")) == HIGH
    assert comp.worst_severity([]) == 0

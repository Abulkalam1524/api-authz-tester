import pytest

from api_authz_tester.compare import Verdict, judge, label, similarity
from api_authz_tester.http import Response

OWNER_BODY = '{"id": 1, "owner": "alice", "text": "secret note"}'
OK = Response(200, OWNER_BODY)


@pytest.mark.parametrize("status", [400, 404, 500])
def test_baseline_not_2xx_is_skipped(status):
    result = judge(Response(status, "x"), Response(200, "x"), 0.9)
    assert result.verdict is Verdict.SKIPPED
    assert result.reason == f"baseline returned {status}"


def test_baseline_network_error_is_skipped():
    result = judge(Response(None, error="timeout"), Response(200, "x"), 0.9)
    assert result.verdict is Verdict.SKIPPED
    assert "timeout" in result.reason


@pytest.mark.parametrize("status", [401, 403, 404, 301, 302])
def test_blocked_is_enforced(status):
    assert judge(OK, Response(status, ""), 0.9).verdict is Verdict.ENFORCED


def test_404_note():
    assert "404 may hide existence" in judge(OK, Response(404, ""), 0.9).reason


def test_same_data_is_bypassed():
    # Key order and whitespace do not matter for JSON.
    attacker = Response(200, '{"text": "secret note", "owner": "alice",  "id": 1}')
    result = judge(OK, attacker, 0.9)
    assert result.verdict is Verdict.BYPASSED
    assert result.similarity == 1.0


def test_different_data_is_review():
    result = judge(OK, Response(200, '{"error": "nothing for you here, sorry"}'), 0.9)
    assert result.verdict is Verdict.REVIEW
    assert result.similarity < 0.9


@pytest.mark.parametrize("status", [400, 405, 409, 422, 429])
def test_other_4xx_is_review(status):
    assert judge(OK, Response(status, ""), 0.9).verdict is Verdict.REVIEW


@pytest.mark.parametrize("attacker", [Response(500, ""), Response(503, ""), Response(None, error="reset")])
def test_5xx_or_network_error_is_error(attacker):
    assert judge(OK, attacker, 0.9).verdict is Verdict.ERROR


def test_threshold_boundary():
    score = similarity("abcdefghij", "abcdefghiX")
    assert judge(Response(200, "abcdefghij"), Response(200, "abcdefghiX"), score).verdict is Verdict.BYPASSED
    assert judge(Response(200, "abcdefghij"), Response(200, "abcdefghiX"), score + 0.01).verdict is Verdict.REVIEW


def test_similarity_rules():
    assert similarity("", "") == 1.0
    assert similarity("  hello ", "hello") == 1.0  # text is stripped
    assert similarity('{"a": 1, "b": 2}', '{"b":2,"a":1}') == 1.0
    assert similarity("abc", "xyz") == 0.0


@pytest.mark.parametrize(
    "attacker, owner, expected",
    [
        (0, 1, ("Missing authentication", "API2:2023")),
        (0, 2, ("Missing authentication", "API2:2023")),
        (1, 2, ("BFLA", "API5:2023")),
        (1, 1, ("BOLA", "API1:2023")),
        (2, 2, ("BOLA", "API1:2023")),
    ],
)
def test_labels(attacker, owner, expected):
    assert label(attacker, owner) == expected

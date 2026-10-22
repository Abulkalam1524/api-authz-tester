"""End to end: run the CLI against the fake API and check every verdict."""

import json

from api_authz_tester.cli import main
from conftest import FAKE_CONFIG

BOLA = "BOLA"
BFLA = "BFLA"
NOAUTH = "Missing authentication"

# request -> {attacker: (verdict, label)}; the owner is in its own column.
EXPECTED = {
    "GET /users/alice": ("alice", {"bob": ("ENFORCED", None), "anonymous": ("ENFORCED", None)}),
    "GET /users/bob": ("bob", {"alice": ("ENFORCED", None), "anonymous": ("ENFORCED", None)}),
    "GET /users/admin": (
        "admin",
        {
            "alice": ("ENFORCED", None),
            "bob": ("ENFORCED", None),
            "anonymous": ("ENFORCED", None),
        },
    ),
    "GET /notes/1": ("alice", {"bob": ("BYPASSED", BOLA), "anonymous": ("ENFORCED", None)}),
    "GET /notes/2": ("bob", {"alice": ("BYPASSED", BOLA), "anonymous": ("ENFORCED", None)}),
    "GET /admin/stats": (
        "admin",
        {
            "alice": ("BYPASSED", BFLA),
            "bob": ("BYPASSED", BFLA),
            "anonymous": ("ENFORCED", None),
        },
    ),
    # No auth at all: logged-in users also get admin's data, so they are BFLA too.
    "GET /debug/config": (
        "admin",
        {
            "alice": ("BYPASSED", BFLA),
            "bob": ("BYPASSED", BFLA),
            "anonymous": ("BYPASSED", NOAUTH),
        },
    ),
    # /me has no parameters, so its owner is admin; alice and bob get their own profile.
    "GET /me": (
        "admin",
        {
            "alice": ("REVIEW", None),
            "bob": ("REVIEW", None),
            "anonymous": ("ENFORCED", None),
        },
    ),
}


def run(fake_env, tmp_path, *extra):
    md, js = tmp_path / "report.md", tmp_path / "report.json"
    code = main(["run", "-c", str(FAKE_CONFIG), "-o", str(md), "--json", str(js), *extra])
    return code, md.read_text(), json.loads(js.read_text())


def test_every_fake_endpoint_gets_the_expected_verdict(fake_env, tmp_path):
    code, _, data = run(fake_env, tmp_path)
    assert code == 1

    tested = {row["request"]: row for row in data["results"] if not row["skipped_reason"]}
    assert set(tested) == set(EXPECTED)
    for request, (owner, attackers) in EXPECTED.items():
        row = tested[request]
        assert row["owner"] == owner, request
        assert row["baseline_status"] == 200, request
        got = {rep["identity"]: (rep["verdict"], rep["label"]) for rep in row["replays"]}
        assert got == attackers, request

    skipped = {row["request"]: row["skipped_reason"] for row in data["results"] if row["skipped_reason"]}
    assert skipped == {"GET /public": "public endpoint (scope.public)"}
    assert data["counts"] == {"ENFORCED": 11, "BYPASSED": 7, "REVIEW": 2, "ERROR": 0, "SKIPPED": 1}


def test_unsafe_delete_is_never_sent_by_default(fake_env, tmp_path):
    run(fake_env, tmp_path)
    assert all(method == "GET" or path == "/login" for method, path in fake_env.state.requests)
    assert ("DELETE", "/notes/1") not in fake_env.state.requests


def test_allow_unsafe_still_skips_delete_without_example_body(fake_env, tmp_path):
    _, _, data = run(fake_env, tmp_path, "--allow-unsafe")
    skipped = {row["request"]: row["skipped_reason"] for row in data["results"] if row["skipped_reason"]}
    assert skipped["DELETE /notes/{note_id}"] == "no example body"
    assert not any(method == "DELETE" for method, _ in fake_env.state.requests)


def test_expired_token_is_refreshed_not_reported_as_enforced(fake_env, tmp_path):
    # Bob's first token dies after one use; without re-login, bob's BOLA on
    # /notes/1 would look ENFORCED (401).
    run(fake_env, tmp_path)
    assert fake_env.state.login_count == {"alice": 1, "bob": 2, "admin": 1}


def test_reports_are_redacted_and_complete(fake_env, tmp_path):
    _, md, data = run(fake_env, tmp_path)
    for text in (md, json.dumps(data)):
        assert "hunter2" not in text  # db_password from /debug/config
        assert "alice-pass" not in text and "bob-pass" not in text
        assert "[REDACTED]" in text

    assert data["identities"] == [
        {"name": "alice", "privilege": 1},
        {"name": "bob", "privilege": 1},
        {"name": "admin", "privilege": 2},
        {"name": "anonymous", "privilege": 0},
    ]
    assert "| `GET /notes/1` | owner (200) | BYPASSED (200) | - | ENFORCED (401) |" in md
    assert "### 1. BOLA (API1:2023): `GET /notes/1`" in md
    assert md.count("Candidate: confirm manually before reporting.") == 7
    assert "-H 'Authorization: Bearer <bob-token>'" in md
    assert "`GET /me` as alice (owner admin): 2xx but different data" in md
    assert "- `GET /public`: public endpoint (scope.public)" in md

    finding = next(
        rep for row in data["results"] for rep in row["replays"] if rep["verdict"] == "BYPASSED"
    )
    assert finding["owasp"] == "API1:2023"
    assert finding["similarity"] == 1.0
    assert finding["curl"].startswith("curl -i -X GET http://127.0.0.1:")


def test_console_summary(fake_env, tmp_path, capsys):
    main(["run", "-c", str(FAKE_CONFIG)])
    out = capsys.readouterr().out
    assert "BYPASSED  7" in out
    assert "BYPASSED  BOLA (API1:2023)  GET /notes/1  bob got alice's data" in out
    assert "hunter2" not in out

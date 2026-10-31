"""End to end with recorded traffic (HAR + Burp XML) instead of an OpenAPI spec."""

import json

from api_authz_tester.cli import main
from conftest import FIXTURES

# request -> (owner, {attacker: (verdict, label)})
EXPECTED = {
    "GET /notes/1": ("alice", {"bob": ("BYPASSED", "BOLA"), "anonymous": ("ENFORCED", None)}),
    "GET /users/alice": ("alice", {"bob": ("ENFORCED", None), "anonymous": ("ENFORCED", None)}),
    "GET /admin/stats": (
        "admin",
        {"alice": ("BYPASSED", "BFLA"), "bob": ("BYPASSED", "BFLA"), "anonymous": ("ENFORCED", None)},
    ),
    "GET /debug/config": (
        "admin",
        {
            "alice": ("BYPASSED", "BFLA"),
            "bob": ("BYPASSED", "BFLA"),
            "anonymous": ("BYPASSED", "Missing authentication"),
        },
    ),
}
SOURCES = {
    "GET /notes/1": "alice.har #1",
    "GET /users/alice": "alice.har #2",
    "GET /admin/stats": "admin.xml #1",
    "GET /debug/config": "admin.xml #2",
}


def traffic_config(tmp_path, fake_api):
    """Copy the config and fixtures, moving the recordings from port 8000 to the test server."""
    host = fake_api.url.removeprefix("http://")
    for name in ("fake_traffic_config.yml", "alice.har", "admin.xml"):
        text = (FIXTURES / name).read_text().replace("127.0.0.1:8000", host)
        (tmp_path / name).write_text(text)
    return str(tmp_path / "fake_traffic_config.yml")


def run(tmp_path, fake_api, *extra):
    config = traffic_config(tmp_path, fake_api)
    md, js = tmp_path / "report.md", tmp_path / "report.json"
    code = main(["run", "-c", config, "-o", str(md), "--json", str(js), *extra])
    return code, md.read_text(), json.loads(js.read_text())


def test_every_recorded_request_gets_the_expected_verdict(fake_env, tmp_path):
    code, _, data = run(tmp_path, fake_env)
    assert code == 1

    tested = {row["request"]: row for row in data["results"] if not row["skipped_reason"]}
    assert set(tested) == set(EXPECTED)
    for request, (owner, attackers) in EXPECTED.items():
        row = tested[request]
        assert row["owner"] == owner, request
        assert row["baseline_status"] == 200, request
        assert row["source"] == SOURCES[request]
        got = {rep["identity"]: (rep["verdict"], rep["label"]) for rep in row["replays"]}
        assert got == attackers, request

    skipped = {row["request"]: row["skipped_reason"] for row in data["results"] if row["skipped_reason"]}
    assert skipped == {"GET /public": "public endpoint (scope.public)"}
    assert data["counts"] == {"ENFORCED": 4, "BYPASSED": 6, "REVIEW": 0, "ERROR": 0, "SKIPPED": 1}


def test_recorded_tokens_and_cookies_are_never_sent(fake_env, tmp_path):
    run(tmp_path, fake_env)
    assert fake_env.state.headers_seen  # the run did send requests
    for headers in fake_env.state.headers_seen:
        for value in headers.values():
            assert "recorded-" not in value
    # Useful recorded headers are kept.
    assert any(h.get("X-Requested-With") == "XMLHttpRequest" for h in fake_env.state.headers_seen)


def test_recorded_unsafe_request_is_not_sent_by_default(fake_env, tmp_path):
    _, md, data = run(tmp_path, fake_env)
    # The only POST /login calls are the tool's own logins: one per identity, plus bob's re-login.
    assert fake_env.state.login_count == {"alice": 1, "bob": 2, "admin": 1}
    for text in (md, json.dumps(data)):
        assert "alice-pass" not in text
        assert "recorded-" not in text


def test_allow_unsafe_sends_the_recorded_body(fake_env, tmp_path):
    _, _, data = run(tmp_path, fake_env, "--allow-unsafe")
    [row] = [row for row in data["results"] if row["request"] == "POST /login"]
    # The recorded body logs in as alice: once as the owner, once as bob, once as anonymous.
    assert row["baseline_status"] == 200
    assert fake_env.state.login_count["alice"] == 1 + 3
    # Different random tokens come back, so the data differs: REVIEW, not BYPASSED.
    assert {rep["identity"]: rep["verdict"] for rep in row["replays"]} == {
        "bob": "REVIEW",
        "anonymous": "REVIEW",
    }


def test_list_shows_recorded_requests_and_sends_nothing(fake_env, tmp_path, capsys):
    assert main(["list", "-c", traffic_config(tmp_path, fake_env)]) == 0
    out = capsys.readouterr().out
    assert "6 recorded requests in scope from 2 traffic file(s)" in out
    assert "owner: alice (alice.har #1)" in out
    assert "owner: admin (admin.xml #2)" in out
    assert "POST    /login" in out and "needs --allow-unsafe" in out
    assert "skipped: 1 duplicate, 1 other host, 1 static file" in out
    assert fake_env.state.requests == []

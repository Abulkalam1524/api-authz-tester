import json

from api_authz_tester.config import Identity, Login
from api_authz_tester.engine import Result
from api_authz_tester.report import REDACTED, curl_command, excerpt, redact


def test_redacts_auth_headers():
    headers = {
        "Authorization": "Bearer abc",
        "Cookie": "sid=1",
        "Set-Cookie": "sid=2",
        "X-API-Key": "k",
        "X-Auth-Token": "t",
        "Content-Type": "application/json",
    }
    assert redact(headers) == {
        "Authorization": REDACTED,
        "Cookie": REDACTED,
        "Set-Cookie": REDACTED,
        "X-API-Key": REDACTED,
        "X-Auth-Token": REDACTED,
        "Content-Type": "application/json",
    }


def test_redacts_nested_json_keys_case_insensitive():
    data = {
        "user": {"name": "alice", "Password": "p", "sessions": [{"AccessToken": "t", "id": 1}]},
        "clientSecret": "s",
        "apiKey": "k",
    }
    assert redact(data) == {
        "user": {"name": "alice", "Password": REDACTED, "sessions": [{"AccessToken": REDACTED, "id": 1}]},
        "clientSecret": REDACTED,
        "apiKey": REDACTED,
    }


def test_redacts_json_inside_a_string():
    body = '{"auth_token": "eyJabc", "user": "bob"}'
    assert json.loads(redact(body)) == {"auth_token": REDACTED, "user": "bob"}
    assert redact("plain text") == "plain text"
    assert redact("{not json") == "{not json"


def test_excerpt_is_redacted_then_truncated():
    body = json.dumps({"password": "hunter2", "data": "x" * 1000})
    text = excerpt(body)
    assert "hunter2" not in text
    assert len(text) == 303 and text.endswith("...")


def test_curl_uses_placeholders():
    login = Login(path="/login", token_from="token")
    alice = Identity(name="alice", privilege=1, login=login)
    keyed = Identity(name="bob", privilege=1, headers={"X-API-Key": "real-key", "X-Env": "test"})
    result = Result(
        method="PUT",
        path_template="/notes/{id}",
        path="/notes/1",
        params={"lang": "en", "api_key": "real-query-key"},
        json_body={"text": "hi", "token": "real-body-token"},
    )

    cmd = curl_command("http://127.0.0.1:5000", result, alice)
    assert "-X PUT" in cmd
    assert "'Authorization: Bearer <alice-token>'" in cmd
    assert "real-query-key" not in cmd and "real-body-token" not in cmd
    assert "lang=en" in cmd

    cmd = curl_command("http://127.0.0.1:5000", result, keyed)
    assert "'X-API-Key: <bob-x-api-key>'" in cmd
    assert "'X-Env: test'" in cmd
    assert "real-key" not in cmd


def test_curl_anonymous_head():
    anon = Identity(name="anonymous", privilege=0)
    result = Result(method="HEAD", path_template="/x", path="/x")
    assert curl_command("http://localhost", result, anon) == "curl -i -I http://localhost/x"

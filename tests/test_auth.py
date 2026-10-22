from api_authz_tester.auth import AuthManager
from api_authz_tester.config import Identity, Login
from api_authz_tester.http import HttpClient, RateLimiter


def identity(name, password, privilege=1):
    login = Login(path="/login", token_from="token", json={"username": name, "password": password})
    return Identity(name=name, privilege=privilege, login=login)


def manager(fake_api, *identities):
    return AuthManager(list(identities), HttpClient(fake_api.url, 5, RateLimiter(1000)))


def test_login_is_lazy_and_cached(fake_api):
    alice = identity("alice", "alice-pass")
    auth = manager(fake_api, alice)
    assert fake_api.state.login_count == {}  # nothing until first use

    for _ in range(3):
        assert auth.send_as(alice, "GET", "/me").status == 200
    assert fake_api.state.login_count == {"alice": 1}
    assert auth.headers_for(alice)["Authorization"].startswith("Bearer ")


def test_relogin_once_after_401(fake_api):
    # The fake API makes bob's first token expire after one use.
    bob = identity("bob", "bob-pass")
    auth = manager(fake_api, bob)

    assert auth.send_as(bob, "GET", "/me").status == 200  # uses up the first token
    assert auth.send_as(bob, "GET", "/me").status == 200  # 401 -> re-login -> retry
    assert fake_api.state.login_count == {"bob": 2}
    assert auth.send_as(bob, "GET", "/me").status == 200  # new token is cached
    assert fake_api.state.login_count == {"bob": 2}


def test_retried_result_is_recorded(fake_api):
    alice = identity("alice", "alice-pass")
    auth = manager(fake_api, alice)
    auth.headers_for(alice)
    auth._headers["alice"] = {"Authorization": "Bearer stale"}  # pretend it expired

    # The stale token gets 401; after re-login the real answer for alice is 403.
    assert auth.send_as(alice, "GET", "/users/bob").status == 403
    assert fake_api.state.login_count["alice"] == 2


def test_static_headers_never_log_in(fake_api):
    anon = Identity(name="anonymous", privilege=0)
    auth = manager(fake_api, anon)
    assert auth.send_as(anon, "GET", "/me").status == 401  # no retry: no login block
    assert fake_api.state.login_count == {}


def test_failed_login_becomes_an_error_response(fake_api):
    eve = identity("alice", "wrong-password")
    resp = manager(fake_api, eve).send_as(eve, "GET", "/me")
    assert resp.status is None
    assert "login as alice failed (status 401)" in resp.error


def test_missing_token_field(fake_api):
    alice = identity("alice", "alice-pass")
    alice.login.token_from = "data.access_token"
    resp = manager(fake_api, alice).send_as(alice, "GET", "/me")
    assert resp.status is None
    assert "no 'data.access_token'" in resp.error

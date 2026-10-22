from api_authz_tester.auth import AuthManager
from api_authz_tester.compare import Verdict
from api_authz_tester.config import Config, Identity, Scope, Target
from api_authz_tester.engine import Engine, build_path, possible_owners
from api_authz_tester.http import HttpClient, RateLimiter
from api_authz_tester.spec import Operation

ALICE = Identity(name="alice", privilege=1, owns={"user_id": "7", "lang": "en"})
BOB = Identity(name="bob", privilege=1, owns={"user_id": "8"})
ADMIN = Identity(name="admin", privilege=2)
ADMIN2 = Identity(name="admin2", privilege=2)
ANON = Identity(name="anonymous", privilege=0)


def test_owners_need_all_path_and_required_query_params():
    op = Operation("GET", "/users/{user_id}", path_params=["user_id"])
    assert possible_owners(op, [ALICE, BOB, ADMIN]) == [ALICE, BOB]
    op.query_params = ["lang"]
    assert possible_owners(op, [ALICE, BOB, ADMIN]) == [ALICE]


def test_no_params_means_highest_privilege_owner():
    op = Operation("GET", "/admin/stats")
    assert possible_owners(op, [ANON, ALICE, ADMIN, ADMIN2]) == [ADMIN]  # first one wins a tie


def test_build_path_url_encodes_values():
    assert build_path("/books/{title}", {"title": "a b/c"}) == "/books/a%20b%2Fc"


def make_engine(fake_api, identities, scope=None):
    config = Config(
        target=Target(base_url=fake_api.url, spec="unused"),
        scope=scope or Scope(),
        identities=identities,
    )
    client = HttpClient(fake_api.url, 5, RateLimiter(1000))
    return Engine(config, AuthManager(identities, client))


def test_unsafe_without_example_body_is_skipped_and_not_sent(fake_api):
    engine = make_engine(fake_api, [ALICE, ANON])
    op = Operation("DELETE", "/notes/{note_id}", path_params=["note_id"])
    [result] = engine.run([op])
    assert result.skipped_reason == "no example body"
    assert fake_api.state.requests == []


def test_no_owner_is_skipped_with_reason(fake_api):
    engine = make_engine(fake_api, [BOB, ANON])
    op = Operation("GET", "/things/{thing_id}", path_params=["thing_id"])
    [result] = engine.run([op])
    assert result.skipped_reason == "no identity owns a value for: thing_id"
    assert fake_api.state.requests == []


def test_public_endpoint_is_not_replayed(fake_api):
    engine = make_engine(fake_api, [ADMIN, ANON], Scope(public=["/public"]))
    [result] = engine.run([Operation("GET", "/public")])
    assert result.skipped_reason == "public endpoint (scope.public)"
    assert result.replays == []


def test_failed_baseline_skips_attackers_without_sending(fake_api):
    owner = Identity(name="owner", privilege=1, owns={"user_id": "nobody"})
    engine = make_engine(fake_api, [owner, ANON])
    [result] = engine.run([Operation("GET", "/users/{user_id}", path_params=["user_id"])])
    assert result.baseline_status == 401  # static-header identity, no token
    [replay] = result.replays
    assert (replay.identity, replay.verdict, replay.reason) == (
        "anonymous",
        Verdict.SKIPPED,
        "baseline returned 401",
    )
    assert len(fake_api.state.requests) == 1


def test_unsafe_with_example_body_sends_the_body(fake_api):
    engine = make_engine(fake_api, [ADMIN, ANON])
    op = Operation("POST", "/login", example_body={"username": "alice", "password": "alice-pass"})
    [result] = engine.run([op])
    assert result.baseline_status == 200
    assert fake_api.state.requests == [("POST", "/login"), ("POST", "/login")]
    assert fake_api.state.login_count == {"alice": 2}  # owner and attacker both sent it

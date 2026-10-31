from pathlib import Path

from api_authz_tester.config import load_config

EXAMPLE = Path(__file__).parent.parent / "examples" / "vampi.config.yml"


def test_vampi_example_loads(monkeypatch):
    monkeypatch.setenv("VAMPI_USER1_PASS", "dummy1")
    monkeypatch.setenv("VAMPI_USER2_PASS", "dummy2")
    monkeypatch.setenv("VAMPI_ADMIN_PASS", "dummy3")
    config = load_config(EXAMPLE)  # loading never fetches the spec URL

    assert config.target.base_url == "http://localhost:5000"
    assert config.target.spec == "http://localhost:5000/openapi.json"
    assert config.scope.methods == ["GET"]
    assert config.scope.public == ["/users/v1", "/books/v1", "/users/v1/{username}"]
    assert [(i.name, i.privilege) for i in config.identities] == [
        ("alice", 1),
        ("bob", 1),
        ("admin", 2),
        ("anonymous", 0),
    ]
    alice = config.identities[0]
    assert alice.login.json == {"username": "name1", "password": "dummy1"}
    assert alice.login.token_from == "auth_token"
    assert alice.owns == {"username": "name1", "book_title": "alice-secret-book"}

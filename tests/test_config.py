import pytest

from api_authz_tester.config import ConfigError, load_config

BASE = """
target:
  base_url: http://localhost:5000
  spec: spec.yml
  rate_limit: 5
  timeout: 10
  similarity: 0.9
identities:
  - name: alice
    privilege: 1
    headers: { X-API-Key: "${ALICE_KEY}" }
    owns: { user_id: 7 }
  - name: anonymous
    privilege: 0
"""


def write(tmp_path, text):
    path = tmp_path / "test.yml"
    path.write_text(text)
    return path


def test_loads_and_expands_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ALICE_KEY", "secret-123")
    config = load_config(write(tmp_path, BASE))
    alice = config.identities[0]
    assert alice.headers == {"X-API-Key": "secret-123"}
    assert alice.owns == {"user_id": "7"}  # numbers become strings
    assert config.target.spec == str(tmp_path / "spec.yml")  # relative to the config
    assert config.scope.include == ["*"]
    assert config.identities[1].login is None


def test_env_inside_longer_string(tmp_path, monkeypatch):
    monkeypatch.setenv("ALICE_KEY", "k")
    monkeypatch.setenv("PORT", "8080")
    text = BASE.replace("http://localhost:5000", "http://localhost:${PORT}")
    assert load_config(write(tmp_path, text)).target.base_url == "http://localhost:8080"


def test_missing_env_var_names_it(tmp_path, monkeypatch):
    monkeypatch.delenv("ALICE_KEY", raising=False)
    with pytest.raises(ConfigError, match=r"ALICE_KEY is not set") as err:
        load_config(write(tmp_path, BASE))
    assert "identities[0].headers.X-API-Key" in str(err.value)


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yml")


@pytest.mark.parametrize(
    "old, new, message",
    [
        ("http://localhost:5000", "ftp://localhost", r"target\.base_url: must be an http\(s\) URL"),
        ("similarity: 0.9", "similarity: 0", r"target\.similarity: must be above 0 and at most 1"),
        ("similarity: 0.9", "similarity: 1.5", r"target\.similarity: must be above 0 and at most 1"),
        ("rate_limit: 5", "rate_limit: 0", r"target\.rate_limit: must be above 0"),
        ("rate_limit: 5", "rate_limit: -1", r"target\.rate_limit: must be above 0"),
        ("timeout: 10", "timeout: fast", r"target\.timeout: must be a number"),
        ("name: anonymous", "name: alice", r"identities\[1\]\.name: duplicate identity name"),
        ("privilege: 0", "privilege: high", r"identities\[1\]\.privilege"),
        ("owns:", "ownz:", r"identities\[0\]\.ownz: unknown field"),
        ("  spec: spec.yml\n", "", r"target\.spec: must be a non-empty string"),
    ],
)
def test_validation_errors_name_the_field(tmp_path, monkeypatch, old, new, message):
    monkeypatch.setenv("ALICE_KEY", "k")
    assert old in BASE
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, BASE.replace(old, new)))


def test_headers_and_login_together_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("ALICE_KEY", "k")
    text = BASE.replace(
        "    owns: { user_id: 7 }",
        "    owns: { user_id: 7 }\n    login: { path: /login, token_from: token }",
    )
    with pytest.raises(ConfigError, match=r"identities\[0\]: use either headers or login"):
        load_config(write(tmp_path, text))


def test_login_defaults(tmp_path):
    text = BASE.replace(
        '    headers: { X-API-Key: "${ALICE_KEY}" }',
        "    login: { path: /login, token_from: data.token }",
    )
    login = load_config(write(tmp_path, text)).identities[0].login
    assert login.method == "POST"
    assert login.header == "Authorization"
    assert login.format == "Bearer {token}"
    assert login.token_from == "data.token"


def test_identities_must_not_be_empty(tmp_path):
    text = BASE.split("identities:")[0] + "identities: []\n"
    with pytest.raises(ConfigError, match="identities: must be a non-empty list"):
        load_config(write(tmp_path, text))

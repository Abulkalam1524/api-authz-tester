import pytest

from api_authz_tester.cli import host_allowed, main
from conftest import FAKE_CONFIG, FIXTURES


def config_with(tmp_path, base_url="${FAKE_API_URL}", include='["/*"]'):
    """A copy of the fake API config with a different base_url or include list."""
    text = FAKE_CONFIG.read_text()
    text = text.replace("base_url: ${FAKE_API_URL}", f"base_url: {base_url}")
    text = text.replace('include: ["/*"]', f"include: {include}")
    text = text.replace("spec: fake_api.yml", f"spec: {FIXTURES / 'fake_api.yml'}")
    path = tmp_path / "cli.yml"
    path.write_text(text)
    return str(path)


def test_exit_1_when_bypassed(fake_env, tmp_path):
    assert main(["run", "-c", str(FAKE_CONFIG)]) == 1


def test_exit_0_when_nothing_bypassed(fake_env, tmp_path):
    assert main(["run", "-c", config_with(tmp_path, include='["/users/*"]')]) == 0


def test_exit_2_on_config_error(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("target: {}\nidentities: []\n")
    assert main(["run", "-c", str(bad)]) == 2
    assert "target.base_url" in capsys.readouterr().err


def test_exit_2_on_missing_env_var(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("FAKE_API_URL", raising=False)
    assert main(["list", "-c", str(FAKE_CONFIG)]) == 2
    assert "FAKE_API_URL is not set" in capsys.readouterr().err


def test_exit_2_on_bad_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["run"])  # missing -c
    assert exc.value.code == 2


def test_exit_2_on_bad_rate(fake_env):
    assert main(["run", "-c", str(FAKE_CONFIG), "--rate", "0"]) == 2


def test_host_guard_refuses_non_local_host(fake_env, tmp_path, capsys):
    path = config_with(tmp_path, base_url="https://api.example.com")
    assert main(["run", "-c", path]) == 2
    assert "--i-am-authorized" in capsys.readouterr().err


def test_host_guard_allows_with_flag(fake_env, tmp_path):
    # Scope matches nothing, so the run passes the guard but sends no request.
    path = config_with(tmp_path, base_url="https://api.example.com", include='["/nothing"]')
    assert main(["run", "-c", path, "--i-am-authorized"]) == 0


def test_host_allowed():
    for url in ("http://localhost:5000", "http://127.0.0.1", "http://[::1]:8080"):
        assert host_allowed(url, authorized=False)
    assert not host_allowed("http://10.0.0.5", authorized=False)
    assert not host_allowed("http://localhost.evil.test", authorized=False)
    assert host_allowed("http://10.0.0.5", authorized=True)


def test_list_sends_no_requests(fake_env, capsys):
    assert main(["list", "-c", str(FAKE_CONFIG)]) == 0
    out = capsys.readouterr().out
    assert "GET     /notes/{note_id}" in out
    assert "owners: alice, bob" in out
    assert "DELETE  /notes/{note_id}" in out and "needs --allow-unsafe" in out
    assert "/login" not in out  # excluded by scope
    assert fake_env.state.requests == []
    assert fake_env.state.login_count == {}

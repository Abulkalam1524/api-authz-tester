"""Shared fixtures: the fake API on 127.0.0.1 and its env vars."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from fake_api import PASSWORDS, FakeState, make_server

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_CONFIG = FIXTURES / "fake_api_config.yml"


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch):
    """Make sure requests to 127.0.0.1 never go through a proxy."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@dataclass
class FakeApi:
    url: str
    state: FakeState


@pytest.fixture
def fake_api():
    server, state = make_server(0)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    yield FakeApi(url=f"http://127.0.0.1:{server.server_address[1]}", state=state)
    server.shutdown()
    server.server_close()


@pytest.fixture
def fake_env(fake_api, monkeypatch):
    """Set the env vars that tests/fixtures/fake_api_config.yml uses."""
    monkeypatch.setenv("FAKE_API_URL", fake_api.url)
    monkeypatch.setenv("FAKE_ALICE_PASS", PASSWORDS["alice"])
    monkeypatch.setenv("FAKE_BOB_PASS", PASSWORDS["bob"])
    monkeypatch.setenv("FAKE_ADMIN_PASS", PASSWORDS["admin"])
    return fake_api

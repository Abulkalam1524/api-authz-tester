import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

from api_authz_tester.http import HttpClient, RateLimiter


class FakeClock:
    """A clock that only moves when sleep() is called (or advance() in the test)."""

    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def advance(self, seconds):
        self.now += seconds


def test_first_request_does_not_wait():
    clock = FakeClock()
    RateLimiter(5, clock=clock, sleep=clock.sleep).acquire()
    assert clock.sleeps == []


def test_requests_are_spaced_by_rate():
    clock = FakeClock()
    limiter = RateLimiter(5, clock=clock, sleep=clock.sleep)
    for _ in range(4):
        limiter.acquire()
    assert clock.sleeps == pytest.approx([0.2, 0.2, 0.2])
    assert clock.now == pytest.approx(100.6)


def test_idle_time_refills_the_bucket():
    clock = FakeClock()
    limiter = RateLimiter(2, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    clock.advance(10)  # long pause: no waiting, and no burst saved up either
    limiter.acquire()
    limiter.acquire()
    assert clock.sleeps == pytest.approx([0.5])


def test_partial_wait():
    clock = FakeClock()
    limiter = RateLimiter(1, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    clock.advance(0.75)
    limiter.acquire()
    assert clock.sleeps == pytest.approx([0.25])


def test_rate_must_be_positive():
    with pytest.raises(ValueError):
        RateLimiter(0)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def test_client_does_not_follow_redirects(tmp_path):
    (tmp_path / "docs").mkdir()
    handler = functools.partial(QuietHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        client = HttpClient(f"http://127.0.0.1:{server.server_address[1]}", 5, RateLimiter(1000))
        resp = client.send("alice", "GET", "/docs")  # the server answers 301 -> /docs/
    finally:
        server.shutdown()
        server.server_close()
    assert resp.status == 301


def test_network_error_is_a_response_not_an_exception():
    # Nothing listens on port 1.
    client = HttpClient("http://127.0.0.1:1", 1, RateLimiter(1000))
    resp = client.send("alice", "GET", "/")
    assert resp.status is None
    assert "ConnectionError" in resp.error


def test_one_session_per_identity():
    client = HttpClient("http://127.0.0.1:1", 1, RateLimiter(1000))
    assert client.session("alice") is client.session("alice")
    assert client.session("alice") is not client.session("bob")

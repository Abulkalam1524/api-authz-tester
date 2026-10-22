"""A small, deliberately vulnerable API for offline tests (stdlib only).

Bugs on purpose:
- GET /notes/{note_id}: any valid token reads any note (BOLA)
- GET /admin/stats:     any valid token works, not only admin (BFLA)
- GET /debug/config:    no auth check at all (missing authentication)

Bob's first token expires after one use, so the tool's re-login-on-401
path is always exercised.

Run it by hand for a demo:  python tests/fake_api.py --port 8000
"""

from __future__ import annotations

import argparse
import json
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PASSWORDS = {"alice": "alice-pass", "bob": "bob-pass", "admin": "admin-pass"}

PROFILES = {
    "alice": {
        "username": "alice",
        "email": "alice@example.test",
        "role": "user",
        "bio": "Backend developer. Likes Go, hiking and very strong tea.",
    },
    "bob": {
        "username": "bob",
        "email": "bob@example.test",
        "role": "user",
        "bio": "Mobile QA engineer; collects vintage cameras.",
    },
    "admin": {
        "username": "admin",
        "email": "root@example.test",
        "role": "admin",
        "bio": "Platform operations team account (on-call rota 24x7).",
    },
}

NOTES = {
    "1": {"id": 1, "owner": "alice", "text": "Alice's private note: the vault code is 1234."},
    "2": {"id": 2, "owner": "bob", "text": "Bob's private note: buy a birthday gift."},
}


@dataclass
class FakeState:
    """Server-side state the tests can inspect."""

    tokens: dict[str, dict] = field(default_factory=dict)  # token -> {user, uses_left}
    login_count: dict[str, int] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)  # (method, path)
    expire_first_token_for: str = "bob"
    lock: threading.Lock = field(default_factory=threading.Lock)


class Handler(BaseHTTPRequestHandler):
    state: FakeState  # set on the subclass made by make_server

    def log_message(self, format, *args):  # keep test output quiet
        pass

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        path = urlparse(self.path).path
        with self.state.lock:
            self.state.requests.append((method, path))
        parts = path.strip("/").split("/")

        if method == "POST" and path == "/login":
            return self._login()
        if method == "GET" and path == "/public":
            return self._send(200, {"message": "Welcome to the fake API", "version": "1.0"})
        if method == "GET" and path == "/debug/config":
            # Bug: no auth check, and it leaks secrets.
            return self._send(
                200, {"debug": True, "db_host": "db.internal", "db_password": "hunter2"}
            )

        user = self._caller()
        if user is None:
            return self._send(401, {"error": "unauthorized"})

        if method == "GET" and path == "/me":
            return self._send(200, PROFILES[user])
        if method == "GET" and path == "/admin/stats":
            # Bug: should check that the caller is admin.
            return self._send(200, {"users": len(PROFILES), "notes": len(NOTES), "uptime": 99.9})
        if len(parts) == 2 and parts[0] == "users" and method == "GET":
            name = parts[1]
            if name not in PROFILES:
                return self._send(404, {"error": "not found"})
            if user != name and user != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, PROFILES[name])
        if len(parts) == 2 and parts[0] == "notes":
            note = NOTES.get(parts[1])
            if note is None:
                return self._send(404, {"error": "not found"})
            if method == "GET":
                # Bug: any logged-in user can read any note.
                return self._send(200, note)
            if method == "DELETE":
                if user != note["owner"] and user != "admin":
                    return self._send(403, {"error": "forbidden"})
                return self._send(204, None)
        return self._send(404, {"error": "not found"})

    def _login(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        name, password = body.get("username"), body.get("password")
        if PASSWORDS.get(name) != password:
            return self._send(401, {"error": "bad credentials"})

        token = secrets.token_hex(16)
        with self.state.lock:
            count = self.state.login_count.get(name, 0) + 1
            self.state.login_count[name] = count
            # The first token for this user works exactly once.
            one_use = name == self.state.expire_first_token_for and count == 1
            self.state.tokens[token] = {"user": name, "uses_left": 1 if one_use else None}
        self._send(200, {"token": token})

    def _caller(self) -> str | None:
        """The user behind the Bearer token, or None if missing/invalid/expired."""
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        with self.state.lock:
            entry = self.state.tokens.get(header[len("Bearer "):])
            if entry is None:
                return None
            if entry["uses_left"] is not None:
                if entry["uses_left"] <= 0:
                    return None
                entry["uses_left"] -= 1
            return entry["user"]

    def _send(self, status: int, payload) -> None:
        data = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_server(port: int = 0) -> tuple[ThreadingHTTPServer, FakeState]:
    """A server bound to 127.0.0.1 (port 0 = any free port). Call serve_forever()."""
    state = FakeState()
    handler = type("FakeHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    return server, state


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the fake vulnerable API.")
    parser.add_argument("--port", type=int, default=8000)
    server, _ = make_server(parser.parse_args().port)
    print(f"Fake API on http://127.0.0.1:{server.server_address[1]} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

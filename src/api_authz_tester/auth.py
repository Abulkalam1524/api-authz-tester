"""Log in as each identity, cache its auth header, and re-login once on 401."""

from __future__ import annotations

import json
from typing import Any

from .config import Identity
from .http import HttpClient, Response


class LoginError(Exception):
    """A login request failed or returned no token."""


class AuthManager:
    def __init__(self, identities: list[Identity], client: HttpClient) -> None:
        self.identities = {ident.name: ident for ident in identities}
        self.client = client
        self.login_count: dict[str, int] = {}
        self._headers: dict[str, dict[str, str]] = {}

    def headers_for(self, identity: Identity) -> dict[str, str]:
        """Return the identity's auth headers, logging in lazily on first use."""
        if identity.login is None:
            return dict(identity.headers)
        if identity.name not in self._headers:
            self._headers[identity.name] = self.login(identity)
        return self._headers[identity.name]

    def login(self, identity: Identity) -> dict[str, str]:
        """Run the login request and build the auth header from the token."""
        login = identity.login
        assert login is not None
        self.login_count[identity.name] = self.login_count.get(identity.name, 0) + 1
        resp = self.client.send(identity.name, login.method, login.path, json_body=login.json)
        if not resp.ok:
            detail = resp.error or f"status {resp.status}"
            raise LoginError(f"login as {identity.name} failed ({detail})")
        token = _find_token(resp.body, login.token_from)
        if token is None:
            raise LoginError(
                f"login as {identity.name}: no '{login.token_from}' in the login response"
            )
        return {login.header: login.format.replace("{token}", token)}

    def send_as(
        self,
        identity: Identity,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        json_body: Any = None,
    ) -> Response:
        """Send a request as an identity. A login failure becomes an error Response."""
        try:
            headers = self.headers_for(identity)
        except LoginError as exc:
            return Response(status=None, error=str(exc))

        resp = self.client.send(identity.name, method, path, headers, params, json_body)
        if resp.status == 401 and identity.login is not None:
            # The token may have expired (VAmPI tokens last about 60 s). A stale
            # token would look like ENFORCED and hide a real bug, so retry once.
            try:
                self._headers[identity.name] = headers = self.login(identity)
            except LoginError as exc:
                return Response(status=None, error=f"re-login after 401: {exc}")
            resp = self.client.send(identity.name, method, path, headers, params, json_body)
        return resp


def _find_token(body: str, token_from: str) -> str | None:
    """Read a token from a JSON body. `token_from` may be dotted, e.g. 'data.token'."""
    try:
        value: Any = json.loads(body)
    except ValueError:
        return None
    for part in token_from.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    if isinstance(value, (str, int)) and str(value):
        return str(value)
    return None

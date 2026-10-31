"""HTTP layer: one requests.Session per identity, a global rate limit, no redirects."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import requests


class RateLimiter:
    """Token bucket that allows `rate` requests per second (bucket size 1).

    The clock and sleep functions are injectable so tests never really sleep.
    """

    def __init__(
        self,
        rate: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be above 0")
        self.rate = rate
        self._clock = clock
        self._sleep = sleep
        self._tokens = 1.0
        self._last = clock()

    def acquire(self) -> None:
        """Wait until one token is available, then use it."""
        now = self._clock()
        self._tokens = min(1.0, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens < 1.0:
            wait = (1.0 - self._tokens) / self.rate
            self._sleep(wait)
            self._last = now + wait
            self._tokens = 1.0
        self._tokens -= 1.0


@dataclass
class Response:
    """What we keep from one HTTP exchange. `status` is None on a network error."""

    status: int | None
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


class HttpClient:
    def __init__(self, base_url: str, timeout: float, limiter: RateLimiter) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.limiter = limiter
        self._sessions: dict[str, requests.Session] = {}

    def session(self, identity: str) -> requests.Session:
        # Separate sessions keep each identity's cookies apart.
        if identity not in self._sessions:
            self._sessions[identity] = requests.Session()
        return self._sessions[identity]

    def send(
        self,
        identity: str,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json_body: Any = None,
        data: bytes | None = None,
    ) -> Response:
        self.limiter.acquire()
        try:
            resp = self.session(identity).request(
                method,
                self.base_url + path,
                headers=headers or {},
                params=params or None,
                json=json_body,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            return Response(status=None, error=f"{type(exc).__name__}: {exc}")
        return Response(status=resp.status_code, body=resp.text, headers=dict(resp.headers))

    def close(self) -> None:
        for session in self._sessions.values():
            session.close()

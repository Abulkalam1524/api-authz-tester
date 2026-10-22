"""Send each baseline request as its owner, replay it as other identities, collect results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .auth import AuthManager
from .compare import Verdict, baseline_problem, judge, label
from .config import Config, Identity
from .http import Response
from .spec import Operation, is_public


@dataclass
class Replay:
    """One attacker's attempt at a baseline request."""

    identity: str
    privilege: int
    verdict: Verdict
    reason: str
    status: int | None = None
    similarity: float | None = None
    label: str | None = None
    owasp: str | None = None
    body: str = ""


@dataclass
class Result:
    """One concrete request (an operation with one owner's values filled in)."""

    method: str
    path_template: str
    path: str
    params: dict[str, str] = field(default_factory=dict)
    json_body: Any = None
    owner: str | None = None
    owner_privilege: int | None = None
    baseline_status: int | None = None
    baseline_body: str = ""
    skipped_reason: str | None = None
    replays: list[Replay] = field(default_factory=list)


def possible_owners(op: Operation, identities: list[Identity]) -> list[Identity]:
    """Identities whose `owns` covers every path and required query parameter.

    An operation with no parameters is owned by the highest-privilege identity.
    """
    needed = op.path_params + op.query_params
    if not needed:
        top = max(ident.privilege for ident in identities)
        return [next(ident for ident in identities if ident.privilege == top)]
    return [ident for ident in identities if all(name in ident.owns for name in needed)]


def build_path(template: str, values: dict[str, str]) -> str:
    """Fill {param} placeholders with URL-encoded values."""
    path = template
    for name, value in values.items():
        path = path.replace("{" + name + "}", quote(value, safe=""))
    return path


class Engine:
    def __init__(self, config: Config, auth: AuthManager) -> None:
        self.config = config
        self.auth = auth

    def run(self, operations: list[Operation]) -> list[Result]:
        results: list[Result] = []
        for op in operations:
            results.extend(self.test_operation(op))
        return results

    def test_operation(self, op: Operation) -> list[Result]:
        skipped = Result(method=op.method, path_template=op.path, path=op.path)
        if is_public(op.path, self.config.scope):
            # Public means privilege 0 may read it, so every higher privilege may too.
            skipped.skipped_reason = "public endpoint (scope.public)"
            return [skipped]
        if not op.is_safe and op.example_body is None:
            skipped.skipped_reason = "no example body"
            return [skipped]
        owners = possible_owners(op, self.config.identities)
        if not owners:
            missing = ", ".join(op.path_params + op.query_params)
            skipped.skipped_reason = f"no identity owns a value for: {missing}"
            return [skipped]
        return [self.test_as_owner(op, owner) for owner in owners]

    def test_as_owner(self, op: Operation, owner: Identity) -> Result:
        result = Result(
            method=op.method,
            path_template=op.path,
            path=build_path(op.path, {p: owner.owns[p] for p in op.path_params}),
            params={q: owner.owns[q] for q in op.query_params},
            json_body=op.example_body,
            owner=owner.name,
            owner_privilege=owner.privilege,
        )
        baseline = self._send(owner, result)
        result.baseline_status = baseline.status
        result.baseline_body = baseline.body

        threshold = self.config.target.similarity
        problem = baseline_problem(baseline)
        for attacker in self.config.identities:
            if attacker.name == owner.name or attacker.privilege > owner.privilege:
                continue  # higher privilege reading lower data is expected
            if problem:
                # Nothing to compare against, so the attacker request is not sent.
                result.replays.append(
                    Replay(attacker.name, attacker.privilege, Verdict.SKIPPED, problem)
                )
                continue
            resp = self._send(attacker, result)
            verdict = judge(baseline, resp, threshold)
            replay = Replay(
                identity=attacker.name,
                privilege=attacker.privilege,
                verdict=verdict.verdict,
                reason=verdict.reason,
                status=resp.status,
                similarity=verdict.similarity,
                body=resp.body,
            )
            if verdict.verdict is Verdict.BYPASSED:
                replay.label, replay.owasp = label(attacker.privilege, owner.privilege)
            result.replays.append(replay)
        return result

    def _send(self, identity: Identity, result: Result) -> Response:
        return self.auth.send_as(
            identity, result.method, result.path, params=result.params, json_body=result.json_body
        )

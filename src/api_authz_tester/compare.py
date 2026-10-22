"""Compare an attacker response with the owner's baseline and give a verdict."""

from __future__ import annotations

import json
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum

from .http import Response


class Verdict(str, Enum):
    ENFORCED = "ENFORCED"
    BYPASSED = "BYPASSED"
    REVIEW = "REVIEW"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class Judgement:
    verdict: Verdict
    reason: str = ""
    similarity: float | None = None


def normalise(body: str) -> str:
    """Canonical JSON (sorted keys) if the body is JSON, else the stripped text."""
    try:
        return json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
    except ValueError:
        return body.strip()


def similarity(a: str, b: str) -> float:
    """0.0 (nothing alike) to 1.0 (identical) after normalising both bodies."""
    a, b = normalise(a), normalise(b)
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def baseline_problem(baseline: Response) -> str | None:
    """Why a baseline cannot be used for comparison, or None if it is a 2xx."""
    if baseline.status is None:
        return f"baseline failed: {baseline.error}"
    if not baseline.ok:
        return f"baseline returned {baseline.status}"
    return None


def judge(baseline: Response, attacker: Response, threshold: float) -> Judgement:
    """Apply the verdict table from the session 1 brief."""
    problem = baseline_problem(baseline)
    if problem:
        return Judgement(Verdict.SKIPPED, problem)

    status = attacker.status
    if status is None:
        return Judgement(Verdict.ERROR, f"no response: {attacker.error}")
    if status in (401, 403) or 300 <= status < 400:
        return Judgement(Verdict.ENFORCED, f"attacker got {status}")
    if status == 404:
        return Judgement(Verdict.ENFORCED, "attacker got 404 (404 may hide existence)")
    if 200 <= status < 300:
        score = similarity(baseline.body, attacker.body)
        if score >= threshold:
            return Judgement(Verdict.BYPASSED, f"same data as owner ({score:.2f})", score)
        return Judgement(
            Verdict.REVIEW, f"2xx but different data ({score:.2f} < {threshold})", score
        )
    if status >= 500:
        return Judgement(Verdict.ERROR, f"attacker got {status}")
    # Other 4xx (400, 405, 422, ...) and anything unusual: a human should look.
    return Judgement(Verdict.REVIEW, f"attacker got {status}")


def label(attacker_privilege: int, owner_privilege: int) -> tuple[str, str]:
    """Name the flaw behind a BYPASSED result: (label, OWASP id)."""
    if attacker_privilege == 0:
        return "Missing authentication", "API2:2023"
    if attacker_privilege < owner_privilege:
        return "BFLA", "API5:2023"
    return "BOLA", "API1:2023"

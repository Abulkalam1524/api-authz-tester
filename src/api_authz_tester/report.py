"""Markdown and JSON reports, console summary, and secret redaction."""

from __future__ import annotations

import json
import re
import shlex
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote_plus, urlencode

from . import __version__
from .compare import Verdict
from .config import Config, Identity
from .engine import Replay, Result

REDACTED = "[REDACTED]"
SENSITIVE_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}
SENSITIVE_PARTS = ("token", "key", "secret", "password")
EXCERPT_LIMIT = 300
# name=value&name=value, as in query strings and form bodies
FORM_PATTERN = re.compile(r"[^=&\s]+=[^&\s]*(&[^=&\s]+=[^&\s]*)*")


def is_sensitive(name: str) -> bool:
    lower = name.lower()
    return lower in SENSITIVE_NAMES or any(part in lower for part in SENSITIVE_PARTS)


def redact(value: Any) -> Any:
    """Hide secret values in headers, JSON data, a JSON string or form data.

    Dict keys that look secret (see is_sensitive) get their value replaced,
    at any depth. Strings that hold JSON are parsed, redacted and re-dumped.
    Form-encoded strings (a=1&password=x) get the secret values replaced.
    Other strings are returned unchanged.
    """
    if isinstance(value, dict):
        return {k: REDACTED if is_sensitive(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str) and value.lstrip()[:1] in ("{", "["):
        try:
            return json.dumps(redact(json.loads(value)))
        except ValueError:
            return value
    if isinstance(value, str) and FORM_PATTERN.fullmatch(value):
        return _redact_form(value)
    return value


def _redact_form(text: str) -> str:
    pairs = []
    for pair in text.split("&"):
        name, _, _ = pair.partition("=")
        pairs.append(f"{name}={REDACTED}" if is_sensitive(unquote_plus(name)) else pair)
    return "&".join(pairs)


def excerpt(body: str) -> str:
    """A redacted body, cut to EXCERPT_LIMIT characters."""
    text = redact(body)
    if len(text) > EXCERPT_LIMIT:
        return text[:EXCERPT_LIMIT] + "..."
    return text


def display_path(result: Result) -> str:
    """The concrete path with its query string, secrets redacted."""
    path, _, query = result.path.partition("?")  # recorded requests keep their query here
    if query:
        path += "?" + redact(query)
    if result.params:
        path += ("&" if query else "?") + urlencode(redact(result.params))
    return path


def curl_command(base_url: str, result: Result, identity: Identity) -> str:
    """A curl command that repeats the request, with secrets as <name-...> placeholders."""
    url = base_url + display_path(result)
    parts = ["curl", "-i"]
    parts += ["-I"] if result.method == "HEAD" else ["-X", result.method]
    parts.append(shlex.quote(url))
    if identity.login is not None:
        value = identity.login.format.replace("{token}", f"<{identity.name}-token>")
        parts += ["-H", shlex.quote(f"{identity.login.header}: {value}")]
    for name, value in identity.headers.items():
        if is_sensitive(name):
            value = f"<{identity.name}-{name.lower()}>"
        parts += ["-H", shlex.quote(f"{name}: {value}")]
    for name, value in result.headers.items():  # kept from recorded traffic
        if is_sensitive(name):
            value = f"<{name.lower()}>"
        parts += ["-H", shlex.quote(f"{name}: {value}")]
    if result.json_body is not None:
        parts += ["-H", shlex.quote("Content-Type: application/json")]
        parts += ["--data", shlex.quote(json.dumps(redact(result.json_body)))]
    if result.raw_body is not None:
        text = result.raw_body.decode("utf-8", errors="replace")
        parts += ["--data-binary", shlex.quote(redact(text))]
    return " ".join(parts)


def count_verdicts(results: list[Result]) -> dict[str, int]:
    counts = {v.value: 0 for v in Verdict}
    for result in results:
        if result.skipped_reason:
            counts[Verdict.SKIPPED.value] += 1
        for replay in result.replays:
            counts[replay.verdict.value] += 1
    return counts


def build_report(
    results: list[Result], config: Config, generated_at: datetime | None = None
) -> dict[str, Any]:
    """Collect everything both report formats show into one plain dict."""
    generated_at = generated_at or datetime.now(timezone.utc)
    identities = {ident.name: ident for ident in config.identities}
    rows = []
    for result in results:
        row = {
            "request": f"{result.method} {display_path(result)}",
            "method": result.method,
            "path_template": result.path_template,
            "path": display_path(result),
            "owner": result.owner,
            "owner_privilege": result.owner_privilege,
            "source": result.source,
            "baseline_status": result.baseline_status,
            "baseline_excerpt": excerpt(result.baseline_body),
            "skipped_reason": result.skipped_reason,
            "replays": [],
        }
        for replay in result.replays:
            item = _replay_dict(replay)
            if replay.verdict is Verdict.BYPASSED:
                item["curl"] = curl_command(
                    config.target.base_url, result, identities[replay.identity]
                )
            row["replays"].append(item)
        rows.append(row)

    return {
        "tool": {"name": "api-authz-tester", "version": __version__},
        "target": config.target.base_url,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "similarity_threshold": config.target.similarity,
        "identities": [{"name": i.name, "privilege": i.privilege} for i in config.identities],
        "counts": count_verdicts(results),
        "results": rows,
    }


def _replay_dict(replay: Replay) -> dict[str, Any]:
    return {
        "identity": replay.identity,
        "privilege": replay.privilege,
        "verdict": replay.verdict.value,
        "reason": replay.reason,
        "status": replay.status,
        "similarity": None if replay.similarity is None else round(replay.similarity, 3),
        "label": replay.label,
        "owasp": replay.owasp,
        "excerpt": excerpt(replay.body),
    }


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2) + "\n"


def render_markdown(data: dict[str, Any]) -> str:
    names = [i["name"] for i in data["identities"]]
    lines = [
        "# Authorization test report",
        "",
        f"- **Target:** {data['target']}",
        f"- **Date:** {data['generated_at']} (UTC)",
        f"- **Tool:** {data['tool']['name']} {data['tool']['version']}",
        "- **Identities:** "
        + ", ".join(f"{i['name']} (privilege {i['privilege']})" for i in data["identities"]),
        f"- **Similarity threshold:** {data['similarity_threshold']}",
        "",
        "| Verdict | Count |",
        "|---|---|",
    ]
    lines += [f"| {verdict} | {count} |" for verdict, count in data["counts"].items()]

    lines += ["", "## Matrix", "", "| Request | " + " | ".join(names) + " |"]
    lines.append("|---" * (len(names) + 1) + "|")
    for row in data["results"]:
        if row["skipped_reason"]:
            continue  # nothing was sent; listed under Skipped
        cells = {name: "-" for name in names}
        cells[row["owner"]] = f"owner ({_status(row['baseline_status'])})"
        for rep in row["replays"]:
            cells[rep["identity"]] = f"{rep['verdict']} ({_status(rep['status'])})"
        lines.append(
            f"| `{_cell(row['request'])}` | " + " | ".join(cells[n] for n in names) + " |"
        )

    findings = [(row, rep) for row, rep in _replays(data) if rep["verdict"] == "BYPASSED"]
    lines += ["", "## Findings"]
    if not findings:
        lines += ["", "No BYPASSED results."]
    for number, (row, rep) in enumerate(findings, start=1):
        lines += [
            "",
            f"### {number}. {rep['label']} ({rep['owasp']}): `{row['request']}`",
            "",
            f"- **Endpoint:** `{row['method']} {row['path_template']}`",
            f"- **Source:** {row['source']}",
            f"- **Owner:** {row['owner']} (privilege {row['owner_privilege']}), "
            f"status {_status(row['baseline_status'])}",
            f"- **Attacker:** {rep['identity']} (privilege {rep['privilege']}), "
            f"status {_status(rep['status'])}",
            f"- **Similarity:** {rep['similarity']:.2f}",
            f"- **Attacker response (excerpt):** `{_inline(rep['excerpt'])}`",
            "",
            "```",
            rep["curl"],
            "```",
            "",
            "Candidate: confirm manually before reporting.",
        ]

    for title, verdict in (("Review", "REVIEW"), ("Errors", "ERROR"), ("Skipped", "SKIPPED")):
        lines += ["", f"## {title}", ""]
        items = [
            f"- `{row['request']}` as {rep['identity']} (owner {row['owner']}): {rep['reason']}"
            for row, rep in _replays(data)
            if rep["verdict"] == verdict
        ]
        if verdict == "SKIPPED":
            items = [
                f"- `{row['method']} {row['path_template']}`: {row['skipped_reason']}"
                for row in data["results"]
                if row["skipped_reason"]
            ] + items
        lines += items or ["None."]
    return "\n".join(lines).rstrip() + "\n"


def console_summary(data: dict[str, Any]) -> list[str]:
    """Short lines for the terminal: one per verdict, then one per finding.

    Built from the report data, which is already redacted.
    """
    lines = [f"{verdict:<9} {count}" for verdict, count in data["counts"].items()]
    for row, rep in _replays(data):
        if rep["verdict"] == "BYPASSED":
            lines.append(
                f"BYPASSED  {rep['label']} ({rep['owasp']})  {row['request']}  "
                f"{rep['identity']} got {row['owner']}'s data"
            )
    return lines


def _replays(data: dict[str, Any]):
    for row in data["results"]:
        for rep in row["replays"]:
            yield row, rep


def _status(status: int | None) -> str:
    return "no response" if status is None else str(status)


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _inline(text: str) -> str:
    # Keep the excerpt on one line and inside one code span.
    return " ".join(text.split()).replace("`", "'")

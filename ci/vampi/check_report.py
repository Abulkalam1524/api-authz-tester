"""Compare an api-authz-tester JSON report with a file of expected verdicts.

Usage: python ci/vampi/check_report.py report.json ci/vampi/expected-vulnerable.json
Exit 0 when every verdict matches, 1 when anything is different, missing or extra.
"""

from __future__ import annotations

import json
import sys

# (request, identity) -> (verdict, label)
Cells = dict[tuple[str, str], tuple[str, str | None]]


def report_cells(report: dict) -> tuple[Cells, set[str]]:
    """The attacker cells and the skipped operations in a tool report."""
    cells: Cells = {}
    skipped = set()
    for row in report["results"]:
        if row["skipped_reason"]:
            skipped.add(row["request"])
        for rep in row["replays"]:
            cells[(row["request"], rep["identity"])] = (rep["verdict"], rep["label"])
    return cells, skipped


def expected_cells(expected: dict) -> tuple[Cells, set[str]]:
    """The same two things, read from an expected-verdicts file."""
    cells: Cells = {
        (c["request"], c["identity"]): (c["verdict"], c.get("label")) for c in expected["cells"]
    }
    return cells, set(expected["skipped"])


def compare(report: dict, expected: dict) -> list[str]:
    """Return one line per difference. An empty list means everything matches."""
    got, got_skipped = report_cells(report)
    want, want_skipped = expected_cells(expected)
    problems = []
    for key in sorted(set(got) | set(want)):
        request, identity = key
        if key not in got:
            problems.append(f"missing:   {request} as {identity} (expected {_show(want[key])})")
        elif key not in want:
            problems.append(f"extra:     {request} as {identity} (got {_show(got[key])})")
        elif got[key] != want[key]:
            problems.append(
                f"different: {request} as {identity}: expected {_show(want[key])}, got {_show(got[key])}"
            )
    for request in sorted(want_skipped - got_skipped):
        problems.append(f"missing:   {request} should be SKIPPED")
    for request in sorted(got_skipped - want_skipped):
        problems.append(f"extra:     {request} was SKIPPED")
    return problems


def _show(cell: tuple[str, str | None]) -> str:
    verdict, label = cell
    return f"{verdict} ({label})" if label else verdict


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print("usage: check_report.py REPORT_JSON EXPECTED_JSON", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        report = json.load(f)
    with open(argv[1], encoding="utf-8") as f:
        expected = json.load(f)

    problems = compare(report, expected)
    if problems:
        print(f"{len(problems)} difference(s) from {argv[1]}:")
        for line in problems:
            print("  " + line)
        return 1
    total = len(expected["cells"]) + len(expected["skipped"])
    print(f"all {total} expected results match {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

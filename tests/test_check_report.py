"""Offline tests for ci/vampi/check_report.py (the VAmPI CI checker)."""

import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "ci" / "vampi" / "check_report.py"
spec = importlib.util.spec_from_file_location("check_report", SCRIPT)
check_report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_report)


def make_report():
    """A tiny report in the tool's JSON format: one tested request, one skipped."""
    return {
        "results": [
            {
                "request": "GET /books/v1/alice-secret-book",
                "skipped_reason": None,
                "replays": [
                    {"identity": "bob", "verdict": "BYPASSED", "label": "BOLA"},
                    {"identity": "anonymous", "verdict": "ENFORCED", "label": None},
                ],
            },
            {"request": "GET /books/v1", "skipped_reason": "public endpoint (scope.public)", "replays": []},
        ]
    }


def make_expected():
    return {
        "cells": [
            {"request": "GET /books/v1/alice-secret-book", "identity": "bob", "verdict": "BYPASSED", "label": "BOLA"},
            {"request": "GET /books/v1/alice-secret-book", "identity": "anonymous", "verdict": "ENFORCED"},
        ],
        "skipped": ["GET /books/v1"],
    }


def test_everything_matches():
    assert check_report.compare(make_report(), make_expected()) == []


def test_different_verdict():
    report = make_report()
    report["results"][0]["replays"][0].update(verdict="ENFORCED", label=None)
    assert check_report.compare(report, make_expected()) == [
        "different: GET /books/v1/alice-secret-book as bob: expected BYPASSED (BOLA), got ENFORCED"
    ]


def test_different_label():
    report = make_report()
    report["results"][0]["replays"][0]["label"] = "BFLA"
    [problem] = check_report.compare(report, make_expected())
    assert "expected BYPASSED (BOLA), got BYPASSED (BFLA)" in problem


def test_missing_and_extra_cells():
    report = make_report()
    report["results"][0]["replays"][1]["identity"] = "eve"
    assert check_report.compare(report, make_expected()) == [
        "missing:   GET /books/v1/alice-secret-book as anonymous (expected ENFORCED)",
        "extra:     GET /books/v1/alice-secret-book as eve (got ENFORCED)",
    ]


def test_skipped_lists_must_match():
    report = make_report()
    report["results"][1]["request"] = "GET /users/v1"
    assert check_report.compare(report, make_expected()) == [
        "missing:   GET /books/v1 should be SKIPPED",
        "extra:     GET /users/v1 was SKIPPED",
    ]


def test_main_exit_codes(tmp_path, capsys):
    report_path, expected_path = tmp_path / "report.json", tmp_path / "expected.json"
    report_path.write_text(json.dumps(make_report()))
    expected_path.write_text(json.dumps(make_expected()))
    assert check_report.main([str(report_path), str(expected_path)]) == 0
    assert "all 3 expected results match" in capsys.readouterr().out

    broken = make_report()
    broken["results"][0]["replays"].pop()
    report_path.write_text(json.dumps(broken))
    assert check_report.main([str(report_path), str(expected_path)]) == 1
    assert "1 difference(s)" in capsys.readouterr().out

    assert check_report.main([str(report_path)]) == 2


def test_expected_files_are_valid():
    # The real expected files must at least load and use known verdicts.
    for name in ("expected-vulnerable.json", "expected-secure.json"):
        data = json.loads((SCRIPT.parent / name).read_text())
        assert data["cells"] and data["skipped"]
        for cell in data["cells"]:
            assert cell["verdict"] in {"ENFORCED", "BYPASSED", "REVIEW", "ERROR", "SKIPPED"}

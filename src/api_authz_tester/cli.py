"""Command-line entry point: `api-authz-tester list` and `api-authz-tester run`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .auth import AuthManager
from .config import Config, ConfigError, load_config
from .engine import Engine, possible_owners
from .http import HttpClient, RateLimiter
from .report import build_report, console_summary, render_json, render_markdown
from .spec import Operation, SpecError, in_scope, load_spec, select_operations
from .traffic import TrafficError, load_traffic

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

EXIT_OK = 0
EXIT_BYPASSED = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api-authz-tester",
        description="Replay REST API requests as several identities to find broken authorization.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    list_cmd = sub.add_parser("list", help="show in-scope operations and their owners")
    list_cmd.add_argument("-c", "--config", required=True, help="path to the YAML config")

    run_cmd = sub.add_parser("run", help="run the tests and write reports")
    run_cmd.add_argument("-c", "--config", required=True, help="path to the YAML config")
    run_cmd.add_argument("-o", "--output", help="write a Markdown report to this file")
    run_cmd.add_argument("--json", help="write a JSON report to this file")
    run_cmd.add_argument(
        "--allow-unsafe", action="store_true", help="also send POST/PUT/PATCH/DELETE"
    )
    run_cmd.add_argument("--rate", type=float, help="max requests per second (overrides config)")
    run_cmd.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you are allowed to test a host that is not localhost",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "list":
            return cmd_list(config)
        return cmd_run(config, args)
    except (ConfigError, SpecError, TrafficError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def cmd_list(config: Config) -> int:
    """Print operations, recorded requests and their owners. Sends no API requests."""
    unsafe = "  [unsafe: needs --allow-unsafe]"
    if config.target.spec:
        operations = in_scope(spec_operations(config), config.scope)
        print(f"{len(operations)} operations in scope for {config.target.base_url}")
        for op in operations:
            owners = ", ".join(i.name for i in possible_owners(op, config.identities)) or "none"
            note = "" if op.is_safe else unsafe
            print(f"  {op.method:<7} {op.path:<40} owners: {owners}{note}")
    if config.traffic:
        recorded, skipped = load_traffic(config)
        print(f"{len(recorded)} recorded requests in scope from {len(config.traffic)} traffic file(s)")
        for rec in recorded:
            note = "" if rec.is_safe else unsafe
            print(f"  {rec.method:<7} {rec.full_path:<40} owner: {rec.owner} ({rec.source}){note}")
        if skipped:
            print("  skipped: " + ", ".join(f"{n} {why}" for why, n in sorted(skipped.items())))
    return EXIT_OK


def spec_operations(config: Config) -> list[Operation]:
    if not config.target.spec:
        return []
    return load_spec(config.target.spec, config.target.timeout)


def cmd_run(config: Config, args: argparse.Namespace) -> int:
    if args.rate is not None:
        if args.rate <= 0:
            raise ConfigError("--rate: must be above 0")
        config.target.rate_limit = args.rate

    if not host_allowed(config.target.base_url, args.i_am_authorized):
        host = urlparse(config.target.base_url).hostname
        print(
            f"error: refusing to test {host}: it is not localhost. Only test systems you "
            "are allowed to test, then pass --i-am-authorized.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    operations = select_operations(spec_operations(config), config.scope, args.allow_unsafe)
    recorded = []
    if config.traffic:
        recorded, _ = load_traffic(config)
        recorded = [rec for rec in recorded if rec.is_safe or args.allow_unsafe]
    client = HttpClient(
        config.target.base_url, config.target.timeout, RateLimiter(config.target.rate_limit)
    )
    try:
        results = Engine(config, AuthManager(config.identities, client)).run(operations, recorded)
    finally:
        client.close()

    data = build_report(results, config)
    if args.output:
        _write(args.output, render_markdown(data))
    if args.json:
        _write(args.json, render_json(data))
    for line in console_summary(data):
        print(line)
    return EXIT_BYPASSED if data["counts"]["BYPASSED"] else EXIT_OK


def host_allowed(base_url: str, authorized: bool) -> bool:
    """Local targets are always allowed; anything else needs --i-am-authorized."""
    return authorized or urlparse(base_url).hostname in LOCAL_HOSTS


def _write(path: str, text: str) -> None:
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot write report {path}: {exc}") from None


if __name__ == "__main__":
    sys.exit(main())

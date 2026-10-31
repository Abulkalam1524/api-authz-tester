"""Prepare a running VAmPI for a test run.

Waits until VAmPI answers, checks its mode, resets the database with
/createdb, and gives alice (name1) and bob (name2) one book each with a known
title, so the tool has objects that belong to each user.

Usage: python ci/vampi/setup_vampi.py http://localhost:5000 --expect-vulnerable 1
Passwords come from VAMPI_USER1_PASS and VAMPI_USER2_PASS.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import requests

# (VAmPI username, env var with its password, book title used in the config)
BOOKS = [
    ("name1", "VAMPI_USER1_PASS", "alice-secret-book"),
    ("name2", "VAMPI_USER2_PASS", "bob-secret-book"),
]


def wait_until_up(base_url: str, timeout: float = 60) -> dict:
    """Return VAmPI's home page JSON once it answers, or exit after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.get(base_url + "/", timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            pass
        time.sleep(1)
    sys.exit(f"VAmPI did not answer at {base_url} within {timeout:.0f} s")


def login(base_url: str, username: str, password: str) -> str:
    resp = requests.post(
        base_url + "/users/v1/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    # VAmPI answers 200 even when the login fails, so look for the token.
    token = resp.json().get("auth_token")
    if not token:
        sys.exit(f"login as {username} failed: {resp.text}")
    return token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare VAmPI for api-authz-tester.")
    parser.add_argument("base_url", help="for example http://localhost:5000")
    parser.add_argument("--expect-vulnerable", choices=["0", "1"], help="fail if VAmPI runs in the other mode")
    args = parser.parse_args(argv)
    base_url = args.base_url.rstrip("/")

    home = wait_until_up(base_url)
    mode = str(home.get("vulnerable"))
    print(f"VAmPI is up at {base_url} (vulnerable={mode})")
    if args.expect_vulnerable is not None and mode != args.expect_vulnerable:
        sys.exit(f"expected vulnerable={args.expect_vulnerable}, but VAmPI runs with vulnerable={mode}")

    requests.get(base_url + "/createdb", timeout=10).raise_for_status()
    print("database reset with /createdb")

    for username, env_var, title in BOOKS:
        password = os.environ.get(env_var)
        if not password:
            sys.exit(f"environment variable {env_var} is not set")
        token = login(base_url, username, password)
        resp = requests.post(
            base_url + "/books/v1",
            json={"book_title": title, "secret": f"secret of {username}"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code != 200:
            sys.exit(f"could not add book {title!r} for {username}: {resp.status_code} {resp.text}")
        print(f"added book {title!r} for {username}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

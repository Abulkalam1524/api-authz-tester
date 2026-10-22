# Session 2 brief: CI against VAmPI

Read `CLAUDE.md` first. Its rules apply to everything below.

## Goal

Prove the tool works on a real application, not only on our fake API. Run it
in GitHub Actions against [VAmPI](https://github.com/erev0s/VAmPI), a
deliberately vulnerable API, in **two modes**:

- `vulnerable=1`: the tool must **find** the real authorization bugs.
- `vulnerable=0` (secure mode): the same checks must come back `ENFORCED`.
  This shows the tool does not raise false alarms.

Every verdict is checked against a table of expected results, so CI fails if
the tool's behaviour changes.

## Done when

1. A new workflow `.github/workflows/vampi.yml` runs on every push and pull
   request (and by hand with `workflow_dispatch`). It is green.
2. It runs VAmPI in both modes and the tool's JSON report matches the expected
   verdicts exactly in both.
3. In the vulnerable run, tokens expire **during** the run, and the bugs are
   still found (this proves re-login on 401 works on a real app).
4. `pytest -q` still passes offline, with new unit tests for the checker script.
5. README "Status", "Usage" and "Roadmap" are updated, with a new "Results on
   VAmPI" section showing the real table from CI, including false positives
   and limitations.
6. One PR from branch `session-2-vampi-ci`, plain-English description, no AI
   attribution.

## Out of scope (do NOT build)

- Burp XML / HAR import (session 3)
- crAPI (the owner tests it by hand)
- Unsafe methods on VAmPI (`--allow-unsafe`). VAmPI's password-change bug is a
  `PUT`; testing it needs example bodies and changes data. Note it as "next".
- Non-authorization bugs in VAmPI (SQL injection, ReDoS, JWT weak key, user
  enumeration, mass assignment)
- New tool features. Only fix a tool bug if running against VAmPI shows one.

## Facts about VAmPI (checked in its source, commit `f16052d`, April 2026)

- Image: `erev0s/vampi` on Docker Hub, port 5000. Settings by env var:
  `vulnerable` (1 or 0) and `tokentimetolive` (seconds, default 60).
- `GET /createdb` fills the database with 3 users: `name1` / `pass1`,
  `name2` / `pass2`, and `admin` / `pass1` (admin). These are public demo
  values from VAmPI's own source, not secrets.
- `POST /users/v1/login` with `{"username", "password"}` returns
  `{"auth_token": ...}`. **A failed login also returns 200**, with an error
  message and no token.
- `POST /books/v1` with `{"book_title", "secret"}` (Bearer token) adds a book
  for that user. Each user also gets a book with a **random** title at
  `/createdb`, so do not use those.
- `GET /books/v1/{book_title}`: needs a token. In vulnerable mode **any** user
  can read any book (BOLA). In secure mode another user's book gives 404.
- `GET /users/v1/_debug`: no auth at all, returns every user **with
  password**. VAmPI says this stays vulnerable even in secure mode.
- `GET /users/v1`, `GET /books/v1` and `GET /users/v1/{username}` need no
  token and are public by design.
- `GET /me`: needs a token, returns the caller's own profile.

## Files to add

```
.github/workflows/vampi.yml       the workflow
ci/vampi/vampi-ci.yml             tool config for CI (not *.config.yml: that is gitignored)
ci/vampi/setup_vampi.py           waits for VAmPI, runs /createdb, creates one book per user
ci/vampi/check_report.py          compares report.json with an expected-verdicts file
ci/vampi/expected-vulnerable.json expected verdicts for vulnerable=1
ci/vampi/expected-secure.json     expected verdicts for vulnerable=0
tests/test_check_report.py        offline unit tests for check_report.py
docs/vampi-results.md             the real result tables and a column for manual confirmation
```

Scripts use the stdlib (and `requests`, already a dependency). No new
dependencies.

## CI config (ci/vampi/vampi-ci.yml)

- `base_url: http://localhost:5000`
- `spec`: the spec **served by the running container** at `/openapi.json`
  (checked: it works), so the spec always matches the image.
- Identities: alice (`name1`, privilege 1, owns `username: name1`,
  `book_title: alice-secret-book`), bob (`name2`, privilege 1, owns
  `username: name2`, `book_title: bob-secret-book`), admin (privilege 2, owns
  `username: admin`), anonymous (privilege 0). Passwords use `${VAR}`.
- Scope: `include: ["/users/v1*", "/books/v1*", "/me"]`, `exclude:
  ["/createdb"]`, `methods: [GET]`.
- **Decision:** `public: ["/users/v1", "/books/v1", "/users/v1/{username}"]`.
  These answer anyone on purpose. Without this, the tool reports about 7
  BYPASSED results that are not real bugs. The README must say this openly.
  (`/users/v1/_debug` is not matched by these patterns, so it is still tested.)

Also update `examples/vampi.config.yml` to match what was learned (the public
list and `/me`), so the example works for a user running VAmPI by hand.

## Workflow (.github/workflows/vampi.yml)

1. Two jobs, or one job with a matrix: `mode: vulnerable` and `mode: secure`.
2. Start VAmPI as a service container. **Pin the image by digest**
   (`erev0s/vampi@sha256:...`) and write the date it was pinned in a comment.
   - vulnerable: `vulnerable=1`, `tokentimetolive=5`
   - secure: `vulnerable=0`, `tokentimetolive=3600`
3. `pip install -e .`, then run `python ci/vampi/setup_vampi.py`.
4. Run the tool. Vulnerable mode uses `--rate 1`, so the run lasts longer than
   5 seconds and tokens expire during it:
   `api-authz-tester run -c ci/vampi/vampi-ci.yml -o report.md --json report.json --rate 1`
   (Checked locally: the run took 23 s, the tool logged in again 3 times, and
   the verdicts were the same as with 60 s tokens.)
5. Check the exit code: it must be **1** in both modes (`/users/v1/_debug` is
   BYPASSED even in secure mode). Any other code fails the job.
6. Run `python ci/vampi/check_report.py report.json ci/vampi/expected-<mode>.json`.
7. Upload `report.md` and `report.json` as build artifacts (they hold only
   VAmPI demo data, and secrets are redacted).

**Decision:** the 3 VAmPI demo passwords are set in the workflow's `env:`
with a comment saying they are VAmPI's public defaults. They are not secrets,
and this avoids setting up GitHub Secrets. The config still reads them with
`${VAR}`, so the "no secrets in the repo" pattern is kept.

## Checker (ci/vampi/check_report.py)

- Input: the tool's JSON report and an expected file.
- Expected file format: one entry per cell, for example
  `{"request": "GET /books/v1/alice-secret-book", "identity": "bob",
  "verdict": "BYPASSED", "label": "BOLA"}`, plus the expected `SKIPPED`
  operations.
- Fails (exit 1) if any cell is different, missing or extra. Prints a short
  table of the differences. Exit 0 when everything matches.
- Tests in `tests/test_check_report.py` use small JSON samples only (no
  network): match, different verdict, missing cell, extra cell.

## Expected verdicts

First predicted from VAmPI's source, then **confirmed by a local run** of
VAmPI (from source at commit `f16052d`, both modes) with the session 1 tool.
CI uses the Docker image, which may differ. If the first CI run gives a
different result, look at it by hand before changing the expected files, and
explain every change from this table in the PR.

| Request | Attacker | vulnerable=1 | vulnerable=0 |
|---|---|---|---|
| `GET /books/v1/alice-secret-book` (owner alice) | bob | BYPASSED (BOLA) | ENFORCED (404) |
| | anonymous | ENFORCED (401) | ENFORCED (401) |
| `GET /books/v1/bob-secret-book` (owner bob) | alice | BYPASSED (BOLA) | ENFORCED (404) |
| | anonymous | ENFORCED (401) | ENFORCED (401) |
| `GET /users/v1/_debug` (owner admin) | alice, bob | BYPASSED (BFLA) | BYPASSED (BFLA) |
| | anonymous | BYPASSED (Missing authentication) | BYPASSED (Missing authentication) |
| `GET /me` (owner admin) | alice, bob | REVIEW (similarity 0.89, see below) | REVIEW (0.89) |
| | anonymous | ENFORCED (401) | ENFORCED (401) |
| `GET /users/v1`, `GET /books/v1`, `GET /users/v1/{username}` | all | SKIPPED (public) | SKIPPED (public) |

**Fragile:** the `/me` answers for admin and name1 are short JSON with the
same keys. Their similarity is **0.89**, just under the 0.9 threshold. So it
is REVIEW today, but a small change (a longer email, another field) could make
it BYPASSED (BFLA), a false positive. Do not change the threshold to hide
anything. Write this down in `docs/vampi-results.md` as a known weakness, and
list "better similarity for short responses" under "Out of scope / next".

**Redaction note:** VAmPI's book response has a field named `secret`, so the
report shows it as `[REDACTED]`. The evidence for the BOLA (the other user's
secret) is therefore hidden in the report. This is the redaction rule working
as designed. Mention it in `docs/vampi-results.md`; the curl command lets a
human see the real value.

## Tool changes

Only if VAmPI shows a real bug in the tool. For each fix:

- first add an offline test that reproduces it (the fake API can be extended),
- then fix it,
- then list it in the PR under "Bugs found by running against VAmPI".

## docs/vampi-results.md

- The two final result tables (from the CI reports).
- For each BYPASSED: the curl command from the report and a column
  "Confirmed by hand" set to "not yet". **The owner fills this column**
  after running VAmPI locally. Do not mark anything as confirmed.
- Known false positives and limitations, in plain words.

## README

- Status: "tested offline (pytest) and in CI against VAmPI in vulnerable and
  secure mode".
- A short "Results on VAmPI" section: the vulnerable vs secure table, one line
  on the public endpoints decision, and a link to `docs/vampi-results.md`.
- Roadmap: tick session 2.
- Add a line linking the VAmPI workflow runs.

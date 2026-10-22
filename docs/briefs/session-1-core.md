# Session 1 brief: core engine

Read `CLAUDE.md` first. Its rules apply to everything below.

## Goal

Build the working core of api-authz-tester: load a config, read an OpenAPI
spec, log in as several identities, replay each in-scope request as the other
identities, and write a Markdown + JSON report with a verdict for every
request. Everything must be proven by an **offline** test suite.

## Done when

1. `pip install -e ".[dev]" && pytest -q` passes on Python 3.10 and 3.12.
2. `api-authz-tester list` and `api-authz-tester run` work end to end against
   the fake API in `tests/`.
3. The end-to-end test asserts the **exact** verdict for every fake endpoint
   (table under "Fake API").
4. `examples/vampi.config.yml` loads without errors (a test checks this, with
   dummy env vars set).
5. README "Status" and "Usage" describe what really works, with a short
   sample report excerpt produced from the fake API.
6. One PR from branch `session-1-core`, plain-English description, no AI attribution.

## Out of scope (do NOT build)

- CI against VAmPI or crAPI (session 2)
- Burp XML / HAR import (session 3)
- GraphQL, mass-assignment fuzzing, concurrency, a GUI

## Module layout

```
src/api_authz_tester/
  config.py    load YAML, expand ${ENV}, validate -> dataclasses
  spec.py      OpenAPI 3.x (JSON or YAML, file path or URL) -> list[Operation]
  auth.py      run login steps, build headers per identity, re-login
  http.py      requests.Session wrapper: rate limit, timeout, no redirects
  compare.py   normalise bodies, similarity score, verdict rules
  engine.py    build baseline + replay requests, collect results
  report.py    Markdown and JSON output, redaction
  cli.py       argparse entry point (main)
```

## Config

The schema is defined by `examples/vampi.config.yml`. Keep it compatible. Also:

- `${VAR}` in any string is replaced from the environment. A missing variable
  is a clear config error that names the variable, not a crash.
- An identity has either `headers` (static) or `login` (or neither, for
  anonymous). `privilege` is an int: 0 anonymous, higher means more access.
- `owns` maps parameter names to values that belong to that identity.
- `scope.include` / `scope.exclude` are glob patterns on the path template.
- Add optional `scope.public`: path globs that are meant to be public.
  Anonymous replays of those are not flagged.
- Validate: unique identity names, `base_url` is http(s), `similarity` is
  above 0 and at most 1, `rate_limit` above 0. Errors must say which field is wrong.

## Engine rules

1. **Operations:** every (method, path template) in the spec that matches the
   scope. Methods other than GET/HEAD/OPTIONS are dropped unless `--allow-unsafe`.
   For unsafe methods use the spec's example body if present, otherwise SKIP
   with the reason "no example body".
2. **Baseline owners:** for each operation, every identity whose `owns` has a
   value for **all** path parameters (and all required query parameters) is a
   possible owner. Operations with no parameters use the highest-privilege
   identity as owner. No possible owner means SKIPPED with the reason.
3. **Attackers:** for each baseline, replay as every *other* identity whose
   privilege is **less than or equal to** the owner's. Higher privilege
   reading lower data is expected, so don't test it.
4. **Login:** log in lazily on first use and cache the header. If a request
   from an identity with a `login` block gets **401**, log in again **once**
   and retry, then record the retried result. This matters: VAmPI tokens
   expire after about 60 seconds, and a stale attacker token would look like
   ENFORCED and hide real bugs.
5. **HTTP:** one `requests.Session` per identity, `allow_redirects=False`,
   timeout from config, a global rate limiter (token bucket; inject the clock
   so tests don't sleep).
6. **Host guard:** if the `base_url` host is not `localhost`, `127.0.0.1` or
   `::1`, refuse to run (exit code 2) unless `--i-am-authorized` is passed.

## Verdict rules (compare.py)

| Baseline | Attacker response | Verdict |
|---|---|---|
| not 2xx | (any) | `SKIPPED` ("baseline returned 4xx/5xx") |
| 2xx | 401, 403, 404, 3xx | `ENFORCED` (note "404 may hide existence") |
| 2xx | 2xx, similarity >= threshold | `BYPASSED` |
| 2xx | 2xx, similarity < threshold | `REVIEW` |
| 2xx | other 4xx | `REVIEW` |
| 2xx | 5xx or network error | `ERROR` |

Similarity: if both bodies are JSON, compare canonical dumps
(`sort_keys=True`); otherwise compare text. Use the `difflib.SequenceMatcher`
ratio. Two empty bodies count as 1.0.

**Labels for BYPASSED:**

| Attacker vs owner | Label |
|---|---|
| attacker privilege 0 | Missing authentication (API2:2023) |
| attacker privilege < owner | BFLA (API5:2023) |
| attacker privilege == owner | BOLA (API1:2023) |

Endpoints in `scope.public` skip anonymous replays.

## Reports

**Markdown** (`-o`):
- Header: target, date/time (UTC), tool version, identities (name + privilege
  only), and a count per verdict.
- Matrix table: one row per concrete request, one column per identity; cells
  show verdict + status code ("owner" for the baseline).
- A **Findings** section with one block per BYPASSED: label, OWASP id,
  endpoint, owner vs attacker, status codes, similarity, and a curl command to
  reproduce it with tokens replaced by placeholders like `<alice-token>`. End
  each block with "Candidate: confirm manually before reporting."
- REVIEW, ERROR and SKIPPED as short lists with reasons.
- Body excerpts truncated to 300 characters, after redaction.

**JSON** (`--json`): the same data, machine-readable.

**Redaction** (one function, used by both formats and the console):
Authorization, Cookie, Set-Cookie, X-API-Key headers, and any header or JSON
key whose name contains token, key, secret or password (case-insensitive).

## CLI

```
api-authz-tester list -c CONFIG
    Load config + spec, print in-scope operations and their possible owners.
    Sends no API requests and never logs in (it may fetch the spec URL).

api-authz-tester run -c CONFIG [-o MD] [--json JSON] [--allow-unsafe]
                     [--rate N] [--i-am-authorized]
    Exit 0 = no BYPASSED, 1 = at least one BYPASSED, 2 = config/usage error.
```

Also print a one-line summary per verdict to the console, redacted.

## Fake API (tests/fake_api.py)

A small vulnerable API on stdlib `http.server.ThreadingHTTPServer`, bound to
`127.0.0.1` on port 0, started by a pytest fixture, plus its OpenAPI spec in
`tests/fixtures/fake_api.yml`. Users: alice and bob (privilege 1), admin
(privilege 2). The e2e test config marks `/public` as public.

| Endpoint | Behaviour | Expected verdicts |
|---|---|---|
| `POST /login` | JSON {username, password} returns {token} | (used by login) |
| `GET /users/{name}` | only that user or admin may read | bob on alice: ENFORCED; anonymous: ENFORCED |
| `GET /notes/{note_id}` | any valid token reads any note (bug) | bob on alice: BYPASSED (BOLA); anonymous: ENFORCED |
| `GET /admin/stats` | any valid token works (bug) | alice/bob: BYPASSED (BFLA); anonymous: ENFORCED |
| `GET /debug/config` | no auth check at all (bug) | anonymous: BYPASSED (Missing authentication) |
| `GET /public` | public by design | not flagged |
| `GET /me` | returns the caller's own profile | bob vs alice: REVIEW |
| `DELETE /notes/{note_id}` | exists in spec | not sent without `--allow-unsafe` |

Make one token expire after its first use for one identity, so the
re-login-on-401 path is covered by a test.

## Unit tests (in addition to e2e)

- config: env expansion, missing env var error, each validation error
- spec: JSON and YAML, path params, required query params, include/exclude/public globs, unsafe-method filter
- compare: every row of both verdict tables
- redaction: headers, nested JSON keys, curl output
- rate limiter with an injected clock
- host guard: refuses a non-local host, allows it with the flag
- CLI exit codes 0 / 1 / 2

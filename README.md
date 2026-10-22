# api-authz-tester

Finds broken authorization in REST APIs by replaying each request as several
users and comparing what comes back.

It targets the two most common API flaws in the
[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/):

| Check | OWASP | Question it answers |
|---|---|---|
| BOLA | API1:2023 | Can Bob read Alice's object by changing an ID? |
| BFLA | API5:2023 | Can a normal user call an admin-only function? |
| Missing authentication | API2:2023 | Does the endpoint answer with no login at all? |

> **Status:** under construction (v0.1). The project skeleton exists; the engine
> is being built. See [Roadmap](#roadmap).

## How it works

1. Read the API's **OpenAPI spec** to get every endpoint in scope.
2. Log in as each **identity** in the config (for example alice, bob, admin, anonymous).
3. For each endpoint, send the request as the identity that **owns** the object.
   This is the baseline.
4. Replay the same request as every **lower- or equal-privilege** identity.
5. Compare each response with the baseline and give a verdict:

| Verdict | Meaning |
|---|---|
| `ENFORCED` | Blocked (401 / 403 / redirect / 404) |
| `BYPASSED` | Got the same data as the owner: **likely vulnerability** |
| `REVIEW` | Got a 2xx but different data: check by hand |
| `ERROR` | 5xx or network error |
| `SKIPPED` | Baseline failed or required values missing |

`BYPASSED` results are **candidates**. Confirm every one manually before
reporting it. The tool narrows the search; it does not replace the tester.

## Safety

- Only test systems you own or are **authorized** to test.
- Only `GET`, `HEAD` and `OPTIONS` are sent by default. Methods that change
  state need `--allow-unsafe`.
- Requests are rate-limited (5 per second by default).
- Any host other than `localhost` needs `--i-am-authorized`.
- Tokens, cookies and API keys are redacted in every report.
- Passwords and tokens go in environment variables (`${VAR}`), never in config files.

## Usage (planned)

```bash
pip install -e ".[dev]"
api-authz-tester list -c my.config.yml       # show what would be tested
api-authz-tester run  -c my.config.yml -o reports/run.md --json reports/run.json
```

See [`examples/vampi.config.yml`](examples/vampi.config.yml) for a full config.

## Roadmap

- [ ] **Session 1:** core engine, CLI, Markdown/JSON reports, offline test suite ([brief](docs/briefs/session-1-core.md))
- [ ] **Session 2:** CI that runs the tool against [VAmPI](https://github.com/erev0s/VAmPI)
- [ ] **Session 3:** import requests from Burp Suite XML and HAR files
- [ ] Manual OWASP API Top 10 assessment of [crAPI](https://github.com/OWASP/crAPI), with tool results validated by hand

## License

MIT

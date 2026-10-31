# Session 3 brief: import recorded traffic (Burp XML and HAR)

Read `CLAUDE.md` first. Its rules apply to everything below.

## Goal

Today the tool only tests endpoints listed in an OpenAPI spec. Many real
targets have no spec, or the spec is incomplete. A tester usually has
**recorded traffic** instead: they click through the app while logged in as
one user, and Burp Suite or the browser saves every request.

Session 3 lets the tool read that recorded traffic and test it, like the Burp
extension Autorize does:

1. Read requests from a **Burp "Save items" XML** file or a **HAR** file.
2. The config says which identity recorded the file (the **owner**).
3. For each recorded request: send it again as the owner (the baseline), then
   replay it as every identity with lower or equal privilege. Same verdicts,
   same labels, same reports as session 1.

## Done when

1. `pip install -e ".[dev]" && pytest -q` passes on Python 3.10 and 3.12, all
   offline.
2. A config with `traffic:` and **no** `spec:` works end to end with
   `api-authz-tester list` and `api-authz-tester run` against the fake API.
3. The end-to-end test asserts the **exact** verdict for every recorded request
   in the fixtures (table under "Fixtures").
4. A test proves the **recorded** tokens and cookies are never sent (the
   fixtures contain fake tokens that the fake API rejects).
5. The VAmPI workflow and all session 1 and 2 tests still pass unchanged.
6. README "Status", "Usage" and "Roadmap" describe what really works.
7. One PR from branch `session-3-traffic-import`, plain-English description,
   no AI attribution.

## Out of scope (do NOT build)

- Burp project files (`.burp`), Postman collections, OpenAPI generated from traffic
- Finding the owner automatically (for example from the recorded token)
- GraphQL, WebSockets, file uploads (multipart bodies)
- Changing recorded IDs (for example trying note 2 when note 1 was recorded):
  that is fuzzing, not authorization replay
- CI against VAmPI with recorded traffic (could be a later session)

## Config

Add an optional top-level `traffic` list. `target.spec` becomes optional, but
a config must have **at least one** of `spec` and `traffic` (clear error if
neither). When both are given, both are tested.

```yaml
target:
  base_url: http://localhost:5000
  # spec: is optional when traffic is given

traffic:
  - file: traffic/alice.har      # relative to the config file
    owner: alice                 # the identity that recorded it
  - file: traffic/admin.xml
    owner: admin
    format: burp                 # optional: har or burp. Default: .har -> har, .xml -> burp
```

Validation (errors name the field, like session 1):

- `traffic[i].file` must exist (checked when loading the traffic, not the config).
- `traffic[i].owner` must be the name of an identity in the config.
- `traffic[i].format` must be `har` or `burp` if given; an unknown extension
  without `format` is an error.
- Unknown fields are an error, as before.

## New module: traffic.py

```
traffic.py   read HAR / Burp XML files -> list[RecordedRequest]
```

```python
@dataclass
class RecordedRequest:
    method: str            # "GET"
    path: str              # "/notes/1", relative to base_url
    query: str             # raw query string, "" if none (order kept)
    headers: dict[str, str]  # only the headers we keep (see below)
    body: bytes | None
    owner: str             # identity name from the config
    source: str            # "alice.har #12" or "admin.xml #3", for the report
```

**HAR** (JSON, version 1.2): use `log.entries[].request`: `method`, `url`,
`headers` (list of name/value), `postData.text` and `postData.mimeType`.

**Burp XML** ("Save items" in Burp): `<items><item>` with `<url>`, `<method>`,
and `<request base64="true">` that holds the full raw HTTP request. Decode it
and split request line, headers and body at the first empty line. Use the
stdlib `xml.etree.ElementTree` and `base64`. If `base64="false"`, the text is
the raw request.

**Which requests are kept:**

- Only requests whose URL starts with `target.base_url` (same scheme, host and
  port; `http://x` and `http://x:80` are the same). The rest of the URL is the
  path. If `base_url` has a path prefix like `/api`, it is removed. Other hosts
  are skipped and counted.
- Static files are skipped: paths ending in `.js .css .map .png .jpg .jpeg .gif
  .svg .ico .woff .woff2 .ttf`.
- Then the normal `scope.include` / `scope.exclude` / `scope.public` globs, the
  `scope.methods` list and the unsafe-method rule, matched against the **concrete
  path** (there is no template).
- Duplicates (same owner, method, path, query and body) are kept once.

**Headers:** the recorded auth must never be sent, because the tool must test
with the identities from the config. Drop `Authorization`, `Cookie`, every
header name that one of the identities sets, `Host`, `Content-Length`,
`Connection`, `Accept-Encoding`, and HTTP/2 pseudo-headers (names that start
with `:`). Keep the rest (for example `Content-Type`, `X-Requested-With`).

## Engine, HTTP and report changes

- `engine.py`: a recorded request becomes a `Result` with a fixed owner (the
  `owner` from the config). Baseline and replays work exactly as in session 1:
  the baseline is sent **again** with the owner's current login; the recorded
  response is not used. Attackers: identities with privilege lower than or
  equal to the owner's. `scope.public` and unsafe-method rules as in session 1.
  An unsafe recorded request with `--allow-unsafe` sends its **recorded** body.
- `http.py`: `send()` also accepts extra headers and a raw `bytes` body (for
  recorded bodies that are not JSON, like form data). JSON from the spec keeps
  working as before.
- `report.py`: every result gets a `source` (`"openapi"` or `"alice.har #12"`),
  shown in the Markdown and JSON reports. The curl command includes the kept
  headers and the body. **Redaction must also cover form-encoded bodies**
  (`a=1&password=x` -> `password=[REDACTED]`), using the same sensitive-name rule.
- `cli.py`: `list` also prints the recorded requests with owner and source, and
  how many were skipped and why (other host, static file, out of scope, unsafe,
  duplicate). It still sends no requests.

## Fixtures and tests

Recorded traffic files contain real tokens, cookies and passwords. **Never
commit real ones.** Add to `.gitignore`: `*.har` and `traffic/`, with an
exception for `tests/fixtures/*.har`. The fixtures are written by hand with
fake tokens such as `recorded-token-must-not-be-sent`.

`tests/fixtures/alice.har` (recorded as alice against the fake API) and
`tests/fixtures/admin.xml` (Burp format, recorded as admin) together contain:

| Recorded request | File | Expected result |
|---|---|---|
| `GET /notes/1` | alice.har | bob: BYPASSED (BOLA); anonymous: ENFORCED |
| `GET /users/alice` | alice.har | bob: ENFORCED; anonymous: ENFORCED |
| `GET /notes/1` again (duplicate) | alice.har | kept once |
| `GET /public` | alice.har | SKIPPED (public) |
| `GET /static/app.js` | alice.har | skipped: static file |
| `GET https://other.example/x` | alice.har | skipped: other host, never sent |
| `POST /login` with a password | alice.har | not sent: unsafe (and the password never appears in any output) |
| `GET /admin/stats` | admin.xml | alice, bob: BYPASSED (BFLA); anonymous: ENFORCED |
| `GET /debug/config` | admin.xml | alice, bob: BYPASSED (BFLA); anonymous: BYPASSED (Missing authentication) |

Every recorded request carries a fake `Authorization` or `Cookie`. If the tool
ever sent them, the owner's baseline would get 401 and the verdicts would be
SKIPPED, so the end-to-end test also proves they are dropped. Add a direct
check too: the fake API records the headers it received, and no request may
contain the fake token.

Unit tests (in addition to e2e):

- traffic: HAR parsing, Burp parsing with base64 true and false, base_url
  matching (ports, path prefix), static and other-host skips, header dropping
  (including `:authority`), duplicates, form and JSON bodies
- config: `traffic` validation errors, "spec or traffic required", relative file paths
- redaction: form-encoded body
- CLI: `list` with traffic sends nothing and shows the skip counts

## README and docs

- Status and Usage: how to save traffic in Burp ("Save items", base64 on) and
  in the browser (DevTools, Network, "Save all as HAR"), the `traffic:` config,
  and the warning that these files hold real secrets and must not be committed.
- A short note on the XML parser: the stdlib parser is used because Burp files
  are produced by the tester. Do not import XML files from untrusted sources.
- Roadmap: tick session 3.

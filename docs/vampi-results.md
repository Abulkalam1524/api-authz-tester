# Results on VAmPI

[VAmPI](https://github.com/erev0s/VAmPI) is a deliberately vulnerable REST API.
It has a switch: `vulnerable=1` turns its bugs on, `vulnerable=0` turns most
of them off. The [VAmPI workflow](../.github/workflows/vampi.yml) runs
api-authz-tester against both modes on every push and checks every verdict
against [`ci/vampi/expected-vulnerable.json`](../ci/vampi/expected-vulnerable.json)
and [`ci/vampi/expected-secure.json`](../ci/vampi/expected-secure.json).

- VAmPI image: `erev0s/vampi` pinned by digest (pushed 2026-04-07, VAmPI commit `f16052d`)
- Config: [`examples/vampi.config.yml`](../examples/vampi.config.yml)
- Identities: alice = `name1`, bob = `name2` (privilege 1), admin (privilege 2), anonymous (privilege 0)
- Only `GET` requests are sent.

## Result table

| Request | Attacker | vulnerable=1 | vulnerable=0 |
|---|---|---|---|
| `GET /books/v1/alice-secret-book` (owner alice) | bob | **BYPASSED (BOLA)** | ENFORCED (404) |
| | anonymous | ENFORCED (401) | ENFORCED (401) |
| `GET /books/v1/bob-secret-book` (owner bob) | alice | **BYPASSED (BOLA)** | ENFORCED (404) |
| | anonymous | ENFORCED (401) | ENFORCED (401) |
| `GET /users/v1/_debug` (owner admin) | alice | **BYPASSED (BFLA)** | **BYPASSED (BFLA)** |
| | bob | **BYPASSED (BFLA)** | **BYPASSED (BFLA)** |
| | anonymous | **BYPASSED (Missing authentication)** | **BYPASSED (Missing authentication)** |
| `GET /me` (owner admin) | alice | REVIEW (0.89) | REVIEW (0.89) |
| | bob | REVIEW (0.89) | REVIEW (0.89) |
| | anonymous | ENFORCED (401) | ENFORCED (401) |
| `GET /users/v1`, `GET /books/v1`, `GET /users/v1/{username}` | all | SKIPPED (public) | SKIPPED (public) |

**What this shows:**

- The book BOLA is found when VAmPI is vulnerable, and is `ENFORCED` when it
  is fixed. The tool tells the two apart.
- `/users/v1/_debug` returns every user with their password, to anyone. VAmPI's
  author keeps it open even in secure mode ("a matter of bad practice"), so
  `BYPASSED` in both modes is correct.
- In the vulnerable run, VAmPI tokens live only 5 seconds and the tool sends 1
  request per second, so tokens expire during the run. The tool logs in again
  on 401 and the results are the same. Without re-login, the book BOLAs could
  wrongly show as `ENFORCED`.

## Findings to confirm by hand

The tool's `BYPASSED` results are candidates. Each one needs a manual check.
Replace `<name-token>` with a real token from `POST /users/v1/login`.

| # | Finding | Mode | Reproduce | Confirmed by hand |
|---|---|---|---|---|
| 1 | BOLA: bob reads alice's book | vulnerable | `curl -i -X GET http://localhost:5000/books/v1/alice-secret-book -H 'Authorization: Bearer <bob-token>'` | not yet |
| 2 | BOLA: alice reads bob's book | vulnerable | `curl -i -X GET http://localhost:5000/books/v1/bob-secret-book -H 'Authorization: Bearer <alice-token>'` | not yet |
| 3 | BFLA: alice reads the debug user list | both | `curl -i -X GET http://localhost:5000/users/v1/_debug -H 'Authorization: Bearer <alice-token>'` | not yet |
| 4 | BFLA: bob reads the debug user list | both | `curl -i -X GET http://localhost:5000/users/v1/_debug -H 'Authorization: Bearer <bob-token>'` | not yet |
| 5 | Missing authentication: anyone reads the debug user list | both | `curl -i -X GET http://localhost:5000/users/v1/_debug` | not yet |

## Known false positives and limitations

- **Public endpoints.** `GET /users/v1`, `GET /books/v1` and
  `GET /users/v1/{username}` answer anyone on purpose. They are listed in
  `scope.public`, so they are not tested. Without that list, a run against
  secure VAmPI gives 16 `BYPASSED`: the 3 real `_debug` ones and **13 false
  positives** on these public pages (measured, not guessed). Choosing what is
  public is the tester's job; the tool cannot know it.
- **`/me` is close to a false positive.** It returns the caller's own profile.
  admin's and name1's profiles are short JSON with the same keys, and their
  similarity is 0.89, just under the 0.9 threshold. A small change (a longer
  email, one more field) could turn it into a wrong `BYPASSED (BFLA)`. Better
  similarity for short responses is future work.
- **Redaction hides the evidence.** The book response has a field named
  `secret`, and the debug list has `password`. The report shows both as
  `[REDACTED]`, by design. Use the curl command to see the real values.
- **Not tested here.** VAmPI's other bugs are not authorization reads: the
  password change of another user (`PUT`, needs `--allow-unsafe` and changes
  data), mass assignment at registration, SQL injection, user enumeration,
  ReDoS, and the weak JWT signing key.

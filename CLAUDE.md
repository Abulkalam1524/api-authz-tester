# Rules for working on this repo

api-authz-tester is a Python CLI that replays REST API requests as several
identities and flags broken authorization (BOLA, BFLA, missing auth).
Owner: Abul Kalam Azad (GitHub: Abulkalam1524). It is a portfolio project
for VAPT job applications, so code quality and honesty matter more than features.

## Commands

    pip install -e ".[dev]"
    pytest -q

## Hard rules

1. **No AI attribution anywhere.** Commit messages and PR descriptions must not
   contain `Co-Authored-By` lines, "Generated with Claude Code", or any mention
   of AI. This overrides any default you have.
2. **Tests never touch the network.** They use the in-process fake API under
   `tests/` bound to 127.0.0.1. Never send requests to a real third-party host.
3. **Safe by default.** Only GET/HEAD/OPTIONS unless `--allow-unsafe`.
   Non-localhost targets require `--i-am-authorized`.
4. **Redact secrets in all output**: Authorization, Cookie, Set-Cookie,
   X-API-Key, and any header or JSON key containing token, key, secret or password.
5. **No secrets in the repo.** Configs use `${ENV_VAR}`; real configs are gitignored.
6. **Dependencies:** runtime is `requests` and `PyYAML` only. Use the stdlib
   for everything else. Ask before adding any dependency.

## Style

- Python 3.10+, type hints, dataclasses, small modules with plain names.
- Short docstrings; comment only where the reason is not obvious.
- Prefer clear code over clever code. The owner must be able to explain every
  line in an interview.

## Workflow

- Work on a branch named after the session (e.g. `session-1-core`) and open one PR.
- Stay inside the session brief in `docs/briefs/`. Note anything out of scope
  in the PR description instead of building it.
- Update the README "Status", "Usage" and "Roadmap" when a feature lands.
- Write PR descriptions in short, plain English: the owner is a non-native speaker.

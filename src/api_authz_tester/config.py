"""Load the YAML config, expand ${ENV} values and validate it into dataclasses."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """The config file is missing, unreadable or invalid."""


@dataclass
class Login:
    path: str
    token_from: str
    method: str = "POST"
    json: dict[str, Any] | None = None
    header: str = "Authorization"
    format: str = "Bearer {token}"


@dataclass
class Identity:
    name: str
    privilege: int
    headers: dict[str, str] = field(default_factory=dict)
    login: Login | None = None
    owns: dict[str, str] = field(default_factory=dict)


@dataclass
class Target:
    base_url: str
    spec: str
    rate_limit: float = 5.0
    timeout: float = 10.0
    similarity: float = 0.9


@dataclass
class Scope:
    include: list[str] = field(default_factory=lambda: ["*"])
    exclude: list[str] = field(default_factory=list)
    methods: list[str] | None = None
    public: list[str] = field(default_factory=list)


@dataclass
class Config:
    target: Target
    scope: Scope
    identities: list[Identity]


def load_config(path: str | Path) -> Config:
    """Read a config file and return a validated Config."""
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from None

    data = expand_env(raw, "")
    config = parse_config(data)

    # A relative spec path is relative to the config file, not the shell.
    spec = config.target.spec
    if not spec.startswith(("http://", "https://")) and not Path(spec).is_absolute():
        config.target.spec = str(path.parent / spec)
    return config


def expand_env(value: Any, where: str) -> Any:
    """Replace ${VAR} in every string with the environment value."""
    if isinstance(value, dict):
        return {k: expand_env(v, _join(where, str(k))) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v, f"{where}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise ConfigError(f"{where}: environment variable {name} is not set")
            return os.environ[name]

        return ENV_PATTERN.sub(replace, value)
    return value


def parse_config(data: Any) -> Config:
    """Validate the expanded YAML data and build the dataclasses."""
    data = _mapping(data, "config")
    _no_unknown(data, "", {"target", "scope", "identities"})
    target = _parse_target(_mapping(data.get("target"), "target"))
    scope = _parse_scope(_mapping(data.get("scope") or {}, "scope"))

    raw_ids = data.get("identities")
    if not isinstance(raw_ids, list) or not raw_ids:
        raise ConfigError("identities: must be a non-empty list")
    identities = [_parse_identity(item, f"identities[{i}]") for i, item in enumerate(raw_ids)]

    seen: set[str] = set()
    for i, ident in enumerate(identities):
        if ident.name in seen:
            raise ConfigError(f"identities[{i}].name: duplicate identity name {ident.name!r}")
        seen.add(ident.name)
    return Config(target=target, scope=scope, identities=identities)


def _parse_target(data: dict[str, Any]) -> Target:
    _no_unknown(data, "target", {"base_url", "spec", "rate_limit", "timeout", "similarity"})
    base_url = _string(data.get("base_url"), "target.base_url")
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"target.base_url: must be an http(s) URL (got {base_url!r})")

    target = Target(base_url=base_url.rstrip("/"), spec=_string(data.get("spec"), "target.spec"))
    target.rate_limit = _number(data.get("rate_limit", target.rate_limit), "target.rate_limit")
    target.timeout = _number(data.get("timeout", target.timeout), "target.timeout")
    target.similarity = _number(data.get("similarity", target.similarity), "target.similarity")
    if target.rate_limit <= 0:
        raise ConfigError(f"target.rate_limit: must be above 0 (got {target.rate_limit})")
    if target.timeout <= 0:
        raise ConfigError(f"target.timeout: must be above 0 (got {target.timeout})")
    if not 0 < target.similarity <= 1:
        raise ConfigError(
            f"target.similarity: must be above 0 and at most 1 (got {target.similarity})"
        )
    return target


def _parse_scope(data: dict[str, Any]) -> Scope:
    _no_unknown(data, "scope", {"include", "exclude", "methods", "public"})
    scope = Scope()
    if "include" in data:
        scope.include = _string_list(data["include"], "scope.include")
    scope.exclude = _string_list(data.get("exclude", []), "scope.exclude")
    scope.public = _string_list(data.get("public", []), "scope.public")
    if data.get("methods") is not None:
        scope.methods = [m.upper() for m in _string_list(data["methods"], "scope.methods")]
    return scope


def _parse_identity(data: Any, where: str) -> Identity:
    data = _mapping(data, where)
    _no_unknown(data, where, {"name", "privilege", "headers", "login", "owns"})
    name = _string(data.get("name"), f"{where}.name")
    privilege = data.get("privilege")
    if not isinstance(privilege, int) or isinstance(privilege, bool) or privilege < 0:
        raise ConfigError(f"{where}.privilege: must be a whole number 0 or above")
    if data.get("headers") and data.get("login"):
        raise ConfigError(f"{where}: use either headers or login, not both")

    headers = {}
    for key, value in _mapping(data.get("headers") or {}, f"{where}.headers").items():
        headers[str(key)] = _string(value, f"{where}.headers.{key}")

    owns = {}
    for key, value in _mapping(data.get("owns") or {}, f"{where}.owns").items():
        if isinstance(value, (dict, list)) or value is None:
            raise ConfigError(f"{where}.owns.{key}: must be a single value")
        owns[str(key)] = str(value)

    login = None
    if data.get("login"):
        login = _parse_login(_mapping(data["login"], f"{where}.login"), f"{where}.login")
    return Identity(name=name, privilege=privilege, headers=headers, login=login, owns=owns)


def _parse_login(data: dict[str, Any], where: str) -> Login:
    _no_unknown(data, where, {"method", "path", "json", "token_from", "header", "format"})
    login = Login(
        path=_string(data.get("path"), f"{where}.path"),
        token_from=_string(data.get("token_from"), f"{where}.token_from"),
    )
    if not login.path.startswith("/"):
        raise ConfigError(f"{where}.path: must start with '/' (got {login.path!r})")
    login.method = _string(data.get("method", login.method), f"{where}.method").upper()
    login.header = _string(data.get("header", login.header), f"{where}.header")
    login.format = _string(data.get("format", login.format), f"{where}.format")
    if "{token}" not in login.format:
        raise ConfigError(f"{where}.format: must contain {{token}}")
    if data.get("json") is not None:
        login.json = _mapping(data["json"], f"{where}.json")
    return login


def _join(where: str, key: str) -> str:
    return f"{where}.{key}" if where else key


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: must be a mapping")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}: must be a non-empty string")
    return value


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}: must be a number (got {value!r})")
    return float(value)


def _string_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: must be a list of strings")
    return value


def _no_unknown(data: dict[str, Any], where: str, allowed: set[str]) -> None:
    # Catches typos like "ownz", which would otherwise silently test nothing.
    for key in data:
        if key not in allowed:
            raise ConfigError(f"{_join(where, str(key))}: unknown field")

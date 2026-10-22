"""Read an OpenAPI 3.x spec (JSON or YAML, file or URL) into a list of operations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import requests
import yaml

from .config import Scope

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class SpecError(Exception):
    """The spec cannot be loaded or is not OpenAPI 3.x."""


@dataclass
class Operation:
    method: str
    path: str
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)  # required ones only
    example_body: Any = None

    @property
    def is_safe(self) -> bool:
        return self.method in SAFE_METHODS

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


def load_spec(source: str, timeout: float = 10.0) -> list[Operation]:
    """Load a spec from a file path or an http(s) URL."""
    if source.startswith(("http://", "https://")):
        try:
            resp = requests.get(source, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise SpecError(f"cannot fetch spec {source}: {exc}") from None
        text = resp.text
    else:
        try:
            text = Path(source).read_text(encoding="utf-8")
        except OSError as exc:
            raise SpecError(f"cannot read spec {source}: {exc}") from None
    return parse_spec(text)


def parse_spec(text: str) -> list[Operation]:
    """Parse spec text (JSON or YAML) into operations, in spec order."""
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"spec is neither JSON nor YAML: {exc}") from None

    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith("3."):
        raise SpecError("spec is not OpenAPI 3.x (missing 'openapi: 3.x' field)")

    operations = []
    for path, item in (doc.get("paths") or {}).items():
        item = _resolve(doc, item)
        shared = item.get("parameters", [])
        for method in HTTP_METHODS:
            if method not in item:
                continue
            op = _resolve(doc, item[method])
            params = _merge_params(doc, shared, op.get("parameters", []))
            operations.append(
                Operation(
                    method=method.upper(),
                    path=path,
                    path_params=[p["name"] for p in params if p.get("in") == "path"],
                    query_params=[
                        p["name"] for p in params if p.get("in") == "query" and p.get("required")
                    ],
                    example_body=_example_body(doc, op),
                )
            )
    return operations


def select_operations(
    operations: list[Operation], scope: Scope, allow_unsafe: bool
) -> list[Operation]:
    """Keep operations that match the scope, dropping unsafe methods unless allowed."""
    return [op for op in in_scope(operations, scope) if op.is_safe or allow_unsafe]


def in_scope(operations: list[Operation], scope: Scope) -> list[Operation]:
    """Apply include/exclude globs and the methods list (ignores the unsafe filter)."""
    result = []
    for op in operations:
        if not any(fnmatchcase(op.path, pattern) for pattern in scope.include):
            continue
        if any(fnmatchcase(op.path, pattern) for pattern in scope.exclude):
            continue
        if scope.methods is not None and op.method not in scope.methods:
            continue
        result.append(op)
    return result


def is_public(path: str, scope: Scope) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in scope.public)


def _resolve(doc: dict[str, Any], obj: Any) -> Any:
    """Follow local '#/...' $ref pointers."""
    seen = set()
    while isinstance(obj, dict) and "$ref" in obj:
        ref = obj["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            raise SpecError(f"unsupported or circular $ref: {ref!r}")
        seen.add(ref)
        obj = doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(obj, dict) or part not in obj:
                raise SpecError(f"$ref not found: {ref}")
            obj = obj[part]
    return obj


def _merge_params(doc: dict[str, Any], shared: list[Any], own: list[Any]) -> list[dict]:
    # Operation-level parameters override path-level ones with the same name and location.
    merged: dict[tuple[str, str], dict] = {}
    for raw in list(shared) + list(own):
        param = _resolve(doc, raw)
        merged[(param.get("name"), param.get("in"))] = param
    return list(merged.values())


def _example_body(doc: dict[str, Any], op: dict[str, Any]) -> Any:
    body = _resolve(doc, op.get("requestBody"))
    if not isinstance(body, dict):
        return None
    media = (body.get("content") or {}).get("application/json")
    if not isinstance(media, dict):
        return None
    if "example" in media:
        return media["example"]
    for example in (media.get("examples") or {}).values():
        example = _resolve(doc, example)
        if isinstance(example, dict) and "value" in example:
            return example["value"]
    schema = _resolve(doc, media.get("schema"))
    if isinstance(schema, dict) and "example" in schema:
        return schema["example"]
    return None

import functools
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

from api_authz_tester.config import Scope
from api_authz_tester.spec import SpecError, is_public, load_spec, parse_spec, select_operations

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/books/{book_id}": {
            "parameters": [{"name": "book_id", "in": "path", "required": True}],
            "get": {
                "parameters": [
                    {"name": "lang", "in": "query", "required": True},
                    {"name": "page", "in": "query"},
                ]
            },
            "put": {
                "requestBody": {
                    "content": {"application/json": {"example": {"title": "new"}}}
                }
            },
            "delete": {},
        },
        "/books": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Book"}}
                    }
                }
            },
            "head": {},
        },
        "/admin/users": {"get": {}},
        "/health": {"options": {}},
    },
    "components": {"schemas": {"Book": {"type": "object", "example": {"title": "x"}}}},
}


def ops_by_key(ops):
    return {(op.method, op.path): op for op in ops}


def test_parse_json_spec():
    ops = ops_by_key(parse_spec(json.dumps(SPEC)))
    get = ops[("GET", "/books/{book_id}")]
    assert get.path_params == ["book_id"]
    assert get.query_params == ["lang"]  # only required query params
    assert ops[("PUT", "/books/{book_id}")].example_body == {"title": "new"}
    assert ops[("POST", "/books")].example_body == {"title": "x"}  # via schema $ref
    assert ops[("DELETE", "/books/{book_id}")].example_body is None
    assert len(ops) == 7


def test_parse_yaml_spec_with_parameter_ref(tmp_path):
    text = """
openapi: "3.1.0"
paths:
  /users/{username}:
    get:
      parameters:
        - $ref: "#/components/parameters/username"
components:
  parameters:
    username: { name: username, in: path, required: true }
"""
    path = tmp_path / "spec.yaml"
    path.write_text(text)
    [op] = load_spec(str(path))
    assert (op.method, op.path, op.path_params) == ("GET", "/users/{username}", ["username"])


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def test_load_spec_from_url(tmp_path):
    (tmp_path / "spec.json").write_text(json.dumps(SPEC))
    handler = functools.partial(QuietHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        ops = load_spec(f"http://127.0.0.1:{server.server_address[1]}/spec.json")
    finally:
        server.shutdown()
        server.server_close()
    assert len(ops) == 7


def test_not_openapi_3():
    with pytest.raises(SpecError, match="not OpenAPI 3"):
        parse_spec('{"swagger": "2.0", "paths": {}}')


def test_missing_spec_file(tmp_path):
    with pytest.raises(SpecError, match="cannot read spec"):
        load_spec(str(tmp_path / "missing.yml"))


def test_include_exclude_globs():
    ops = parse_spec(json.dumps(SPEC))
    scope = Scope(include=["/books*"], exclude=["/books"])
    keys = {(op.method, op.path) for op in select_operations(ops, scope, allow_unsafe=False)}
    assert keys == {("GET", "/books/{book_id}")}


def test_unsafe_methods_need_allow_unsafe():
    ops = parse_spec(json.dumps(SPEC))
    safe = {op.method for op in select_operations(ops, Scope(), allow_unsafe=False)}
    assert safe == {"GET", "HEAD", "OPTIONS"}
    everything = {op.method for op in select_operations(ops, Scope(), allow_unsafe=True)}
    assert everything == {"GET", "HEAD", "OPTIONS", "PUT", "POST", "DELETE"}


def test_scope_methods_list():
    ops = parse_spec(json.dumps(SPEC))
    scope = Scope(methods=["GET", "DELETE"])
    methods = {op.method for op in select_operations(ops, scope, allow_unsafe=True)}
    assert methods == {"GET", "DELETE"}


def test_public_globs():
    scope = Scope(public=["/health", "/docs/*"])
    assert is_public("/health", scope)
    assert is_public("/docs/{page}", scope)
    assert not is_public("/admin/users", scope)

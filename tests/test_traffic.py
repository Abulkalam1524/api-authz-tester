import base64
import json

import pytest

from api_authz_tester.config import Config, Identity, Login, Scope, Target, TrafficFile
from api_authz_tester.traffic import (
    TrafficError,
    load_traffic,
    parse_burp,
    parse_har,
    relative_path,
    split_raw_request,
)


def har(*requests):
    return json.dumps({"log": {"version": "1.2", "entries": [{"request": r} for r in requests]}}).encode()


def har_request(method, url, headers=(), text=None, mime="application/json"):
    req = {"method": method, "url": url, "headers": [{"name": n, "value": v} for n, v in headers]}
    if text is not None:
        req["postData"] = {"mimeType": mime, "text": text}
    return req


def burp(*items):
    body = "".join(
        f"<item><url><![CDATA[{url}]]></url><method><![CDATA[{method}]]></method>"
        f'<request base64="{b64}"><![CDATA[{request}]]></request></item>'
        for url, method, request, b64 in items
    )
    return f'<?xml version="1.0"?><items burpVersion="2026.10">{body}</items>'.encode()


RAW = b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&password=b"


# ------------------------------------------------------------------ parsing


def test_parse_har():
    data = har(
        har_request("get", "http://h/notes/1?view=full", [("Accept", "application/json")]),
        har_request("POST", "http://h/login", text='{"u": 1}'),
    )
    first, second = parse_har(data)
    assert (first.method, first.url, first.headers, first.body) == (
        "GET", "http://h/notes/1?view=full", [("Accept", "application/json")], None,
    )
    assert second.body == b'{"u": 1}'


@pytest.mark.parametrize("data", [b"not json", b'{"log": {}}', har({"url": "http://h/"})])
def test_parse_har_errors(data):
    with pytest.raises(TrafficError):
        parse_har(data)


def test_parse_burp_base64_true_and_false():
    data = burp(
        ("http://h/login", "POST", base64.b64encode(RAW).decode(), "true"),
        ("http://h/me", "GET", "GET /me HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n", "false"),
    )
    login, me = parse_burp(data)
    assert login.method == "POST" and login.url == "http://h/login"
    assert ("Content-Type", "application/x-www-form-urlencoded") in login.headers
    assert login.body == b"user=a&password=b"
    assert me.headers == [("Authorization", "Bearer x")] and me.body is None


def test_parse_burp_with_doctype():
    data = b'<?xml version="1.0"?>\n<!DOCTYPE items [\n<!ELEMENT items (item*)>\n]>\n' + burp(
        ("http://h/me", "GET", "GET /me HTTP/1.1\r\n\r\n", "false")
    ).split(b"?>", 1)[1]
    assert len(parse_burp(data)) == 1


@pytest.mark.parametrize(
    "data, message",
    [
        (b"<items><item>", "not valid XML"),
        (b"<root/>", "expected <items>"),
        (b"<items><item><url>http://h/</url></item></items>", "no url, method or request"),
        (burp(("http://h/", "GET", "%%%", "true")), "invalid base64"),
    ],
)
def test_parse_burp_errors(data, message):
    with pytest.raises(TrafficError, match=message):
        parse_burp(data)


def test_split_raw_request_handles_bare_newlines():
    headers, body = split_raw_request(b"GET / HTTP/1.1\nA: 1\nB:2\n\n")
    assert headers == [("A", "1"), ("B", "2")] and body is None


# ------------------------------------------------------------------ base_url matching


@pytest.mark.parametrize(
    "url, base, expected",
    [
        ("http://h/notes/1", "http://h", ("/notes/1", "")),
        ("http://h:80/notes/1?a=1&b=2", "http://h", ("/notes/1", "a=1&b=2")),
        ("https://h:443/x", "https://h", ("/x", "")),
        ("http://h:8000/x", "http://h:8000", ("/x", "")),
        ("http://h/api/notes/1", "http://h/api", ("/notes/1", "")),
        ("http://h/api", "http://h/api/", ("/", "")),
        ("http://h", "http://h", ("/", "")),
        ("http://h:8001/x", "http://h:8000", None),
        ("https://h/x", "http://h", None),
        ("http://other/x", "http://h", None),
        ("http://h/apiv2/x", "http://h/api", None),
    ],
)
def test_relative_path(url, base, expected):
    assert relative_path(url, base) == expected


# ------------------------------------------------------------------ load_traffic


def make_config(tmp_path, data, name="t.har", fmt="har", scope=None):
    path = tmp_path / name
    path.write_bytes(data)
    alice = Identity(name="alice", privilege=1, login=Login(path="/login", token_from="t", header="X-Auth"))
    keyed = Identity(name="bob", privilege=1, headers={"X-API-Key": "k"})
    return Config(
        target=Target(base_url="http://h"),
        scope=scope or Scope(),
        identities=[alice, keyed],
        traffic=[TrafficFile(file=str(path), owner="alice", format=fmt)],
    )


def test_load_traffic_filters_and_counts(tmp_path):
    data = har(
        har_request("GET", "http://h/notes/1"),
        har_request("GET", "http://h/notes/1"),          # duplicate
        har_request("GET", "http://h/notes/1?v=2"),      # different query: kept
        har_request("GET", "http://h/app/main.JS"),      # static file
        har_request("GET", "http://other/notes/1"),      # other host
        har_request("GET", "http://h/admin/users"),      # out of scope
        har_request("DELETE", "http://h/notes/1"),       # unsafe: kept, caller decides
    )
    config = make_config(tmp_path, data, scope=Scope(exclude=["/admin/*"]))
    recorded, skipped = load_traffic(config)
    assert [(r.method, r.full_path, r.source) for r in recorded] == [
        ("GET", "/notes/1", "t.har #1"),
        ("GET", "/notes/1?v=2", "t.har #3"),
        ("DELETE", "/notes/1", "t.har #7"),
    ]
    assert all(r.owner == "alice" for r in recorded)
    assert not recorded[2].is_safe
    assert skipped == {"duplicate": 1, "static file": 1, "other host": 1, "out of scope": 1}


def test_load_traffic_drops_recorded_auth_headers(tmp_path):
    headers = [
        ("Authorization", "Bearer recorded"),
        ("cookie", "s=recorded"),
        ("X-Auth", "recorded"),            # alice's login header
        ("x-api-key", "recorded"),         # bob's static header
        (":authority", "h"),
        ("Host", "h"),
        ("Content-Length", "3"),
        ("Connection", "keep-alive"),
        ("Accept-Encoding", "gzip"),
        ("Accept", "application/json"),
        ("X-Requested-With", "XMLHttpRequest"),
    ]
    [rec] = load_traffic(make_config(tmp_path, har(har_request("GET", "http://h/x", headers))))[0]
    assert rec.headers == {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}


def test_load_traffic_keeps_form_and_json_bodies(tmp_path):
    data = burp(
        ("http://h/login", "POST", base64.b64encode(RAW).decode(), "true"),
        ("http://h/notes", "POST", 'POST /notes HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"a": 1}', "false"),
    )
    recorded, _ = load_traffic(make_config(tmp_path, data, name="t.xml", fmt="burp"))
    assert [r.body for r in recorded] == [b"user=a&password=b", b'{"a": 1}']
    assert recorded[0].headers == {"Content-Type": "application/x-www-form-urlencoded"}


def test_missing_traffic_file(tmp_path):
    config = make_config(tmp_path, b"")
    config.traffic[0].file = str(tmp_path / "missing.har")
    with pytest.raises(TrafficError, match="cannot read traffic file"):
        load_traffic(config)

"""Read recorded traffic (HAR or Burp "Save items" XML) into requests the engine can replay."""

from __future__ import annotations

import base64
import binascii
import json
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from .config import Config, TrafficFile
from .spec import SAFE_METHODS, matches_scope

STATIC_EXTENSIONS = (
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
)

# Never replayed: the recorded login must not be used, and these are set by requests itself.
DROP_HEADERS = {"authorization", "cookie", "host", "content-length", "connection", "accept-encoding"}

DEFAULT_PORTS = {"http": 80, "https": 443}


class TrafficError(Exception):
    """A traffic file cannot be read."""


@dataclass
class Captured:
    """One request as it was recorded, before any filtering."""

    method: str
    url: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes | None = None


@dataclass
class RecordedRequest:
    """A recorded request that will be replayed. `path` is relative to target.base_url."""

    method: str
    path: str
    query: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    owner: str = ""
    source: str = ""

    @property
    def is_safe(self) -> bool:
        return self.method in SAFE_METHODS

    @property
    def full_path(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path


def load_traffic(config: Config) -> tuple[list[RecordedRequest], Counter]:
    """Read every traffic file in the config and keep the requests that are in scope.

    Returns the kept requests (in file order) and a count of skipped ones by reason.
    Unsafe methods are kept here; the caller drops them unless --allow-unsafe.
    """
    drop = set(DROP_HEADERS)
    for ident in config.identities:
        drop.update(name.lower() for name in ident.headers)
        if ident.login is not None:
            drop.add(ident.login.header.lower())

    kept: list[RecordedRequest] = []
    skipped: Counter = Counter()
    seen: set[tuple] = set()
    for entry in config.traffic:
        for number, cap in enumerate(read_file(entry), start=1):
            source = f"{Path(entry.file).name} #{number}"
            location = relative_path(cap.url, config.target.base_url)
            if location is None:
                skipped["other host"] += 1
                continue
            path, query = location
            if path.lower().endswith(STATIC_EXTENSIONS):
                skipped["static file"] += 1
                continue
            if not matches_scope(cap.method, path, config.scope):
                skipped["out of scope"] += 1
                continue
            key = (entry.owner, cap.method, path, query, cap.body)
            if key in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(key)
            headers = {
                name: value
                for name, value in cap.headers
                if name.lower() not in drop and not name.startswith(":")
            }
            kept.append(
                RecordedRequest(cap.method, path, query, headers, cap.body, entry.owner, source)
            )
    return kept, skipped


def read_file(entry: TrafficFile) -> list[Captured]:
    try:
        data = Path(entry.file).read_bytes()
    except OSError as exc:
        raise TrafficError(f"cannot read traffic file {entry.file}: {exc}") from None
    if entry.format == "har":
        return parse_har(data, entry.file)
    return parse_burp(data, entry.file)


def parse_har(data: bytes, name: str = "HAR") -> list[Captured]:
    """Parse a HAR 1.2 file (browser DevTools: Network, 'Save all as HAR')."""
    try:
        entries = json.loads(data)["log"]["entries"]
    except (ValueError, KeyError, TypeError):
        raise TrafficError(f"{name}: not a HAR file (expected log.entries)") from None
    captured = []
    for i, entry in enumerate(entries):
        try:
            req = entry["request"]
            headers = [(h["name"], h["value"]) for h in req.get("headers", [])]
            text = (req.get("postData") or {}).get("text")
            captured.append(
                Captured(req["method"].upper(), req["url"], headers, text.encode() if text else None)
            )
        except (KeyError, TypeError, AttributeError):
            raise TrafficError(f"{name}: entry {i + 1} has no request method or url") from None
    return captured


def parse_burp(data: bytes, name: str = "Burp XML") -> list[Captured]:
    """Parse a Burp Suite 'Save items' XML file.

    Uses the stdlib parser: only import files you saved yourself, not XML from
    untrusted sources.
    """
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise TrafficError(f"{name}: not valid XML ({exc})") from None
    if root.tag != "items":
        raise TrafficError(f"{name}: not a Burp 'Save items' file (expected <items>)")
    captured = []
    for i, item in enumerate(root.findall("item")):
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "").strip().upper()
        request = item.find("request")
        if not url or not method or request is None:
            raise TrafficError(f"{name}: item {i + 1} has no url, method or request")
        raw = (request.text or "").encode()
        if request.get("base64") == "true":
            try:
                raw = base64.b64decode(raw, validate=True)
            except binascii.Error:
                raise TrafficError(f"{name}: item {i + 1} has invalid base64") from None
        headers, body = split_raw_request(raw)
        captured.append(Captured(method, url, headers, body))
    return captured


def split_raw_request(raw: bytes) -> tuple[list[tuple[str, str]], bytes | None]:
    """Split a raw HTTP request into its headers and body. The request line is skipped."""
    raw = raw.replace(b"\r\n", b"\n")
    head, _, body = raw.partition(b"\n\n")
    headers = []
    for line in head.decode("latin-1").split("\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers.append((name.strip(), value.strip()))
    return headers, body or None


def relative_path(url: str, base_url: str) -> tuple[str, str] | None:
    """The (path, query) of `url` relative to base_url, or None if it is another host."""
    target, base = urlsplit(url), urlsplit(base_url)
    if target.scheme.lower() != base.scheme.lower():
        return None
    if (target.hostname or "") != (base.hostname or ""):
        return None
    if _port(target) != _port(base):
        return None
    prefix = base.path.rstrip("/")
    path = target.path or "/"
    if prefix:
        if path != prefix and not path.startswith(prefix + "/"):
            return None
        path = path[len(prefix):] or "/"
    return path, target.query


def _port(parts: SplitResult) -> int | None:
    return parts.port or DEFAULT_PORTS.get(parts.scheme.lower())

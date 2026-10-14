"""Reading and writing HTTP/1.x messages on asyncio streams.

The proxy works on raw bytes so it can record exactly what crossed the wire.
Bodies are always de-chunked when read, then re-framed with Content-Length
when written, so every stored body is the plain payload.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

MAX_HEAD = 64 * 1024
MAX_BODY = 64 * 1024 * 1024

# Headers that describe one TCP hop, not the message. A proxy must not pass
# them on (RFC 9110 section 7.6.1).
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class HttpError(Exception):
    """The peer sent something that is not valid HTTP/1.x."""


class Headers:
    """Ordered, case-insensitive header list that keeps duplicates."""

    def __init__(self, items: list[tuple[str, str]] | None = None):
        self.items: list[tuple[str, str]] = list(items or [])

    def get(self, name: str, default: str | None = None) -> str | None:
        name = name.lower()
        for k, v in self.items:
            if k.lower() == name:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.items if k.lower() == name]

    def remove(self, name: str) -> None:
        name = name.lower()
        self.items = [(k, v) for k, v in self.items if k.lower() != name]

    def set(self, name: str, value: str) -> None:
        lowered = name.lower()
        for i, (k, _) in enumerate(self.items):
            if k.lower() == lowered:
                self.items[i] = (k, value)
                self.items = self.items[: i + 1] + [
                    (k2, v2) for k2, v2 in self.items[i + 1 :] if k2.lower() != lowered
                ]
                return
        self.items.append((name, value))

    def has_token(self, name: str, token: str) -> bool:
        """True if a comma-separated header such as Connection holds token."""
        token = token.lower()
        return any(
            part.strip().lower() == token
            for value in self.get_all(name)
            for part in value.split(",")
        )

    def copy(self) -> "Headers":
        return Headers(self.items)

    def to_bytes(self) -> bytes:
        return b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in self.items)

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)


@dataclass
class Request:
    method: str
    target: str
    version: str = "HTTP/1.1"
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""

    def head_bytes(self) -> bytes:
        line = f"{self.method} {self.target} {self.version}\r\n".encode("latin-1")
        return line + self.headers.to_bytes() + b"\r\n"

    def to_bytes(self) -> bytes:
        return self.head_bytes() + self.body


@dataclass
class Response:
    status: int
    reason: str = ""
    version: str = "HTTP/1.1"
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""

    def head_bytes(self) -> bytes:
        line = f"{self.version} {self.status} {self.reason}\r\n".encode("latin-1")
        return line + self.headers.to_bytes() + b"\r\n"

    def to_bytes(self) -> bytes:
        return self.head_bytes() + self.body


def parse_headers(lines: list[str]) -> Headers:
    headers = Headers()
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            raise HttpError("obsolete header line folding is not supported")
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise HttpError(f"bad header line: {line!r}")
        headers.items.append((name, value.strip()))
    return headers


def parse_request_head(head: bytes) -> Request:
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise HttpError(f"bad request line: {lines[0]!r}")
    method, target, version = parts
    return Request(method, target, version, parse_headers(lines[1:]))


def parse_response_head(head: bytes) -> Response:
    lines = head.decode("latin-1").split("\r\n")
    version, _, rest = lines[0].partition(" ")
    code, _, reason = rest.partition(" ")
    if not version.startswith("HTTP/1.") or not code.isdigit():
        raise HttpError(f"bad status line: {lines[0]!r}")
    return Response(int(code), reason, version, parse_headers(lines[1:]))


async def read_head(reader: asyncio.StreamReader) -> bytes | None:
    """Read up to and including the blank line. None means a clean EOF."""
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        if not exc.partial.strip():
            return None
        raise HttpError("connection closed in the middle of a message head") from exc
    except asyncio.LimitOverrunError as exc:
        raise HttpError("message head too large") from exc
    if len(head) > MAX_HEAD:
        raise HttpError("message head too large")
    return head[:-4]


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    body = bytearray()
    while True:
        size_line = await reader.readuntil(b"\r\n")
        size_text = size_line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise HttpError(f"bad chunk size {size_text!r}") from exc
        if size == 0:
            # Skip trailer fields up to the final blank line.
            while (await reader.readuntil(b"\r\n")) != b"\r\n":
                pass
            return bytes(body)
        if len(body) + size > MAX_BODY:
            raise HttpError("body too large")
        body += await reader.readexactly(size)
        if await reader.readexactly(2) != b"\r\n":
            raise HttpError("chunk not followed by CRLF")


async def read_body(
    reader: asyncio.StreamReader,
    headers: Headers,
    *,
    response_to: str | None = None,
    status: int = 0,
) -> bytes:
    """Read a message body framed the way RFC 9112 section 6.3 describes.

    response_to is the request method when reading a response, else None.
    """
    if response_to is not None:
        if response_to == "HEAD" or 100 <= status < 200 or status in (204, 304):
            return b""
    if headers.has_token("Transfer-Encoding", "chunked"):
        return await _read_chunked(reader)
    length = headers.get("Content-Length")
    if length is not None:
        if not length.strip().isdigit():
            raise HttpError(f"bad Content-Length {length!r}")
        size = int(length)
        if size > MAX_BODY:
            raise HttpError("body too large")
        return await reader.readexactly(size)
    if response_to is None:
        return b""
    # A response with no framing ends when the server closes the connection.
    body = await reader.read(MAX_BODY + 1)
    while True:
        more = await reader.read(MAX_BODY + 1 - len(body))
        if not more:
            break
        body += more
        if len(body) > MAX_BODY:
            raise HttpError("body too large")
    return body


async def read_request(reader: asyncio.StreamReader) -> Request | None:
    head = await read_head(reader)
    if head is None:
        return None
    req = parse_request_head(head)
    req.body = await read_body(reader, req.headers)
    return req


async def read_response(reader: asyncio.StreamReader, method: str) -> Response:
    head = await read_head(reader)
    if head is None:
        raise HttpError("server closed the connection without a response")
    resp = parse_response_head(head)
    resp.body = await read_body(reader, resp.headers, response_to=method, status=resp.status)
    return resp


def strip_hop_by_hop(headers: Headers, keep_upgrade: bool = False) -> Headers:
    """Copy headers without hop-by-hop ones, including any named in Connection."""
    named = {
        part.strip().lower()
        for value in headers.get_all("Connection")
        for part in value.split(",")
        if part.strip()
    }
    drop = (HOP_BY_HOP | named) - ({"upgrade"} if keep_upgrade else set())
    out = Headers([(k, v) for k, v in headers if k.lower() not in drop])
    if keep_upgrade and headers.get("Upgrade"):
        out.set("Connection", "Upgrade")
    return out

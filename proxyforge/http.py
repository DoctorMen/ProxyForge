"""Reading and writing HTTP/1.x messages on asyncio streams.

The proxy works on raw bytes so it can record exactly what crossed the wire.
Bodies are always de-chunked when read, then re-framed with Content-Length
when written, so every stored body is the plain payload.
"""

from __future__ import annotations

import asyncio
import zlib
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


class ShortBody(HttpError):
    """The peer closed the connection before sending the body it promised.

    Real servers do this (a wrong Content-Length is a finding in itself), so
    callers keep `partial`, what did arrive, instead of discarding it.
    """

    def __init__(self, partial: bytes, expected: int | None):
        promised = f"{expected} promised" if expected is not None else "an unknown number of chunked"
        super().__init__(f"server closed the connection after {len(partial)} of {promised} body bytes")
        self.partial = partial
        self.expected = expected


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
    incomplete: str = ""  # set when the body is shorter than the server promised

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
    try:
        return await _read_chunks(reader, body)
    except asyncio.IncompleteReadError as exc:
        # exc.partial holds the start of the chunk being read when the peer hung up.
        raise ShortBody(bytes(body) + exc.partial, None) from exc


async def _read_chunks(reader: asyncio.StreamReader, body: bytearray) -> bytes:
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
        try:
            return await reader.readexactly(size)
        except asyncio.IncompleteReadError as exc:
            raise ShortBody(exc.partial, size) from exc
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
    try:
        resp.body = await read_body(reader, resp.headers, response_to=method, status=resp.status)
    except ShortBody as exc:
        # Keep what arrived; the proxy records the mismatch and passes the bytes on.
        resp.body, resp.incomplete = exc.partial, str(exc)
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


DECODE_LIMIT = 4 * MAX_BODY  # a stored body may inflate this far (256 MiB), no further


def _inflate(data: bytes, wbits: int, limit: int) -> tuple[bytes, bool]:
    """zlib/gzip decode with an output cap. gzip bodies may hold several members."""
    out = bytearray()
    while data:
        d = zlib.decompressobj(wbits)
        try:
            out += d.decompress(data, limit - len(out) + 1)
        except zlib.error:
            if not out:
                raise
            break  # trailing junk after a good member: keep what decoded
        if len(out) > limit or d.unconsumed_tail:
            del out[limit:]
            return bytes(out), True
        if not d.eof or wbits != 16 + zlib.MAX_WBITS:
            break
        data = d.unused_data  # another gzip member may follow (RFC 1952)
    return bytes(out), False


def decode_content_info(body: bytes, headers: Headers) -> tuple[bytes, bool]:
    """Undo Content-Encoding so a body can be read: (decoded, cut_at_limit).

    gzip and deflate always work and are capped at DECODE_LIMIT so a
    compression bomb from the target can't eat all memory. Brotli needs the
    optional `brotli` package; without it the proxy asks servers for
    gzip/deflate instead (see proxy.py). Unknown or corrupt data passes
    through unchanged.
    """
    encoding = (headers.get("Content-Encoding") or "").lower().strip()
    if not body or encoding in ("", "identity"):
        return body, False
    try:
        if encoding in ("gzip", "x-gzip"):
            return _inflate(body, 16 + zlib.MAX_WBITS, DECODE_LIMIT)
        if encoding == "deflate":
            try:
                return _inflate(body, zlib.MAX_WBITS, DECODE_LIMIT)
            except zlib.error:
                return _inflate(body, -zlib.MAX_WBITS, DECODE_LIMIT)
        if encoding == "br":
            try:
                import brotli
            except ImportError:
                return body, False
            return brotli.decompress(body), False
    except Exception:  # corrupt data: show the raw bytes rather than nothing
        return body, False
    return body, False


def decode_content(body: bytes, headers: Headers) -> bytes:
    return decode_content_info(body, headers)[0]

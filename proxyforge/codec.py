"""Decoder: encode and decode the formats web apps hide data in.

Each codec turns bytes into bytes. `smart_decode` peels layers one at a
time (for example base64 wrapped around URL-encoding) and shows each step,
which is how you work out what a strange token or cookie really holds.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import html
import json
import re
from urllib.parse import quote_from_bytes, unquote_to_bytes


def _b64decode(data: bytes, altchars: bytes | None = None) -> bytes:
    data = re.sub(rb"\s+", b"", data)
    data += b"=" * (-len(data) % 4)
    return base64.b64decode(data, altchars=altchars, validate=True)


def _url_all(data: bytes) -> bytes:
    return "".join(f"%{b:02X}" for b in data).encode()


def _jwt_decode(data: bytes) -> bytes:
    parts = data.strip().split(b".")
    if len(parts) != 3:
        raise ValueError("a JWT has three dot-separated parts")
    header = json.loads(_b64decode(parts[0], b"-_"))
    payload = json.loads(_b64decode(parts[1], b"-_"))
    out = {"header": header, "payload": payload,
           "signature": parts[2].decode() or "(empty: unsigned token)",
           "note": "signature NOT verified"}
    return json.dumps(out, indent=2).encode()


ENCODERS = {
    "url": lambda d: quote_from_bytes(d, safe="").encode(),
    "url-all": _url_all,
    "base64": base64.b64encode,
    "base64url": lambda d: base64.urlsafe_b64encode(d).rstrip(b"="),
    "hex": lambda d: binascii.hexlify(d),
    "html": lambda d: html.escape(d.decode("utf-8", "replace"), quote=True).encode(),
    "gzip": lambda d: gzip.compress(d, mtime=0),
}

DECODERS = {
    "url": lambda d: unquote_to_bytes(d.replace(b"+", b" ")),
    "url-all": lambda d: unquote_to_bytes(d),
    "base64": lambda d: _b64decode(d),
    "base64url": lambda d: _b64decode(d, b"-_"),
    "hex": lambda d: binascii.unhexlify(re.sub(rb"[\s:]", b"", d)),
    "html": lambda d: html.unescape(d.decode("utf-8", "replace")).encode(),
    "gzip": gzip.decompress,
    "jwt": _jwt_decode,
}


def encode(data: bytes, chain: list[str]) -> bytes:
    for name in chain:
        if name not in ENCODERS:
            raise ValueError(f"unknown encoder {name!r}; choose from {', '.join(ENCODERS)}")
        data = ENCODERS[name](data)
    return data


def decode(data: bytes, chain: list[str]) -> bytes:
    for name in chain:
        if name not in DECODERS:
            raise ValueError(f"unknown decoder {name!r}; choose from {', '.join(DECODERS)}")
        data = DECODERS[name](data)
    return data


def _printable(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(text) and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.95


JWT_RE = re.compile(rb"^eyJ[\w-]*\.eyJ[\w-]*\.[\w-]*$")
HEX_RE = re.compile(rb"^(?:[0-9a-fA-F]{2})+$")
B64_RE = re.compile(rb"^[A-Za-z0-9+/]+={0,2}$")
B64URL_RE = re.compile(rb"^[A-Za-z0-9_-]+={0,2}$")


def guess(data: bytes) -> str | None:
    """Name the decoder that most likely applies to data, or None."""
    s = data.strip()
    if not s:
        return None
    if JWT_RE.match(s):
        return "jwt"
    if s[:2] == b"\x1f\x8b":
        return "gzip"
    if re.search(rb"%[0-9a-fA-F]{2}", s):
        return "url"
    if re.search(rb"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", s):
        return "html"
    candidates = []
    if HEX_RE.match(s) and len(s) >= 4:
        candidates.append("hex")
    if len(s) >= 8 and B64_RE.match(s):
        candidates.append("base64")
    if len(s) >= 8 and B64URL_RE.match(s):
        candidates.append("base64url")
    for name in candidates:
        try:
            out = DECODERS[name](s)
        except (ValueError, binascii.Error):
            continue
        if _printable(out) or out[:2] == b"\x1f\x8b":
            return name
    return None


def smart_decode(data: bytes, max_steps: int = 10) -> list[tuple[str, bytes]]:
    """Peel encodings until nothing more applies. Returns [(codec, result), ...]."""
    steps = []
    for _ in range(max_steps):
        name = guess(data)
        if name is None:
            break
        try:
            new = DECODERS[name](data.strip())
        except (ValueError, binascii.Error, OSError):
            break
        if new == data:
            break
        steps.append((name, new))
        data = new
        if name == "jwt":
            break
    return steps

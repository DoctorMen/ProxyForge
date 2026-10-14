"""Target scope: which hosts you are allowed to test.

A scope file is TOML:

    include = ["example.com", "*.example.com", "https://api.example.org/v2/*"]
    exclude = ["*.example.com/logout*", "status.example.com"]

Each entry is [scheme://]host[:port][/path]. Host and path take shell-style
wildcards (* and ?). "*.example.com" does not match "example.com" itself;
list both if you want both. Exclude always wins over include.

Active tools refuse anything out of scope. The proxy still passes
out-of-scope traffic so your browser keeps working, but does not record or
decrypt it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ScopeRule:
    scheme: str | None
    host: str
    port: int | None
    path: str | None

    @classmethod
    def parse(cls, text: str) -> "ScopeRule":
        text = text.strip()
        if not text:
            raise ValueError("empty scope entry")
        scheme = None
        if "://" in text:
            scheme, text = text.split("://", 1)
            scheme = scheme.lower()
            if scheme not in DEFAULT_PORTS:
                raise ValueError(f"unsupported scheme {scheme!r} in scope entry")
        hostport, slash, path = text.partition("/")
        host, port = hostport, None
        if hostport.startswith("["):  # IPv6 literal, e.g. [::1]:8443
            end = hostport.index("]")
            host, rest = hostport[1:end], hostport[end + 1 :]
            if rest.startswith(":"):
                port = int(rest[1:])
        elif hostport.count(":") == 1:
            host, port_text = hostport.split(":")
            port = int(port_text)
        if not host:
            raise ValueError(f"scope entry {text!r} has no host")
        return cls(scheme, host.lower(), port, "/" + path if slash else None)

    def matches_host(self, scheme: str, host: str, port: int) -> bool:
        if self.scheme and self.scheme != scheme:
            return False
        if self.port is not None and self.port != port:
            return False
        if self.port is None and self.scheme and port != DEFAULT_PORTS[self.scheme]:
            return False
        return fnmatchcase(host.lower(), self.host)

    def matches(self, scheme: str, host: str, port: int, path: str) -> bool:
        if not self.matches_host(scheme, host, port):
            return False
        if self.path is None:
            return True
        return fnmatchcase(path, self.path) or fnmatchcase(path, self.path + "*")


class Scope:
    def __init__(self, include: list[str] | None = None, exclude: list[str] | None = None):
        self.include = [ScopeRule.parse(e) for e in include or []]
        self.exclude = [ScopeRule.parse(e) for e in exclude or []]

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = tomllib.loads(Path(path).read_text())
        unknown = set(data) - {"include", "exclude"}
        if unknown:
            raise ValueError(f"unknown keys in scope file: {sorted(unknown)}")
        return cls(data.get("include", []), data.get("exclude", []))

    @property
    def empty(self) -> bool:
        return not self.include

    def allows_url(self, url: str) -> bool:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS or not parts.hostname:
            return False
        port = parts.port or DEFAULT_PORTS[scheme]
        path = parts.path or "/"
        if any(r.matches(scheme, parts.hostname, port, path) for r in self.exclude):
            return False
        return any(r.matches(scheme, parts.hostname, port, path) for r in self.include)

    def allows_host(self, scheme: str, host: str, port: int) -> bool:
        """Could any URL on this host be in scope? Used before decrypting TLS.

        Host-wide excludes (no path) block the host; path excludes are left
        for allows_url to apply per request.
        """
        if any(r.path is None and r.matches_host(scheme, host, port) for r in self.exclude):
            return False
        return any(r.matches_host(scheme, host, port) for r in self.include)

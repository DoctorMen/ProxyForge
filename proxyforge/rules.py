"""Match-and-replace rules applied to traffic as it passes through the proxy.

A rules file is TOML:

    [[rule]]
    where = "request_header"     # request_header, request_body,
                                 # response_header, response_body
    match = "^User-Agent:.*$"    # Python regular expression
    replace = "User-Agent: proxyforge"

Header rules work on one "Name: value" line at a time:
  - a match with an empty replace deletes the header line;
  - an empty match with a replace adds that line as a new header.
Body rules run the regex over the whole body (as bytes).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .http import Headers

WHERE = ("request_header", "request_body", "response_header", "response_body")


@dataclass
class Rule:
    where: str
    match: str
    replace: str
    comment: str = ""

    def __post_init__(self):
        if self.where not in WHERE:
            raise ValueError(f"rule 'where' must be one of {WHERE}, got {self.where!r}")
        if not self.match and not self.where.endswith("header"):
            raise ValueError("body rules need a match pattern")
        if self.where.endswith("body"):
            self._re = re.compile(self.match.encode())
        elif self.match:
            self._re = re.compile(self.match, re.IGNORECASE)
        else:
            self._re = None

    def apply_headers(self, headers: Headers) -> bool:
        if self._re is None:
            name, sep, value = self.replace.partition(":")
            if not sep:
                raise ValueError(f"header to add must look like 'Name: value': {self.replace!r}")
            headers.items.append((name.strip(), value.strip()))
            return True
        changed = False
        out: list[tuple[str, str]] = []
        for k, v in headers:
            line = f"{k}: {v}"
            new = self._re.sub(self.replace, line)
            if new == line:
                out.append((k, v))
                continue
            changed = True
            if new.strip():
                name, _, value = new.partition(":")
                out.append((name.strip(), value.strip()))
        headers.items = out
        return changed

    def apply_body(self, body: bytes) -> tuple[bytes, bool]:
        new = self._re.sub(self.replace.encode(), body)
        return new, new != body


class RuleSet:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules = list(rules or [])

    @classmethod
    def load(cls, path: str | Path) -> "RuleSet":
        data = tomllib.loads(Path(path).read_text())
        return cls([Rule(**r) for r in data.get("rule", [])])

    def _apply(self, prefix: str, headers: Headers, body: bytes) -> tuple[bytes, list[int]]:
        hits = []
        for i, rule in enumerate(self.rules):
            if rule.where == f"{prefix}_header":
                if rule.apply_headers(headers):
                    hits.append(i)
            elif rule.where == f"{prefix}_body":
                body, changed = rule.apply_body(body)
                if changed:
                    hits.append(i)
        return body, hits

    def apply_request(self, headers: Headers, body: bytes) -> tuple[bytes, list[int]]:
        """Edits headers in place; returns the new body and the indexes of rules that fired."""
        return self._apply("request", headers, body)

    def apply_response(self, headers: Headers, body: bytes) -> tuple[bytes, list[int]]:
        return self._apply("response", headers, body)

"""Comparer: show what changed between two requests or responses.

The useful question in testing is usually "what is different when I change
one thing?" For example a 200 vs 403, or one extra field in a JSON body
that leaks another user's data.
"""

from __future__ import annotations

import difflib
import json

from .http import Headers


def _lines(body: bytes) -> list[str] | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Pretty-print JSON so a one-line API response diffs field by field.
    try:
        text = json.dumps(json.loads(text), indent=2, sort_keys=True)
    except (ValueError, TypeError):
        pass
    return text.splitlines()


def header_changes(a: Headers, b: Headers) -> list[str]:
    ignore = {"date", "etag", "content-length", "last-modified", "expires", "connection", "keep-alive"}
    da = {k.lower(): v for k, v in a}
    db = {k.lower(): v for k, v in b}
    out = []
    for name in sorted(set(da) | set(db)):
        if name in ignore:
            continue
        if name not in db:
            out.append(f"- {name}: {da[name]}")
        elif name not in da:
            out.append(f"+ {name}: {db[name]}")
        elif da[name] != db[name]:
            out.append(f"~ {name}: {da[name]}  ->  {db[name]}")
    return out


def body_diff(a: bytes, b: bytes, label_a: str, label_b: str, context: int = 3) -> list[str]:
    la, lb = _lines(a), _lines(b)
    if la is None or lb is None:
        if a == b:
            return []
        first = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        return [f"binary bodies differ: {len(a)}B vs {len(b)}B, first difference at byte {first}"]
    return list(difflib.unified_diff(la, lb, label_a, label_b, n=context, lineterm=""))

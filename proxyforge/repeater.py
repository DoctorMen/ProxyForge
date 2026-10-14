"""Repeater: take a request, change it, send it again, and compare.

Requests are edited as plain text ("raw" form), exactly what goes on the
wire. A raw request file looks like:

    GET /rest/basket/1 HTTP/1.1
    Host: 127.0.0.1:3000
    Authorization: Bearer eyJ...

    (optional body)

Every resend is saved to history as a new flow, so your testing leaves an
evidence trail you can cite in a report.
"""

from __future__ import annotations

from .http import HttpError, Request, parse_request_head
from .history import Flow


def to_raw(req: Request) -> str:
    """Request -> editable text. Binary bodies can't round-trip through an editor."""
    head = req.head_bytes().decode("latin-1").replace("\r\n", "\n")
    try:
        body = req.body.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("this request has a binary body; edit it with --body @file instead")
    return head + body


def from_raw(text: str) -> Request:
    """Editable text -> Request. Accepts \\n or \\r\\n line endings."""
    text = text.replace("\r\n", "\n")
    # Editors often add a trailing newline; a GET with only that has no body.
    head, sep, body = text.partition("\n\n")
    if not sep:
        head, body = text.rstrip("\n"), ""
    req = parse_request_head(head.strip("\n").replace("\n", "\r\n").encode("latin-1"))
    if body.strip("\n") == "" and req.headers.get("Content-Length") in (None, "0"):
        body = ""
    req.body = body.encode("utf-8")
    return req


def apply_edits(
    req: Request,
    *,
    method: str | None = None,
    path: str | None = None,
    set_headers: list[str] | None = None,
    body: bytes | None = None,
) -> Request:
    """Return a copy of req with command-line edits applied.

    set_headers entries are "Name: value" (replace or add) or "Name:" (remove).
    """
    out = Request(req.method, req.target, req.version, req.headers.copy(), req.body)
    if method:
        out.method = method.upper()
    if path:
        if not path.startswith("/"):
            raise ValueError("--path must start with /")
        out.target = path
    for item in set_headers or []:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"header must look like 'Name: value' or 'Name:', got {item!r}")
        if value.strip():
            out.headers.set(name.strip(), value.strip())
        else:
            out.headers.remove(name.strip())
    if body is not None:
        out.body = body
    return out


def describe(flow: Flow) -> str:
    """One summary line for a sent flow."""
    if flow.response is None:
        return f"#{flow.id}  ERR  {flow.request.method} {flow.url}  {flow.error}"
    r = flow.response
    return (f"#{flow.id}  {r.status} {r.reason}  {flow.request.method} {flow.url}  "
            f"{len(r.body)}B  {flow.duration_ms}ms")


__all__ = ["to_raw", "from_raw", "apply_edits", "describe", "HttpError"]

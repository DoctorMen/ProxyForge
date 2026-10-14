"""Send one HTTP request straight to a server (no proxy in between).

Repeater and, later, Intruder and the scanner use this. Every active tool
checks the target against the scope before sending anything.
"""

from __future__ import annotations

import asyncio
import ssl
import time

from .history import Flow
from .http import HttpError, Request, read_response
from .scope import Scope

TIMEOUT = 30


class OutOfScope(Exception):
    """The target is not in the scope file, so active tools must not touch it."""


def check_scope(url: str, scope: Scope | None, no_scope: bool) -> None:
    """Active tools need an explicit decision about scope.

    Pass a scope file (the URL must be in it), or pass no_scope=True to say
    you own the target. Refusing by default protects you from typos that
    would send attack traffic to a host you're not allowed to test.
    """
    if scope is not None and not scope.empty:
        if not scope.allows_url(url):
            raise OutOfScope(f"{url} is not in scope")
        return
    if not no_scope:
        raise OutOfScope(
            "active tools need a scope file (-s scope.toml) or --no-scope "
            "to confirm you own the target"
        )


def default_context(insecure: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def prepare(req: Request, host: str, port: int, scheme: str) -> Request:
    """Fix up framing so the server reads exactly the body we send."""
    out = Request(req.method, req.target, "HTTP/1.1", req.headers.copy(), req.body)
    if not out.headers.get("Host"):
        default = 443 if scheme == "https" else 80
        host_part = f"[{host}]" if ":" in host else host
        out.headers.set("Host", host_part if port == default else f"{host_part}:{port}")
    out.headers.remove("Transfer-Encoding")
    if out.body or out.headers.get("Content-Length") is not None or out.method in ("POST", "PUT", "PATCH"):
        out.headers.set("Content-Length", str(len(out.body)))
    out.headers.set("Connection", "close")
    return out


async def send(
    scheme: str,
    host: str,
    port: int,
    req: Request,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = TIMEOUT,
) -> Flow:
    """Send req and return a Flow (response or error filled in). Never raises for network errors."""
    out = prepare(req, host, port, scheme)
    flow = Flow(scheme, host, port, out)
    started = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port,
                ssl=(ssl_context or default_context()) if scheme == "https" else None,
                server_hostname=host if scheme == "https" else None,
                limit=256 * 1024,
            ),
            timeout,
        )
        writer.write(out.to_bytes())
        await writer.drain()
        resp = await asyncio.wait_for(read_response(reader, out.method), timeout)
        while 100 <= resp.status < 200 and resp.status != 101:
            resp = await asyncio.wait_for(read_response(reader, out.method), timeout)
        flow.response = resp
        if resp.incomplete:
            flow.note = resp.incomplete
    except (OSError, ssl.SSLError, HttpError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        flow.error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    finally:
        flow.duration_ms = int((time.monotonic() - started) * 1000)
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass
    return flow

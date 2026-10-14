"""The intercepting proxy.

Point a browser (or curl -x) at it and every in-scope request and response is
recorded to the project's history. HTTPS is decrypted by answering CONNECT
with a certificate signed by the proxy's own CA (see ca.py).

Request flow for one client connection:

    client --plain HTTP--> proxy --> upstream server        (http:// URLs)
    client --CONNECT host:443--> proxy
           <--200-- ; TLS with our fake cert ; requests --> upstream over TLS

Out-of-scope HTTPS is tunnelled without decryption, so sites you are not
testing keep their real certificates and nothing about them is stored.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Callable

from .ca import CertAuthority
from .history import Flow, History
from .http import (
    Headers,
    HttpError,
    Request,
    Response,
    parse_request_head,
    read_body,
    read_head,
    read_response,
    strip_hop_by_hop,
)
from .rules import RuleSet
from .scope import Scope

CONNECT_TIMEOUT = 15
RESPONSE_TIMEOUT = 120
LOCAL_HOST = "proxyforge"  # browse to http://proxyforge/ through the proxy to get the CA


def split_authority(authority: str, default_port: int) -> tuple[str, int]:
    """'host:port' or '[v6]:port' -> (host, port)."""
    if authority.startswith("["):
        end = authority.index("]")
        host, rest = authority[1:end], authority[end + 1 :]
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    host, sep, port = authority.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        return host, int(port)
    return authority, default_port


def split_absolute_url(target: str) -> tuple[str, str, int, str]:
    """'http://h:8080/a?b' -> ('http', 'h', 8080, '/a?b') keeping the raw path."""
    scheme, sep, rest = target.partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in ("http", "https"):
        raise HttpError(f"proxy request needs an absolute http(s) URL, got {target!r}")
    cut = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    authority, path = rest[:cut], rest[cut:]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if not path.startswith("/"):
        path = "/" + path
    host, port = split_authority(authority, 443 if scheme == "https" else 80)
    if not host:
        raise HttpError(f"no host in {target!r}")
    return scheme, host.lower(), port, path


def client_wants_keep_alive(req: Request) -> bool:
    h = req.headers
    if h.has_token("Connection", "close") or h.has_token("Proxy-Connection", "close"):
        return False
    if req.version == "HTTP/1.0":
        return h.has_token("Connection", "keep-alive") or h.has_token("Proxy-Connection", "keep-alive")
    return True


READABLE_CODINGS = ("gzip", "x-gzip", "deflate", "identity")


def narrow_accept_encoding(value: str) -> str:
    """Drop codings we can't decode (br, zstd) from an Accept-Encoding value.

    The client's own list is respected otherwise: "br" alone becomes
    "identity" rather than something the client never offered.
    """
    kept = []
    for part in value.split(","):
        coding = part.split(";", 1)[0].strip().lower()
        if coding in READABLE_CODINGS and part.strip() not in kept:
            kept.append(part.strip())
    return ", ".join(kept) if kept else "identity"


def has_body_semantics(method: str, status: int) -> bool:
    return method != "HEAD" and status >= 200 and status not in (204, 304)


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, ssl.SSLError):
        pass


class ProxyServer:
    def __init__(
        self,
        ca: CertAuthority,
        history: History,
        scope: Scope | None = None,
        rules: RuleSet | None = None,
        *,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
        upstream_ssl: ssl.SSLContext | None = None,
        record_out_of_scope: bool = False,
        readable_bodies: bool = True,
        log: Callable[[str], None] = print,
    ):
        self.ca = ca
        self.history = history
        self.scope = scope or Scope()
        self.rules = rules or RuleSet()
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.record_out_of_scope = record_out_of_scope
        # Browsers ask for brotli/zstd, which the standard library can't unpack.
        # Asking for gzip/deflate instead keeps every stored body readable by
        # `show`, `diff` and the HAR export without extra packages.
        self.readable_bodies = readable_bodies
        self.log = log
        if upstream_ssl is None:
            upstream_ssl = ssl.create_default_context()
            upstream_ssl.set_alpn_protocols(["http/1.1"])
        self.upstream_ssl = upstream_ssl
        self._server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._handle_client, self.listen_host, self.listen_port, limit=256 * 1024
        )
        self.listen_port = self._server.sockets[0].getsockname()[1]
        return self.listen_port

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._tasks):
            task.cancel()

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()

    # -- scope -------------------------------------------------------------

    def _recorded(self, url: str) -> bool:
        return self.scope.empty or self.record_out_of_scope or self.scope.allows_url(url)

    def _decrypt(self, host: str, port: int) -> bool:
        return self.scope.empty or self.record_out_of_scope or self.scope.allows_host("https", host, port)

    # -- connection handling ----------------------------------------------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._serve(reader, writer, "http", None, None)
        except (ConnectionError, OSError, ssl.SSLError, asyncio.IncompleteReadError):
            pass
        except HttpError as exc:
            await self._send_error(writer, 400, str(exc), keep_alive=False)
        finally:
            self._tasks.discard(task)
            await _close(writer)

    async def _serve(self, reader, writer, scheme: str, tls_host: str | None, tls_port: int | None) -> None:
        while True:
            head = await read_head(reader)
            if head is None:
                return
            req = parse_request_head(head)
            if req.method == "CONNECT":
                if scheme != "http":
                    raise HttpError("CONNECT inside a TLS tunnel is not supported")
                await self._connect(req, reader, writer)
                return
            if req.headers.get("Expect", "").lower() == "100-continue":
                req.headers.remove("Expect")
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            req.body = await read_body(reader, req.headers)
            keep_alive = client_wants_keep_alive(req)

            if scheme == "http" and req.target.startswith("/"):
                await self._serve_local(req, writer, keep_alive)
            else:
                if req.target.startswith(("http://", "https://")):
                    t_scheme, host, port, path = split_absolute_url(req.target)
                    if scheme == "https" and t_scheme != "https":
                        raise HttpError("plain-HTTP URL sent inside a TLS tunnel")
                else:
                    t_scheme, host, port, path = scheme, tls_host, tls_port, req.target
                if host == LOCAL_HOST:
                    await self._serve_local(Request(req.method, path, req.version, req.headers, req.body), writer, keep_alive)
                elif await self._forward(t_scheme, host, port, path, req, reader, writer, keep_alive):
                    return  # the connection became a raw tunnel (e.g. WebSocket)
            if not keep_alive:
                return

    async def _connect(self, req: Request, reader, writer) -> None:
        host, port = split_authority(req.target, 443)
        host = host.lower()
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        if not self._decrypt(host, port):
            await self._tunnel(host, port, reader, writer)
            return
        await writer.start_tls(self.ca.server_context(host))
        await self._serve(reader, writer, "https", host, port)

    async def _tunnel(self, host: str, port: int, reader, writer) -> None:
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            return
        await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        await _close(up_writer)

    # -- forwarding --------------------------------------------------------

    async def _forward(self, scheme, host, port, path, req: Request, reader, writer, keep_alive) -> bool:
        upgrade = bool(req.headers.get("Upgrade")) and req.headers.has_token("Connection", "upgrade")
        headers = strip_hop_by_hop(req.headers, keep_upgrade=upgrade)
        default_port = 443 if scheme == "https" else 80
        if not headers.get("Host"):
            host_part = f"[{host}]" if ":" in host else host
            headers.set("Host", host_part if port == default_port else f"{host_part}:{port}")
        out = Request(req.method, path, "HTTP/1.1", headers, req.body)
        flow = Flow(scheme, host, port, out)
        record = self._recorded(flow.url)

        if record and self.readable_bodies and out.headers.get("Accept-Encoding"):
            out.headers.set("Accept-Encoding", narrow_accept_encoding(out.headers.get("Accept-Encoding")))
        if record and self.rules.rules:
            out.body, flow.rules_fired = self.rules.apply_request(out.headers, out.body)
        had_framing = req.headers.get("Content-Length") is not None or req.headers.has_token(
            "Transfer-Encoding", "chunked"
        )
        if out.body or had_framing:
            out.headers.set("Content-Length", str(len(out.body)))
        if not upgrade:
            out.headers.set("Connection", "close")

        started = time.monotonic()
        up_writer = None
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=self.upstream_ssl if scheme == "https" else None,
                    server_hostname=host if scheme == "https" else None,
                    limit=256 * 1024,
                ),
                CONNECT_TIMEOUT,
            )
            up_writer.write(out.to_bytes())
            await up_writer.drain()
            resp = await asyncio.wait_for(read_response(up_reader, out.method), RESPONSE_TIMEOUT)
            while 100 <= resp.status < 200 and resp.status != 101:
                resp = await asyncio.wait_for(read_response(up_reader, out.method), RESPONSE_TIMEOUT)
        except (OSError, ssl.SSLError, HttpError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            if up_writer is not None:
                await _close(up_writer)
            flow.error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            flow.duration_ms = int((time.monotonic() - started) * 1000)
            if record:
                self.history.add(flow)
            self._log_flow(flow)
            await self._send_error(writer, 502, f"proxyforge could not reach {host}:{port}\n{flow.error}", keep_alive)
            return False
        flow.duration_ms = int((time.monotonic() - started) * 1000)
        if resp.incomplete:
            flow.note = resp.incomplete

        if resp.status == 101:
            flow.response = resp
            flow.note = "connection upgraded; later frames are not recorded"
            if record:
                self.history.add(flow)
            self._log_flow(flow)
            writer.write(resp.head_bytes())
            await writer.drain()
            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
            await _close(up_writer)
            return True
        await _close(up_writer)

        client_headers = strip_hop_by_hop(resp.headers)
        body = resp.body
        if record and self.rules.rules:
            body, fired = self.rules.apply_response(client_headers, body)
            flow.rules_fired += fired
        if has_body_semantics(out.method, resp.status):
            client_headers.set("Content-Length", str(len(body)))
        client_headers.set("Connection", "keep-alive" if keep_alive else "close")
        flow.response = Response(resp.status, resp.reason, resp.version, client_headers.copy(), body)
        flow.response.headers.remove("Connection")
        if record:
            self.history.add(flow)
        self._log_flow(flow)
        writer.write(Response(resp.status, resp.reason, "HTTP/1.1", client_headers, body).to_bytes())
        await writer.drain()
        return False

    # -- local pages and errors ---------------------------------------------

    async def _serve_local(self, req: Request, writer, keep_alive: bool) -> None:
        if req.target.split("?")[0] in ("/cert", "/ca.pem"):
            body, ctype = self.ca.cert_pem, "application/x-x509-ca-cert"
            extra = [("Content-Disposition", 'attachment; filename="proxyforge-ca.pem"')]
        else:
            body = (
                b"<!doctype html><title>proxyforge</title><h1>proxyforge is running</h1>"
                b'<p><a href="/cert">Download the CA certificate</a> and trust it in your '
                b"browser to inspect HTTPS. Only do this in a browser profile you use for testing.</p>"
            )
            ctype, extra = "text/html; charset=utf-8", []
        headers = Headers([("Content-Type", ctype), ("Content-Length", str(len(body))), *extra,
                           ("Connection", "keep-alive" if keep_alive else "close")])
        writer.write(Response(200, "OK", "HTTP/1.1", headers, b"" if req.method == "HEAD" else body).to_bytes())
        await writer.drain()

    async def _send_error(self, writer, status: int, message: str, keep_alive: bool) -> None:
        body = (message + "\n").encode()
        reason = {400: "Bad Request", 502: "Bad Gateway"}.get(status, "Error")
        headers = Headers([("Content-Type", "text/plain; charset=utf-8"),
                           ("Content-Length", str(len(body))),
                           ("Connection", "keep-alive" if keep_alive else "close")])
        try:
            writer.write(Response(status, reason, "HTTP/1.1", headers, body).to_bytes())
            await writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            pass

    def _log_flow(self, flow: Flow) -> None:
        status = flow.response.status if flow.response else "ERR"
        size = len(flow.response.body) if flow.response else 0
        fid = flow.id if flow.id is not None else "-"
        extra = f"  {flow.error}" if flow.error else ""
        self.log(f"{fid:>5}  {status}  {flow.request.method:<7} {flow.url}  {size}B  {flow.duration_ms}ms{extra}")

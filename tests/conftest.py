"""Test fixtures: a small upstream web app (HTTP and HTTPS) and a running proxy.

Everything listens on 127.0.0.1 with random ports, so tests need no network.
"""

from __future__ import annotations

import asyncio
import gzip
import http.server
import socket
import socketserver
import ssl
import threading
from pathlib import Path

import pytest

from proxyforge.ca import CertAuthority
from proxyforge.history import History
from proxyforge.proxy import ProxyServer
from proxyforge.rules import RuleSet
from proxyforge.scope import Scope


class AppHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status: int, body: bytes, ctype="text/plain", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.path == "/hello":
            self._send(200, b"hello world", extra=[("Set-Cookie", "session=abc123; HttpOnly")])
        elif self.path.startswith("/headers"):
            text = "".join(f"{k}: {v}\n" for k, v in self.headers.items())
            self._send(200, text.encode())
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"first-", b"second-", b"third"):
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif self.path == "/gzip":
            self._send(200, gzip.compress(b'{"secret": "gzipped json"}'), "application/json",
                       [("Content-Encoding", "gzip")])
        elif self.path == "/nocontent":
            self.send_response(204)
            self.end_headers()
        elif self.path == "/short":
            # Promises 20 bytes, sends 12, hangs up: a wrong Content-Length.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "20")
            self.end_headers()
            self.wfile.write(b"only twelve!")
            self.close_connection = True
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self._send(200, b"echo:" + body)


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


@pytest.fixture(scope="session")
def site_ca(tmp_path_factory) -> CertAuthority:
    """Stands in for a real public CA that signed the upstream site's certificate."""
    return CertAuthority(tmp_path_factory.mktemp("site-ca"))


@pytest.fixture(scope="session")
def http_app():
    server = _serve(ThreadingServer(("127.0.0.1", 0), AppHandler))
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture(scope="session")
def https_app(site_ca):
    server = ThreadingServer(("127.0.0.1", 0), AppHandler)
    ctx = site_ca.server_context("localhost")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    _serve(server)
    yield server.server_address[1]
    server.shutdown()


class UpgradeHandler(socketserver.StreamRequestHandler):
    """Answers any request with 101 Switching Protocols, then echoes bytes."""

    def handle(self):
        while self.rfile.readline() not in (b"\r\n", b""):
            pass
        self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\n\r\n")
        while data := self.request.recv(1024):
            self.request.sendall(data.upper())


@pytest.fixture(scope="session")
def upgrade_app():
    server = _serve(socketserver.ThreadingTCPServer(("127.0.0.1", 0), UpgradeHandler))
    server.daemon_threads = True
    yield server.server_address[1]
    server.shutdown()


class RunningProxy:
    """Runs a ProxyServer on its own event loop in a background thread."""

    def __init__(self, tmp: Path, site_ca: CertAuthority, scope=None, rules=None, **kw):
        self.ca = CertAuthority(tmp / "proxy-ca")
        self.db_path = str(tmp / "project.db")
        self.history = History(self.db_path)
        # SQLite objects may only be used on the thread that made them, so
        # the proxy gets its own History on the loop thread.
        upstream = ssl.create_default_context(cafile=str(site_ca.cert_path))
        self.lines: list[str] = []
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)
            self.proxy = ProxyServer(
                self.ca, History(self.db_path), scope or Scope(), rules or RuleSet(),
                listen_port=0, upstream_ssl=upstream, log=self.lines.append, **kw,
            )
            self.port = self.loop.run_until_complete(self.proxy.start())
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        assert ready.wait(10)

    def client_context(self) -> ssl.SSLContext:
        """What a browser that trusts the proxy CA would use."""
        return ssl.create_default_context(cafile=str(self.ca.cert_path))

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.proxy.close(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.history.close()


@pytest.fixture
def make_proxy(tmp_path, site_ca):
    started = []

    def make(**kw) -> RunningProxy:
        p = RunningProxy(tmp_path, site_ca, **kw)
        started.append(p)
        return p

    yield make
    for p in started:
        p.stop()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

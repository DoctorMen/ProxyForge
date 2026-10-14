"""Route maps and the coverage report: what the app has versus what you've hit.

Recon tools find routes by reading code; the proxy sees the routes you
actually exercised. Comparing the two answers three questions a tester
needs before writing anything up:

    untested   routes the code has that never appeared in history
    tested     routes you hit, with the statuses you got
    unmapped   paths you hit that the static map has no route for
               (middleware, generated CRUD, mounted routers, dynamic code)

Route maps come from REA's `analyze-javascript-application` Evidence JSON
or from a plain text list, and are stored in the project database so the
report can be re-run as the history grows.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .history import Flow

ROUTE_VERBS = {
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH",
    "head": "HEAD", "options": "OPTIONS", "all": "ANY", "route": "ANY", "use": "ANY",
}
# Receivers whose .get/.post/... are HTTP *clients*, not route registrations.
CLIENT_RECEIVERS = {
    "fetch", "axios", "http", "$http", "httpclient", "request", "got", "superagent", "ky",
    "client", "api", "agent", "session", "requests", "xhr",
}
# Static files (served by middleware) are counted, not listed, in the report.
STATIC_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".avif", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".webm", ".txt",
    ".html", ".htm", ".json", ".xml", ".pdf", ".zip",
}


@dataclass
class Route:
    method: str            # GET, POST, ... or ANY
    pattern: str           # Express-style path: /api/Users/:id
    kind: str              # server | router | client | spa
    source: str = ""       # file the route came from
    line: int | None = None
    mechanism: str = ""    # how it was found, e.g. call:app.get
    origin: str = ""       # file the map was imported from
    id: int | None = None

    @property
    def where(self) -> str:
        return f"{self.source}:{self.line}" if self.source and self.line else self.source

    @property
    def regex(self) -> re.Pattern:
        return pattern_regex(self.pattern)

    def matches(self, method: str, path: str) -> bool:
        if self.method != "ANY" and self.method != method.upper():
            return False
        return self.regex.match(path_only(path)) is not None


@dataclass
class ImportResult:
    routes: list[Route]
    skipped: Counter = field(default_factory=Counter)
    warnings: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


# -- Express-style patterns ----------------------------------------------------

def path_only(target: str) -> str:
    """'/a/b?x=1#f' -> '/a/b'. Also accepts full URLs."""
    if "://" in target:
        target = urlsplit(target).path or "/"
    # A raw request target has no fragment: a '#' in it is part of the path.
    path = target.split("?", 1)[0]
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path or "/"


_PATTERN_CACHE: dict[str, re.Pattern] = {}


def pattern_regex(pattern: str) -> re.Pattern:
    """Compile an Express 4 style path to a regex over the request path.

    :name      one segment            /api/Users/:id   matches /api/Users/7
    :name?     optional segment       /files/:name?    matches /files and /files/a
    *  or **   anything               /ftp/*           matches /ftp/x/y
    Trailing slashes are ignored and matching is case-insensitive, which is
    how Express matches by default.
    """
    cached = _PATTERN_CACHE.get(pattern)
    if cached is not None:
        return cached
    out = []
    for piece in re.split(r"(\*+|:[A-Za-z_][A-Za-z0-9_]*\??)", pattern):
        if not piece:
            continue
        if piece.startswith("*"):
            if out and out[-1].endswith("/"):
                # "/ftp/*" also covers /ftp and /ftp/ (the star may be empty).
                out[-1] = out[-1][:-1]
                out.append("(?:/.*)?")
            else:
                out.append(".*")
        elif piece.startswith(":"):
            if piece.endswith("?"):
                # The preceding "/" belongs to the optional segment.
                if out and out[-1].endswith("/"):
                    out[-1] = out[-1][:-1]
                out.append("(?:/[^/]+)?")
            else:
                out.append("[^/]+")
        else:
            out.append(re.escape(piece))
    body = "".join(out)
    if len(pattern) > 1 and pattern.endswith("/"):
        body = body[: -len(re.escape("/"))]
    regex = re.compile("^" + body + "/?$", re.IGNORECASE)
    _PATTERN_CACHE[pattern] = regex
    return regex


# -- importing maps ------------------------------------------------------------

def _classify(mechanism: str, value: str) -> tuple[str, str] | None:
    """(method, kind) for one REA endpoint observation, or None to skip it."""
    if not isinstance(value, str) or not value:
        return None
    if mechanism == "property:path":
        # Angular/React router paths: pages in the browser, not HTTP endpoints.
        return ("ANY", "spa") if (value.startswith("/") or value == "**") else None
    if mechanism.startswith("call:"):
        receiver, _, verb = mechanism[5:].rpartition(".")
        if not receiver and verb in ("fetch", "request", "axios", "got", "ky"):
            return ("ANY", "client") if value.startswith(("/", "http://", "https://")) else None
        verb = verb.lower()
        if verb not in ROUTE_VERBS or not value.startswith("/"):
            return None
        last = receiver.rsplit(".", 1)[-1].lower()
        if last in CLIENT_RECEIVERS or last.endswith("client"):
            return (ROUTE_VERBS[verb] if verb != "route" else "ANY", "client")
        if last in ("router", "route", "routes") or last.endswith("router"):
            return (ROUTE_VERBS[verb], "router")
        return (ROUTE_VERBS[verb], "server")
    return None


def load_rea(path: str | Path) -> ImportResult:
    """Read routes out of REA `analyze-javascript-application` Evidence JSON."""
    path = Path(path)
    with path.open("rb") as fh:
        doc = json.load(fh)
    body = doc.get("normalized_result", doc) if isinstance(doc, dict) else {}
    graph = body.get("graph") if isinstance(body, dict) else None
    if not isinstance(graph, dict) or "nodes" not in graph:
        raise ValueError(
            f"{path} is not REA analyze-javascript-application output "
            "(expected normalized_result.graph.nodes)"
        )
    result = ImportResult(routes=[], stats=dict(body.get("statistics") or {}))
    seen: dict[tuple[str, str, str], Route] = {}
    for node in graph["nodes"]:
        if node.get("kind") != "endpoint":
            continue
        for obs in node.get("observations", []):
            props = obs.get("properties") or {}
            mechanism, value = props.get("mechanism", ""), props.get("value", "")
            classified = _classify(mechanism, value)
            if classified is None:
                result.skipped[mechanism or "?"] += 1
                continue
            method, kind = classified
            key = (method, value, kind)
            if key in seen:
                continue
            loc = ((obs.get("evidence") or {}).get("location") or {})
            source, line = "", None
            if loc.get("available") and isinstance(loc.get("value"), dict):
                source = loc["value"].get("source", "") or ""
                start = loc["value"].get("start") or {}
                line = start.get("line")
            seen[key] = Route(method, value, kind, source, line, mechanism, path.name)
    result.routes = list(seen.values())

    # REA tells you when it ran out of room; the usual fix is to point it at
    # a smaller folder (the server code without the frontend and test data).
    starved = sorted({
        m.group(1) for text in body.get("limitations", []) if isinstance(text, str)
        for m in [re.match(r"^(\S+): Resource constraint", text)] if m
    })
    if starved:
        shown = ", ".join(starved[:5]) + (f" and {len(starved) - 5} more" if len(starved) > 5 else "")
        plural = "file" if len(starved) == 1 else "files"
        result.warnings.append(
            f"REA skipped semantic analysis of {len(starved)} {plural} for lack of result budget "
            f"({shown}). Routes registered there may be missing: run REA on the folder that "
            "holds the server code only (not the frontend or test data)."
        )
    coverage = graph.get("coverage") or {}
    if coverage.get("status") not in (None, "complete"):
        result.warnings.append(f"REA reports graph coverage '{coverage.get('status')}'; "
                               "treat missing routes as unknown, not absent.")
    return result


def load_list(path: str | Path) -> ImportResult:
    """Read 'METHOD /path' or '/path' lines (any method); '#' starts a comment."""
    path = Path(path)
    result = ImportResult(routes=[])
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 1:
            method, pattern = "ANY", parts[0]
        elif len(parts) == 2:
            method, pattern = parts[0].upper(), parts[1]
        else:
            raise ValueError(f"{path}:{n}: expected 'METHOD /path' or '/path', got {raw!r}")
        if method not in set(ROUTE_VERBS.values()) | {"ANY", "*"}:
            raise ValueError(f"{path}:{n}: unknown method {method!r}")
        if not pattern.startswith("/"):
            raise ValueError(f"{path}:{n}: path must start with /, got {pattern!r}")
        result.routes.append(Route("ANY" if method == "*" else method, pattern, "server",
                                   path.name, n, "list", path.name))
    return result


# -- storage -------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS routes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    origin    TEXT NOT NULL,
    kind      TEXT NOT NULL,
    method    TEXT NOT NULL,
    pattern   TEXT NOT NULL,
    mechanism TEXT NOT NULL DEFAULT '',
    source    TEXT NOT NULL DEFAULT '',
    line      INTEGER
);
"""


class RouteStore:
    """Imported routes, kept in the same SQLite project file as the history."""

    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def replace(self, origin: str, routes: list[Route]) -> int:
        """Store routes for one origin file, dropping that file's earlier import."""
        self.db.execute("DELETE FROM routes WHERE origin = ?", (origin,))
        self.db.executemany(
            "INSERT INTO routes (origin, kind, method, pattern, mechanism, source, line) VALUES (?,?,?,?,?,?,?)",
            [(origin, r.kind, r.method, r.pattern, r.mechanism, r.source, r.line) for r in routes],
        )
        self.db.commit()
        return len(routes)

    def all(self, kinds: tuple[str, ...] | None = None) -> list[Route]:
        rows = self.db.execute(
            "SELECT id, origin, kind, method, pattern, mechanism, source, line FROM routes ORDER BY id"
        ).fetchall()
        routes = [Route(method, pattern, kind, source, line, mechanism, origin, rid)
                  for rid, origin, kind, method, pattern, mechanism, source, line in rows]
        if kinds:
            routes = [r for r in routes if r.kind in kinds]
        return routes

    def origins(self) -> list[tuple[str, int]]:
        return self.db.execute(
            "SELECT origin, count(*) FROM routes GROUP BY origin ORDER BY origin"
        ).fetchall()


# -- the report ----------------------------------------------------------------

@dataclass
class Hit:
    route: Route
    flows: list[Flow]

    @property
    def statuses(self) -> list[int]:
        return sorted({f.response.status for f in self.flows if f.response})


@dataclass
class Unmapped:
    method: str
    path: str
    flows: list[Flow]


@dataclass
class Report:
    host: str | None
    tested: list[Hit]
    untested: list[Route]
    unmapped: list[Unmapped]
    static: list[Unmapped]
    flows_seen: int

    @property
    def total(self) -> int:
        return len(self.tested) + len(self.untested)

    @property
    def percent(self) -> int:
        return round(100 * len(self.tested) / self.total) if self.total else 0

    def to_dict(self) -> dict:
        def route(r: Route) -> dict:
            return {"method": r.method, "pattern": r.pattern, "kind": r.kind,
                    "source": r.source, "line": r.line, "mechanism": r.mechanism}
        return {
            "host": self.host,
            "flows_seen": self.flows_seen,
            "routes": self.total,
            "tested_count": len(self.tested),
            "percent": self.percent,
            "tested": [{**route(h.route), "statuses": h.statuses, "flows": [f.id for f in h.flows]}
                       for h in self.tested],
            "untested": [route(r) for r in self.untested],
            "unmapped": [{"method": u.method, "path": u.path, "flows": [f.id for f in u.flows]}
                         for u in self.unmapped],
            "static": [{"method": u.method, "path": u.path, "flows": [f.id for f in u.flows]}
                       for u in self.static],
        }


def coverage(routes: list[Route], flows: list[Flow], host: str | None = None,
             kinds: tuple[str, ...] = ("server", "router")) -> Report:
    """Match recorded flows against the route map.

    Only server-side routes count toward coverage; client calls and SPA
    pages are not HTTP endpoints you can test directly.
    """
    routes = [r for r in routes if r.kind in kinds]
    if host:
        hostname = host.split(":")[0].lower()
        flows = [f for f in flows if f.host.lower() == hostname
                 and (":" not in host or f.port == int(host.rsplit(":", 1)[1]))]
    hits: dict[int, list[Flow]] = defaultdict(list)
    loose: dict[tuple[str, str], list[Flow]] = defaultdict(list)
    for flow in flows:
        method, path = flow.request.method.upper(), path_only(flow.request.target)
        # Longest pattern wins so /api/Users/:id beats /api/Users/* style overlaps.
        candidates = [i for i, r in enumerate(routes) if r.matches(method, path)]
        if candidates:
            best = max(candidates, key=lambda i: (len(routes[i].pattern), routes[i].method != "ANY"))
            hits[best].append(flow)
        else:
            loose[(method, path)].append(flow)
    tested = [Hit(routes[i], hits[i]) for i in sorted(hits)]
    untested = [r for i, r in enumerate(routes) if i not in hits]
    unmapped, static = [], []
    for (method, path), fl in sorted(loose.items()):
        item = Unmapped(method, path, fl)
        ext = Path(path).suffix.lower()
        (static if ext in STATIC_EXTENSIONS else unmapped).append(item)
    return Report(host, tested, untested, unmapped, static, len(flows))


def _method_key(m: str) -> int:
    order = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"]
    return order.index(m) if m in order else len(order)


def format_report(report: Report, show: str = "all", examples: int = 5) -> str:
    lines = []
    where = f" for {report.host}" if report.host else ""
    lines.append(f"Coverage{where}: {len(report.tested)} of {report.total} server routes hit "
                 f"({report.percent}%) across {report.flows_seen} flows")
    lines.append(f"  untested {len(report.untested):>4}   routes in the map you never sent a request to")
    lines.append(f"  tested   {len(report.tested):>4}   routes seen in history")
    lines.append(f"  unmapped {len(report.unmapped):>4}   paths you hit that the map has no route for")
    lines.append(f"  static   {len(report.static):>4}   files (js, css, images) not counted")
    if show in ("all", "untested") and report.untested:
        lines.append("")
        lines.append("UNTESTED  (try these next)")
        for r in sorted(report.untested, key=lambda r: (r.pattern.lower(), _method_key(r.method))):
            tag = "  (router; mount point unknown)" if r.kind == "router" else ""
            lines.append(f"  {r.method:<7} {r.pattern:<50} {r.where}{tag}")
    if show in ("all", "tested") and report.tested:
        lines.append("")
        lines.append("TESTED")
        for h in sorted(report.tested, key=lambda h: (h.route.pattern.lower(), _method_key(h.route.method))):
            ids = " ".join(f"#{f.id}" for f in h.flows[:examples] if f.id is not None)
            more = f" +{len(h.flows) - examples}" if len(h.flows) > examples else ""
            statuses = " ".join(str(s) for s in h.statuses) or "no response"
            lines.append(f"  {h.route.method:<7} {h.route.pattern:<50} {len(h.flows):>3} flows  "
                         f"status {statuses:<12} {ids}{more}")
    if show in ("all", "unmapped") and report.unmapped:
        lines.append("")
        lines.append("UNMAPPED  (seen in history, no route in the map: middleware, generated CRUD, "
                     "mounted routers, or code the recon tool could not read)")
        for u in report.unmapped:
            ids = " ".join(f"#{f.id}" for f in u.flows[:examples] if f.id is not None)
            lines.append(f"  {u.method:<7} {u.path:<50} {len(u.flows):>3} flows  {ids}")
    return "\n".join(lines)


__all__ = [
    "Route", "ImportResult", "RouteStore", "Report", "Hit", "Unmapped",
    "load_rea", "load_list", "coverage", "format_report", "pattern_regex", "path_only",
]

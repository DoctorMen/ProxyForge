"""HTTP history, stored in a SQLite project file.

Every recorded request/response pair is a "flow". Storing them in SQLite
means the history survives restarts and you can query it with any SQLite
tool, e.g. `sqlite3 project.db "select id, host, path from flows"`.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .http import Headers, Request, Response

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started      REAL NOT NULL,
    duration_ms  INTEGER,
    scheme       TEXT NOT NULL,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    req_version  TEXT NOT NULL,
    req_headers  TEXT NOT NULL,
    req_body     BLOB NOT NULL,
    status       INTEGER,
    reason       TEXT,
    resp_version TEXT,
    resp_headers TEXT,
    resp_body    BLOB,
    error        TEXT,
    rules_fired  TEXT NOT NULL DEFAULT '[]',
    note         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS flows_host ON flows(host);
"""


@dataclass
class Flow:
    scheme: str
    host: str
    port: int
    request: Request
    response: Response | None = None
    started: float = field(default_factory=time.time)
    duration_ms: int | None = None
    error: str | None = None
    rules_fired: list[int] = field(default_factory=list)
    note: str = ""
    id: int | None = None

    @property
    def url(self) -> str:
        default = {"http": 80, "https": 443}[self.scheme]
        host = f"[{self.host}]" if ":" in self.host else self.host
        netloc = host if self.port == default else f"{host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.request.target}"


class History:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def add(self, flow: Flow) -> int:
        r, s = flow.request, flow.response
        cur = self.db.execute(
            """INSERT INTO flows (started, duration_ms, scheme, host, port, method, path,
                req_version, req_headers, req_body, status, reason, resp_version,
                resp_headers, resp_body, error, rules_fired, note)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                flow.started,
                flow.duration_ms,
                flow.scheme,
                flow.host,
                flow.port,
                r.method,
                r.target,
                r.version,
                json.dumps(r.headers.items),
                r.body,
                s.status if s else None,
                s.reason if s else None,
                s.version if s else None,
                json.dumps(s.headers.items) if s else None,
                s.body if s else None,
                flow.error,
                json.dumps(flow.rules_fired),
                flow.note,
            ),
        )
        self.db.commit()
        flow.id = cur.lastrowid
        return flow.id

    @staticmethod
    def _row_to_flow(row: sqlite3.Row | tuple) -> Flow:
        (fid, started, duration, scheme, host, port, method, path, req_version, req_headers,
         req_body, status, reason, resp_version, resp_headers, resp_body, error, rules, note) = row
        req = Request(method, path, req_version, Headers([tuple(h) for h in json.loads(req_headers)]), req_body)
        resp = None
        if status is not None:
            resp = Response(
                status, reason or "", resp_version,
                Headers([tuple(h) for h in json.loads(resp_headers)]), resp_body or b"",
            )
        return Flow(scheme, host, port, req, resp, started, duration, error,
                    json.loads(rules), note, fid)

    def get(self, flow_id: int) -> Flow | None:
        row = self.db.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        return self._row_to_flow(row) if row else None

    def query(
        self,
        host: str | None = None,
        method: str | None = None,
        status: int | None = None,
        contains: str | None = None,
        limit: int | None = None,
    ) -> list[Flow]:
        """Filter flows. host takes wildcards; contains searches the URL path."""
        sql, args = "SELECT * FROM flows WHERE 1=1", []
        if method:
            sql += " AND method = ?"
            args.append(method.upper())
        if status is not None:
            sql += " AND status = ?"
            args.append(status)
        if contains:
            sql += " AND instr(path, ?) > 0"
            args.append(contains)
        sql += " ORDER BY id"
        flows = [self._row_to_flow(r) for r in self.db.execute(sql, args)]
        if host:
            flows = [f for f in flows if fnmatchcase(f.host, host.lower())]
        if limit is not None:
            flows = flows[-limit:]
        return flows

    def count(self) -> int:
        return self.db.execute("SELECT count(*) FROM flows").fetchone()[0]

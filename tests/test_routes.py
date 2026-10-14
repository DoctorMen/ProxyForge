"""Route maps and the coverage report (REA import)."""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

import pytest

from proxyforge import routes
from proxyforge.cli import main
from proxyforge.history import Flow, History
from proxyforge.http import Headers, Request, Response, decode_content
from proxyforge.routes import (
    Route, RouteStore, coverage, format_report, load_list, load_rea, match_pattern, path_only,
    printable, split_host,
)

FIXTURE = Path(__file__).parent / "fixtures" / "rea-juice-shop.json"


def flow(method: str, target: str, status: int | None = 200, host="127.0.0.1", port=3000) -> Flow:
    resp = Response(status, "OK", "HTTP/1.1", Headers(), b"{}") if status else None
    return Flow("http", host, port, Request(method, target), resp)


# -- Express-style patterns ----------------------------------------------------

@pytest.mark.parametrize("pattern,path,expected", [
    ("/api/Users/:id", "/api/Users/7", True),
    ("/api/Users/:id", "/api/Users", False),
    ("/api/Users/:id", "/api/Users/7/basket", False),
    ("/api/Users", "/api/users/", True),              # Express is case-insensitive, non-strict
    ("/api/Users", "/api/Users?q=1#x", True),         # query and fragment are not part of the path
    ("/rest/basket/:id/coupon/:coupon", "/rest/basket/1/coupon/WMNSDY2019", True),
    ("/files/:name?", "/files", True),
    ("/files/:name?", "/files/a.txt", True),
    ("/files/:name?", "/files/a/b", False),
    ("/ftp/*", "/ftp/legal.md", True),
    ("/ftp/*", "/ftp/a/b/c", True),
    ("/ftp/*", "/ftp/", True),
    ("/ftp/*", "/ftpx", False),
    ("/", "/", True),
    ("/", "/x", False),
    ("/a.b", "/axb", False),                           # dots are literal, not regex wildcards
    ("**", "/anything/at/all", True),
    ("/metrics", "http://127.0.0.1:3000/metrics", True),
    ("/api/Users/:id(\\d+)", "/api/Users/7", True),        # constraints are matched as a plain segment
    ("/ftp(?!/quarantine)/:file", "/ftp/legal.md", False),  # regex syntax is literal, never compiled
    ("/a/:x?/b", "/a/b", True),
    ("/a/:x?/b", "/a/1/b", True),
    ("/a/*/end", "/a/1/2/3/end", True),
    ("/a/*/end", "/a/end", True),
    ("/a/*/end", "/b/end", False),
])
def test_pattern_matching(pattern, path, expected):
    assert match_pattern(pattern, path_only(path)) is expected


def test_regex_syntax_in_a_pattern_is_plain_text():
    # Express 4 would compile the lookahead; the matcher never does, so the
    # pattern only matches a path spelled exactly like it.
    assert match_pattern("/ftp(?!/quarantine)/:file", "/ftp(?!/quarantine)/x")
    assert not match_pattern("/ftp(?!/quarantine)/:file", "/ftp/quarantine/x")


def test_use_routes_match_everything_under_their_prefix():
    assert match_pattern("/api", "/api/Users/7", prefix=True)
    assert match_pattern("/api", "/api", prefix=True)
    assert not match_pattern("/api", "/apiary", prefix=True)
    assert not match_pattern("/api", "/api/Users/7")
    r = Route("ANY", "/ftp", "server", mechanism="call:app.use")
    assert r.prefix and r.matches("GET", "/ftp/legal.md")


def test_hostile_patterns_cannot_make_matching_slow():
    import time
    pattern = "/" + "/".join(["*"] * 12) + "/end"
    path = "/" + "a/" * 3000 + "x"
    started = time.monotonic()
    assert not match_pattern(pattern, path)
    assert match_pattern(":a?" * 12 + "/end", "/end")
    assert time.monotonic() - started < 2.0


def test_printable_keeps_terminal_escapes_visible():
    assert printable("/ok path") == "/ok path"
    assert printable("/x\x1b[31mred\r\n") == "/x\\x1b[31mred\\r\\n"


def test_split_host():
    assert split_host("127.0.0.1:3000") == ("127.0.0.1", 3000)
    assert split_host("Shop.Example.com") == ("shop.example.com", None)
    assert split_host("[::1]:3000") == ("::1", 3000)
    assert split_host("*.example.com") == ("*.example.com", None)
    with pytest.raises(ValueError):
        split_host("host:notaport")


def test_route_method_must_match_unless_any():
    r = Route("GET", "/api/Users/:id", "server")
    assert r.matches("get", "/api/Users/1")
    assert not r.matches("DELETE", "/api/Users/1")
    assert Route("ANY", "/api/Users/:id", "server").matches("DELETE", "/api/Users/1")


# -- importing REA output ------------------------------------------------------

def test_import_real_rea_output_keeps_server_routes_only():
    result = load_rea(FIXTURE)
    by_kind = {}
    for r in result.routes:
        by_kind.setdefault(r.kind, []).append((r.method, r.pattern))
    assert ("GET", "/rest/basket/:id") in by_kind["server"]
    assert ("ANY", "/api/Users/:id") in by_kind["server"]      # app.route() takes every method
    assert ("PATCH", "/rest/products/reviews") in by_kind["server"]
    assert ("DELETE", "/api/Addresss/:id") in by_kind["server"]
    assert by_kind["router"] == [("GET", "/"), ("POST", "/")]  # routes/dataErasure.ts, mount unknown
    assert by_kind["spa"] == [("ANY", "**")]                   # Angular wildcard page, not an endpoint
    assert by_kind["client"] == [("ANY", "/api/Challenges/")]  # fetch() in the browser bundle
    # config.get("application.name") and req.get("host") are not HTTP paths.
    assert result.skipped["call:config.get"] == 13
    assert result.skipped["call:req.get"] == 1
    assert all(r.kind != "server" or r.pattern.startswith("/") for r in result.routes)


def test_import_keeps_where_each_route_was_found():
    result = load_rea(FIXTURE)
    basket = next(r for r in result.routes if r.pattern == "/rest/basket/:id")
    assert basket.where == "server.ts:631"
    assert basket.mechanism == "call:app.get"
    assert basket.origin == "rea-juice-shop.json"


def test_import_keeps_same_pattern_from_different_files(tmp_path):
    # router.get("/") in every routes/*.ts file is a different endpoint each time.
    doc = json.loads(FIXTURE.read_text())
    nodes = doc["normalized_result"]["graph"]["nodes"]
    root = next(n for n in nodes if n["kind"] == "endpoint"
                and any(o["properties"]["value"] == "/" and o["properties"]["mechanism"] == "call:router.get"
                        for o in n["observations"]))
    copy = json.loads(json.dumps(root))
    for o in copy["observations"]:
        o["evidence"]["location"]["value"]["source"] = "routes/orders.ts"
    nodes.append(copy)
    (tmp_path / "two.json").write_text(json.dumps(doc))
    found = sorted(r.where for r in load_rea(tmp_path / "two.json").routes
                   if (r.method, r.pattern) == ("GET", "/"))
    assert found == ["routes/dataErasure.ts:24", "routes/orders.ts:24"]


def test_import_tolerates_broken_shapes_with_a_clear_error(tmp_path):
    doc = json.loads(FIXTURE.read_text())
    doc["normalized_result"]["graph"]["nodes"][0]["observations"] = "nonsense"
    doc["normalized_result"]["statistics"] = ["not", "a", "dict"]
    (tmp_path / "odd.json").write_text(json.dumps(doc))
    clean = {(r.method, r.pattern) for r in load_rea(FIXTURE).routes}
    odd = {(r.method, r.pattern) for r in load_rea(tmp_path / "odd.json").routes}
    assert clean - odd == {("POST", "/rest/user/login")}  # only the broken node is lost
    doc["normalized_result"]["graph"]["nodes"] = None
    (tmp_path / "bad.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="analyze-javascript-application"):
        load_rea(tmp_path / "bad.json")


def test_import_dedupes_repeated_registrations(tmp_path):
    # Juice Shop registers POST /api/Users several times (server.ts:436, 448, 449, 450).
    doc = json.loads(FIXTURE.read_text())
    nodes = doc["normalized_result"]["graph"]["nodes"]
    users = [n for n in nodes if n["kind"] == "endpoint"
             and any(o["properties"]["value"] == "/api/Users" for o in n["observations"])]
    assert users, "fixture lost the /api/Users node"
    nodes.append(json.loads(json.dumps(users[0])))  # a second copy of the same node
    (tmp_path / "dup.json").write_text(json.dumps(doc))
    result = load_rea(tmp_path / "dup.json")
    assert sum(1 for r in result.routes if (r.method, r.pattern) == ("POST", "/api/Users")) == 1


def test_import_warns_when_rea_ran_out_of_budget():
    result = load_rea(FIXTURE)
    assert any("skipped semantic analysis of 1 file" in w and "server.ts" in w for w in result.warnings)
    assert any("partial" in w for w in result.warnings)


def test_import_rejects_other_json(tmp_path):
    other = tmp_path / "har.json"
    other.write_text(json.dumps({"log": {"entries": []}}))
    with pytest.raises(ValueError, match="analyze-javascript-application"):
        load_rea(other)


def test_import_list_file(tmp_path):
    f = tmp_path / "routes.txt"
    f.write_text("# hand-written map\nGET /rest/basket/:id\n/metrics  # any method\nPOST /api/Users\n\n")
    result = load_list(f)
    assert [(r.method, r.pattern) for r in result.routes] == [
        ("GET", "/rest/basket/:id"), ("ANY", "/metrics"), ("POST", "/api/Users")]
    (tmp_path / "use.txt").write_text("USE /api\n")
    [use] = load_list(tmp_path / "use.txt").routes
    assert use.method == "ANY" and use.prefix and use.matches("DELETE", "/api/Users/1")
    bad = tmp_path / "bad.txt"
    bad.write_text("GET basket\n")
    with pytest.raises(ValueError, match="must start with /"):
        load_list(bad)


# -- storage -------------------------------------------------------------------

def test_store_replaces_an_earlier_import_of_the_same_file(tmp_path):
    store = RouteStore(str(tmp_path / "p.db"))
    assert store.replace("a.json", [Route("GET", "/one", "server"), Route("GET", "/two", "server")]) == (2, 0)
    store.replace("b.txt", [Route("GET", "/three", "server")])
    assert store.replace("a.json", [Route("GET", "/one", "server")]) == (1, 2)
    assert [(r.origin, r.pattern) for r in store.all()] == [("b.txt", "/three"), ("a.json", "/one")]
    assert store.origins() == [("a.json", 1), ("b.txt", 1)]
    store.close()


# -- coverage ------------------------------------------------------------------

def test_coverage_sorts_flows_into_tested_untested_unmapped_and_static():
    r = load_rea(FIXTURE)
    flows = [
        flow("GET", "/rest/basket/6"), flow("GET", "/rest/basket/1", 200), flow("GET", "/rest/basket/9", 401),
        flow("GET", "/rest/user/whoami"), flow("GET", "/api/Users/5"), flow("PUT", "/api/Users/5"),
        flow("GET", "/api/Challenges/?name=Score%20Board"),      # generated by finale-rest: not in the map
        flow("GET", "/main.js"), flow("GET", "/assets/i18n/en.json"),
        flow("GET", "/rest/products/search?q=", None),           # no response (upstream error)
    ]
    for i, f in enumerate(flows, 1):
        f.id = i
    rep = coverage(r.routes, flows)
    tested = {(h.route.method, h.route.pattern): h for h in rep.tested}
    assert tested[("GET", "/rest/basket/:id")].statuses == [200, 401]
    assert [f.id for f in tested[("GET", "/rest/basket/:id")].flows] == [1, 2, 3]
    assert ("ANY", "/api/Users/:id") in tested and len(tested[("ANY", "/api/Users/:id")].flows) == 2
    assert tested[("GET", "/rest/products/search")].statuses == []
    assert ("DELETE", "/api/Addresss/:id") in {(r.method, r.pattern) for r in rep.untested}
    assert [(u.method, u.path) for u in rep.unmapped] == [("GET", "/api/Challenges")]
    assert sorted(u.path for u in rep.static) == ["/assets/i18n/en.json", "/main.js"]
    # Client calls and SPA pages are not counted as testable routes.
    assert rep.total == len([x for x in r.routes if x.kind in ("server", "router")])
    assert rep.percent == round(100 * len(rep.tested) / rep.total)


def test_coverage_prefers_the_most_specific_route():
    rs = [Route("ANY", "/api/*", "server"), Route("GET", "/api/Users/:id", "server"), Route("ANY", "/api/Users/:id", "server"),
          Route("GET", "/api/Users/me", "server")]
    rep = coverage(rs, [flow("GET", "/api/Users/3"), flow("GET", "/api/Users/me")])
    hits = {(h.route.method, h.route.pattern): [f.request.target for f in h.flows] for h in rep.tested}
    # A literal segment beats :id even though ":id" is the longer string.
    assert hits == {("GET", "/api/Users/:id"): ["/api/Users/3"], ("GET", "/api/Users/me"): ["/api/Users/me"]}


def test_coverage_host_filter():
    rs = [Route("GET", "/x", "server")]
    flows = [flow("GET", "/x", host="a.test", port=80), flow("GET", "/x", host="b.test", port=8443)]
    assert coverage(rs, flows, host="a.test").flows_seen == 1
    assert coverage(rs, flows, host="b.test:8443").flows_seen == 1
    assert coverage(rs, flows, host="b.test:80").flows_seen == 0
    assert coverage(rs, flows, host="B.TEST").flows_seen == 1
    assert coverage(rs, flows, host="*.test").flows_seen == 2
    v6 = [flow("GET", "/x", host="::1", port=3000)]
    assert coverage(rs, v6, host="[::1]:3000").flows_seen == 1
    assert coverage(rs, v6, host="::1").flows_seen == 1


def test_report_escapes_control_characters_from_the_app():
    rs = [Route("GET", "/x\x1b[31m", "server", "srv.ts\r\nUNTESTED", 1)]
    text = format_report(coverage(rs, []))
    assert "\x1b" not in text and "\r" not in text
    assert "/x\\x1b[31m" in text and "srv.ts\\r\\nUNTESTED" in text


def test_report_text_and_json():
    r = load_rea(FIXTURE)
    flows = [flow("GET", "/rest/basket/6"), flow("GET", "/socket.io/?EIO=4")]
    flows[0].id, flows[1].id = 6, 7
    rep = coverage(r.routes, flows, host="127.0.0.1:3000")
    text = format_report(rep)
    assert text.splitlines()[0].startswith("Coverage for 127.0.0.1:3000: 1 of")
    assert "GET     /rest/basket/:id" in text and "#6" in text
    assert "UNMAPPED" in text and "/socket.io" in text
    assert "DELETE  /api/Addresss/:id" in text and "server.ts:479" in text
    assert "(router; mount point unknown)" in text
    assert "UNMAPPED" not in format_report(rep, show="untested")
    data = rep.to_dict()
    assert data["tested"][0]["flows"] == [6] and data["tested_count"] == 1
    assert data["unmapped"] == [{"method": "GET", "path": "/socket.io", "flows": [7]}]
    json.dumps(data)  # must be serialisable


# -- the commands end to end ---------------------------------------------------

def test_cli_import_and_coverage(tmp_path, capsys):
    db = str(tmp_path / "p.db")
    history = History(db)
    for f in [flow("GET", "/rest/basket/6"), flow("GET", "/rest/basket/1"), flow("GET", "/api/Challenges/?x=1"),
              flow("GET", "/main.js")]:
        history.add(f)
    history.close()

    assert main(["import-rea", "-p", db, str(FIXTURE)]) == 0
    out, err = capsys.readouterr()
    assert "imported 18 routes from rea-juice-shop.json: 1 client, 2 router, 14 server, 1 spa" in out
    assert "skipped 14 endpoint observations" in out
    assert "warning: REA skipped semantic analysis" in err

    assert main(["routes", "-p", db, "--kind", "server", "--contains", "basket"]) == 0
    out, _ = capsys.readouterr()
    assert "GET     /rest/basket/:id" in out and "PUT     /rest/basket/:id/coupon/:coupon" in out

    assert main(["coverage", "-p", db, "--host", "127.0.0.1:3000"]) == 0
    out, _ = capsys.readouterr()
    assert "1 of 16 server routes hit (6%) across 4 flows" in out
    assert "UNTESTED" in out and "TESTED" in out and "UNMAPPED" in out
    assert "static      1" in out

    assert main(["coverage", "-p", db, "--json"]) == 0
    data = json.loads(capsys.readouterr()[0])
    assert data["tested"][0]["pattern"] == "/rest/basket/:id" and data["tested"][0]["flows"] == [1, 2]

    # A text list adds to the map; the next report counts it.
    (tmp_path / "extra.txt").write_text("GET /api/Challenges\n")
    assert main(["import-routes", "-p", db, str(tmp_path / "extra.txt")]) == 0
    assert main(["coverage", "-p", db, "--show", "unmapped"]) == 0
    out, _ = capsys.readouterr()
    assert "2 of 17 server routes" in out and "UNMAPPED" not in out

    # Re-importing the same file replaces its earlier routes and says so; a
    # same-named file elsewhere is a different import.
    assert main(["import-routes", "-p", db, str(tmp_path / "extra.txt")]) == 0
    assert "replaced 1 routes imported earlier from this file" in capsys.readouterr()[0]
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "extra.txt").write_text("GET /api/Hints\n")
    assert main(["import-routes", "-p", db, str(tmp_path / "other" / "extra.txt")]) == 0
    assert main(["routes", "-p", db, "--contains", "/api/"]) == 0
    out, err = capsys.readouterr()
    assert "/api/Challenges" in out and "/api/Hints" in out and "extra.txt (1), extra.txt (1)" in err

    # --host accepts wildcards and ports like `history --host`; --kinds is checked.
    assert main(["coverage", "-p", db, "--host", "127.*:3000", "--show", "untested"]) == 0
    assert "across 4 flows" in capsys.readouterr()[0]
    assert main(["coverage", "-p", db, "--kinds", "server, bogus"]) == 2
    assert "unknown route kind(s) ['bogus']" in capsys.readouterr()[1]


def test_cli_coverage_without_routes_explains(tmp_path, capsys):
    db = str(tmp_path / "empty.db")
    History(db).close()
    assert main(["coverage", "-p", db]) == 1
    assert "import-rea" in capsys.readouterr()[1]


def test_cli_import_rea_rejects_wrong_file(tmp_path, capsys):
    f = tmp_path / "x.json"
    f.write_text("{}")
    assert main(["import-rea", "-p", str(tmp_path / "p.db"), str(f)]) == 2
    assert "error:" in capsys.readouterr()[1]


@pytest.mark.skipif(not os.environ.get("PROXYFORGE_REA_JSON"), reason="set PROXYFORGE_REA_JSON to a full REA output file")
def test_import_full_real_rea_file():
    result = load_rea(os.environ["PROXYFORGE_REA_JSON"])
    assert any(r.kind == "server" for r in result.routes)


# -- readable bodies -----------------------------------------------------------

def test_decode_content_gzip_deflate_and_passthrough():
    raw = b'{"version":"20.3.0"}'
    assert decode_content(gzip.compress(raw), Headers([("Content-Encoding", "gzip")])) == raw
    import zlib
    assert decode_content(zlib.compress(raw), Headers([("Content-Encoding", "deflate")])) == raw
    assert decode_content(zlib.compress(raw)[2:-4], Headers([("Content-Encoding", "deflate")])) == raw
    assert decode_content(raw, Headers()) == raw
    assert decode_content(b"not gzip", Headers([("Content-Encoding", "gzip")])) == b"not gzip"
    assert decode_content(b"\x1b\x00", Headers([("Content-Encoding", "br")])) in (b"\x1b\x00", b"")


def test_show_decodes_gzip_bodies(tmp_path, capsys):
    db = str(tmp_path / "p.db")
    history = History(db)
    f = flow("GET", "/gzip")
    f.response = Response(200, "OK", "HTTP/1.1", Headers([("Content-Encoding", "gzip"), ("Content-Type", "application/json")]),
                          gzip.compress(b'{"secret": "gzipped json"}'))
    history.add(f)
    history.close()
    assert main(["show", "-p", db, "1", "--response-only"]) == 0
    out = capsys.readouterr()[0]
    assert '{"secret": "gzipped json"}' in out and "[body decoded from gzip" in out

"""Part 2: Repeater, Decoder and Comparer."""

import base64
import json

import pytest

from proxyforge import codec
from proxyforge.cli import main
from proxyforge.client import OutOfScope, check_scope
from proxyforge.history import History
from proxyforge.http import Headers, Request
from proxyforge.repeater import apply_edits, from_raw, to_raw
from proxyforge.scope import Scope

from .test_proxy import via_proxy


# -- decoder -----------------------------------------------------------------

@pytest.mark.parametrize("name", list(codec.ENCODERS))
def test_every_encoder_round_trips(name):
    data = "id=1&name=<k> 'ü' /x?".encode()
    assert codec.decode(codec.encode(data, [name]), [name]) == data


def test_chains_apply_in_order():
    data = b'{"admin": false}'
    wrapped = codec.encode(data, ["base64", "url"])
    assert codec.decode(wrapped, ["url", "base64"]) == data


def test_smart_decode_peels_layers():
    inner = b"user=k&role=admin"
    token = codec.encode(codec.encode(inner, ["url-all"]), ["base64"])
    steps = codec.smart_decode(token)
    assert [name for name, _ in steps] == ["base64", "url"]
    assert steps[-1][1] == inner


def test_smart_decode_reads_a_jwt_without_trusting_it():
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=")
    jwt = part({"alg": "none", "typ": "JWT"}) + b"." + part({"sub": "25", "role": "customer"}) + b"."
    [(name, out)] = codec.smart_decode(jwt)
    decoded = json.loads(out)
    assert name == "jwt"
    assert decoded["payload"] == {"sub": "25", "role": "customer"}
    assert decoded["note"] == "signature NOT verified"
    assert "unsigned" in decoded["signature"]


def test_smart_decode_leaves_plain_text_alone():
    assert codec.smart_decode(b"hello world") == []


def test_unknown_codec_is_an_error():
    with pytest.raises(ValueError):
        codec.decode(b"x", ["rot13"])


# -- repeater building blocks -----------------------------------------------

def test_raw_round_trip_and_crlf_tolerance():
    req = Request("POST", "/login", "HTTP/1.1",
                  Headers([("Host", "x"), ("Content-Type", "application/json")]), b'{"a":1}')
    text = to_raw(req)
    assert "\r" not in text  # editors see normal newlines
    back = from_raw(text.replace("\n", "\r\n"))
    assert (back.method, back.target, back.body) == ("POST", "/login", b'{"a":1}')
    assert back.headers.items == req.headers.items


def test_raw_get_with_trailing_newline_has_no_body():
    assert from_raw("GET / HTTP/1.1\nHost: x\n").body == b""
    assert from_raw("GET / HTTP/1.1\nHost: x\n\n\n").body == b""


def test_apply_edits():
    req = Request("GET", "/rest/basket/6", "HTTP/1.1", Headers([("Host", "x"), ("Cookie", "a=b")]))
    out = apply_edits(req, method="post", path="/rest/basket/1",
                      set_headers=["X-Test: 1", "Cookie:"], body=b"hi")
    assert (out.method, out.target, out.body) == ("POST", "/rest/basket/1", b"hi")
    assert out.headers.items == [("Host", "x"), ("X-Test", "1")]
    assert req.target == "/rest/basket/6"  # original untouched
    with pytest.raises(ValueError):
        apply_edits(req, path="no-slash")


def test_active_tools_need_a_scope_decision():
    with pytest.raises(OutOfScope, match="--no-scope"):
        check_scope("http://127.0.0.1/", None, no_scope=False)
    check_scope("http://127.0.0.1/", None, no_scope=True)
    scope = Scope(include=["app.test"])
    check_scope("https://app.test/x", scope, no_scope=False)
    with pytest.raises(OutOfScope):
        check_scope("https://evil.test/", scope, no_scope=True)  # a scope file always wins


# -- end to end through the CLI ---------------------------------------------

def test_repeat_flow_with_edits_and_diff(make_proxy, http_app, tmp_path, capsys):
    proxy = make_proxy()
    via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/hello")
    db = proxy.db_path
    capsys.readouterr()

    # Resend flow 1 unchanged: same answer, saved as flow 2.
    assert main(["repeat", "1", "-p", db, "--no-scope"]) == 0
    out = capsys.readouterr()
    assert "hello world" in out.out and out.err.startswith("#2  200 OK")

    # Change the path: the server now says 404. Saved as flow 3.
    assert main(["repeat", "1", "-p", db, "--no-scope", "--path", "/missing", "-H", "X-Test: yes"]) == 0
    capsys.readouterr()
    h = History(db)
    flow3 = h.get(3)
    assert flow3.response.status == 404 and flow3.request.headers.get("X-Test") == "yes"
    assert flow3.note == "repeater: from flow 1"

    assert main(["diff", "1", "3", "-p", db]) == 0
    diff = capsys.readouterr().out
    assert "status: 200 vs 404" in diff
    assert "-hello world" in diff and "+not found" in diff
    assert "~ set-cookie" not in diff and "- set-cookie: session=abc123; HttpOnly" in diff


def test_repeat_post_body_and_raw_file(make_proxy, http_app, tmp_path, capsys):
    proxy = make_proxy()
    db = proxy.db_path
    raw = tmp_path / "req.http"
    raw.write_text("POST /echo HTTP/1.1\nHost: whatever\nContent-Type: text/plain\n\nfirst\n")
    assert main(["repeat", "-p", db, "--raw", str(raw), "--url", f"http://127.0.0.1:{http_app}",
                 "--no-scope"]) == 0
    assert "echo:first" in capsys.readouterr().out
    assert main(["repeat", "1", "-p", db, "--no-scope", "--body", "second"]) == 0
    assert "echo:second" in capsys.readouterr().out
    assert main(["raw", "1", "-p", db]) == 0
    assert capsys.readouterr().out.startswith("POST /echo HTTP/1.1\n")


def test_repeat_refuses_without_scope_and_out_of_scope(make_proxy, http_app, tmp_path, capsys):
    proxy = make_proxy()
    via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/hello")
    assert main(["repeat", "1", "-p", proxy.db_path]) == 3
    assert "--no-scope" in capsys.readouterr().err
    scope = tmp_path / "scope.toml"
    scope.write_text('include = ["only-this.test"]\n')
    assert main(["repeat", "1", "-p", proxy.db_path, "-s", str(scope)]) == 3
    assert "not in scope" in capsys.readouterr().err
    assert History(proxy.db_path).count() == 1  # nothing was sent or saved


def test_repeat_over_https(make_proxy, https_app, site_ca, capsys, monkeypatch):
    import ssl
    from proxyforge import cli
    proxy = make_proxy()
    monkeypatch.setattr(cli, "default_context",
                        lambda insecure=False: ssl.create_default_context(cafile=str(site_ca.cert_path)))
    from .test_proxy import via_tunnel
    via_tunnel(proxy, https_app, "GET", "/hello")
    assert main(["repeat", "1", "-p", proxy.db_path, "--no-scope", "--path", "/headers"]) == 0
    assert f"host: localhost:{https_app}" in capsys.readouterr().out.lower()


def test_decode_cli(capsys):
    assert main(["decode", "dXNlcj1rJTI2cm9sZT1hZG1pbg=="]) == 0
    out = capsys.readouterr().out
    assert "[1] base64:" in out and "[2] url:" in out and "user=k&role=admin" in out
    assert main(["encode", "a b&c", "-c", "url,base64"]) == 0
    assert capsys.readouterr().out.strip() == "YSUyMGIlMjZj"
    assert main(["decode", "plain words"]) == 1


def test_repeater_keeps_a_short_body(http_app):
    import asyncio
    from proxyforge.client import send
    flow = asyncio.run(send("http", "127.0.0.1", http_app, Request("GET", "/short")))
    assert flow.response.body == b"only twelve!"
    assert "12 of 20 promised" in flow.note

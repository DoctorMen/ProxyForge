"""End-to-end: real clients talk through a running proxy to real servers."""

import http.client
import json
import socket
import ssl

import pytest

from proxyforge import har
from proxyforge.cli import main
from proxyforge.rules import Rule, RuleSet
from proxyforge.scope import Scope

from .conftest import free_port


def via_proxy(proxy, method, url, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    conn.request(method, url, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def via_tunnel(proxy, port, method, path, context=None, body=None, headers=None):
    conn = http.client.HTTPSConnection("127.0.0.1", proxy.port, timeout=10,
                                       context=context or proxy.client_context())
    conn.set_tunnel("localhost", port)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def test_plain_http_is_forwarded_and_recorded(make_proxy, http_app):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/hello")
    assert (resp.status, body) == (200, b"hello world")
    [flow] = proxy.history.query()
    assert flow.url == f"http://127.0.0.1:{http_app}/hello"
    assert flow.response.body == b"hello world"
    assert flow.response.headers.get("Set-Cookie") == "session=abc123; HttpOnly"


def test_post_body_reaches_server(make_proxy, http_app):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "POST", f"http://127.0.0.1:{http_app}/echo", body=b"a=1&b=2",
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert body == b"echo:a=1&b=2"
    assert proxy.history.query()[0].request.body == b"a=1&b=2"


def test_hop_by_hop_headers_not_forwarded(make_proxy, http_app):
    proxy = make_proxy()
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers",
                        headers={"Proxy-Authorization": "Basic c2VjcmV0", "X-Keep": "yes"})
    text = body.decode().lower()
    assert "proxy-authorization" not in text and "x-keep: yes" in text


def test_chunked_response_is_dechunked(make_proxy, http_app):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/chunked")
    assert body == b"first-second-third"
    assert resp.getheader("Content-Length") == str(len(body))
    assert proxy.history.query()[0].response.body == b"first-second-third"


def test_head_and_204(make_proxy, http_app):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "HEAD", f"http://127.0.0.1:{http_app}/hello")
    assert resp.status == 200 and body == b"" and resp.getheader("Content-Length") == "11"
    resp, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/nocontent")
    assert resp.status == 204


def test_keep_alive_serves_several_requests_on_one_connection(make_proxy, http_app):
    proxy = make_proxy()
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    for _ in range(3):
        conn.request("GET", f"http://127.0.0.1:{http_app}/hello")
        assert conn.getresponse().read() == b"hello world"
    conn.close()
    assert proxy.history.count() == 3


def test_https_is_decrypted_with_proxy_ca(make_proxy, https_app):
    proxy = make_proxy()
    resp, body = via_tunnel(proxy, https_app, "GET", "/hello")
    assert body == b"hello world"
    [flow] = proxy.history.query()
    assert flow.url == f"https://localhost:{https_app}/hello"


def test_https_client_that_does_not_trust_proxy_ca_is_refused(make_proxy, https_app):
    proxy = make_proxy()
    untrusting = ssl.create_default_context()  # system CAs only
    with pytest.raises(ssl.SSLCertVerificationError):
        via_tunnel(proxy, https_app, "GET", "/hello", context=untrusting)


def test_upstream_certificate_is_verified(make_proxy, https_app, site_ca):
    # A proxy that trusts nothing the site's CA signed must refuse the site.
    proxy = make_proxy()
    proxy.proxy.upstream_ssl = ssl.create_default_context()
    resp, body = via_tunnel(proxy, https_app, "GET", "/hello")
    assert resp.status == 502 and b"CERTIFICATE_VERIFY_FAILED" in body
    assert "SSLCertVerificationError" in proxy.history.query()[0].error


def test_out_of_scope_https_is_tunnelled_not_decrypted(make_proxy, https_app, site_ca):
    proxy = make_proxy(scope=Scope(include=["in-scope.test"]))
    # The client only trusts the site's real CA: this works only if the proxy
    # passes TLS through untouched.
    site_trust = ssl.create_default_context(cafile=str(site_ca.cert_path))
    resp, body = via_tunnel(proxy, https_app, "GET", "/hello", context=site_trust)
    assert body == b"hello world"
    assert proxy.history.count() == 0


def test_out_of_scope_http_is_forwarded_but_not_recorded(make_proxy, http_app):
    proxy = make_proxy(scope=Scope(include=[f"127.0.0.1:{http_app}/hello"]))
    via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/hello")
    resp, _ = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers")
    assert resp.status == 200
    assert [f.request.target for f in proxy.history.query()] == ["/hello"]


def test_match_replace_rules_change_traffic(make_proxy, http_app):
    rules = RuleSet([
        Rule("request_header", "^User-Agent:.*$", "User-Agent: proxyforge-test"),
        Rule("response_body", "world", "proxyforge"),
    ])
    proxy = make_proxy(rules=rules)
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers", headers={"User-Agent": "curl"})
    assert "user-agent: proxyforge-test" in body.decode().lower()
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/hello")
    assert body == b"hello proxyforge"
    flows = proxy.history.query()
    assert flows[0].rules_fired == [0] and flows[1].rules_fired == [1]  # no User-Agent sent the 2nd time


def test_unreachable_upstream_gives_502_and_is_recorded(make_proxy):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{free_port()}/")
    assert resp.status == 502
    [flow] = proxy.history.query()
    assert flow.response is None and "ConnectionRefused" in flow.error


def test_connection_upgrade_becomes_a_tunnel(make_proxy, upgrade_app):
    proxy = make_proxy()
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as s:
        s.sendall(f"GET http://127.0.0.1:{upgrade_app}/ws HTTP/1.1\r\nHost: x\r\n"
                  "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(1024)
        assert head.startswith(b"HTTP/1.1 101")
        s.sendall(b"ping")
        assert s.recv(1024) == b"PING"
    assert proxy.history.query()[0].response.status == 101


def test_proxy_serves_its_ca_certificate(make_proxy):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "GET", "http://proxyforge/cert")
    assert body == proxy.ca.cert_pem
    assert proxy.history.count() == 0


def test_garbage_request_gets_400(make_proxy):
    proxy = make_proxy()
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=10) as s:
        s.sendall(b"NOT HTTP AT ALL\r\n\r\n")
        assert s.recv(1024).startswith(b"HTTP/1.1 400")


def test_har_export_and_cli(make_proxy, http_app, https_app, tmp_path, capsys):
    proxy = make_proxy()
    via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/hello")
    via_tunnel(proxy, https_app, "GET", "/gzip")
    via_proxy(proxy, "POST", f"http://127.0.0.1:{http_app}/echo?x=1", body=b"data=1",
              headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "a=b"})

    out = tmp_path / "out.har"
    assert main(["har", "-p", proxy.db_path, str(out)]) == 0
    log = json.loads(out.read_text())["log"]
    assert log["version"] == "1.2" and len(log["entries"]) == 3
    hello, gz, post = log["entries"]
    assert hello["response"]["cookies"] == [{"name": "session", "value": "abc123"}]
    assert json.loads(gz["response"]["content"]["text"]) == {"secret": "gzipped json"}
    assert post["request"]["queryString"] == [{"name": "x", "value": "1"}]
    assert post["request"]["postData"]["text"] == "data=1"
    assert post["request"]["cookies"] == [{"name": "a", "value": "b"}]

    capsys.readouterr()
    assert main(["history", "-p", proxy.db_path, "--method", "POST"]) == 0
    listed = capsys.readouterr().out
    assert "/echo?x=1" in listed and "/hello" not in listed
    assert main(["show", "-p", proxy.db_path, "1"]) == 0
    shown = capsys.readouterr().out
    assert shown.startswith("GET /hello HTTP/1.1") and "hello world" in shown


def test_browser_accept_encoding_is_narrowed_to_what_we_can_decode(make_proxy, http_app):
    proxy = make_proxy()
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers",
                        headers={"Accept-Encoding": "gzip, deflate, br, zstd"})
    assert "accept-encoding: gzip, deflate\n" in body.decode().lower()
    # Only codings the client offered are kept; "br" alone becomes identity.
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers",
                        headers={"Accept-Encoding": "br;q=1.0, zstd"})
    assert "accept-encoding: identity\n" in body.decode().lower()
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers",
                        headers={"Accept-Encoding": "identity"})
    assert "accept-encoding: identity\n" in body.decode().lower()


def test_keep_accept_encoding_passes_it_through(make_proxy, http_app):
    proxy = make_proxy(readable_bodies=False)
    _, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/headers",
                        headers={"Accept-Encoding": "br"})
    assert "accept-encoding: br\n" in body.decode().lower()


def test_short_body_is_kept_and_noted_not_turned_into_502(make_proxy, http_app):
    proxy = make_proxy()
    resp, body = via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/short")
    assert (resp.status, body) == (200, b"only twelve!")
    assert resp.getheader("Content-Length") == "12"
    [flow] = proxy.history.query()
    assert flow.response.body == b"only twelve!"
    assert flow.note == "server closed the connection after 12 of 20 promised body bytes"


def test_har_urls_are_valid_rfc3986(make_proxy, http_app, tmp_path):
    proxy = make_proxy()
    # Browsers send [ and ] raw; HAR validators (REA's included) want RFC 3986.
    via_proxy(proxy, "GET", f"http://127.0.0.1:{http_app}/files/[1]%20x/a?q=[2]")
    out = tmp_path / "out.har"
    assert main(["har", "-p", proxy.db_path, str(out)]) == 0
    [entry] = json.loads(out.read_text())["log"]["entries"]
    assert entry["request"]["url"] == f"http://127.0.0.1:{http_app}/files/%5B1%5D%20x/a?q=%5B2%5D"

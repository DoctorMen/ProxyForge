import asyncio
import ssl

import pytest
from cryptography import x509

from proxyforge.ca import CertAuthority
from proxyforge.http import Headers, HttpError, parse_request_head, read_request, read_response, strip_hop_by_hop
from proxyforge.proxy import split_absolute_url, split_authority
from proxyforge.rules import Rule, RuleSet
from proxyforge.scope import Scope


def parse(reader_fn, data: bytes, *args):
    """Run an async reader over bytes, as if they arrived on a socket."""
    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await reader_fn(reader, *args)
    return asyncio.run(go())


# -- HTTP parsing ------------------------------------------------------------

def test_reads_request_with_content_length():
    req = parse(read_request, b"POST /a?b=1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloEXTRA")
    assert (req.method, req.target, req.body) == ("POST", "/a?b=1", b"hello")
    assert req.headers.get("host") == "x"


def test_reads_chunked_response_and_trailers():
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: y\r\n\r\n"
    resp = parse(read_response, raw, "GET")
    assert resp.status == 200 and resp.body == b"hello world"


def test_response_without_framing_reads_to_eof():
    resp = parse(read_response, b"HTTP/1.0 200 OK\r\n\r\nall of it", "GET")
    assert resp.body == b"all of it"


def test_head_and_304_have_no_body():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    assert parse(read_response, raw, "HEAD").body == b""
    raw = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n"
    assert parse(read_response, raw, "GET").body == b""


@pytest.mark.parametrize("head", [
    b"GET / HTTP/2.0",
    b"GET /",
    b"GET / HTTP/1.1\r\nBad Header Line",
    b"GET / HTTP/1.1\r\n folded: header",
])
def test_rejects_malformed_heads(head):
    with pytest.raises(HttpError):
        parse_request_head(head)


def test_strip_hop_by_hop_drops_headers_named_in_connection():
    h = Headers([("Connection", "close, X-Secret"), ("X-Secret", "1"), ("Keep-Alive", "5"),
                 ("Accept", "*/*"), ("Proxy-Authorization", "Basic abc")])
    assert strip_hop_by_hop(h).items == [("Accept", "*/*")]


def test_headers_set_replaces_all_duplicates():
    h = Headers([("A", "1"), ("b", "2"), ("a", "3")])
    h.set("a", "9")
    assert h.items == [("A", "9"), ("b", "2")]


@pytest.mark.parametrize("target,expected", [
    ("http://example.com/a?b", ("http", "example.com", 80, "/a?b")),
    ("http://Example.com:8080", ("http", "example.com", 8080, "/")),
    ("http://example.com?q=1", ("http", "example.com", 80, "/?q=1")),
    ("https://[::1]:8443/x", ("https", "::1", 8443, "/x")),
    ("http://user:pw@host/x", ("http", "host", 80, "/x")),
])
def test_split_absolute_url(target, expected):
    assert split_absolute_url(target) == expected


def test_split_authority():
    assert split_authority("example.com:443", 80) == ("example.com", 443)
    assert split_authority("[2001:db8::1]:8443", 443) == ("2001:db8::1", 8443)
    assert split_authority("example.com", 443) == ("example.com", 443)


# -- scope -------------------------------------------------------------------

def test_scope_rules():
    s = Scope(
        include=["example.com", "*.example.com", "https://api.example.org/v2/*", "lab.test:8443"],
        exclude=["*.example.com/logout*", "status.example.com"],
    )
    assert s.allows_url("https://example.com/")
    assert s.allows_url("http://shop.example.com/cart")
    assert not s.allows_url("https://shop.example.com/logout?x=1")
    assert not s.allows_url("https://status.example.com/")
    assert not s.allows_url("https://evil-example.com/")
    assert s.allows_url("https://api.example.org/v2/users")
    assert not s.allows_url("https://api.example.org/v1/users")
    assert not s.allows_url("http://api.example.org/v2/users")       # scheme pinned
    assert not s.allows_url("https://api.example.org:8443/v2/users")  # default port pinned
    assert s.allows_url("https://lab.test:8443/")
    assert not s.allows_url("https://lab.test/")
    assert s.allows_host("https", "shop.example.com", 443)   # path exclude doesn't block host
    assert not s.allows_host("https", "status.example.com", 443)


def test_scope_file_rejects_unknown_keys(tmp_path):
    f = tmp_path / "scope.toml"
    f.write_text('includes = ["x.com"]\n')
    with pytest.raises(ValueError):
        Scope.load(f)


def test_empty_scope_allows_nothing_by_itself():
    assert Scope().empty and not Scope().allows_url("https://example.com/")


# -- match and replace -------------------------------------------------------

def test_header_rules_replace_delete_and_add():
    rs = RuleSet([
        Rule("request_header", "^User-Agent:.*$", "User-Agent: proxyforge"),
        Rule("request_header", "^Cookie:.*$", ""),
        Rule("request_header", "", "X-Bug-Bounty: k"),
    ])
    h = Headers([("User-Agent", "curl/8"), ("Cookie", "a=b"), ("Accept", "*/*")])
    body, fired = rs.apply_request(h, b"")
    assert h.items == [("User-Agent", "proxyforge"), ("Accept", "*/*"), ("X-Bug-Bounty", "k")]
    assert fired == [0, 1, 2]


def test_body_rule():
    rs = RuleSet([Rule("response_body", r"admin=false", "admin=true")])
    body, fired = rs.apply_response(Headers(), b"user=1&admin=false")
    assert body == b"user=1&admin=true" and fired == [0]


def test_bad_rule_where():
    with pytest.raises(ValueError):
        Rule("everywhere", "a", "b")


def test_rules_file(tmp_path):
    f = tmp_path / "rules.toml"
    f.write_text('[[rule]]\nwhere = "response_header"\nmatch = "^Server:.*$"\nreplace = ""\n')
    assert len(RuleSet.load(f).rules) == 1


# -- certificate authority ---------------------------------------------------

def test_ca_is_reused_and_key_is_private(tmp_path):
    a = CertAuthority(tmp_path)
    b = CertAuthority(tmp_path)
    assert a.cert_pem == b.cert_pem
    assert (tmp_path / "ca.key").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("host,san_type", [("shop.example.com", x509.DNSName), ("10.0.0.5", x509.IPAddress)])
def test_leaf_cert_names_host_and_chains_to_ca(tmp_path, host, san_type):
    ca = CertAuthority(tmp_path)
    leaf = ca.sign_leaf(host)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(v) for v in san.get_values_for_type(san_type)] == [host]
    leaf.verify_directly_issued_by(ca.cert)
    assert isinstance(ca.server_context(host), ssl.SSLContext)


def test_narrow_accept_encoding():
    from proxyforge.proxy import narrow_accept_encoding
    assert narrow_accept_encoding("gzip, deflate, br, zstd") == "gzip, deflate"
    assert narrow_accept_encoding("br") == "identity"
    assert narrow_accept_encoding("gzip;q=0.5, br;q=1.0") == "gzip;q=0.5"
    assert narrow_accept_encoding("*") == "identity"
    assert narrow_accept_encoding("identity") == "identity"


def test_har_clean_url():
    from proxyforge.har import clean_url
    assert clean_url("http://h:3000/a b/[x]?q=1&r=[2]") == "http://h:3000/a%20b/%5Bx%5D?q=1&r=%5B2%5D"
    assert clean_url("http://h/%E1%93%9A-#x") == "http://h/%E1%93%9A-%23x"   # already-encoded bytes stay
    assert clean_url("https://h/plain/path?a=b&c=d") == "https://h/plain/path?a=b&c=d"
    assert clean_url("http://h") == "http://h"
    # Raw UTF-8 bytes on the wire are stored latin-1; they come out as the bytes sent.
    assert clean_url("http://h/caf" + "é".encode("utf-8").decode("latin-1")) == "http://h/caf%C3%A9"
    assert clean_url("http://h/a%?q=50%") == "http://h/a%25?q=50%25"   # a lone % is not an escape


def test_decode_content_is_capped_and_reads_every_gzip_member(monkeypatch):
    import gzip
    import zlib
    from proxyforge import http
    from proxyforge.http import Headers, decode_content_info
    bomb = zlib.compress(b"\0" * 5_000_000, 9)   # 5 MB of zeros in ~5 KB
    monkeypatch.setattr(http, "DECODE_LIMIT", 100_000)
    out, cut = decode_content_info(bomb, Headers([("Content-Encoding", "deflate")]))
    assert cut and len(out) == 100_000
    two = gzip.compress(b"first,") + gzip.compress(b"second")
    assert decode_content_info(two, Headers([("Content-Encoding", "gzip")])) == (b"first,second", False)

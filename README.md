# proxyforge

A small, readable web security testing proxy, written in Python. It is a
clean-room build of the ideas in Burp Suite Professional: the features were
worked out from PortSwigger's public documentation and from open-source
tools (OWASP ZAP, mitmproxy, Caido), not from Burp's code.

**Status: part 1 of 10.** What works today is the intercepting proxy:
HTTP and HTTPS capture, a scope file, match-and-replace rules, a SQLite
history you can search, and HAR export. Everything listed below as
"planned" does not exist yet.

| Burp Pro feature | proxyforge | Status |
|---|---|---|
| Proxy, HTTP history, TLS interception | `proxyforge run`, `history`, `show` | done |
| Target scope | TOML scope file, enforced | done |
| Match and replace | TOML rules file | done |
| Save/export traffic | SQLite project file, HAR 1.2 export | done |
| Repeater, Decoder, Comparer | `repeat`, `decode`, `diff` | planned (part 2) |
| Intruder (4 attack types) | `fuzz` | planned (part 3) |
| Passive scanner | | planned (part 4) |
| Active scanner, BChecks | YAML checks | planned (part 5) |
| Collaborator (out-of-band) | self-hosted catcher | planned (part 6) |
| Crawler, content discovery | | planned (part 7) |
| Sequencer | token randomness tests | planned (part 8) |
| Reports, extensions | | planned (part 9) |
| GUI | web UI | planned (part 10) |

## Only test what you are allowed to test

Use this on your own lab, on deliberately vulnerable apps, and on bug bounty
targets that are in the program's scope. Put those targets in a scope file:
the proxy will not decrypt or record anything else, and the attack tools
planned for later parts will refuse to send to anything outside it.

## Install

Needs Python 3.11 or newer.

```bash
git clone https://github.com/DoctorMen/proxyforge
cd proxyforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
pytest            # expect: 43 passed
```

## Do it yourself: capture your first traffic

This uses a practice web server on your own machine, so nothing leaves it.

**Terminal 1**, start a practice web server:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

**Terminal 2**, start the proxy with the example scope and rules:

```bash
proxyforge run -p lab.db -s examples/scope.toml -r examples/rules.toml
```

Expected output (your CA path will differ):

```
proxyforge 0.1.0 listening on 127.0.0.1:8080
  project: lab.db   CA: /home/you/.proxyforge/ca.pem
  scope: examples/scope.toml   rules: 2
  try: curl -x http://127.0.0.1:8080 --cacert /home/you/.proxyforge/ca.pem https://example.com/
```

**Terminal 3**, send two requests through it (`-x` means "use this proxy"):

```bash
curl -s -x http://127.0.0.1:8080 http://127.0.0.1:8000/ | head -3
curl -s -x http://127.0.0.1:8080 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/nope
```

Terminal 2 prints one line per request:

```
    1  200  GET     http://127.0.0.1:8000/  425B  1ms
    2  404  GET     http://127.0.0.1:8000/nope  335B  5ms
```

List and inspect what was recorded:

```bash
proxyforge history -p lab.db
proxyforge show -p lab.db 1
```

`show` prints the request exactly as it was sent. Notice two things the
rules file did: an `X-Bug-Bounty: your-handle` header was added to the
request, and the server's `Server:` header was removed from the response.

```
GET / HTTP/1.1
Host: 127.0.0.1:8000
User-Agent: curl/8.5.0
Accept: */*
X-Bug-Bounty: your-handle
Connection: close

------------------------------------------------------------
HTTP/1.0 200 OK
Date: Wed, 14 Oct 2026 01:19:25 GMT
Content-type: text/html; charset=utf-8
Content-Length: 425

<!DOCTYPE HTML>
...
```

If curl seems to skip the proxy and nothing is printed in terminal 2, your
shell probably sets `NO_PROXY` to include 127.0.0.1. Run `unset NO_PROXY no_proxy`
and try again.

## HTTPS

To read HTTPS the proxy makes its own certificate authority (CA) and signs a
certificate for each site on the fly. Your client must trust that CA.

```bash
proxyforge ca > proxyforge-ca.pem        # creates ~/.proxyforge/ca.pem on first run
curl -x http://127.0.0.1:8080 --cacert proxyforge-ca.pem https://example.com/
```

For a browser, make a separate Firefox profile for testing
(`firefox -P`), set its proxy to 127.0.0.1:8080, browse to
`http://proxyforge/`, download the certificate, and import it under
Settings > Privacy & Security > Certificates > View Certificates >
Authorities. Never install the CA in your everyday browser: anyone holding
`~/.proxyforge/ca.key` could impersonate any website to it.

The proxy checks the real site's certificate on the way out. For a lab
target with a self-signed certificate, pass `--upstream-ca lab-ca.pem`, or
`--insecure-upstream` as a last resort.

## Scope

```toml
include = ["example.com", "*.example.com", "https://api.example.org/v2/*"]
exclude = ["*.example.com/logout*"]
```

Entries are `[scheme://]host[:port][/path]` with `*` wildcards.
`*.example.com` does not cover `example.com` itself, so list both.
Exclude wins. Check a URL without sending anything:

```bash
proxyforge scope -s examples/scope.toml https://shop.example.com/cart https://shop.example.com/logout https://evil.com/
```

```
IN   https://shop.example.com/cart
OUT  https://shop.example.com/logout
OUT  https://evil.com/
```

With no scope file everything is recorded, which is fine for your own lab.

## Match and replace

See `examples/rules.toml`. Header rules work on one `Name: value` line at a
time: an empty `replace` deletes the line, an empty `match` adds `replace`
as a new header. Body rules are regexes over the raw body; they won't match
inside a gzip-compressed response. Rules only touch in-scope traffic.

## HAR export (and REA)

```bash
proxyforge har -p lab.db lab.har
```

HAR is the format browser dev tools use. The file opens in Chrome or Firefox
dev tools (Network tab, import), in OWASP ZAP, and in
[REA](https://github.com/morluto/rea) for deeper analysis of the captured
traffic.

## How it works

```
browser --"GET http://site/x"------------> proxy --> site:80
browser --"CONNECT site:443"-------------> proxy
        <--"200 Connection Established"--
        ==TLS, cert for "site" signed by proxyforge CA==
        --"GET /x"-----------------------> proxy ==TLS==> site:443
```

| File | What it does |
|---|---|
| `proxyforge/http.py` | Parses and writes HTTP/1.1 messages: Content-Length, chunked, read-to-close, hop-by-hop headers |
| `proxyforge/ca.py` | Creates the CA and per-site certificates with `cryptography` |
| `proxyforge/proxy.py` | The asyncio proxy: CONNECT, TLS interception, forwarding, WebSocket pass-through |
| `proxyforge/scope.py` | Scope matching |
| `proxyforge/rules.py` | Match and replace |
| `proxyforge/history.py` | SQLite history |
| `proxyforge/har.py` | HAR 1.2 export |
| `proxyforge/cli.py` | The `proxyforge` command |

Known limits in part 1: HTTP/1.1 only (the proxy offers only HTTP/1.1 to
both sides, so HTTP/2 sites fall back), no live "intercept and edit before
sending" yet (that comes with the UI), and frames after a WebSocket upgrade
are passed through but not recorded.

## Tests

`pytest` runs 43 tests. The end-to-end tests start real HTTP and HTTPS
servers on 127.0.0.1 and send traffic through a running proxy. They check,
among other things, that:

- HTTPS is decrypted only for clients that trust the proxy CA;
- the proxy refuses a site whose certificate it can't verify;
- out-of-scope HTTPS is tunnelled untouched and never recorded;
- chunked, gzip, HEAD, 204, keep-alive and WebSocket upgrades are handled;
- match-and-replace rules change the traffic and are logged per request.

CI runs them on Python 3.11 to 3.13, then smoke-tests the real CLI with curl.

## How this was built

I'm building this to learn how web security tools work inside. I wrote it
with help from an AI assistant (Claude), working one part at a time, and I
review and test each part before it's merged. The commit history shows
where the assistant co-authored code.

## License

MIT. Not affiliated with PortSwigger. "Burp Suite" is their trademark, used
here only to describe which features this project re-creates.

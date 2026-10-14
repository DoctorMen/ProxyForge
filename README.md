# proxyforge

A small, readable web security testing proxy, written in Python. It is a
clean-room build of the ideas in Burp Suite Professional: the features were
worked out from PortSwigger's public documentation and from open-source
tools (OWASP ZAP, mitmproxy, Caido), not from Burp's code.

**Status: part 2 of 10.** What works today: the intercepting proxy
(HTTP and HTTPS capture, scope file, match-and-replace rules, a SQLite
history you can search, HAR export) and the manual testing tools
(Repeater, Decoder, Comparer). Everything listed below as "planned" does
not exist yet.

| Burp Pro feature | proxyforge | Status |
|---|---|---|
| Proxy, HTTP history, TLS interception | `proxyforge run`, `history`, `show` | done |
| Target scope | TOML scope file, enforced | done |
| Match and replace | TOML rules file | done |
| Save/export traffic | SQLite project file, HAR 1.2 export | done |
| Repeater, Decoder, Comparer | `repeat`, `raw`, `decode`, `encode`, `diff` | done |
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
pytest            # expect: 64 passed
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

## Repeater: change a request and send it again

Take any recorded flow, change one thing, and resend it. Each resend is
saved to history as a new flow (marked `repeater: from flow N`), so your
testing leaves an evidence trail.

```bash
proxyforge repeat 1 -p lab.db --no-scope --path /nope
```

```
#2  404 File not found  GET http://127.0.0.1:8000/nope  335B  6ms
HTTP/1.0 404 File not found
Server: SimpleHTTP/0.6 Python/3.13.16
...
```

Edits you can combine:

| Option | Does |
|---|---|
| `--path /rest/basket/2` | new path and query |
| `-X POST` | new method |
| `-H "Authorization: Bearer ..."` | set a header (repeatable); `-H "Cookie:"` removes one |
| `--body 'text'` or `--body @file` | new body; Content-Length is fixed for you |
| `-e` | open the whole request in your editor (`$EDITOR`, default nano) |
| `--url https://host:port` | send somewhere else |
| `--raw req.http --url ...` | send a request you wrote in a text file |

`proxyforge raw 5 -p lab.db > req.http` saves a flow's request as text to
edit and replay with `--raw`.

Repeater, and every attack tool after it, refuses to send anything until you
make a scope decision: pass `-s scope.toml` (the target must be in it) or
`--no-scope` to say you own the target.

```
$ proxyforge repeat 1 -p lab.db
refused: active tools need a scope file (-s scope.toml) or --no-scope to confirm you own the target
```

**Practice: find an IDOR in OWASP Juice Shop.** Run Juice Shop locally
(`docker run -d -p 3000:3000 bkimminich/juice-shop`), log in through the
proxy, and open your basket. Then ask for someone else's:

```bash
proxyforge history -p juice.db --contains basket        # find your basket flow, e.g. 6
proxyforge repeat 6 -p juice.db --no-scope --path /rest/basket/1
proxyforge diff 6 NEW -p juice.db    # NEW = the flow number repeat printed
```

If the response has `"UserId": 1` while you are logged in as another user,
the server is not checking who owns the basket.

## Decoder

`proxyforge decode` guesses the encoding and peels it layer by layer:

```bash
proxyforge decode 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiayIsInJvbGUiOiJjdXN0b21lciJ9.'
```

```
[1] jwt:
{
  "header": {
    "alg": "none"
  },
  "payload": {
    "user": "k",
    "role": "customer"
  },
  "signature": "(empty: unsigned token)",
  "note": "signature NOT verified"
}
```

Choose the steps yourself with `-c`, in order:
`proxyforge decode -c url,base64 'eyJhIjoxfQ%3D%3D'` (prints `{"a":1}`), and
`proxyforge encode -c base64,url '{"role":"admin"}'`.
Codecs: url, url-all, base64, base64url, hex, html, gzip, and jwt (decode only).

## Comparer

```bash
proxyforge diff 1 2 -p lab.db            # responses
proxyforge diff 1 2 -p lab.db --request  # requests
```

```
A  #1  GET http://127.0.0.1:8000/
B  #2  GET http://127.0.0.1:8000/nope
status: 200 vs 404   length: 460 vs 335   time: 2ms vs 6ms
headers: changed
  ~ content-type: text/html; charset=utf-8  ->  text/html;charset=utf-8
body: changed
--- #1
+++ #2
...
```

Headers that change on every response (Date, ETag, Content-Length,
Connection) are ignored. JSON bodies are pretty-printed first, so a
one-line API response diffs field by field.

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
| `proxyforge/client.py` | Sends one request directly to a server; the scope gate for active tools |
| `proxyforge/repeater.py` | Raw request text, edits |
| `proxyforge/codec.py` | Decoder: codecs and layer guessing |
| `proxyforge/compare.py` | Comparer: header and body diffs |
| `proxyforge/cli.py` | The `proxyforge` command |

Known limits: HTTP/1.1 only (the proxy offers only HTTP/1.1 to
both sides, so HTTP/2 sites fall back), no live "intercept and edit before
sending" yet (that comes with the UI), and frames after a WebSocket upgrade
are passed through but not recorded.

## Tests

`pytest` runs 64 tests. The end-to-end tests start real HTTP and HTTPS
servers on 127.0.0.1 and send traffic through a running proxy. They check,
among other things, that:

- HTTPS is decrypted only for clients that trust the proxy CA;
- the proxy refuses a site whose certificate it can't verify;
- out-of-scope HTTPS is tunnelled untouched and never recorded;
- chunked, gzip, HEAD, 204, keep-alive and WebSocket upgrades are handled;
- match-and-replace rules change the traffic and are logged per request.

CI runs them on Python 3.11 to 3.13, then smoke-tests the real CLI with curl.

## Where it differs from Burp on purpose

- Active tools refuse to send until you give a scope file or say `--no-scope`.
  A typo can't send attack traffic to a host you aren't allowed to test.
- History is a plain SQLite file. Query it with any SQL tool.
- Every Repeater send is kept as evidence with a note saying where it came from.
- HAR export feeds the traffic to REA and browser dev tools.
- Planned: the scanner will run PortSwigger's open BCheck files (LGPL-3.0
  community library), and each check will be proven in CI against an app
  with a planted bug.

## How this was built

I'm building this to learn how web security tools work inside. I wrote it
with help from an AI assistant (Claude), working one part at a time, and I
review and test each part before it's merged. The commit history shows
where the assistant co-authored code.

## License

MIT. Not affiliated with PortSwigger. "Burp Suite" is their trademark, used
here only to describe which features this project re-creates.

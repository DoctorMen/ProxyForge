"""Command line: `proxyforge <command>`. Run `proxyforge -h` for the list."""

from __future__ import annotations

import argparse
import asyncio
import os
import ssl
import sys
from pathlib import Path

from . import __version__, codec, har
from .ca import CertAuthority
from .client import OutOfScope, check_scope, default_context, send
from .compare import body_diff, header_changes
from .history import History
from .http import Headers, HttpError
from .proxy import ProxyServer, split_absolute_url, split_authority
from .repeater import apply_edits, describe, from_raw, to_raw
from .rules import RuleSet
from .scope import Scope

DEFAULT_CA_DIR = Path(os.environ.get("PROXYFORGE_HOME", Path.home() / ".proxyforge"))
DEFAULT_PROJECT = "proxyforge.db"


def _headers_text(headers: Headers) -> str:
    return "".join(f"{k}: {v}\n" for k, v in headers)


def _body_text(body: bytes, limit: int = 4000) -> str:
    if not body:
        return ""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return f"[{len(body)} bytes of binary data]\n"
    if len(text) > limit:
        return text[:limit] + f"\n[... {len(text) - limit} more characters]\n"
    return text + ("\n" if not text.endswith("\n") else "")


def _filters(args) -> dict:
    return dict(host=args.host, method=args.method, status=args.status, contains=args.contains)


def cmd_run(args) -> int:
    ca = CertAuthority(args.ca_dir)
    scope = Scope.load(args.scope) if args.scope else Scope()
    rules = RuleSet.load(args.rules) if args.rules else RuleSet()
    upstream = ssl.create_default_context(cafile=args.upstream_ca)
    upstream.set_alpn_protocols(["http/1.1"])
    if args.insecure_upstream:
        upstream.check_hostname = False
        upstream.verify_mode = ssl.CERT_NONE
    host, port = split_authority(args.listen, 8080)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: listening on {host}; anyone who can reach this port can use your proxy",
              file=sys.stderr)
    history = History(args.project)
    proxy = ProxyServer(ca, history, scope, rules, listen_host=host, listen_port=port,
                        upstream_ssl=upstream, record_out_of_scope=args.record_out_of_scope)

    async def main():
        bound = await proxy.start()
        print(f"proxyforge {__version__} listening on {host}:{bound}")
        print(f"  project: {args.project}   CA: {ca.cert_path}")
        print(f"  scope: {'everything (no scope file)' if scope.empty else args.scope}"
              f"   rules: {len(rules.rules)}")
        print(f"  try: curl -x http://{host}:{bound} --cacert {ca.cert_path} https://example.com/")
        await proxy.serve_forever()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        history.close()
    return 0


def cmd_ca(args) -> int:
    ca = CertAuthority(args.ca_dir)
    print(f"# CA certificate: {ca.cert_path}", file=sys.stderr)
    print(f"# private key:    {ca.key_path} (keep this secret)", file=sys.stderr)
    sys.stdout.write(ca.cert_pem.decode())
    return 0


def cmd_history(args) -> int:
    history = History(args.project)
    flows = history.query(**_filters(args), limit=args.limit)
    for f in flows:
        status = f.response.status if f.response else "ERR"
        size = len(f.response.body) if f.response else 0
        print(f"{f.id:>5}  {status}  {f.request.method:<7} {f.url}  {size}B")
    print(f"{len(flows)} of {history.count()} flows", file=sys.stderr)
    return 0


def cmd_show(args) -> int:
    history = History(args.project)
    flow = history.get(args.id)
    if flow is None:
        print(f"no flow {args.id}", file=sys.stderr)
        return 1
    r = flow.request
    if not args.response_only:
        print(f"{r.method} {r.target} {r.version}")
        print(_headers_text(r.headers) + "\n" + _body_text(r.body), end="")
    if not args.request_only:
        if not args.response_only:
            print("\n" + "-" * 60)
        if flow.response is None:
            print(f"(no response: {flow.error})")
        else:
            s = flow.response
            print(f"{s.version} {s.status} {s.reason}")
            print(_headers_text(s.headers) + "\n" + _body_text(s.body), end="")
    if flow.rules_fired:
        print(f"\n[match/replace rules applied: {flow.rules_fired}]")
    return 0


def cmd_har(args) -> int:
    history = History(args.project)
    flows = history.query(**_filters(args))
    Path(args.output).write_text(har.dumps(flows))
    print(f"wrote {len(flows)} entries to {args.output}")
    return 0


def cmd_scope(args) -> int:
    scope = Scope.load(args.scope)
    code = 0
    for url in args.urls:
        ok = scope.allows_url(url)
        code |= 0 if ok else 1
        print(f"{'IN ' if ok else 'OUT'}  {url}")
    return code


def _read_body_arg(value: str | None) -> bytes | None:
    if value is None:
        return None
    if value.startswith("@"):
        return Path(value[1:]).read_bytes()
    return value.encode()


def _edit_in_editor(text: str) -> str:
    import subprocess
    import tempfile
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
    with tempfile.NamedTemporaryFile("w+", suffix=".http", delete=False) as fh:
        fh.write(text)
        name = fh.name
    try:
        subprocess.run([*editor.split(), name], check=True)
        return Path(name).read_text()
    finally:
        os.unlink(name)


def _print_response(flow, body_limit: int) -> None:
    if flow.response is None:
        return
    s = flow.response
    print(f"{s.version} {s.status} {s.reason}")
    print(_headers_text(s.headers) + "\n" + _body_text(s.body, body_limit), end="")


def cmd_repeat(args) -> int:
    history = History(args.project)
    if args.raw:
        if not args.url:
            print("--raw needs --url to say where to send it, e.g. --url https://example.com", file=sys.stderr)
            return 2
        req = from_raw(Path(args.raw).read_text())
        scheme = host = port = None
        note = f"repeater: from {args.raw}"
    else:
        if args.id is None:
            print("give a flow id, or --raw FILE --url URL", file=sys.stderr)
            return 2
        source = history.get(args.id)
        if source is None:
            print(f"no flow {args.id}", file=sys.stderr)
            return 1
        req, scheme, host, port = source.request, source.scheme, source.host, source.port
        note = f"repeater: from flow {args.id}"
    if args.url:
        scheme, host, port, base_path = split_absolute_url(args.url)
        if args.raw is None and base_path != "/" and not args.path:
            args.path = base_path
        req.headers.remove("Host")
    req = apply_edits(req, method=args.method, path=args.path, set_headers=args.header,
                      body=_read_body_arg(args.body))
    if args.edit:
        req = from_raw(_edit_in_editor(to_raw(req)))
    target_url = f"{scheme}://{host}:{port}{req.target}"
    scope = Scope.load(args.scope) if args.scope else None
    try:
        check_scope(target_url, scope, args.no_scope)
    except OutOfScope as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    flow = asyncio.run(send(scheme, host, port, req, default_context(args.insecure), args.timeout))
    flow.note = note
    if not args.no_save:
        history.add(flow)
    if args.show_request:
        print(to_raw(flow.request).rstrip("\n") + "\n\n" + "-" * 60)
    print(describe(flow), file=sys.stderr)
    _print_response(flow, args.limit)
    return 0 if flow.response is not None else 1


def cmd_raw(args) -> int:
    flow = History(args.project).get(args.id)
    if flow is None:
        print(f"no flow {args.id}", file=sys.stderr)
        return 1
    sys.stdout.write(to_raw(flow.request))
    return 0


def _input_bytes(text: str | None) -> bytes:
    if text is None or text == "-":
        return sys.stdin.buffer.read().rstrip(b"\n")
    return text.encode()


def _show_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return "hex: " + data.hex()


def cmd_decode(args) -> int:
    data = _input_bytes(args.text)
    if args.chain:
        print(_show_bytes(codec.decode(data, args.chain.split(","))))
        return 0
    steps = codec.smart_decode(data)
    if not steps:
        print("no known encoding detected; try -c with one of: " + ", ".join(codec.DECODERS),
              file=sys.stderr)
        return 1
    for i, (name, out) in enumerate(steps, 1):
        print(f"[{i}] {name}:")
        print(_show_bytes(out))
    return 0


def cmd_encode(args) -> int:
    print(_show_bytes(codec.encode(_input_bytes(args.text), args.chain.split(","))))
    return 0


def cmd_diff(args) -> int:
    history = History(args.project)
    a, b = history.get(args.a), history.get(args.b)
    for fid, f in ((args.a, a), (args.b, b)):
        if f is None:
            print(f"no flow {fid}", file=sys.stderr)
            return 1
    print(f"A  #{a.id}  {a.request.method} {a.url}")
    print(f"B  #{b.id}  {b.request.method} {b.url}")
    if args.request:
        ha, hb, ba, bb = a.request.headers, b.request.headers, a.request.body, b.request.body
        if a.request.target != b.request.target or a.request.method != b.request.method:
            print(f"~ request line: {a.request.method} {a.request.target}  ->  {b.request.method} {b.request.target}")
    else:
        if a.response is None or b.response is None:
            print("one of the flows has no response", file=sys.stderr)
            return 1
        ha, hb, ba, bb = a.response.headers, b.response.headers, a.response.body, b.response.body
        print(f"status: {a.response.status} vs {b.response.status}   "
              f"length: {len(ba)} vs {len(bb)}   time: {a.duration_ms}ms vs {b.duration_ms}ms")
    changes = header_changes(ha, hb)
    print("headers: " + ("identical (ignoring Date, ETag, Content-Length, Connection)" if not changes else "changed"))
    for line in changes:
        print("  " + line)
    diff = body_diff(ba, bb, f"#{a.id}", f"#{b.id}", args.context)
    print("body: " + ("identical" if not diff else "changed"))
    for line in diff:
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="proxyforge", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def project(sp):
        sp.add_argument("-p", "--project", default=DEFAULT_PROJECT, help="SQLite project file")

    def filters(sp):
        sp.add_argument("--host", help="host, wildcards allowed (*.example.com)")
        sp.add_argument("--method")
        sp.add_argument("--status", type=int)
        sp.add_argument("--contains", help="text that must appear in the path")

    run = sub.add_parser("run", help="start the proxy")
    project(run)
    run.add_argument("-l", "--listen", default="127.0.0.1:8080")
    run.add_argument("-s", "--scope", help="scope TOML file (default: record everything)")
    run.add_argument("-r", "--rules", help="match/replace rules TOML file")
    run.add_argument("--ca-dir", default=DEFAULT_CA_DIR)
    run.add_argument("--upstream-ca", help="extra CA file to trust for upstream servers")
    run.add_argument("--insecure-upstream", action="store_true",
                     help="don't verify upstream certificates (lab targets only)")
    run.add_argument("--record-out-of-scope", action="store_true",
                     help="decrypt and record traffic outside the scope too")
    run.set_defaults(func=cmd_run)

    ca = sub.add_parser("ca", help="create (if needed) and print the CA certificate")
    ca.add_argument("--ca-dir", default=DEFAULT_CA_DIR)
    ca.set_defaults(func=cmd_ca)

    hist = sub.add_parser("history", help="list recorded flows")
    project(hist)
    filters(hist)
    hist.add_argument("-n", "--limit", type=int, help="only the last N flows")
    hist.set_defaults(func=cmd_history)

    show = sub.add_parser("show", help="print one flow's request and response")
    project(show)
    show.add_argument("id", type=int)
    group = show.add_mutually_exclusive_group()
    group.add_argument("--request-only", action="store_true")
    group.add_argument("--response-only", action="store_true")
    show.set_defaults(func=cmd_show)

    h = sub.add_parser("har", help="export flows as a HAR file")
    project(h)
    filters(h)
    h.add_argument("output")
    h.set_defaults(func=cmd_har)

    rp = sub.add_parser("repeat", help="edit a request and send it again (Repeater)")
    project(rp)
    rp.add_argument("id", type=int, nargs="?", help="flow id to start from")
    rp.add_argument("--raw", help="send a raw request file instead of a flow")
    rp.add_argument("--url", help="where to send it: scheme://host[:port][/path]")
    rp.add_argument("-X", "--method")
    rp.add_argument("--path", help="new path and query, e.g. /rest/basket/2")
    rp.add_argument("-H", "--header", action="append",
                    help="'Name: value' to set, 'Name:' to remove (repeatable)")
    rp.add_argument("--body", help="new body text, or @file")
    rp.add_argument("-e", "--edit", action="store_true", help="open the request in $EDITOR first")
    rp.add_argument("-s", "--scope", help="scope file; the target must be in it")
    rp.add_argument("--no-scope", action="store_true", help="I own this target; skip the scope check")
    rp.add_argument("--insecure", action="store_true", help="don't verify the server's certificate")
    rp.add_argument("--timeout", type=float, default=30)
    rp.add_argument("--show-request", action="store_true")
    rp.add_argument("--no-save", action="store_true", help="don't add the result to history")
    rp.add_argument("--limit", type=int, default=4000, help="max body characters to print")
    rp.set_defaults(func=cmd_repeat)

    raw = sub.add_parser("raw", help="print a flow's request as editable text")
    project(raw)
    raw.add_argument("id", type=int)
    raw.set_defaults(func=cmd_raw)

    dec = sub.add_parser("decode", help="decode text; guesses the layers if -c is not given")
    dec.add_argument("text", nargs="?", help="text to decode (default: read stdin)")
    dec.add_argument("-c", "--chain", help="decoders to apply in order: " + ",".join(codec.DECODERS))
    dec.set_defaults(func=cmd_decode)

    enc = sub.add_parser("encode", help="encode text with one or more encoders")
    enc.add_argument("text", nargs="?", help="text to encode (default: read stdin)")
    enc.add_argument("-c", "--chain", required=True, help="encoders in order: " + ",".join(codec.ENCODERS))
    enc.set_defaults(func=cmd_encode)

    df = sub.add_parser("diff", help="compare two flows (Comparer)")
    project(df)
    df.add_argument("a", type=int)
    df.add_argument("b", type=int)
    df.add_argument("--request", action="store_true", help="compare requests instead of responses")
    df.add_argument("--context", type=int, default=3, help="lines of context around changes")
    df.set_defaults(func=cmd_diff)

    sc = sub.add_parser("scope", help="check URLs against a scope file")
    sc.add_argument("-s", "--scope", required=True)
    sc.add_argument("urls", nargs="+")
    sc.set_defaults(func=cmd_scope)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # Output piped into `head` etc. was closed early; that's not an error.
        sys.stderr.close()
        return 0
    except (ValueError, HttpError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

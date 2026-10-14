"""Command line: `proxyforge <command>`. Run `proxyforge -h` for the list."""

from __future__ import annotations

import argparse
import asyncio
import os
import ssl
import sys
from pathlib import Path

from . import __version__, har
from .ca import CertAuthority
from .history import History
from .http import Headers
from .proxy import ProxyServer, split_authority
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

    sc = sub.add_parser("scope", help="check URLs against a scope file")
    sc.add_argument("-s", "--scope", required=True)
    sc.add_argument("urls", nargs="+")
    sc.set_defaults(func=cmd_scope)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)

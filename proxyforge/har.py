"""Export history as HAR 1.2, the JSON format browsers' dev tools use.

A HAR file opens in Chrome/Firefox dev tools, in OWASP ZAP, and in REA
(`inspect_web_network_capture`), so traffic captured here can be analysed
with those tools too.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, quote, urlsplit

from . import __version__
from .history import Flow
from .http import Headers, decode_content


def _text_or_base64(body: bytes) -> dict:
    try:
        return {"text": body.decode("utf-8")}
    except UnicodeDecodeError:
        return {"text": base64.b64encode(body).decode(), "encoding": "base64"}


def _headers(headers: Headers) -> list[dict]:
    return [{"name": k, "value": v} for k, v in headers]


def _request_cookies(headers: Headers) -> list[dict]:
    out = []
    for line in headers.get_all("Cookie"):
        for part in line.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep:
                out.append({"name": name, "value": value})
    return out


def _response_cookies(headers: Headers) -> list[dict]:
    out = []
    for line in headers.get_all("Set-Cookie"):
        jar = SimpleCookie()
        try:
            jar.load(line)
        except Exception:
            continue
        out.extend({"name": m.key, "value": m.value} for m in jar.values())
    return out


def clean_url(url: str) -> str:
    """Percent-encode characters a browser leaves raw (spaces, [, ], quotes, non-ASCII).

    Browsers send such paths as-is, but HAR consumers that validate the
    schema (REA does) reject any URL that is not valid RFC 3986.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        return url
    authority, slash, path = rest.partition("/")
    return scheme + sep + authority + slash + quote(path, safe="/:@!$&'()*+,;=%~-._?")


def flow_to_entry(flow: Flow) -> dict:
    req, resp = flow.request, flow.response
    url = clean_url(flow.url)
    request = {
        "method": req.method,
        "url": url,
        "httpVersion": req.version,
        "headers": _headers(req.headers),
        "queryString": [
            {"name": k, "value": v}
            for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ],
        "cookies": _request_cookies(req.headers),
        "headersSize": len(req.head_bytes()),
        "bodySize": len(req.body),
    }
    if req.body:
        post = _text_or_base64(req.body)
        if "encoding" in post:  # HAR postData has no encoding field
            post = {"text": post["text"], "comment": "base64-encoded binary body"}
        request["postData"] = {
            "mimeType": req.headers.get("Content-Type", "application/octet-stream"),
            **post,
        }
    if resp is not None:
        content = decode_content(resp.body, resp.headers)
        response = {
            "status": resp.status,
            "statusText": resp.reason,
            "httpVersion": resp.version,
            "headers": _headers(resp.headers),
            "cookies": _response_cookies(resp.headers),
            "content": {
                "size": len(content),
                "mimeType": resp.headers.get("Content-Type", ""),
                **_text_or_base64(content),
            },
            "redirectURL": resp.headers.get("Location", ""),
            "headersSize": len(resp.head_bytes()),
            "bodySize": len(resp.body),
        }
    else:
        response = {
            "status": 0, "statusText": "", "httpVersion": "", "headers": [], "cookies": [],
            "content": {"size": 0, "mimeType": ""}, "redirectURL": "",
            "headersSize": -1, "bodySize": -1, "_error": flow.error or "",
        }
    total = flow.duration_ms or 0
    return {
        "startedDateTime": dt.datetime.fromtimestamp(flow.started, dt.timezone.utc).isoformat(),
        "time": total,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": total, "receive": 0},
        "comment": f"proxyforge flow {flow.id}",
    }


def to_har(flows: list[Flow]) -> dict:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "proxyforge", "version": __version__},
            "entries": [flow_to_entry(f) for f in flows],
        }
    }


def dumps(flows: list[Flow]) -> str:
    return json.dumps(to_har(flows), indent=2)

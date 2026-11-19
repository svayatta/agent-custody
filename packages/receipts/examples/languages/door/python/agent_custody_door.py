"""Ask an agent-custody door in authz mode ("authz": true) about each request before the app runs, as nginx
auth_request does. Standard library only; copy this file into your project.

- ``DoorMiddleware``: Django middleware. Add ``"agent_custody_door.DoorMiddleware"`` first in ``MIDDLEWARE`` and set
  ``AGENT_CUSTODY_DOOR_URL`` in the environment.
- ``DoorWSGI``: WSGI middleware, for Django's ``application`` in ``wsgi.py``, Flask's ``app.wsgi_app``, or any WSGI app.

A door that cannot be reached, does not answer within the timeout, or allows without a receipt is a 503: the request
never runs ungated. Any answer but 200 goes to the client as the door gave it.
"""
import http
import http.client
import json
import os
import urllib.error
import urllib.request
from urllib.parse import quote

RECEIPT_HEADER = "X-Agent-Custody-Receipt"
CLASS_HEADER = "X-Agent-Custody-Class"
LOG_PENDING_HEADER = "X-Agent-Custody-Log-Pending"
# Hop-by-hop and body fields stay off the check, which is its own GET with no body. The three the door decides on are
# set here, never copied from the client.
NOT_FORWARDED = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
                 "content-length", "expect", "x-original-method", "x-original-uri", "x-forwarded-for"}
# The door's credentials: the door reads them, the app does not get them.
DOOR_ONLY = ("HTTP_X_AGENT_CUSTODY_GRANT", "HTTP_X_AGENT_CUSTODY_AGENT")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Verdict:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = headers
        self.receipt = headers.get(RECEIPT_HEADER, "")
        self.arrival_class = headers.get(CLASS_HEADER, "")
        self.allowed = status == 200 and bool(self.receipt)

    def door_headers(self):
        """The door's headers for the response: on an allow and on a refusal."""
        return [(k, v) for k, v in self.headers.items() if k in (RECEIPT_HEADER, CLASS_HEADER, LOG_PENDING_HEADER)]

    def refusal_headers(self):
        return [(k, v) for k, v in self.headers.items() if k in ("Content-Type", "Retry-After")] + self.door_headers()


def _unavailable(reason):
    body = json.dumps({"error": "not passed on: " + reason}).encode()
    return Verdict(503, body, {"Content-Type": "application/json"})


class DoorClient:
    def __init__(self, door_url, timeout=5.0):
        self.url = door_url.rstrip("/") + "/_agent_custody"
        self.timeout = timeout
        # no proxy from the environment and no redirects: the check goes to the door and nowhere else
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        self.opener.addheaders = []

    def check(self, method, uri, headers, remote):
        """Ask the door about one request. ``headers`` is a list of (lower-case name, value)."""
        req = urllib.request.Request(self.url, method="GET")
        for name, value in headers:
            if name not in NOT_FORWARDED:
                req.add_header(name, value)
        req.add_header("X-Original-Method", method)
        req.add_header("X-Original-URI", uri)
        req.add_header("X-Forwarded-For", remote)
        try:
            with self.opener.open(req, timeout=self.timeout) as res:
                status, body, got = res.status, res.read(65536), res.headers
        except urllib.error.HTTPError as e:
            status, body, got = e.code, e.read(65536), e.headers
        except (OSError, http.client.HTTPException, ValueError):  # refused, timed out, reset, malformed, or a header value http.client will not send
            return _unavailable("the door could not be reached")
        names = (RECEIPT_HEADER, CLASS_HEADER, LOG_PENDING_HEADER, "Content-Type", "Retry-After")
        verdict = Verdict(status, body, {n: got[n] for n in names if got.get(n)})
        if status == 200 and not verdict.receipt:
            return _unavailable("the door allowed the request without a receipt")
        return verdict


def environ_headers(environ):
    """The request's headers from a WSGI environ or Django's ``request.META``, as (lower-case name, value)."""
    out = []
    for key, value in environ.items():
        if key.startswith("HTTP_") and isinstance(value, str):
            out.append((key[5:].replace("_", "-").lower(), value))
        elif key == "CONTENT_TYPE" and value:
            out.append(("content-type", value))
    return out


def environ_uri(environ):
    """The path and query as the client sent them: the server's raw target if it keeps one, else re-encoded."""
    raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")
    if isinstance(raw, str) and raw.startswith("/"):
        return raw
    path = environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")
    try:
        data = path.encode("latin-1")  # WSGI: the bytes of the decoded path, as latin-1
    except UnicodeEncodeError:
        data = path.encode("utf-8")  # Django under ASGI keeps the decoded path as text
    query = environ.get("QUERY_STRING", "")
    return (quote(data, safe="/:@&+$,-_.!~*'()") or "/") + ("?" + query if query else "")


def _admit(environ, verdict):
    for key in DOOR_ONLY:
        environ.pop(key, None)
    environ["HTTP_X_AGENT_CUSTODY_RECEIPT"] = verdict.receipt
    environ["HTTP_X_AGENT_CUSTODY_CLASS"] = verdict.arrival_class


def _status_line(code):
    try:
        return "%d %s" % (code, http.HTTPStatus(code).phrase)
    except ValueError:
        return "%d Unknown" % code


class DoorWSGI:
    def __init__(self, app, door_url=None, timeout=5.0):
        self.app = app
        self.door = DoorClient(door_url or os.environ["AGENT_CUSTODY_DOOR_URL"], timeout)

    def __call__(self, environ, start_response):
        verdict = self.door.check(environ["REQUEST_METHOD"], environ_uri(environ), environ_headers(environ), environ.get("REMOTE_ADDR", ""))
        if not verdict.allowed:
            start_response(_status_line(verdict.status), verdict.refusal_headers())
            return [verdict.body]
        _admit(environ, verdict)

        def start(status, headers, exc_info=None):
            return start_response(status, list(headers) + verdict.door_headers(), exc_info)

        return self.app(environ, start)


class DoorMiddleware:
    def __init__(self, get_response, door_url=None, timeout=None):
        self.get_response = get_response
        self.door = DoorClient(door_url or os.environ["AGENT_CUSTODY_DOOR_URL"], timeout or float(os.environ.get("AGENT_CUSTODY_DOOR_TIMEOUT", "5")))

    def __call__(self, request):
        meta = request.META
        verdict = self.door.check(request.method, environ_uri(meta), environ_headers(meta), meta.get("REMOTE_ADDR", ""))
        if not verdict.allowed:
            from django.http import HttpResponse

            response = HttpResponse(verdict.body, status=verdict.status, content_type=verdict.headers.get("Content-Type"))
            for name, value in verdict.refusal_headers():
                if name != "Content-Type":
                    response[name] = value
            return response
        _admit(meta, verdict)
        request.__dict__.pop("headers", None)  # Django caches request.headers from META on first read
        response = self.get_response(request)
        for name, value in verdict.door_headers():
            response[name] = value
        return response

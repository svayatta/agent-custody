# The door middleware in front of a WSGI app served by wsgiref, and the Django middleware called as Django calls it.
# Django is not installed here: its part runs with a stand-in for django.http.HttpResponse and a request carrying only
# what the middleware reads (method, META). DOOR_URL points at `agent-custody door` with "authz": true; CUSTODY_GRANT
# is a passport scoped to the refund route.
import http.client
import os
import socket
import sys
import threading
import types
from wsgiref.simple_server import WSGIRequestHandler, make_server

from agent_custody_door import CLASS_HEADER, RECEIPT_HEADER, DoorMiddleware, DoorWSGI

door_url, grant = os.environ.get("DOOR_URL", ""), os.environ.get("CUSTODY_GRANT", "")
if not door_url or not grant:
    sys.exit("python: set DOOR_URL and CUSTODY_GRANT")


def check(ok, msg):
    if not ok:
        sys.exit("python: " + msg)


seen = {}


# --- WSGI, over a real socket -------------------------------------------------------------------------------------
def shop(environ, start_response):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    seen.update(ran=True, receipt=environ.get("HTTP_X_AGENT_CUSTODY_RECEIPT"), cls=environ.get("HTTP_X_AGENT_CUSTODY_CLASS"),
                grant=environ.get("HTTP_X_AGENT_CUSTODY_GRANT"), body=environ["wsgi.input"].read(length).decode())
    start_response("200 OK", [("Content-Type", "application/json")])
    return [b'{"shop":"answered"}']


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def serve(app):
    server = make_server("127.0.0.1", 0, app, handler_class=Quiet)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def request(server, method, target, body="", headers=None):
    seen.clear()
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=30)
    conn.request(method, target, body=body.encode() or None, headers=dict({"Host": "shop.example"}, **(headers or {})))
    res = conn.getresponse()
    out = (res.status, res.getheader(RECEIPT_HEADER), res.read().decode())
    conn.close()
    return out


wsgi = serve(DoorWSGI(shop, door_url, timeout=5))

# 1. A public read: allowed, and the app sees the door's receipt in place of the one the client forged.
status, receipt, _ = request(wsgi, "GET", "/catalogue/shoes?colour=red", headers={RECEIPT_HEADER: "forged", "X-Forwarded-For": "198.51.100.66", "User-Agent": "example-browser"})
check(status == 200 and seen.get("ran") and seen["receipt"] not in (None, "forged") and seen["receipt"] == receipt and seen["cls"] == "unknown", "wsgi allowed read: %s %r" % (status, seen))
print("python wsgi: GET /catalogue/shoes allowed, class", seen["cls"])
print("receipt allowed", seen["receipt"])

# 2. An unknown arrival's refund: refused with the door's 403 and body; the app never runs. The client's own
# X-Original-* headers do not change what the door decides on.
status, receipt, text = request(wsgi, "POST", "/refunds", '{"amount":1000}', {"Content-Type": "application/json", "X-Original-Method": "GET", "X-Original-URI": "/catalogue/free"})
check(status == 403 and not seen and receipt and "refused by the door's policy" in text, "wsgi refused refund: %s %s" % (status, text))
print("python wsgi: POST /refunds refused 403")
print("receipt denied", receipt)

# 3. A verified agent's refund: allowed after the door committed it to the log; the app gets the body, the receipt,
# and the class, and never the grant.
status, receipt, _ = request(wsgi, "POST", "/refunds", '{"amount":1000}', {"Content-Type": "application/json", "X-Agent-Custody-Grant": grant})
check(status == 200 and seen.get("ran") and seen["cls"] == "verified" and seen["grant"] is None and seen["body"] == '{"amount":1000}' and seen["receipt"] == receipt, "wsgi verified refund: %s %r" % (status, seen))
print("python wsgi: POST /refunds with a passport allowed, class", seen["cls"])
print("receipt verified", seen["receipt"])
wsgi.shutdown()


# --- Django: the middleware called with a request, as Django's handler calls it ----------------------------------
class HttpResponse:
    """What the middleware uses of django.http.HttpResponse: content, status, content_type, and header assignment."""

    def __init__(self, content=b"", status=200, content_type=None):
        self.content, self.status_code, self.headers = content, status, {"Content-Type": content_type or "text/html; charset=utf-8"}

    def __setitem__(self, name, value):
        self.headers[name] = value

    def __getitem__(self, name):
        return self.headers[name]


sys.modules["django"] = types.ModuleType("django")
sys.modules["django.http"] = types.ModuleType("django.http")
sys.modules["django.http"].HttpResponse = HttpResponse


class Request:
    def __init__(self, method, path, query="", headers=None, body=""):
        self.method = method
        self.META = {"REQUEST_METHOD": method, "SCRIPT_NAME": "", "PATH_INFO": path, "QUERY_STRING": query, "REMOTE_ADDR": "203.0.113.7",
                     "SERVER_NAME": "shop.example", "SERVER_PORT": "443", "HTTP_HOST": "shop.example", **(headers or {})}
        self.body = body


def view(request):
    seen.update(ran=True, receipt=request.META.get("HTTP_X_AGENT_CUSTODY_RECEIPT"), cls=request.META.get("HTTP_X_AGENT_CUSTODY_CLASS"),
                grant=request.META.get("HTTP_X_AGENT_CUSTODY_GRANT"), body=request.body)
    return HttpResponse(b'{"shop":"answered"}', content_type="application/json")


def django_call(middleware, request):
    seen.clear()
    return middleware(request)


django = DoorMiddleware(view, door_url=door_url, timeout=5)
res = django_call(django, Request("GET", "/catalogue/shoes", "colour=red", {"HTTP_X_AGENT_CUSTODY_RECEIPT": "forged", "HTTP_X_FORWARDED_FOR": "198.51.100.66", "HTTP_USER_AGENT": "example-browser"}))
check(res.status_code == 200 and seen.get("ran") and seen["receipt"] not in (None, "forged") and seen["receipt"] == res[RECEIPT_HEADER] and seen["cls"] == "unknown", "django allowed read: %s %r" % (res.status_code, seen))
print("python django: GET /catalogue/shoes allowed, class", seen["cls"])
print("receipt allowed", seen["receipt"])

res = django_call(django, Request("POST", "/refunds", headers={"CONTENT_TYPE": "application/json", "HTTP_X_ORIGINAL_METHOD": "GET", "HTTP_X_ORIGINAL_URI": "/catalogue/free"}, body='{"amount":1000}'))
check(res.status_code == 403 and not seen and res.headers.get(RECEIPT_HEADER) and b"refused by the door's policy" in res.content and res["Content-Type"].startswith("application/json"), "django refused refund: %s %r" % (res.status_code, res.content))
print("python django: POST /refunds refused 403")
print("receipt denied", res[RECEIPT_HEADER])

res = django_call(django, Request("POST", "/refunds", headers={"CONTENT_TYPE": "application/json", "HTTP_X_AGENT_CUSTODY_GRANT": grant}, body='{"amount":1000}'))
check(res.status_code == 200 and seen.get("ran") and seen["cls"] == "verified" and seen["grant"] is None and seen["receipt"] == res[RECEIPT_HEADER] and res[CLASS_HEADER] == "verified", "django verified refund: %s %r" % (res.status_code, seen))
print("python django: POST /refunds with a passport allowed, class", seen["cls"])
print("receipt verified", seen["receipt"])

# 4. A door that is down, and one that never answers: 503, and neither app runs.
gone = socket.socket()
gone.bind(("127.0.0.1", 0))
gone_url = "http://127.0.0.1:%d" % gone.getsockname()[1]
gone.close()
res = django_call(DoorMiddleware(view, door_url=gone_url, timeout=2), Request("GET", "/catalogue/shoes"))
check(res.status_code == 503 and not seen, "django, unreachable door: %s" % res.status_code)
down = serve(DoorWSGI(shop, gone_url, timeout=2))
status, _, _ = request(down, "GET", "/catalogue/shoes")
down.shutdown()
check(status == 503 and not seen, "wsgi, unreachable door: %s" % status)
print("fail-closed unreachable", status)
silent = socket.socket()  # accepts connections and never answers
silent.bind(("127.0.0.1", 0))
silent.listen(8)
silent_url = "http://127.0.0.1:%d" % silent.getsockname()[1]
res = django_call(DoorMiddleware(view, door_url=silent_url, timeout=0.5), Request("GET", "/catalogue/shoes"))
check(res.status_code == 503 and not seen, "django, silent door: %s" % res.status_code)
stalled = serve(DoorWSGI(shop, silent_url, timeout=0.5))
status, _, _ = request(stalled, "GET", "/catalogue/shoes")
stalled.shutdown()
silent.close()
check(status == 503 and not seen, "wsgi, silent door: %s" % status)
print("fail-closed timeout", status)
print("OK")

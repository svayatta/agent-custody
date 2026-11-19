# The door in Go, Rails, Django, and Spring

> Middleware for sites that are not Node. Each is a client of [the door in authz mode](door.md#behind-nginx-or-envoy-authz-mode); the check it calls is in [the reference](../../../site/reference/door.md#authz-mode).

A Node site runs the door in its own process ([the door in your Node app](door-middleware.md)). A site in Go, Ruby on Rails, Django, or Spring keeps the door as a separate process in authz mode and asks it about each request from a middleware, the way nginx `auth_request` asks it. The door classifies the arrival, runs the Cedar policy for its route, commits a request that can change something to the log, writes the receipt, and answers 200 or a refusal. The middleware runs your code only on the 200.

Four clients, standard library only, each a file to copy into your project:

| framework | file | what it is |
| --- | --- | --- |
| Go `net/http` | [examples/languages/door/go/door.go](../examples/languages/door/go/door.go) | `Door(doorURL, timeout) func(http.Handler) http.Handler` |
| Rails, or any Rack app | [examples/languages/door/ruby/agent_custody_door.rb](../examples/languages/door/ruby/agent_custody_door.rb) | `AgentCustody::Door`, a Rack middleware |
| Django, or any WSGI app | [examples/languages/door/python/agent_custody_door.py](../examples/languages/door/python/agent_custody_door.py) | `DoorMiddleware` (Django) and `DoorWSGI` (WSGI) |
| Spring, or the JDK `HttpServer` | [examples/languages/door/java/CustodyDoor.java](../examples/languages/door/java/CustodyDoor.java), [CustodyDoorFilter.java](../examples/languages/door/java/CustodyDoorFilter.java) | `CustodyDoor`, a `java.net.http` client, and a `com.sun.net.httpserver.Filter`; the Spring filter is [a snippet below](#spring) |

## Why authz mode, and not the sidecar

The sidecar (`agent-custody serve`) is the SDK for agents in other languages: an agent's process tells it about its own tool calls, and it records them as `claimed`. A site's middleware is on the other side. It needs the door's decision about a request it received: the arrival classified by the grant or Web Bot Auth signature it presented, the route matched, the Cedar policy run with the door's arrival fact, a POST committed to the log before the app runs, and a receipt with `issuer.kind: "door"`. The door's authz check does all of that already, for nginx and Envoy, so each middleware is a client of that check and nothing in the door changed.

## Run the door

The door config for authz mode: no `origin`, `"authz": true`, and `"trustProxy": true`, which authz mode requires; the middleware is the proxy.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "authz": true,
  "trustProxy": true,
  "routes": [
    { "name": "catalogue", "methods": ["GET"], "path": "/catalogue/*" },
    { "name": "refund", "methods": ["POST"], "path": "/refunds" }
  ],
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

```cedar
permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"refund", resource) when { context.facts.arrival.class == "verified" };
```

```bash
npx agent-custody door --config door.json --port 8780
```

The door believes what the middleware tells it, so let only the app reach it: bind it to loopback on the app's host (the default) or to a private network. Anyone who can reach the door can have it write receipts for requests that never happened.

## What every client does

For each request, before your code runs, the middleware sends the door a `GET <door>/_agent_custody` with:

- `X-Original-Method` and `X-Original-URI`: the request's method, and its path and query as the client sent them (the raw target where the framework keeps one, else the path re-encoded).
- `X-Forwarded-For`: the address the framework reports for the request (`RemoteAddr`, `REMOTE_ADDR`, `getRemoteAddr()`). The middleware sets all three itself; a client's own copies are never forwarded.
- Every other header of the request, the client's `Host` included, except the hop-by-hop fields and `Content-Length`, `Transfer-Encoding`, and `Expect`: the check has no body. This is what nginx `auth_request` sends. The door reads the grant (`X-Agent-Custody-Grant`, or `Authorization: Bearer`), `X-Agent-Custody-Agent`, the Web Bot Auth fields, the challenge header, and the `Host`, `User-Agent`, `Accept`, and `Content-Type` it records.

Then:

| the door | the middleware |
| --- | --- |
| 200 with `X-Agent-Custody-Receipt` | runs your code. The request has the door's `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class` in place of any the client sent, and no `X-Agent-Custody-Grant` or `X-Agent-Custody-Agent`. The response gets the receipt and class headers, and `X-Agent-Custody-Log-Pending` when the door sent it |
| any other status: 403 refused, 400, 503 when the log would not commit a POST, 500 | answers with the door's status, body, `Content-Type`, `Retry-After`, and receipt headers. Your code does not run |
| cannot be reached, no answer within the timeout (5 seconds by default), or a 200 without a receipt | answers 503 `{"error": "not passed on: ..."}`. Your code does not run, and there is no receipt: nothing was decided |

The request body stays where it is: the door never reads it, and your code reads it as it would without the middleware.

## Go

```go
http.ListenAndServe("127.0.0.1:8080", Door("http://127.0.0.1:8780", 5*time.Second)(mux))
```

`door.go` is `package main`; rename the package when you copy it. The handler gets a clone of the request with the door's headers; the client's `Host` goes to the door as `Host`.

## Rails

`config/application.rb`, with `agent_custody_door.rb` in `lib/`:

```ruby
require_relative "../lib/agent_custody_door"
config.middleware.insert_before 0, AgentCustody::Door, door_url: ENV.fetch("AGENT_CUSTODY_DOOR_URL"), timeout: 5
```

First in the stack, so that no other middleware acts on a request the door refuses. Any Rack app takes it the same way: `use AgentCustody::Door, door_url: "http://127.0.0.1:8780"` in `config.ru`. The app reads the door's headers as `request.headers["X-Agent-Custody-Receipt"]` (Rails) or `env["HTTP_X_AGENT_CUSTODY_RECEIPT"]` (Rack).

## Django

`settings.py`, with `agent_custody_door.py` on the path and `AGENT_CUSTODY_DOOR_URL` (and optionally `AGENT_CUSTODY_DOOR_TIMEOUT`, in seconds) in the environment:

```python
MIDDLEWARE = [
    "agent_custody_door.DoorMiddleware",
    # ...the rest, after the door
]
```

A view reads `request.headers["X-Agent-Custody-Receipt"]`. For a WSGI app, or to put the door in front of all of Django in `wsgi.py`:

```python
from agent_custody_door import DoorWSGI
application = DoorWSGI(get_wsgi_application(), "http://127.0.0.1:8780")
```

The timeout applies to each socket operation of the check (`urllib`), not to the check as a whole.

## Spring

`CustodyDoor` is the client, JDK only. Start the JVM with `-Djdk.httpclient.allowRestrictedHeaders=host`: `java.net.http` refuses to send a `Host` of the caller's choosing without it, and the door checks a Web Bot Auth signature against the client's `Host`. The constructor throws without the flag rather than send the door its own address. A request without a `User-Agent` is checked with an empty one, because `java.net.http` sends its own when the field is absent.

For the JDK's own server, `context.getFilters().add(new CustodyDoorFilter(door))`. For Spring MVC or Spring Boot, a servlet filter around the same client:

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustodyDoorSpringFilter extends OncePerRequestFilter {
    private final CustodyDoor door = new CustodyDoor(URI.create(System.getenv("AGENT_CUSTODY_DOOR_URL")), Duration.ofSeconds(5));

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (String name : Collections.list(req.getHeaderNames())) headers.put(name, Collections.list(req.getHeaders(name)));
        String target = req.getRequestURI() + (req.getQueryString() == null ? "" : "?" + req.getQueryString());
        CustodyDoor.Verdict v = door.check(req.getMethod(), target, headers, req.getRemoteAddr());
        v.doorHeaders().forEach(res::setHeader);
        if (!v.allowed()) {
            res.setStatus(v.status());
            if (v.contentType() != null) res.setContentType(v.contentType());
            res.getOutputStream().write(v.body());
            return;
        }
        TreeMap<String, List<String>> admitted = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        admitted.putAll(headers);
        CustodyDoor.DOOR_ONLY.forEach(admitted::remove);
        admitted.put(CustodyDoor.RECEIPT, List.of(v.receipt()));
        admitted.put(CustodyDoor.CLASS, List.of(v.arrivalClass()));
        chain.doFilter(new HttpServletRequestWrapper(req) {
            @Override public String getHeader(String name) { List<String> l = admitted.get(name); return l == null || l.isEmpty() ? null : l.get(0); }
            @Override public Enumeration<String> getHeaders(String name) { return Collections.enumeration(admitted.getOrDefault(name, List.of())); }
            @Override public Enumeration<String> getHeaderNames() { return Collections.enumeration(admitted.keySet()); }
        }, res);
    }
}
```

**This snippet is not compiled or run by the test suite**, which has no Spring or servlet jars. What the suite runs is `CustodyDoor` and `CustodyDoorFilter` under the JDK's `HttpServer`; the Spring filter calls the same `check` with the servlet request's method, raw URI and query, headers, and remote address.

## What the tests run

`test/door-languages.test.ts` starts a door in authz mode as its own process and runs each example: [Go](../examples/languages/door/go/main.go) (`go run .`), [Ruby](../examples/languages/door/ruby/main.rb) (`ruby main.rb`), [Python](../examples/languages/door/python/main.py) (`python3 main.py`), and [Java](../examples/languages/door/java/DoorExample.java) (`javac`, then `java` with the `Host` flag). A missing toolchain skips its language, visibly. Each example checks, and prints `OK` only after:

1. A public read with a forged `X-Agent-Custody-Receipt` and `X-Forwarded-For`: allowed, and the app sees the door's receipt, which equals the one on the response.
2. An unknown arrival's refund that also sends its own `X-Original-Method: GET` and `X-Original-URI: /catalogue/free`: 403 with the door's body, and the app does not run.
3. A verified agent's refund with a passport: allowed, the app gets the body, the receipt, and class `verified`, and not the grant.
4. A door that is down and a door that accepts the connection and never answers: 503, and the app does not run.

The test then reads each receipt the example printed from the door's directory and requires that it verifies, that the allowed read recorded the original path, query, `Host`, and `User-Agent` and not the forged address, that the refused refund was decided as a POST to the refund route, and that the verified refund's authorization was in the log before the 200.

The frameworks are not installed in the test suite and there is no network to install them. Go's middleware is the `net/http` interface itself, called through `ServeHTTP`. The Rack middleware is called with a Rack env, as Rails and every Rack server call it. `DoorWSGI` runs under `wsgiref` over a real socket. `DoorMiddleware` is called as Django's handler calls it, with a request that carries only `method` and `META` and a stand-in for `django.http.HttpResponse`. The JDK filter runs under the JDK's `HttpServer` over a real socket. The Spring filter is not run.

## What the receipts record, and what they do not

Everything that [authz mode](door.md#behind-nginx-or-envoy-authz-mode) records, and nothing more: `issuer.framework` is `authz`, an allow is `withheld` (the door decided, and the middleware, not the door, ran your code), a refusal is `denied`, and no receipt carries the body or your app's answer. A policy rule on `context.args.body` errors and denies, so a rule on an amount belongs in your code.

- **The address is the one the framework reports.** Behind a load balancer it is the balancer's, and the door's `rate` signal counts every arrival through it as one source. Pass the client's address yourself (the value your framework trusts after its own proxy settings) if that matters to a policy.
- **The door's word is trusted.** An allow receipt shows that the door allowed the request, not that the app ran it.
- **Not covered:** a request your framework answers before the middleware runs (a static file served by the web server, a route mounted outside the middleware stack).

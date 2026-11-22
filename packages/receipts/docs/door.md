# The door

> How it works and when to use it. Every field, route, and flag is in [the reference](../../../site/reference/door.md).

The gateway stands between an agent and the tools it uses. The door stands between the world and your own HTTP surface: a website, an API, a form. Every arrival, a browser, an API client, a crawler, or an agent acting for someone, is classified by what it presented, decided by a Cedar policy for the route it hit, relayed to your origin or refused, and receipted either way. The receipt is the same signed, logged, independently verifiable receipt the gateway issues, with `issuer.kind: "door"`.

New to the door? [Put the door in front of a site](door-quickstart.md) walks through one form in about fifteen minutes. A Node site can run the same decision loop in its own process instead, as Express middleware or around a Next.js route handler: [the door in your Node app](door-middleware.md). Already run nginx or Envoy? The door can answer their authz checks instead of relaying, and the site keeps its proxy: [behind nginx or Envoy](#behind-nginx-or-envoy-authz-mode). A site in Go, Rails, Django, or Spring can ask the same check from a middleware: [the door in Go, Rails, Django, and Spring](door-languages.md). A site already on Cloudflare can run the door at the edge, as a Worker: [the door as a Cloudflare Worker](door-worker.md).

This is the first piece of the agent front door. It answers "what may this arrival do here" and "what did it do, provably". It does not yet answer "is this an agent" for web traffic: that is detection, and the door records only what it can check. An agent that wants to be known can say so in a way the door checks: a grant, or a [Web Bot Auth signature](#web-bot-auth-signatures). Read [what the door knows](#what-the-door-knows-about-an-arrival) before writing a policy.

```bash
agent-custody keygen --dir keys --name door
agent-custody check --config door.json
agent-custody door --config door.json --port 8780
```

To run it as a service, the gateway image has a `door` mode (`docker run ... ghcr.io/svayatta/agent-custody-gateway:<version> door`, config at `/config/door.json`, key created at `/data/keys/door.key`), and [deploy/door](../../../deploy/door/README.md#as-a-reverse-proxy-from-the-gateway-image) has a compose file in front of a stand-in site, Kubernetes manifests, a systemd unit, and the smoke test that every build of the image passes.

## The config file

`door.json`, paths relative to the file. Loaded with `loadDoorConfig(path)`.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000", "timeoutMs": 30000 },
  "routes": [
    { "name": "catalogue", "methods": ["GET"], "path": "/catalogue/*" },
    { "name": "refund", "methods": ["POST"], "path": "/refunds" },
    { "name": "api", "path": "/api/*" }
  ],
  "unmatchedRoute": "other",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

Every field of the config, with its type and default, is in [the door reference](../../../site/reference/door.md#config).

`agent-custody check --config door.json` reads a door config the way the door would: unknown keys, the key, the principal keys, the policy (including a permit that names an agent without requiring a verified arrival, see below), the routes, what is precommitted, the challenge provider or its absence, the partner engine and its key, the revocation file, the origin's scheme, every credential variable the door reads at startup (origin headers, the log, Splunk, OTel, the capture key, the challenge secret), and the paths. It exits 1 on an error.

## What the door knows about an arrival

The door records one fact for every arrival, `arrival`, observed by the door itself, and the policy reads it as `context.facts.arrival`:

| field | values | meaning |
| --- | --- | --- |
| `class` | `verified`, `claimed`, `unknown` | `verified`: a grant signed by a trusted principal, inside its window, naming this route among its scopes; or, with no grant, a [Web Bot Auth signature](#web-bot-auth-signatures) that checked against the key its agent's directory publishes. `claimed`: something was asserted that the door could not accept: a grant from a stranger, an expired one, a revoked one, one for other routes, one presented under another agent's signature, a declared agent name, or a signature that did not check or was not checked. `unknown`: nothing was presented |
| `subject` | string | the agent named in a verified grant; else the signature agent of a verified signature (its https origin); else the declared name or the agent a rejected grant named; else `unknown`. Only a verified subject reaches the Cedar `principal` |
| `grant` | `verified`, `out-of-scope`, `invalid`, `revoked`, `wrong-sender`, `absent` | what became of the grant header, with `grantError` when it was not accepted. `revoked`: the grant verified, and it or a grant above it in its chain is in `revokedGrants` (see [revoking a grant](#revoking-a-grant)). `wrong-sender`: the grant verified, and the request is signed by a signature agent, or by a did:key, that the grant does not name |
| `signature` | `verified`, `invalid`, `unavailable`, `unchecked`, `absent` | what became of an RFC 9421 signature tagged `web-bot-auth`, with `signatureError` when it was not verified. `unchecked`: a `Signature-Input` arrived and the config has no `webBotAuth`, so it is a claim. See [Web Bot Auth signatures](#web-bot-auth-signatures) |
| `signatureAgent`, `signatureKeyid` | strings | the `Signature-Agent` origin and the keyid the signature named. For a signature by a did:key's key, both are the did:key. Checked only when `signature` is `verified` |
| `declared` | string | the `x-agent-custody-agent` header, when sent. A claim |
| `remote` | string | the arrival's address |
| `challenge` | `{ provider, outcome, error? }` | only when `challenge` is configured. `passed`: the provider confirmed the token the arrival sent. `failed`: the provider refused the token (`invalid-input-response`, `timeout-or-duplicate`, `expired-input-response`, `already-seen-response`, `missing-input-response`, with the codes in `error`), it confirmed a token issued on another hostname or for another action, or the token was longer than 4096 characters, which is refused without calling the provider. `unavailable`: the provider did not answer in time, answered a non-200, a redirect, or something that is not JSON, answered a code that is its own or the operator's fault (`internal-error`, `bad-request`, `missing-input-secret`, `invalid-input-secret`, `sitekey-secret-mismatch`, `invalid-sitekey`, `missing-sitekey`, `invalid-remoteip`: a rotated secret gives every person one of these), or `maxInFlight` checks were already waiting. `absent`: no token. A passed challenge leaves `class` as it was: it says a provider's test was passed in front of this arrival, not who the arrival is |
| `partner` | `{ engine, outcome, error? }` | only when `partner` is configured and the route is in `partner.routes`. `verified`: the engine's verdict was signed for this arrival under `partner.keyFile`, and is the `partner` fact. `rejected`: the engine answered with anything else. `unavailable`: it did not answer in time or at all. See [a partner engine's verdict](#a-partner-engines-verdict) |
| `rate` | `{ by, burst, minute }` | arrivals from the same source in the last 10 and 60 seconds, this one included, whatever was decided about them, counted by this door process alone. `by` is `agent` for a verified arrival (counted by the agent's name across addresses) or `remote` (by address). A pace, not a verdict |
| `method`, `path`, `route` | strings | what arrived, and the route it fell under |

[Door signals](door-signals.md) says, for each field, what it establishes and what it does not, and how a policy should read it. [Door error rates](door-error-rates.md) measures how often `class` is wrong for each kind of arrival, with the method, and scores your own receipts against your labels with `agent-custody door error-rates`.

There is no `human` class. The door cannot tell a person from a program that presents nothing, and it does not pretend to. With `challenge` configured, a policy can require a passed challenge on a route instead; without it, a policy that lets `unknown` through on a route is letting everything through on that route, and should say so.

**Presenting a passport.** There are two passports, and an agent may present both. A Web Bot Auth signature proves which agent sent the request ([below](#web-bot-auth-signatures)). A grant says what a principal you trust lets that agent do. An agent presents its grant exactly as it does to the HTTP gateway: the DSSE envelope as base64url in `Authorization: Bearer <value>` or in `X-Agent-Custody-Grant`. The scopes of the grant are route names. A grant that travelled in `Authorization` is stripped before the request is relayed, so the origin never sees it; one in the custom header is stripped too. The door's own headers are added to the relayed request: `X-Agent-Custody-Receipt` (the receipt id), `X-Agent-Custody-Class`, and `X-Forwarded-For`, `-Host`, `-Proto`, with `X-Real-IP` when `trustProxy` is off.

**A grant alone is bearer-grade; a grant under its agent's signature is bound to its sender.** The door checks the grant's signature, window, and scope. On its own, that does not show that the sender holds the agent's key. Anyone who holds the grant's bytes is that agent until the grant expires, and every verified receipt carries the grant in `delegation`, so a person who can read one receipt can replay its grant. When the request also carries a Web Bot Auth signature that the door verified, and the grant names that signature agent (`"agent": "https://crawler.example"`), the grant is bound to its sender: a thief has the grant's bytes but not the agent's signing key, and a captured signature serves one request (its nonce) for at most `maxAgeSeconds`. A grant presented under another agent's signature is `wrong-sender`, and the arrival is `claimed`. A grant with no signature, or with one that did not verify, is still verified, bearer-grade, as before, so a route that needs the binding says so in its policy: `context.facts.arrival.grant == "verified" && context.facts.arrival.signature == "verified"` holds only for a bound grant, since a mismatch makes `grant` `wrong-sender`. For bearer grants, issue door grants with short lifetimes (minutes, not days), scope them to the routes they need, bound what a route allows per call in the policy, and treat receipt files and logs as holding live credentials until those grants expire.

**A did:key agent.** <a id="a-did-key-agent"></a>A grant may name its agent by a [did:key](https://w3c-ccg.github.io/did-key-spec/), the identifier of its Ed25519 key, `did:key:z6Mk...`: `agent-custody grant --agent-key agent.pub --did-key ...` issues one. The door checks the identifier after the principal's signature, on the grant and on every grant above it in its chain, with the check that the gateway and the verifiers use (`verifyDelegation`): it must decode to an Ed25519 key, and when that grant also carries `agentKey`, that must be the same key. A parent's `agentKey` is what verified the link below it, so a parent whose did:key and `agentKey` disagree makes the arrival `claimed` too, with `link <n>` in `grantError`. An identifier longer than 100 characters is refused before it is decoded. Either failure makes the arrival `claimed` with `grant: "invalid"` and the reason in `grantError`, because the grant says two things about who the agent is, or something that names no key. A grant that checks is `verified`, as any other, with the did:key as `subject`, the Cedar principal (`Agent::"did:key:z6Mk..."`), and the receipt's agent, attested. A did:key says which key; it does not prove that the sender holds it. Alone, a did:key grant is bearer-grade like any grant, and a Web Bot Auth signature names an https origin, not a did:key, so a did:key grant under a signature is `wrong-sender`.

**A did:key grant under a signature by its own key is bound to its sender.** <a id="a-did-key-signature"></a>With `webBotAuth` configured, the agent signs the request as for [Web Bot Auth](#web-bot-auth-signatures) (RFC 9421, Ed25519, `tag="web-bot-auth"`, `@authority` covered, `created`, `expires`, and a nonce), and sets `keyid` to its did:key. It sends no `Signature-Agent`, and the door fetches no directory, because the did:key carries the key. The door applies the same checks of the window, the authority, the covered components, and the nonce, and verifies the signature with the key that the did:key names. When the grant verifies and names that did:key, the arrival is `verified` with `signature: "verified"`, and `signatureAgent` and `signatureKeyid` are the did:key. The policy condition for a bound grant, `context.facts.arrival.grant == "verified" && context.facts.arrival.signature == "verified"`, holds for it. A did:key grant under a signature by another did:key's key, or under a Web Bot Auth signature from an https origin, is `wrong-sender`, and the arrival is `claimed`. Anyone can make a key and its did:key, so a did:key signature counts only with a verified grant that names it. With no grant, with a grant that is not verified, or with a grant for another agent, the door records `signature: "invalid"` and the reason in `signatureError`, and the arrival is never `verified` by that signature. `agents` does not list a did:key: the grant of a trusted principal is what admits it. The door keeps the nonce of a did:key signature only when a trusted principal signed the request's grant for that did:key, so signatures by keys that no principal granted cannot fill the nonce store. A door without `webBotAuth` records the signature as `unchecked`, and the grant stays bearer-grade.

**Revoking a grant.** <a id="revoking-a-grant"></a>With `revokedGrants` in the config, a grant can be withdrawn before it expires: the file is the gateway's, a JSON array of grant digests, and `agent-custody revoke --config door.json --grant grant.json` appends one. The door re-reads the file when it changes and checks every grant against it after the signature and before the window and the scope, so a running door classifies the next arrival that carries the grant as `claimed` with `grant: "revoked"`, and the Cedar principal is not the agent. Revoking a grant revokes every grant delegated from it (`grantError` says "a grant above it in its chain has been revoked"). A file that is there and cannot be read stops the door from starting; one that becomes unreadable while it runs makes every grant `revoked` until it can be read, so a broken list never lets a grant through. A missing file is an empty list. Without `revokedGrants`, a grant stands until it expires, and `check` warns when the door trusts principals.

<a id="challenging-a-human"></a>**Challenging a human.** The door builds no CAPTCHA. With `challenge` configured, a page in front of a protected route renders the provider's widget (Cloudflare Turnstile or hCaptcha) with `siteKey`, and sends the token the widget produced in the `challenge.header` header of its request. The door posts the token and the secret from `secretEnv` to the provider's `siteverify` endpoint, with a timeout, and records the answer as `challenge.outcome`. It adds the arrival's address as `remoteip` only with `trustProxy`, where that address is the client's; without it the socket's address may be a proxy's, and the provider would refuse a token the client solved. It never follows a redirect, which would resend the secret and the token elsewhere. To hCaptcha it also sends `siteKey` as `sitekey`: an hCaptcha secret belongs to the account, and without it a token solved on the account's easiest widget would pass on the hardest. A Turnstile secret belongs to one widget already. `success` alone does not pass: the token must have been issued on one of `hostnames`, and for `action` when one is set, or a token solved on another site that uses this site key, or for another widget, would count. At most `maxInFlight` checks wait on the provider at once; an arrival past that is `unavailable`. The token is stripped before the request is relayed, and neither the token nor the secret is recorded. A policy admits a person on a form route with

```cedar
permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.challenge.outcome == "passed" };
```

and a refused arrival that has not passed is told how in the 403 body: `challenge: { provider, siteKey, header }`, so a page can render the widget and try again.

**A token serves one request.** Turnstile and hCaptcha refuse a token they have seen (`timeout-or-duplicate`, `already-seen-response`), and the door keeps no pass between requests: it does not set a cookie or remember an address. So the page must take a new token for every request it sends to a challenged route, and for every retry: call `turnstile.reset()` or `hcaptcha.reset()` after each request, and wait for the new token before the next. The door checks the token before it reads the body, so a request refused for its size (413), its path (400), or by the policy has used its token too. A second request that sends the same token is `failed`, and the person sees another 403. The outcome is a signal, not a class: a `verified` agent that also passes a challenge is still the agent its grant names, and an `unknown` arrival that passes is still `unknown`, with `challenge.outcome: "passed"` beside it. What the provider's pass means, and what it does not, is in [door signals](door-signals.md). Passkeys are not a provider here: a passkey proves possession of a credential the site registered, which is a login, not a challenge, and belongs to the origin.

### Protecting a form with one line

A form on a static site cannot set a header, and the door reads the challenge token from one. With `challenge` configured, the door serves a script that bridges the two, at `/.well-known/agent-custody-door/form.js`. The page adds one line:

```html
<script src="/.well-known/agent-custody-door/form.js" defer></script>
```

The script is built from the challenge config: the provider, the public site key, the header, and the action. The secret is never in it. In the browser it does the following:
- It loads the provider's script (`challenges.cloudflare.com` for Turnstile, `js.hcaptcha.com` for hCaptcha) and renders the widget in every form on the page whose method is POST and whose action is on the page's own origin. A GET form, or one that posts to another site, is left alone. To protect only some forms, give a selector on the tag: `<script src="..." data-forms="#contact" defer></script>`.
- On submit it sends the form with `fetch`, the widget's token in the door's challenge header and the form's fields as the browser would send them (form-encoded, or multipart when the form says `enctype="multipart/form-data"`). A submit button's `formaction`, `formmethod`, and `formenctype` override the form's, as in a native post; a button that posts with GET, or to another site, is left to the browser. It removes the widget's own copy of the token from the fields, so the token never reaches the receipt.
- It follows the answer as a form post would. A redirect is followed; an HTML page replaces the current one; a refusal leaves the page and says why under the widget. Then it resets the widget, because [a token serves one request](#challenging-a-human).

The door decides the request as any other arrival: the token is verified with the provider, the outcome is the arrival's `challenge` signal, and the policy for the form's route decides. The site's backend gets the request with `X-Agent-Custody-Receipt`, or never hears of it. A client without JavaScript, or a bot that posts the form directly, sends no token: when the route's policy requires `context.facts.arrival.challenge.outcome == "passed"`, as it should for a protected form, that arrival gets the 403 with the way in.

What to get right:
- **`hostnames`** must name the hosts the page is served on, or a passed token fails.
- **A form handler that redirects** must answer 303 (or 302) to a URL on the same site. The script follows it as a page load. A redirect to another site fails in `fetch`, because the request carried the challenge header: the door has already relayed the form, so the page says the answer did not arrive and the form may have been sent. A 307 or 308 makes the browser send the POST again with the same token, which the provider refuses as a duplicate.
- **Not covered, and refused rather than let through:** a form added to the page after the script ran; a form sent from code with `form.submit()`, which fires no submit event; and a form the script skips because its own method is GET or its own action is on another site, which gets no widget, so a button on it with `formmethod="post"` and an action on this site posts with no token. Each posts natively, and the policy refuses it with a bare 403.
- **A button that posts natively** (GET, or to another site) takes no token with it: the script disables the widget's hidden token fields first, so hCaptcha's live token does not reach another site's body or a query string.
- **A Content-Security-Policy** must allow the provider's script and frame (`script-src` and `frame-src` for the hosts above), and the script itself (`script-src 'self'` when the door serves the site).
- **In authz mode** the proxy serves the site, so route `/.well-known/agent-custody-door/form.js` to the door (`location = /.well-known/agent-custody-door/form.js { proxy_pass http://door:8780; }`).
- **In-process**, the Express middleware serves the script itself; a Next.js site adds a route that returns `guard.formScript()` ([the door in your Node app](door-middleware.md#a-form-protected-by-the-challenge)).

The tests run the script in a DOM stand-in against a real door and a stand-in provider. By hand, with Cloudflare's test keys below and a static page, the widget rendered and passed in a browser, the form reached the site with its receipt id, and a POST without the script was refused 403. The script is served with a query string as well (`form.js?v=2`), so a cache-busting habit does not break it. Tutorial: [54-door-form.ts](../examples/54-door-form.ts).

### A run against Turnstile's test keys

The tests stub `siteverify`. This run calls the real one once. Cloudflare publishes [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) that need no account: the site key `1x00000000000000000000AA`, the secret `1x0000000000000000000000000000000AA` (validation always succeeds), the secret `2x0000000000000000000000000000000AA` (validation always fails), and the dummy token `XXXX.DUMMY.TOKEN.XXXX`. The test secrets accept only the dummy token. Cloudflare answers a test key with the hostname `example.com`, so the config names that hostname. These secrets are public. A real secret still goes only into the environment, never into the config or a flag.

The run used the CLI from this repository on 2026-11-10. `policy.cedar`:

```cedar
// The form is for an arrival that has passed the challenge.
permit(principal, action == Action::"form", resource)
when { context.facts.arrival.challenge.outcome == "passed" };
```

`door.json`:

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000" },
  "routes": [{ "name": "form", "methods": ["POST"], "path": "/form" }],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl",
  "challenge": {
    "provider": "turnstile",
    "siteKey": "1x00000000000000000000AA",
    "secretEnv": "TURNSTILE_SECRET",
    "hostnames": ["example.com"]
  }
}
```

A stand-in origin answers every request with `{"ok":true}`:

```bash
agent-custody keygen --dir keys --name door
node -e 'require("http").createServer((q,s)=>{s.setHeader("content-type","application/json");s.end(JSON.stringify({ok:true}))}).listen(3000,"127.0.0.1")' &
```

**The pass run.** Start the door with the secret that always succeeds, and send the dummy token:

```bash
TURNSTILE_SECRET=1x0000000000000000000000000000000AA agent-custody door --config door.json --port 8780 &
curl -sS -i -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' \
  -H 'x-agent-custody-challenge: XXXX.DUMMY.TOKEN.XXXX' -d '{"name":"test"}'
```

```text
HTTP/1.1 200 OK
x-agent-custody-receipt: 74c1e645-3b3e-4306-a70c-057ea0e61d41
content-type: application/json
date: Tue, 10 Nov 2026 02:24:05 GMT
x-agent-custody-class: unknown
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{"ok":true}
```

**The fail run.** Stop the door. Start it again with the secret that always fails, and send the same request:

```bash
TURNSTILE_SECRET=2x0000000000000000000000000000000AA agent-custody door --config door.json --port 8780 &
curl -sS -i -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' \
  -H 'x-agent-custody-challenge: XXXX.DUMMY.TOKEN.XXXX' -d '{"name":"test"}'
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-receipt: 01b840df-6a79-408a-9d3b-32dac88787d8
content-type: application/json
cache-control: no-store
x-agent-custody-class: unknown
Date: Tue, 10 Nov 2026 02:24:13 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{"error":"refused by the door's policy","reason":"no permit policy matched","receipt":"01b840df-6a79-408a-9d3b-32dac88787d8","challenge":{"provider":"turnstile","siteKey":"1x00000000000000000000AA","header":"x-agent-custody-challenge"}}
```

**Verify both receipts.** Both exit 0:

```bash
agent-custody verify receipts/74c1e645-3b3e-4306-a70c-057ea0e61d41.json --issuer-key keys/door.pub --log log.jsonl
```

```text
PASS  receipt signature (issuer key)  (keyid e316d40ebc50)
PASS  receipt payload type
PASS  structural parts in clear
PASS  issuer kind is known  (door / http)
PASS  issuer keyid matches signer
PASS  door receipt carries a policy decision
PASS  principal is claimed, not attested  (no signed delegation in this receipt)
PASS  request args digest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  execution result digest
PASS  withheld facts.arrival.resultDigest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  policy decision consistent with execution  (allow -> executed)
PASS  no policy errors on an allow
PASS  authorization signature (issuer key)  (keyid e316d40ebc50)
PASS  authorization names this call  (form for receipt 74c1e645-3b3)
PASS  authorization tree head signature  (keyid e316d40ebc50)
PASS  authorization log inclusion proof  (leaf 0 of 1)
PASS  authorization logged before execution  (authorization leaf 0, receipt leaf 1)
PASS  tree head signature  (issuer key e316d40ebc50)
PASS  tree head matches inclusion proof size
PASS  log inclusion proof  (leaf 1 of 2, root 67f4115b31c2)
PASS  log file root matches tree head  (recomputed 67f4115b31c2)

RESULT: VERIFIED

ISSUER: door (http), unknown issuer kind

field           provenance  value
principal       claimed     (none)
agent           claimed     unknown
model           claimed     (none supplied)
tool            observed    form
args            claimed     {"$rest":{"$custody":"withheld","sha256":"8f41daf2…"},"bodyBytes":15,"headers":{"accept":"*/*","content-type":"application/json","host":"127.0.0.1:8780","user-agent":"curl/8.7.1"},"method":"POST","path":"/form"}
fact.arrival    observed    {"challenge":{"outcome":"passed","provider":"turnstile"},"class":"unknown","grant":"absent","method":"POST","path":"/form","rate":{"burst":1,"by":"remote","minute":1},"remote":"127.0.0.1","route":"form","signature":false,"subject":"unknown"}
policy          observed    allow [policy0] policy 71e3eefa3599
authorization   observed    committed to the log as leaf 0, before the call was forwarded
execution       observed    executed
```

```bash
agent-custody verify receipts/01b840df-6a79-408a-9d3b-32dac88787d8.json --issuer-key keys/door.pub --log log.jsonl
```

```text
PASS  receipt signature (issuer key)  (keyid e316d40ebc50)
PASS  receipt payload type
PASS  structural parts in clear
PASS  issuer kind is known  (door / http)
PASS  issuer keyid matches signer
PASS  door receipt carries a policy decision
PASS  principal is claimed, not attested  (no signed delegation in this receipt)
PASS  request args digest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  withheld facts.arrival.resultDigest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  withheld execution.reason  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  policy decision consistent with execution  (deny -> denied)
PASS  no policy errors on an allow
PASS  tree head signature  (issuer key e316d40ebc50)
PASS  tree head matches inclusion proof size
PASS  log inclusion proof  (leaf 2 of 3, root 54a065656fa2)
PASS  log file root matches tree head  (recomputed 54a065656fa2)

RESULT: VERIFIED

ISSUER: door (http), unknown issuer kind

field           provenance  value
principal       claimed     (none)
agent           claimed     unknown
model           claimed     (none supplied)
tool            observed    form
args            claimed     {"$rest":{"$custody":"withheld","sha256":"255b518c…"},"bodyBytes":15,"headers":{"accept":"*/*","content-type":"application/json","host":"127.0.0.1:8780","user-agent":"curl/8.7.1"},"method":"POST","path":"/form"}
fact.arrival    observed    {"challenge":{"error":"invalid-input-response","outcome":"failed","provider":"turnstile"},"class":"unknown","grant":"absent","method":"POST","path":"/form","rate":{"burst":1,"by":"remote","minute":1},"remote":"127.0.0.1","route":"form","signature":false,"subject":"unknown"}
policy          observed    deny [] policy 71e3eefa3599
execution       observed    denied: (reason withheld under the capture rule)
```

The pass run's receipt records `challenge.outcome: "passed"`, and the door relayed the request. The fail run's receipt records `challenge.outcome: "failed"` with Cloudflare's code `invalid-input-response`, and the policy refused the request. The token does not appear in either receipt.

**What this run shows, and what it does not.** Test keys prove the wire path, not bot detection. The door reaches the real `siteverify`, sends the secret and the token, and records the answer. A test secret gives a fixed answer and no widget runs, so the run says nothing about how well Turnstile tells a person from a bot. The run did not exercise the `unavailable` outcome, a hostname mismatch, an action mismatch, the `timeout-or-duplicate` code, or `remoteip` (the config sets no `trustProxy`, so the door sent none). `test/door.test.ts` covers those against a stubbed `siteverify`. In the output above, the two `sha256` digests are shortened to eight characters and `…`. Nothing else is changed. The CLI was `agent-custody` 0.16.2, run from this repository at commit `64285ef`. That version had no note for door receipts, so its `ISSUER` lines end with `unknown issuer kind`; later versions say what a door receipt proves there: the arriving party could not forge it and is attested only when it presented a grant, and a request that reached the origin some other way leaves no receipt.

## Web Bot Auth signatures

Web Bot Auth is the IETF draft for bots and agents that identify themselves by signing their requests ([draft-meunier-web-bot-auth-architecture-05](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture-05), with the key directory of [draft-meunier-http-message-signatures-directory-05](https://datatracker.ietf.org/doc/html/draft-meunier-http-message-signatures-directory-05)). The agent signs each request with an RFC 9421 HTTP message signature and names, in the `Signature-Agent` header, the https origin that publishes its keys at `/.well-known/http-message-signatures-directory`. With `webBotAuth` configured, the door fetches that directory and checks the signature. A request that checks, with no grant, is `verified` as the signature agent: the subject and the Cedar principal are the origin, `Agent::"https://crawler.example"`.

```json
"webBotAuth": { "agents": ["https://crawler.example"], "authorities": ["shop.example"] }
```

`agents` lists the signature agents whose directories the door will fetch. `authorities` lists the hosts this door serves. The other fields and their defaults are in [the reference](../../../site/reference/door.md#config).

**What the door checks**, in order. The first that fails is the `signatureError`. For a signature whose `keyid` is a did:key, steps 3 (the `Signature-Agent` part), 4, and 8 do not apply, and step 9 uses the key that the did:key names: see [a did:key signature](#a-did-key-signature).

1. A `Signature-Input` member tagged `web-bot-auth` (the first one, when there are several), and a byte sequence under the same label in `Signature`. A signature with another tag is for some other purpose, and the arrival is `invalid` for this one.
2. `keyid`, `created`, and `expires` are present; `alg`, when present, is `ed25519`. The keyid is the RFC 7638 thumbprint of the agent's Ed25519 key, as the draft requires. The door checks Ed25519 only, the draft's algorithm; RSA-PSS and ECDSA signatures are `invalid` with that reason.
3. The signature covers `@authority` and the `Signature-Agent` member that names the directory (`"signature-agent";key="<member>"`, or the whole field in the draft's legacy string form). Without that coverage, anyone could move a signature under another agent's name.
4. The `Signature-Agent` URI is https, an origin or its directory URL, and one of `agents`. Anything else is refused without a fetch, so an arrival never chooses what the door fetches and cannot point it at an internal address. An `http:` directory and an inline `data:` directory are refused: an inline directory carries its own key and proves nothing.
5. The window: `created` at most `clockSkewSeconds` (60) in the future, `expires` after `created`, and now no later than `expires`, nor than `created` plus `maxAgeSeconds` (300), each with the skew. The draft allows a 24-hour signature; the door accepts one for five minutes after it was made, whatever `expires` says.
6. `@authority` is the request's `Host`, lowercase, without `:443` or `:80`, and it must be one of `authorities`. The client writes the `Host`, so without this list a signature made for another site could be sent here with that site's `Host` and verify. Behind a proxy, the proxy must pass the `Host` through.
7. The nonce. By default (`requireNonce`) a signature must carry one, and a nonce already used with this agent and key is a replay. The door remembers a nonce until the signature it came with could no longer be accepted, so a signature serves one request. A minimal Web Bot Auth signature covers only the authority and the `Signature-Agent`, so without this rule a captured signature would serve any method and path on this site until it aged out. `agent-custody check` warns when `requireNonce` is off.
8. The directory: `GET <origin>/.well-known/http-message-signatures-directory` over https, with `AbortSignal.timeout(timeoutMs)`, never following a redirect (a redirect is a directory on another origin, and `invalid`), served as `application/http-message-signatures-directory+json`, at most `maxDirectoryBytes`, a JWKS. It is kept `cacheSeconds` (300); a failed fetch is asked again after 30 seconds. One fetch at a time per agent.
9. The key whose thumbprint is the keyid, inside its `nbf` and `exp` when the directory gives them, and the Ed25519 signature over the RFC 9421 signature base. The base is built from `@method`, `@authority`, `@path`, `@query`, and header fields (whole, or one dictionary member with `;key`). A signature that covers another derived component (`@target-uri`, `@scheme`, `@request-target`, `@query-param`) or a component parameter other than `key` is `invalid`, and the reason names it.

| `signature` | when |
| --- | --- |
| `verified` | every check above passed |
| `invalid` | one of them failed: the reason is in `signatureError`. A signature agent not in `agents`, a redirect, the wrong media type, or a directory too large is the agent's fault or an attack, and `invalid` |
| `unavailable` | the directory did not answer in time, answered a non-200, or the door holds `maxNonces` nonces and cannot record another. The network's or the door's state, not the arrival's |
| `unchecked` | a `Signature-Input` arrived and the config has no `webBotAuth` |
| `absent` | no `Signature-Input` and no `Signature` |

**What a verified signature does not show.** It shows that a key published at the signature agent's origin signed this request, for this door's authority, in the last few minutes, once. It does not cover the body: the door does not check `Content-Digest`, and a signature over `@authority` alone does not cover the method, the path, or the query either; the receipt records them as they arrived, as `claimed` arguments. It does not show that the origin is a crawler you know or that it behaves well: `agents` is the list of origins you chose to check, and a policy decides what each may do. The door does not check the directory's own response signatures (directory draft, section 5.2, a SHOULD): it fetches the directory over https from the origin the signature names, and the signature covers that name, so a directory that lists another agent's key cannot claim that agent's requests. Nonces are remembered by one door process, so two doors, or one restart, accept a nonce once each; `maxAgeSeconds` bounds that. A key the agent adds to its directory is seen once the cached copy expires.

**In the receipt.** A signature-verified arrival without a grant has `agent: { id: "https://crawler.example", provenance: "observed" }` and `principal: { id: null, provenance: "claimed" }`. The agent is the door's own observation, as the egress witness's agent is: the check was against a directory the door fetched, which a reader of the receipt cannot repeat, so it is not `attested`. The arrival fact records `signature`, `signatureAgent`, and `signatureKeyid`. A bound grant's receipt is the verified grant's receipt as before, `attested`, with `signature: "verified"` in the arrival fact. No verifier check changed.

**The published vectors.** The tests check the door against the published Ed25519 vectors that use the RFC 9421 test key (appendix B.1.4): RFC 9421's B.2.6 request, whose signature base and signature the door reproduces, and the Web Bot Auth draft's A.2.1 (a signature over `@authority` alone) and A.2.3 (`Signature-Agent` in the legacy string form), whose published signatures verify. The draft's A.2.2, `Signature-Agent` as a dictionary member, prints a signature that does not verify against its own printed signature base, so the tests sign that layout themselves with the RFC's published private key. No test fetches a real directory or uses a real crawler's key: the directories are built in the test and served by a stubbed fetch.

A policy that admits one crawler on the API by its signature, and refunds only for a grant bound to its sender:

```cedar
permit(principal == Agent::"https://crawler.example", action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };

permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.grant == "verified" &&
  context.facts.arrival.signature == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};
```

Tutorial: [47-web-bot-auth.ts](../examples/47-web-bot-auth.ts).

## A partner engine's verdict

A site that already pays for bot detection (Cloudflare Bot Management, HUMAN, DataDome) can give the door that engine's verdict, signed. The door builds no detector of its own here: it asks the engine, checks the engine's signature, and lets the policy decide on the verdict. The engine sits behind an adapter that holds an Ed25519 key; `scripts/fake-partner.ts` is a stand-in.

```json
"partner": {
  "engine": "datadome",
  "url": "https://bot-adapter.internal/verdict",
  "keyFile": "keys/engine.pub",
  "routes": ["refund", "api"],
  "timeoutMs": 1500,
  "onFailure": "deny"
}
```

- **The question.** For an arrival on one of `routes` (`["*"]` for all), the door POSTs `url` a JSON body: `{ receiptId, route, method, path, remote, class, headers }`, with `receiptId` the id of the receipt it is writing and `headers` the four the receipt records (`user-agent`, `content-type`, `accept`, `host`). Never the query, the body, the grant, the challenge token, or a cookie. The question carries `AbortSignal.timeout(timeoutMs)`, follows no redirect, and the door reads at most `maxResponseBytes` (16 KiB) of the answer. At most `maxInFlight` (64) questions wait at once.
- **The answer.** `{ verdict: { engine, verdict, score? }, signature }`, where `signature` is a DSSE envelope in the upstream attestation format (`src/upstream.ts`): payload type `application/vnd.agent-custody.upstream+json`, payload `{ receiptId, tool, contentDigest }` with `tool` the route and `contentDigest` the digest of `verdict`. `signVerdict(verdict, key, receiptId, route)` in `src/door-partner.ts` makes one. `engine` must equal the config's, `verdict` is a short word, `score` an integer, and no other field is accepted.
- **What the door accepts.** A signature that verifies under `keyFile`, names this receipt and route, and is exactly that plain attestation (one signature, canonical payload, nothing added). Anything else is `rejected`, with the reason in `arrival.partner.error`. Since the receipt id is fresh for every arrival, a verdict signed for one arrival cannot be replayed onto another.
- **What the policy reads.** An accepted verdict is `context.facts.partner`, `{ engine, verdict, score? }`. Without one there is no `partner` fact, and `arrival.partner` says why. A rule reads it as `context.facts has partner && context.facts.partner.verdict == "human"`, so a missing verdict denies.
- **When there is no verified verdict** (the engine down, slow, busy, or a bad signature, a verdict for another arrival): `onFailure: "deny"`, the default, refuses the arrival with 503 and a `withheld` receipt, whatever the policy said, and relays nothing. `onFailure: "absent"` lets the policy decide without the fact, so a rule that requires it denies and a rule that does not mention it allows as it would anyway. Neither turns an outage into an allow on a route whose rule needs the verdict. A policy deny still answers 403 first. In observe mode the refusal is printed, not enforced, as a deny is.
- **What the receipt carries.** `facts.partner` is `{ tool: "door.partner", args: {}, value: <verdict>, resultDigest, provenance: "attested", attestation: <the engine's envelope> }`, and `facts.arrival.partner` records the outcome. Under the door's default capture rule, and any rule that leaves the facts in clear, the envelope stays in clear beside the verdict; under a private facts rule it is withheld with the verdict. The verifier runs `fact partner signature (upstream key)`: given the engine's public key with `--upstream-key` (or `upstreamKeys`), it checks the signature, the receipt id, the route, and the digest of the verdict as recorded. Without the key the check fails, because the receipt says the verdict is attested and the reader cannot confirm it. A verdict pasted from another receipt, or edited, fails it. The TypeScript, browser, and Python verifiers run the same check (vectors `door-partner-attested`, `door-partner-without-key`, `door-partner-wrong-key`, `resigned-door-partner-moved`).

What the verdict means, and what it does not, is in [door signals](door-signals.md#the-partner-verdict). Tutorial: [52-door-partner-verdict.ts](../examples/52-door-partner-verdict.ts).

## How an arrival becomes a Cedar request

| Cedar slot | value |
| --- | --- |
| `principal` | `Agent::"<agent>"` for the agent a verified grant names, or the signature agent of a verified signature (`Agent::"https://crawler.example"`); `Agent::"unknown"` for every other arrival. A declared name and the agent a rejected grant names stay in the arrival fact: a permit on `principal == Agent::"shopping-agent"` cannot be satisfied by sending a header |
| `action` | `Action::"<route>"` |
| `resource` | `Tool::"<route>"` |
| `context.args` | `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`. `query` holds every parameter by name, as own properties, so `?constructor=x` is a parameter. `headers` carries `user-agent`, `content-type`, `accept`, and `host` only. `body` is present for a JSON body of at most 64 KiB; every body the door read is recorded by `bodyDigest` (sha256 of the raw bytes) and `bodyBytes`. A body above `maxBodyBytes` is dropped as it passes the limit and recorded as `bodyBytes` read so far and `bodyOversized: true`, with no digest and no `body`. The policy reads a copy that Cedar accepts: Cedar has no `null` and no non-integer number, and refuses the whole request on either, so in the copy a `null` member is dropped and a number that is not a safe integer becomes its string (`9.99` becomes `"9.99"`). A rule that compares such a value as a number then errors, and that rule's deny is the answer. The receipt keeps the body as it arrived. **Provenance: claimed** |
| `context.facts.arrival` | the fact above. **Provenance: observed** |
| `context.grant` | `{ principal, scopes }`, present only when the arrival is `verified`. **Provenance: attested** |

Every rule the gateway's policies obey applies: default deny, `forbid` wins, an evaluation error is a deny, the policy digest is in the receipt. A policy for the shop in the tutorial:

```cedar
// The catalogue is public: humans, agents, anyone.
permit(principal, action == Action::"catalogue", resource);

// Refunds: a verified agent, in its grant's scope, for a positive amount of at most £50.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};

// Everything else on the API is for verified agents.
permit(principal, action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
```

A refund without a JSON body, with no `amount`, or with an `amount` that is not an integer (`45.5` reaches the policy as `"45.5"`), is an evaluation error and a deny. That is the behaviour you want in front of a payments route. The bound has two ends on purpose: `amount <= 5000` alone admits `{"amount": -1}`, and the door relays the body as it came.

A permit that names an agent, `permit(principal == Agent::"shopping-agent", action == Action::"refund", resource)`, admits only an arrival whose verified grant names that agent, since nothing else reaches the principal slot. `agent-custody check` still warns on such a permit when it does not also require `context.facts.arrival.class == "verified"`: the same text in a gateway policy reads differently, and the condition says what the permit relies on.

## Before the origin hears of it

A request that can change something at the origin, any method but GET, HEAD, and OPTIONS, and any arrival at a route named in `precommit`, is committed to the log before it is relayed, exactly as the gateway's precommit does for a consequential tool call: the door signs an authorization statement (the receipt without its outcome), appends it, writes it as `receipts/<receiptId>.authorization.json`, and only then relays. The receipt embeds it as `authorization`, and the verifier checks that it names this receipt and sits in the log before it. A door that dies between the relay and the receipt leaves the authorization behind, so the side effect has a record and a retry can be told from a first attempt. If the log will not take the authorization, the request is not relayed: 503 and a `withheld` receipt. In observe mode it is relayed and the missing authorization is printed.

## What the arrival gets back

| the door's decision | HTTP | body | receipt `execution.status` |
| --- | --- | --- | --- |
| policy allows, origin answered | the origin's status and body, plus the door's headers | the origin's | `executed`, or `failed` when the origin answered 5xx |
| policy denies, whatever the body's size | 403 | `{ error, reason, receipt }`, plus `challenge: { provider, siteKey, header }` when a challenge is configured and this arrival has not passed it | `denied` |
| origin unreachable: the connection was refused or the host did not resolve | 502 | `{ error, detail, receipt }`, "the origin could not be reached" | `error`; the request never left the door |
| the request left, and its answer did not arrive: a timeout, a reset, or a body that stopped after the headers | 504 | `{ error, detail, receipt }`, "the origin may have acted on the request ... Do not retry" | `error`, and `execution.error` says the origin may have acted. Find out from the origin before retrying a refund |
| policy allows, body above `maxBodyBytes` | 413 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the log refused the authorization | 503 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the partner engine gave no verified verdict and `partner.onFailure` is `deny` | 503 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the path does not decode cleanly | 400 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the origin's response above `maxResponseBytes` | 502 | `{ error, receipt }`, and "do not retry" | `executed` or `failed`: the origin acted; `result` carries the status and `bodyOversized: true`, no digest |
| the receipt could not be written | 500 | `{ error, outcome, receipt }` | none on disk; `outcome` says whether the origin acted, so that a refund is not retried on the strength of a 500 |
| more than `maxInFlight` arrivals at once | 503, `Retry-After: 1` | `{ error }` | none: the arrival was not read, decided, or relayed |

A redirect from the origin to its own host, on any scheme or port, is rewritten to a path, so the client's next request comes back through the door and is classified again. A path under the origin's path loses that prefix; any other path, including one that `..` takes out of it, is kept as it is. A redirect to another host is relayed as sent. Every `Set-Cookie` the origin sent reaches the client. An `Expect: 100-continue` is the client's conversation with the door, which answers it; the origin does not see the header.

Every answer carries `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`. When the log did not take the receipt, it waits in `receipts/outbox/` and the answer also carries `X-Agent-Custody-Log-Pending: true`; a serving door appends the outbox every 30 seconds, as the gateway does.

`GET /.well-known/agent-custody-door` answers the door's key id, the policy digest in force, the version, and the count of pending receipts.

## What a receipt records of the query and the body

A query can carry an API key (`?api_key=sk_live_...`) and a JSON body a password. When the config gives a route no `capture` rule, and has no `"*"` rule, the door applies its own private rule to it: `method`, `path`, `headers` (the four above), `bodyBytes`, and `bodyOversized` stay in clear, and the query, the body, and `bodyDigest` leave one salted commitment, `request.args.$rest`, in their place. The policy still decides on the real values, because the rule is applied after the decision, and the receipt still verifies. As under any private rule, the denial reason and the policy's error messages are withheld too; the client's 403 still carries the reason. The facts (the arrival) and the result (the origin's status and digest) stay in clear.

To record more in clear, give the route a rule of its own, as for the gateway ([private evidence](configuration.md)): `{ "capture": { "refund": { "args": { "mode": "digest", "clear": ["method", "path", "body"] } } } }` keeps a refund's body in clear, and `{ "capture": { "*": { "args": { "mode": "clear" } } } }` keeps every route's arguments in clear, as before.

## The receipt

A door receipt is a v0.2 receipt with `issuer.kind: "door"` and `issuer.framework: "http"` (`"authz"` when it answered a proxy's check, [below](#behind-nginx-or-envoy-authz-mode)). The route is the tool, observed. `request.args` is the arrival as the table above describes it, claimed. `facts.arrival` is the door's observation; `facts.partner`, when present, is a partner engine's signed verdict, attested ([above](#a-partner-engines-verdict)). When the arrival was verified by a grant, `principal` and `agent` are attested and `delegation` carries the grant. When it was verified by a signature alone, `principal` is `{ id: null, provenance: "claimed" }` and `agent` is the signature agent, observed. Otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent` is the subject, claimed. `execution.result` for a relayed call is `{ status, contentType?, bodyBytes, bodyDigest }`: the origin's body is never copied into the receipt, only committed to.

The verifier runs `door receipt carries a policy decision` in place of the gateway's two checks, and otherwise the same checks: a verified arrival's receipt passes `delegation binds principal and agent` and `executed tool within delegated scope`; an unknown arrival's passes `principal is claimed, not attested`; a receipt that carries an `authorization` passes the authorization checks, including `authorization logged before execution`. Both verifiers, the Python verifier, and `policy simulate` accept door receipts; the conformance vectors `door-unknown-executed`, `door-unknown-denied`, and `door-verified-executed` pin them. The `door-grant-*` vectors pin each passport the door may be shown: an expired grant, one signed by a key it does not trust, a revoked grant, a delegated grant (with `delegation chain to the principal`), and a delegated grant whose parent was revoked. Each one the door refuses is a claimed arrival whose receipt verifies with no delegation; the `resigned-door-grant-*` vectors paste the refused grant into the receipt as if the door had accepted it, and fail `delegation valid at receipt time` or `delegation signature (principal key)`.

## Behind nginx or Envoy: authz mode

A site that already runs nginx or Envoy need not send its traffic through the door. With `"authz": true` in the config the door relays nothing and has no origin: it answers the proxy's external-auth check for each request, and the proxy relays or refuses. `deploy/door/` has a stock [nginx.conf](../../../deploy/door/nginx.conf) (`auth_request`) and a stock [envoy.yaml](../../../deploy/door/envoy.yaml) (`ext_authz`, HTTP mode), with the door config and policy they run against, and `deploy/door/demo.sh` runs each in front of a stand-in site: an allowed read, a refused refund, a verified agent's refund, and every receipt verified.

```json
{ "identity": { "keyFile": "keys/door.key" }, "authz": true, "trustProxy": true, "routes": [...], "policyFile": "policy.cedar", "receiptsDir": "receipts", "logFile": "log.jsonl" }
```

- **What the door reads.** The proxy sets `X-Original-Method` (the original request's method) and `X-Original-URI` (its path and query), and `X-Forwarded-For` (the client's address; `trustProxy` is required, and the door takes the last address), and passes the client's headers the door reads: the grant, `X-Agent-Custody-Agent`, `Signature`, `Signature-Input`, `Signature-Agent`, the challenge header, `User-Agent`, `Accept`, `Content-Type`, and the client's `Host`. The check request's own method and path are the proxy's and are ignored; the door decides, and checks a [Web Bot Auth](#web-bot-auth-signatures) signature, on the original method, target, and `Host`; a check without the two `X-Original-*` headers is answered 400 with no receipt.
- **What it answers.** 200 with `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`, which the proxy passes to the origin in place of anything the client sent under those names; 403 on a refusal; 503 when the log refused the authorization of a request that can change something; 400 for a path that does not decode cleanly. nginx relays only on a 2xx, refuses on 401 and 403, and answers 500 for anything else; Envoy relays only on 200 and returns anything else to the client. Both stock configs fail closed when the door is down.
- **Commit before relay still holds.** Any method but GET, HEAD, and OPTIONS, and any route in `precommit`, is committed to the log before the door answers 200, so the evidence exists before the proxy can relay the request.

**What its receipts record: the decision, not the result.** In authz mode the door never sees the request body or the origin's answer. The proxy holds the body and relays it after the 200, and the answer goes from the origin to the client through the proxy. So:

- `issuer.framework` is `authz`.
- `request.args` has `method`, `path`, `query`, and `headers`, and no `body`, `bodyBytes`, or `bodyDigest`. A rule on `context.args.body` errors and denies; a rule on an amount belongs at the origin, or in a door that relays.
- An allow is `execution.status: "withheld"` with the reason "allowed; the door answered the proxy's authz check and relays nothing ...": the door relayed nothing. A deny is `denied`. No authz receipt is ever `executed`, `failed`, or `error`, and none carries a result: whether the proxy relayed the request, and what the origin answered, is in no receipt.
- The verifier runs `door authz decided, relayed nothing` on such a receipt, in TypeScript, in the browser, and in Python, and the report says the receipt records a decision. A receipt re-signed to claim a result fails it (vector `resigned-door-authz-executed`); vectors `door-authz-allowed`, `door-authz-denied`, and `door-authz-verified-precommitted` pin the honest ones.

**What to get right in the proxy.**

- The door believes the proxy's headers. Let only the proxy reach it: anyone who can reach the door can have it write receipts for requests that never happened, and an allow receipt does not prove that the proxy relayed anything. The stock configs keep the door off the published ports.
- The proxy sets `X-Original-Method`, `X-Original-URI`, and `X-Forwarded-For` itself, replacing any copy the client sent (nginx `proxy_set_header`, Envoy `headers_to_add` with `use_remote_address: true`). A config that passes the client's copies lets the client choose what the door decides on.
- The door decides on the path as it normalises it (percent-decoded once, empty segments merged) and refuses a segment that decodes to a slash or a dot segment; the proxy relays the path as the client sent it. Relay it unchanged (nginx `proxy_pass` with no URI part, no Envoy rewrite) and let the origin normalise as the door does, or a path the origin reads differently is a way around a route.
- The stock configs strip `X-Agent-Custody-Grant` and `X-Agent-Custody-Agent` before the origin. `Authorization` reaches the origin unchanged, since the origin may use it: behind a proxy an agent should send its grant in `X-Agent-Custody-Grant`.
- Envoy sends the door only the client headers in `allowed_headers`. A new header the policy reads, such as a challenge header under another name, goes into that list.

## What it does not do yet

- Detect agents in web or API traffic itself. An agent that signs per Web Bot Auth is identified by its signature, and a partner engine's signed verdict can be had; beyond those the only signals are the ones in the arrival fact: `declared` is a claim and `rate` is a pace ([door signals](door-signals.md)).
- Authenticate to a partner engine. The question carries no credential: put the adapter that holds the engine's API key and the signing key where only the door reaches it.
- Check AP2 mandates.
- Check every Web Bot Auth signature: Ed25519 only (no RSA-PSS or ECDSA), the components listed above only, no `Content-Digest`, no response signatures on the directory, and nonces in one process's memory (the Worker keeps them in a Durable Object that every isolate reaches: [the door as a Cloudflare Worker](door-worker.md#web-bot-auth-nonces)). A signature agent must be listed in `agents`; the door does not fetch the directory of an origin it was not told about.
- Challenge an arrival with a passkey. Turnstile and hCaptcha are the providers; see [challenging a human](#challenging-a-human).
- Bind a grant to its sender without a signature. A grant presented alone is bearer-grade; under its agent's Web Bot Auth signature, or under a signature by the key of its did:key agent, it is bound: see [presenting a passport](#what-the-door-knows-about-an-arrival).
- Stream a request body: the body is read whole, up to `maxBodyBytes`, so that the policy can read it and the receipt can commit to it.
- Relay a response larger than `maxResponseBytes`, or stream one: the body is relayed whole so that its digest can be recorded. A larger one is not held: reading stops at the limit, the client gets 502, and the receipt records that the origin answered.

Tutorials: [40-door.ts](../examples/40-door.ts), the proxy; [48-door-app.ts](../examples/48-door-app.ts), in-process; [49-door-authz.ts](../examples/49-door-authz.ts), behind nginx or Envoy; [examples/languages/door](../examples/languages/door), middleware for Go, Rails, Django, and Spring; [52-door-partner-verdict.ts](../examples/52-door-partner-verdict.ts), a partner engine's signed verdict; [56-door-worker.ts](../examples/56-door-worker.ts), the door as a Cloudflare Worker, in workerd; [58-door-error-rates.ts](../examples/58-door-error-rates.ts), the error rates.

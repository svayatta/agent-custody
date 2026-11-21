# The door as a Cloudflare Worker

> For a site already on Cloudflare. How the door works is in [the door](door.md); every field is in [the reference](../../../site/reference/door.md). The template and the deploy steps are in [deploy/door/cloudflare-worker](../../../deploy/door/cloudflare-worker/README.md).

The Worker runs the door's own decision loop (`src/door-core.ts`) at Cloudflare's edge, so each request to the site reaches the Worker first. It classifies the arrival (`verified`, `claimed`, or `unknown`), decides with the site's Cedar policy for the route, and relays an allowed request to the origin with `fetch`. It answers a refused one with the door's refusal. Every decision gets a door receipt, the same receipt the Node door writes: issuer kind `door`, framework `cloudflare-worker`. The receipt goes to the log over HTTP and to an R2 bucket. `agent-custody verify` checks it with the Worker's public key and the log, as it checks any door receipt.

It is the same code as the reverse proxy, the in-process door, and authz mode, with different I/O:

| | Node door | Worker |
| --- | --- | --- |
| signing key | `identity.keyFile` | the `DOOR_KEY` secret |
| policy | `policyFile`, re-read when it changes | the `DOOR_POLICY` variable; a change is a deploy |
| config | `door.json` | the `DOOR_CONFIG` variable, without the fields that name files |
| receipts | the receipts directory | the `RECEIPTS` R2 bucket, same names: `<id>.json`, `<id>.authorization.json`, `salts/<id>.json`, `outbox/<id>.json` |
| log | `logFile` or `log.url` | `LOG_URL`, its keys pinned in `LOG_KEYS`, token in the `LOG_TOKEN` secret |
| receipts whose log append failed | the outbox, flushed every 30 seconds | the bucket's outbox, flushed by a cron trigger every minute |
| trusted principal keys, revoked grants | files, re-read | the `TRUSTED_PRINCIPAL_KEYS` and `REVOKED_GRANTS` variables; a change is a deploy |
| the arrival's address | the socket, or `X-Forwarded-For` with `trustProxy` | `CF-Connecting-IP`, which Cloudflare sets |
| Web Bot Auth nonces, arrival rates | one process's memory | one isolate's memory |

## What reaches the policy

Everything the Node door gives it: the arrival fact, the request's arguments, and the grant. Web Bot Auth works unchanged. The request's own `Signature`, `Signature-Input`, and `Signature-Agent` headers reach the Worker, and directories are fetched with `fetch` and cached in the isolate. A grant in `X-Agent-Custody-Grant` or `Authorization: Bearer` is checked as at any door.

Where the zone has Cloudflare Bot Management, its score and verified-bot flag enter as a fact named `cloudflare`, labelled `observed`. They reach the policy as `context.facts.cloudflare.score` and `context.facts.cloudflare.verifiedBot`. Cloudflare does not sign them, unlike a partner engine's verdict, which enters `attested`. The fact is read only when `request.cf.botManagement` carries an integer score and a boolean flag, and is never required. A policy that reads it should test for it first: `context.facts has cloudflare && context.facts.cloudflare.score < 30`.

## When R2 or the log is unavailable

The rules are the door's own. A request that can change something (any method but `GET`, `HEAD`, and `OPTIONS`, and every route in `precommit`) reaches the origin only after its authorization is committed. That means appended to the log and stored in the bucket. If either fails, the request is answered 503 and not relayed.

A safe request whose receipt the log will not take is relayed anyway. Its receipt is signed and kept in `outbox/` in the bucket, the answer carries `x-agent-custody-log-pending: true`, and the cron appends it once the log is back.

What is lost when R2 is down for a safe request: the log takes the receipt's leaf, but the bundle cannot be stored. The origin has already answered, and its answer is not relayed. The client gets 500 saying that the origin acted and that the request was not recorded, so nobody retries it. The log then holds a leaf whose bundle exists nowhere. If both the log and R2 are down, the receipt cannot be kept in the outbox either, and the client gets the same 500.

There is no lock between isolates. Two flushes at once can each append the same outbox entry, which puts the receipt in the log under two leaves. Either inclusion proves it.

## Limits

- **Bundle.** 517 KB of JavaScript (115 KB gzipped), plus Cedar's WebAssembly: 4.3 MB, 1.42 MB gzipped. That is about 1.5 MB compressed, within the free plan's 3 MB and the paid plans' 10 MB.
- **CPU time.** A warm decision for a `GET`, run locally in workerd (Miniflare 4.20260730), takes 3.2 ms median and 3.5 ms at the 90th percentile. That is wall time, including a local log append of about 0.6 ms and an R2 write. workerd does not expose CPU time to the code it runs, so the figure to plan with is the one in the Workers dashboard of a real deployment. The first request of an isolate also instantiates Cedar's module and parses the policy, which is not in that figure. The free plan allows 10 ms of CPU per request, which a cold start may exceed. The paid plans allow far more.
- **What the Node door does that the Worker does not:** authz mode for nginx and Envoy, a partner engine, OpenTelemetry and Splunk export, a local receipts directory, a local log file, `trustProxy`, and reloading the policy or the revocation list without a deploy.
- **Nonces live in one isolate.** Cloudflare runs many isolates, in many places, and starts new ones at will. A captured Web Bot Auth signature is refused a second time by the isolate that saw it, but another isolate accepts it once, until `maxAgeSeconds`. The Node door has the same limit across processes; at the edge there are simply more of them. Keep `maxAgeSeconds` short.
- **Arrival rates live in one isolate too.** A pace rule sees what one isolate counted.

## The signing key

The key is a Worker secret: stored by Cloudflare, given to the Worker as a binding, and readable by any code deployed to that Worker. Anyone who can deploy to the Worker, or read its bindings through the account, can sign receipts as the door. It is not held in a hardware module. Give deploy rights to as few people as you would give the key file of a Node door, and rotate it the same way. Rotating means a new key, a new public key handed to whoever verifies, and the old public key kept for older receipts.

## What was checked, and how

- `test/door-worker.test.ts` builds the Worker with the same script `wrangler deploy` runs and serves it in workerd, with local stand-ins for the origin, the log, and a crawler's key directory. It checks the following:
  - an unknown arrival on a protected route is refused and never reaches the origin;
  - a verified Web Bot Auth arrival is relayed and its receipt verifies;
  - a forged signature, or the same signature twice, is not verified;
  - a grant is checked at the edge;
  - a precommit request is not relayed when the log is down;
  - a safe request's receipt goes to the outbox and the cron appends it;
  - the Bot Management fact is recorded;
  - the Worker's Ed25519 signature is byte for byte the one Node makes over the same bytes;
  - `agent-custody verify` accepts a Worker receipt;
  - a config that names a file is refused with nothing relayed.
- `test/door-worker-io.test.ts` checks the bucket issuer in Node, where a store can be made to fail: a precommit request whose authorization the bucket cannot store is not relayed.
- [56-door-worker.ts](../examples/56-door-worker.ts) is the same run as a tutorial.

A deployment to Cloudflare itself, with the receipts it produced, is not recorded here yet.

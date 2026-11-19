# The door in your Node app

> How to run it and what it records. Every export and header is in [the reference](../../../site/reference/door.md#in-process).

[The door](door.md) is a reverse proxy: it stands in front of your site and relays what the policy allows. A Node site can run the same decision loop inside its own process instead. Express takes it as middleware, `app.use(door("door.json"))`. A Next.js App Router route takes it as a wrapper around the route's handler, `export const POST = guard.route(handler)`.

The decision is the proxy's own, from the same code: the arrival is classified (`verified`, `claimed`, or `unknown`, with a [Web Bot Auth signature](door.md#web-bot-auth-signatures) checked when the config has `webBotAuth`), its body is read up to `maxBodyBytes`, the Cedar policy for its route decides, a request that can change something is committed to the log before your code runs, and every arrival gets a signed, logged receipt with `issuer.kind: "door"`. A refused arrival gets the same answer the proxy gives (403 with the reason, 413, 503, 400), and your code never runs for it.

Use the proxy when the site is not Node, when you cannot change its code, or when you want the door in a separate process from the app. Use the in-process door when the site is Express or Next.js and you would rather not run and secure a second process.

## The config

The proxy's `door.json` without `origin`: there is nothing to relay to, because an allowed request goes on to your own code. The in-process door refuses a config that names an origin, and the proxy refuses one that does not. `maxResponseBytes` does nothing here: the app's answer streams to the client as it would without the door and is hashed as it goes, never held. Every other field means what [the reference](../../../site/reference/door.md#config) says, and `agent-custody check --config door.json` checks the file.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "routes": [
    { "name": "page", "methods": ["GET"], "path": "/" },
    { "name": "refund", "methods": ["POST"], "path": "/api/refunds" }
  ],
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

## Quick start: the parts both frameworks share

You need Node 22 or later and `curl`. The in-process door is in `@agent-custody/receipts` from 0.16.7.

The door signs every receipt with its own key. The principal key belongs to whoever vouches for an agent: it signs the agent's passport, and the door trusts what it signs. Run these in the app's directory, after the framework step below has created it:

```bash
npx agent-custody keygen --dir keys --name door
npx agent-custody keygen --dir keys --name principal
```

`policy.cedar`. The page is public; a refund needs an agent with a passport, for a positive amount of at most 5000 (minor units, since Cedar has no decimals):

```cedar
permit(principal, action == Action::"page", resource);

permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};
```

`door.json` is the config above. Keep `keys/`, `receipts/`, and `log.jsonl` out of git.

## Express

```bash
mkdir shop && cd shop
npm init -y
npm install express @agent-custody/receipts
```

Then the keys, `policy.cedar`, and `door.json` from above, and `server.mjs`:

```js
import express from "express";
import { door } from "@agent-custody/receipts/door";

const app = express();
app.use(door("door.json"));  // first: before the body parsers and the routes
app.use(express.json());
app.get("/", (req, res) => res.send(`hello, ${req.get("x-agent-custody-class")} visitor\n`));
app.post("/api/refunds", (req, res) => res.json({ refunded: req.body.amount }));
app.listen(3000, "127.0.0.1");
```

```bash
node server.mjs &
```

Put the door before the body parsers. It reads the body to decide, then hands the same bytes to whatever reads the request after it, so `express.json()`, `express.urlencoded()`, a multipart parser, or `for await (const chunk of req)` see what the policy saw. A parser that runs before the door leaves it nothing to read: the policy then sees an empty body.

## Next.js (App Router)

```bash
npx create-next-app@latest shop --yes
cd shop
npm install @agent-custody/receipts
```

Then the keys, `policy.cedar`, and `door.json` from above, in the project's root. Three files; `create-next-app --yes` puts `app/` in the root (under `src/` if you chose that layout).

`next.config.ts`: add `serverExternalPackages`, and keep what `create-next-app` put there. The door loads Cedar's WebAssembly and reads its key and policy from disk, so Next must load the package with Node rather than bundle it; without this line every wrapped route answers 500 with `ENOENT ... cedar_wasm_bg.wasm`.

```ts
const nextConfig: NextConfig = {
  serverExternalPackages: ["@agent-custody/receipts"],
  // ...the options create-next-app wrote stay as they are
};
```

`lib/door.ts`, one door for the process, which every wrapped route shares:

```ts
import { join } from "node:path";
import { door } from "@agent-custody/receipts/door";

export const guard = door(join(process.cwd(), "door.json"));
```

`app/api/refunds/route.ts`:

```ts
import { guard } from "@/lib/door";

export const POST = guard.route(async (req: Request) => {
  const { amount } = await req.json();
  return Response.json({ refunded: amount });
});
```

```bash
npm run dev
```

The handler gets the request Next made, a `NextRequest` with `nextUrl` and `cookies`, with the door's headers set and the grant removed, and reads its body as it would without the door. Route handlers run in Node by default; the door does not run in the Edge runtime.

This quick start was run on a fresh `create-next-app@latest` (Next.js 16.4.6, Turbopack, Cache Components on) under `next dev`, and after `next build` under `next start`, with the package installed from a tarball of this repository. From `create-next-app` to a verified receipt took 76 seconds of machine time, most of it `create-next-app` and `npm install`; the time to read the page and type the five files is yours to add.

## Try it

The same requests work against either app on port 3000; the output below is the Express app's, and the Next.js route answered the same. An unknown arrival asks for a refund and is refused before your code runs:

```bash
curl -si -X POST http://127.0.0.1:3000/api/refunds -H 'content-type: application/json' -d '{"amount":1000}'
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-receipt: 06db4beb-0525-4069-9a26-2dab0fd2010d
x-agent-custody-class: unknown

{"error":"refused by the door's policy","reason":"no permit policy matched","receipt":"06db4beb-0525-4069-9a26-2dab0fd2010d"}
```

The principal signs a passport for its agent, scoped to the refund route, and the agent sends it:

```bash
npx agent-custody grant --key keys/principal.key --principal shop-owner --agent shopping-agent --scopes refund --out grant.json
PASSPORT=$(node -e 'process.stdout.write(Buffer.from(require("fs").readFileSync("grant.json","utf8")).toString("base64url"))')
curl -si -X POST http://127.0.0.1:3000/api/refunds -H 'content-type: application/json' -H "x-agent-custody-grant: $PASSPORT" -d '{"amount":4500}'
```

```text
HTTP/1.1 200 OK
x-agent-custody-receipt: bed5bf0b-958e-48cb-806d-2bbb92b937c1
x-agent-custody-class: verified

{"refunded":4500}
```

Verify the agent's receipt with public keys only:

```bash
npx agent-custody verify receipts/bed5bf0b-958e-48cb-806d-2bbb92b937c1.json --issuer-key keys/door.pub --principal-key keys/principal.pub --log log.jsonl
```

```text
PASS  issuer kind is known  (door / node-middleware)
PASS  delegation signature (principal key)  (signed by f3c85fd65a70)
PASS  executed tool within delegated scope  (refund)
PASS  policy decision consistent with execution  (allow -> executed)
PASS  authorization logged before execution  (authorization leaf 2, receipt leaf 3)
PASS  log inclusion proof  (leaf 3 of 4, root 9c8b6f262453)

RESULT: VERIFIED
```

The refund was in the log before your handler ran. The output is cut to the lines that matter; the full report lists every check. Your receipt ids differ; take them from the `x-agent-custody-receipt` headers. The output above is from the Express app, run from this repository at the commit that added the in-process door, with the headers cut to the door's; a Next.js route's receipt says `door / fetch-route`.

## What your code receives

An allowed request reaches your code with:

- `X-Agent-Custody-Receipt`: the receipt id, and `X-Agent-Custody-Class`: `verified`, `claimed`, or `unknown`. The door sets both; a client that sends either has its value replaced.
- No grant: `X-Agent-Custody-Grant` is removed, and so is `Authorization` when it carried the grant. `X-Agent-Custody-Agent` and the challenge header are removed too. In Express they leave `req.headers` and `req.rawHeaders` both.
- The body the door read, unchanged.

The door does not touch the client-address headers (`X-Forwarded-For`, `X-Real-IP`, and the rest) as the proxy does: in-process, your app reads the socket itself, and what it trusts is its own setting (`app.set("trust proxy")` in Express).

The answer your code gives goes back as it is, with `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class` added.

## What the receipt records of your answer, and what it does not

| | Express | Next.js route handler |
| --- | --- | --- |
| status | `res.statusCode` when the response finished; 5xx is `failed`, anything else `executed` | the `Response` status; 5xx is `failed` |
| body | `bodyBytes` and `bodyDigest` (sha256) of every byte the app wrote through `res.write` and `res.end`, after any middleware registered later (a `compression()` after the door: the compressed bytes); not the chunked framing | `bodyBytes` and `bodyDigest` of the `Response` body, hashed on a second branch of the stream while the first goes to the client |
| content type | the `Content-Type` header the app set | the `Response`'s `Content-Type` |
| the app failed partway | the connection closed before the response finished: `error`, "the app may have acted on the request" | the handler threw: `error` with its message, and the throw goes on to Next; the body stream failed: `error` with the bytes read so far |
| when the receipt is written | after the response finished | after the body stream ended |

What is not recorded, or not the same as the proxy:

- **The receipt of an allowed request is written after the answer has gone.** The answer cannot say whether the log took the receipt, so there is no `X-Agent-Custody-Log-Pending` on it (a receipt the log refused waits in `receipts/outbox/` and is appended later, as for the proxy). If the receipt cannot be written at all, the client already has the app's answer: the door prints the failure on stderr, where the proxy would have answered 500. The authorization of a refund, written before your code ran, is on disk either way.
- **The response headers** other than `Content-Type`, as for the proxy.
- **Next.js pages, Server Actions, and the `middleware.ts` / `proxy.ts` file are not covered.** Only the route handlers you wrap are decided and receipted. Next's middleware runs before the route and cannot see its answer, so a receipt from it could not say what the app did; the door does not offer one. A `GET` handler that Next prerenders at build time (`export const dynamic = "force-static"`) runs at build time, not per request: do not wrap one.
- **A signature on a fetch request.** A Web Bot Auth signature is checked over the request as the route handler gets it: a field sent more than once arrives joined with `, `, and a `Request` built without a `Host` field takes its authority from its URL. In Express the door reads every value of each field, as the proxy does.
- **The arrival's address in Next.js.** A route handler gets no socket. Without `trustProxy` the arrival's `remote` is `unknown`, and the `rate` signal counts every unknown arrival as one source. Behind a proxy you run, or on a host that sets `X-Forwarded-For` (Vercel does), set `trustProxy: true` and the door takes the last address in it.
- **A refused request's body in Express.** For an arrival the door refuses, the body is read up to `maxBodyBytes` and the rest drained, as by the proxy; nothing after the door runs.

## Why Express and Next.js are not dependencies

`@agent-custody/receipts/door` imports neither framework, and neither is a dependency or a peer dependency of the package. The middleware is typed on `node:http`'s `IncomingMessage` and `ServerResponse`, which an Express request and response extend, so it fits Express, Connect, or a plain `http.createServer`; the tests run it under Express 5 only. The wrapper is typed on the fetch `Request` and `Response`, which a `NextRequest` extends, and keeps the handler's own parameter types, so Next's route type check sees the handler it expects. A peer dependency would only add an install warning for every user of the gateway or the SDK, who has neither framework, and tie each release to a framework version range the door does not need. The repository's tests run the middleware under Express 5.2.1, a devDependency only, and the wrapper with plain fetch `Request` objects.

Tutorial: [48-door-app.ts](../examples/48-door-app.ts).

# The door as a Shopify app

> For a Shopify store that lets agents place orders and ask for refunds. How the door works is in [the door](door.md). The server, its policy, and its smoke test are in [deploy/door/shopify](../../../deploy/door/shopify/README.md).

Shopify hosts the storefront, so no proxy can stand in front of it. A Shopify app is a server that you run. So the app runs the [in-process door](door-middleware.md) in front of two routes that an agent calls. The door decides each request first. The route runs only for a request that the policy allows. Each decision, allowed or refused, gets a door receipt.

The server serves one store for each process. It is `node:http` with no framework.

## What it protects

| route | what it does | Shopify call |
| --- | --- | --- |
| `POST /orders` | makes a draft order for the buyer. The body is `{ "lines": [{ "variant_id", "quantity" }], "email" }`. The answer has the draft order id, the total in minor units, and the `invoice_url` | `draftOrderCreate` |
| `POST /refunds` | refunds part of an order. The body is `{ "order_id", "amount", "reason" }`. `amount` is an integer in minor units. The request needs an `Idempotency-Key` header | `refundCreate` |

An order moves no money. The draft order has the tag `agent-custody`, and its note says `agent-custody receipt <receipt id>`, so the store's own record points to the receipt. The buyer pays at the Shopify checkout through the `invoice_url`. The app never completes a draft order.

A refund reads the order's successful `SALE` or `CAPTURE` transaction. It then calls `refundCreate` with a `REFUND` transaction on that parent, with its gateway and its currency. The app converts the minor units to Shopify's decimal string with the exponent of the currency, which `Intl.NumberFormat` gives: 1999 USD is `19.99`, and 500 JPY is `500`.

## The policy

`deploy/door/shopify/policy.cedar` is the default policy.

| route | admits | refuses |
| --- | --- | --- |
| `order` | a `verified` agent whose registry passport verified, and that is on the store's `agents` admission list | everything else |
| `refund` | the same agent, when `0 < amount <= 50000` | everything else, and each amount outside the limit |

A signature with no passport is not enough: anyone can make a key. The passport says who the agent is and who owns it. The admission list says that this store accepts it. The list is `deploy/door/shopify/admission.json`. The door reads it again when it changes. To admit an agent, add its registry entry:

```json
{ "lists": { "agents": [{ "registry": "https://app.agent-custody.dev/", "agentId": "agt_..." }] } }
```

Change the limit in `policy.cedar`. The limit is in minor units, so 50000 is 500.00 in a currency with two decimals.

## The idempotency key

A refund moves money, and an agent may retry. So the app needs an `Idempotency-Key` header (1 to 128 printable characters) and refuses a refund without one. The app keeps the keys in `data/idempotency.json`.

1. The app writes the key as `pending` before it calls Shopify.
2. It writes the answer as `done` after the call.
3. A retry with a `done` key gets the stored answer. No second refund is made.
4. A retry with a `pending` key gets 409.
5. A retry with a key that was used for another order or amount gets 422.

If Shopify refuses the refund (`userErrors`, or a 4xx), Shopify did nothing, so the app frees the key and a retry runs. If the answer may hide an action (a 5xx, a timeout, a restart of the app), the key stays `pending`. A person must then check the order in Shopify. A second refund is worse than a refund that waits.

## What a receipt records

- The decision, the policy digest, and the arrival: the class, the passport (the registry, the agent id, the owner), and the admission lists. The receipt has `issuer.framework: "node-middleware"`.
- For a refund, the arguments in clear: the order id, the amount, and the reason. For an order, the arguments are withheld, because they hold the buyer's email.
- The outcome that the agent saw: the HTTP status of the answer, its content type, its size, and its digest. A Shopify `userErrors` value is a 422. A non-200 answer from Shopify, and an answer that is not JSON, are a 502. A 502 is `failed` in the receipt.

`agent-custody verify` and `verifyBundle` accept each receipt.

## Install on a development store

You need Node 22 or later.

1. In the [Shopify Dev Dashboard](https://dev.shopify.com/dashboard), create an app. Give it the scopes `write_draft_orders`, `read_orders`, and `write_orders`.
2. Create a development store, and install the app on it.
3. Get the credentials. Either copy the Admin API access token (`shpat_...`) as `SHOPIFY_ADMIN_TOKEN`, or copy the client id and the client secret of the app as `SHOPIFY_CLIENT_ID` and `SHOPIFY_CLIENT_SECRET`. The app then uses the client-credentials grant and keeps the token until it expires.
4. In `deploy/door/shopify`, run `npm install`.
5. Make the door's key, and put the public key of your agent registry in `keys/registry.pub`:

   ```bash
   npx agent-custody keygen --dir data/keys --name door
   ```

6. In `door.json`, set `webBotAuth.authorities` to the host name that agents use for the app, with the port when it is not 443. A signature must cover that `@authority`.
7. Add the agent to `admission.json`.
8. Run it:

   ```bash
   SHOPIFY_SHOP=your-store.myshopify.com SHOPIFY_ADMIN_TOKEN=shpat_... node start.ts
   ```

`SHOPIFY_SHOP` is the `x.myshopify.com` domain. `PORT` (default 8790) and `HOST` (default `127.0.0.1`) set the address. Put your own TLS in front of it. The app pins one Admin API version, `API_VERSION` in `server.ts`. `SHOPIFY_BASE_URL` replaces `https://$SHOPIFY_SHOP`. The tests use it to reach a stand-in.

Secrets come from the environment only. No file in the repository holds a token.

### Smoke test

`smoke.ts` runs by hand against the development store. CI does not run it, because it needs a real store. Set `SHOPIFY_SHOP`, the credentials, and `SMOKE_VARIANT_ID` (the id of a variant of the store), then run `node deploy/door/shopify/smoke.ts` from the repository root. It makes a registry key, a passport, and an agent. It starts the server, places one order as the agent, and shows that an agent with no passport gets 403. It then verifies each receipt. It leaves one draft order in the store.

## Limits

- **One store for each process.** There is no multi-store OAuth and no App Store listing.
- **One process.** The idempotency keys are in the memory and in one file of one process. Two processes on one data directory do not see each other's pending keys.
- **No app proxy.** The app does not serve the `/apps/...` path on the storefront domain. Agents call the app at its own address.
- **No completeness check.** The app has no webhooks. It cannot tell you about an order or a refund that someone made in Shopify without the door.
- **No ownership check for a refund.** The policy does not check that an order belongs to the agent that places the refund. Any admitted agent may refund any order, up to the limit.
- **The receipt records the decision and the answer, not the Shopify state.** The note on the draft order is the link back.
- **The framework label is `node-middleware`.** The in-process door has no option for another label.

## What was checked, and how

- `test/door-shopify.test.ts` runs the server with the shipped policy and config, and a stand-in Shopify Admin API on loopback that records each mutation. It checks the admitted order and its receipt, the refusal of an agent with no passport and of an agent that is not on the list (and no call to Shopify), the refund limit, the decimal amount for USD and JPY, the idempotency key (one `refundCreate`, 409 while pending, a missing key), and the `userErrors` and 500 answers.
- Not checked: a real Shopify store, the pinned API version against Shopify, the client-credentials grant against Shopify, and an agent that calls through the public internet.

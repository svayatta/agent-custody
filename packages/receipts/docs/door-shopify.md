# The door as a Shopify app

> For a Shopify store that lets agents place orders and ask for refunds. How the door works is in [the door](door.md). The server, its policy, and its smoke test are in [deploy/door/shopify](../../../deploy/door/shopify/README.md).

Shopify hosts the storefront, so no proxy can stand in front of it. A Shopify app is a server that you run. So the app runs the [in-process door](door-middleware.md) in front of two routes that an agent calls. The door decides each request first. The route runs only for a request that the policy allows. Each decision, allowed or refused, gets a door receipt.

The server serves one store for each process. It is `node:http` with no framework.

## What it protects

| route | what it does | Shopify call |
| --- | --- | --- |
| `POST /orders` | makes a draft order for the buyer. The body is `{ "lines": [{ "variant_id", "quantity" }], "email" }`. The answer has the draft order id, the total in minor units, and the `invoice_url`. The total is in the shop's currency (the answer names it), not in the presentment currency of the buyer | `draftOrderCreate` |
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

A refund moves money, and an agent may retry. So the app needs an `Idempotency-Key` header (1 to 128 printable characters) and refuses a refund without one.

The app sends `refundCreate` with Shopify's `@idempotent(key: ...)` directive. Shopify requires it for this mutation. The app takes the sha256 hex of the agent and the header, `sha256(agent|key)`, and gives Shopify its first 32 characters in the form of a UUID, as a literal on the `refundCreate` field. So Shopify makes one refund for each key, and one agent cannot read or block the key of another agent.

The app knows the agent from the keyid of the request's Web Bot Auth signature. The door gives the app no subject: it passes only the receipt id and the class. It keeps `Signature-Input`, and the door has checked that signature. The refund route admits only a `verified` arrival, so the keyid is the did:key of the agent that holds the passport. The app refuses a refund whose `Signature-Input` has no keyid or more than one.

The app keeps a record in `data/idempotency.json`.

1. The app reads the order's sale or capture. If this read fails, the app writes nothing.
2. It writes the key as `pending`, and calls Shopify.
3. It writes the answer as `done` after the call.
4. A retry with a `done` key gets the stored answer. No second refund is made.
5. A retry with a `pending` key, after a failure that left the result unknown or after a restart of the app, sends the same mutation with the same Shopify key. Shopify then returns the first refund or makes it once.
6. A retry with a key that was used for another order or amount gets 422. The order id counts in its `gid://shopify/Order/...` form.
7. A request gets 409 while another request with the same key is in flight in this process, and while any other refund of the same order is in flight.

If Shopify refuses the refund (`userErrors`, or a 4xx), Shopify did nothing, so the app frees the key. If Shopify answers with a refund id, the refund happened and the key is `done`, even when the answer also has errors.

If the result of the call is unknown (a 5xx, a timeout, an answer that is not JSON), the agent gets 504 with `{ "error", "outcome_unknown": true, "retry": "same Idempotency-Key" }`. The agent must retry with the same key. The receipt of that try says `failed` with status 504, because the door records each answer of 500 or more as `failed`.

## What a receipt records

- The decision, the policy digest, and the arrival: the class, the passport (the registry, the agent id, the owner), and the admission lists. The receipt has `issuer.framework: "node-middleware"`.
- For a refund, the arguments in clear: the order id, the amount, and the reason. For an order, the arguments are withheld, because they hold the buyer's email.
- The outcome that the agent saw: the HTTP status of the answer, its content type, its size, and its digest. A Shopify `userErrors` value is a 422. A refusal from Shopify (a 4xx, or an error with no data) and a failed order lookup are a 502. A refund whose result is unknown is a 504. The door records a 502 and a 504 as `failed`. The app gives the agent no text of its own errors: the detail goes to the log of the server.

`agent-custody verify` and `verifyBundle` accept each receipt.

## Install on a development store

You need Node 22.18 or later, which strips types by default. The published package `@agent-custody/receipts` 0.16.14 has the `./door` export (checked with `npm view`).

1. In the [Shopify Dev Dashboard](https://dev.shopify.com/dashboard), create an app. Give it the scopes `write_draft_orders`, `read_orders`, and `write_orders`. An order that is older than 60 days needs `read_all_orders` too, or the refund route cannot read it.
2. Create a development store, and install the app on it.
3. Get the credentials. Use the client id and the client secret of the app (**Settings** in the Dev Dashboard) as `SHOPIFY_CLIENT_ID` and `SHOPIFY_CLIENT_SECRET`. The app asks for a token with the client-credentials grant (form-encoded) and keeps it until it expires, about 24 hours. On a 401 it drops the token and sends the call again once. The grant works only when the app and the store belong to the same Shopify organization.

   `SHOPIFY_ADMIN_TOKEN` (`shpat_...`) is for a legacy custom app only. Since 2026-01-01 nobody can create a custom app in the Shopify admin, so a new store has no such token.
4. In `deploy/door/shopify`, run `npm install`.
5. Make the door's key, and put the public key of your agent registry in `keys/registry.pub`:

   ```bash
   npx agent-custody keygen --dir data/keys --name door
   ```

6. In `door.json`, set `webBotAuth.authorities` to the host name that agents use for the app, with the port when it is not 443. A signature must cover that `@authority`.
7. Add the agent to `admission.json`.
8. Run it:

   ```bash
   SHOPIFY_SHOP=your-store.myshopify.com SHOPIFY_CLIENT_ID=... SHOPIFY_CLIENT_SECRET=... node start.ts
   ```

`SHOPIFY_SHOP` is the `x.myshopify.com` domain. `PORT` (default 8790) and `HOST` (default `127.0.0.1`) set the address. Put your own TLS in front of it. The app pins one Admin API version, `API_VERSION` in `server.ts`. `SHOPIFY_BASE_URL` replaces `https://$SHOPIFY_SHOP`. The tests use it to reach a stand-in.

Secrets come from the environment only. No file in the repository holds a token.

### Smoke test

`smoke.ts` runs by hand against the development store. CI does not run it, because it needs a real store. Set `SHOPIFY_SHOP`, the credentials, and `SMOKE_VARIANT_ID` (the id of a variant of the store), then run `node deploy/door/shopify/smoke.ts` from the repository root. It makes a registry key, a passport, and an agent. It starts the server, places one order as the agent, and shows that an agent with no passport gets 403. With `SHOPIFY_SMOKE_ORDER_ID` (a paid order of the store, for example one paid with the Bogus Gateway), it also refunds 1 minor unit twice with one key, and checks that both answers are the same refund. Look in the store for one refund. The script then verifies each receipt. It leaves one draft order in the store.

## Limits

- **One store for each process.** There is no multi-store OAuth and no App Store listing.
- **One process.** The in-flight locks are in the memory of one process, and the record is one file. Two processes on one data directory do not see each other's in-flight refunds. Shopify still makes one refund for each key.
- **No cumulative cap.** The refund limit applies to each call. Nothing limits the sum of the refunds of one agent or one order, except what Shopify allows for the order. This is a limit, not built.
- **No app proxy.** The app does not serve the `/apps/...` path on the storefront domain. Agents call the app at its own address.
- **No completeness check.** The app has no webhooks. It cannot tell you about an order or a refund that someone made in Shopify without the door.
- **No ownership check for a refund.** The policy does not check that an order belongs to the agent that places the refund. Any admitted agent may refund any order, up to the limit.
- **The receipt records the decision and the answer, not the Shopify state.** The note on the draft order is the link back.
- **The framework label is `node-middleware`.** The in-process door has no option for another label.

## What was checked, and how

- `test/door-shopify.test.ts` runs the server with the shipped policy and config, and a stand-in Shopify Admin API on loopback that records each mutation. It checks the admitted order and its receipt, the refusal of an agent with no passport and of an agent that is not on the list (and no call to Shopify), the refund limit, the decimal amount for USD and JPY, the idempotency key (one `refundCreate`, 409 while pending, a missing key), and the `userErrors` and 500 answers.
- Facts about Shopify that the code follows (checked against shopify.dev on 2026-11-25, not against a store): 2026-10 is the latest stable Admin API version, `refundCreate` requires `@idempotent`, the token request is form-encoded, a transaction's `gateway` may be null, and `RefundInput.currency` is the presentment currency.
- Not checked: a real Shopify store, the GraphQL shapes against Shopify's own schema, the client-credentials grant against Shopify, and an agent that calls through the public internet.

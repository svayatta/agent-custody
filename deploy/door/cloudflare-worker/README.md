# The door as a Cloudflare Worker

The door's decision loop at Cloudflare's edge, in front of a site already on Cloudflare: each request is classified, decided by the site's Cedar policy, relayed to the origin or refused, and receipted to an R2 bucket and the hosted log. What it does and its limits: [the door as a Cloudflare Worker](../../../packages/receipts/docs/door-worker.md).

`wrangler.toml` holds variables only. The signing key and the log token are secrets, set below, and never written to a file in this directory.

## What you need

- A Cloudflare account with the site's zone, and `wrangler` (`npx wrangler@4`) logged in.
- A tenant on the hosted log (or any agent-custody log), its token, and its id.
- Node 22 and this repository with its dependencies (`bun install` at the root): `wrangler deploy` runs `packages/receipts/scripts/build-door-worker.ts` to build the Worker.

## Deploy

```bash
alias agent-custody='npx -y -p @agent-custody/receipts agent-custody'
```

1. The door's key. Keep `door.key` as you would any signing key; hand `door.pub` to whoever verifies the receipts.

   ```bash
   agent-custody keygen --dir keys --name door
   ```

2. The bucket and the secrets, from this directory.

   ```bash
   npx wrangler@4 r2 bucket create agent-custody-door-receipts
   ```

   ```bash
   npx wrangler@4 secret put DOOR_KEY < keys/door.key
   ```

   ```bash
   npx wrangler@4 secret put LOG_TOKEN
   ```

   The log token is read from the prompt, never from a file or the command line. A secret the config names (`challenge.secretEnv`, `captureKeyEnv`, or a value in `origin.headerEnv`) is put the same way, under the name the config gives it.

3. The variables, in `wrangler.toml`:
   - `ORIGIN_URL`, where allowed requests go;
   - `LOG_URL` and `LOG_KEYS`, the log's public key from `https://log.agent-custody.dev/.well-known/agent-custody-log.json`. `LOG_HASH_ONLY` stays `"true"` for a log someone else runs, and `LOG_ID` is set only if your log names itself in its tree heads;
   - `TRUSTED_PRINCIPAL_KEYS`, if agents will present grants;
   - `TRUSTED_REGISTRY_KEYS`, if agents will present an [agent registry](../../../packages/receipts/docs/agent-registry.md) passport (with `webBotAuth` in `DOOR_CONFIG`);
   - `DOOR_POLICY` and `DOOR_CONFIG`.

   Uncomment `routes` and set your zone so that the Worker stands in front of the site. The `NONCES` Durable Object binding stays as it is: with `webBotAuth` in `DOOR_CONFIG` it keeps each signature's nonce where every isolate can see it, and `wrangler deploy` creates it, with no step of its own. `DOOR_CONFIG` takes the door config's fields except those that name files or a Node door's modes (`identity`, `policyFile`, `receiptsDir`, `logFile`, `log`, `trustedPrincipalKeys`, `revokedGrants`, `authz`, `trustProxy`, `partner`, `otel`, `splunk`, and `origin.url`). The Worker refuses a config that has one and says where the value comes from instead.

4. Deploy.

   ```bash
   npx wrangler@4 deploy
   ```

## Check it

One refused request and one allowed, with the template's policy: anyone may read the catalogue, and only an agent with a grant for `orders` may place an order.

```bash
curl -si https://shop.example.com/products/tea | grep -i '^x-agent-custody'
```

```bash
curl -si -X POST https://shop.example.com/orders -H 'content-type: application/json' -d '{"sku":"tea","qty":1}' | grep -i -e '^HTTP' -e '^x-agent-custody'
```

The first answers 200 with `x-agent-custody-class: unknown` and a receipt id. The second answers 403, refused before it reached the origin, with its own receipt id. Fetch each receipt from the bucket and verify it against the Worker's public key and the log:

```bash
npx wrangler@4 r2 object get agent-custody-door-receipts/RECEIPT-ID.json --file receipt.json --remote
```

```bash
agent-custody verify receipt.json --issuer-key keys/door.pub --log-url https://log.agent-custody.dev/t/YOUR-TENANT/
```

`GET /.well-known/agent-custody-door` answers the Worker's key id and policy digest.

## Locally

`packages/receipts/examples/56-door-worker.ts` builds this Worker and runs it in workerd (Miniflare) against a local log and a stand-in origin, with no Cloudflare account: one order refused, one relayed under a grant, both receipts verified.

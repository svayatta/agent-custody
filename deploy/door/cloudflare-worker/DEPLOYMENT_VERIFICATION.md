# Door Worker Deployment Verification Guide

This guide documents the complete process for deploying the agent-custody door Worker to a real Cloudflare account and verifying its receipts. Follow these steps when you have access to real Cloudflare credentials.

## Prerequisites

- A Cloudflare account with API token (Account › Workers Scripts › Edit, Workers R2 Storage › Edit, Account Settings › Read)
- A tenant on the hosted log (e.g., `door-worker-test`) with URL, log ID, and API key
- Node 22 and this repository with dependencies installed (`bun install`)
- An origin to protect (test URL)

## Step-by-Step Deployment Process

### 1. Generate Door Keys

```bash
alias agent-custody='npx -y -p @agent-custody/receipts agent-custody'
agent-custody keygen --dir keys --name door
```

Keep `keys/door.key` private and `keys/door.pub` for verification.

### 2. Configure wrangler.toml

Set these variables in `wrangler.toml`:
- `ORIGIN_URL`: Your test origin URL
- `LOG_URL`: Your tenant's log URL (e.g., `https://log.agent-custody.dev/t/door-worker-test/`)
- `LOG_ID`: Your tenant's log ID
- `LOG_KEYS`: The log's public key from `https://log.agent-custody.dev/.well-known/agent-custody-log.json`
- `TRUSTED_PRINCIPAL_KEYS`: If using grants
- `DOOR_POLICY` and `DOOR_CONFIG`: As needed

### 3. Create R2 Bucket

```bash
npx wrangler@4 r2 bucket create agent-custody-door-receipts
```

### 4. Set Secrets

```bash
npx wrangler@4 secret put DOOR_KEY < keys/door.key
npx wrangler@4 secret put LOG_TOKEN
```

For `LOG_TOKEN`, enter your tenant's API key when prompted.

### 5. Deploy Worker

```bash
npx wrangler@4 deploy
```

Note the workers.dev URL and bundle size reported.

### 6. Test Requests

Send one allowed request and one refused request:

```bash
# Allowed request (GET /products/1)
curl -si YOUR-WORKER-URL.workers.dev/products/1 | grep -i '^x-agent-custody'

# Refused request (POST /orders)
curl -si -X POST YOUR-WORKER-URL.workers.dev/orders -H 'content-type: application/json' -d '{"sku":"tea","qty":1}' | grep -i -e '^HTTP' -e '^x-agent-custody'
```

### 7. Fetch Receipts

```bash
# Fetch allowed receipt
npx wrangler@4 r2 object get agent-custody-door-receipts/ALLOWED-RECEIPT-ID.json --file allowed-receipt.json --remote

# Fetch refused receipt
npx wrangler@4 r2 object get agent-custody-door-receipts/REFUSED-RECEIPT-ID.json --file refused-receipt.json --remote
```

### 8. Verify Receipts

```bash
# Verify allowed receipt
agent-custody verify allowed-receipt.json --issuer-key keys/door.pub --log-url YOUR-LOG-URL/

# Verify refused receipt
agent-custody verify refused-receipt.json --issuer-key keys/door.pub --log-url YOUR-LOG-URL/
```

## Verification Checklist

- [ ] `wrangler deploy` succeeded (note bundle size)
- [ ] Allowed request reached origin (200 response with receipt)
- [ ] Refused request was blocked (403 response with receipt)
- [ ] Both receipts verify with `agent-custody verify`
- [ ] Log inclusion check passes for both receipts
- [ ] Bundle size is under 3MB (free plan limit)

## Documentation

Record the deployment results in `packages/receipts/docs/door-worker.md`, including:
- Bundle size reported by wrangler
- CPU time for requests
- Verification results
- Any issues encountered

## Troubleshooting

- If `wrangler deploy` fails, check API token permissions and account ID
- If receipts don't verify, check door public key and log URL
- If requests don't reach origin, check routes configuration in wrangler.toml
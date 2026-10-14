# The hosted log

The log at `log.agent-custody.dev` is the reference log server run by us, for teams whose receipts need a signer that is not their own operator. It holds leaf hashes, never receipts. Everything on this page also applies to a log you run yourself from [deploy/](https://github.com/svayatta/agent-custody/tree/main/deploy).

## Plans

| plan | appends a calendar month | price |
| --- | --- | --- |
| `free` | 10,000 | $0 |
| `team` | 1,000,000 | $50 a month |
| `enterprise` | no allowance | by conversation |

An append past the allowance is refused:

```
HTTP 429
Retry-After: <seconds to the start of next month>
{ "error": "monthly quota reached: 10000 of 10000 appends on the free plan; it resets at the start of next month, or move to a larger plan" }
```

The gateway's log client retries a 429 three times with backoff and then fails the call: a pre-committed call is withheld, any other returns an error to the agent. Nothing acts without evidence. See [pricing](https://agent-custody.dev/pricing).

## Registering: the portal

`https://app.agent-custody.dev/` is one page. Registering creates the account, the tenant, and its first key, shown once. The page's own API, which any HTTP client may use with the session cookie it sets:

| route | body | response |
| --- | --- | --- |
| `GET /auth/github`, `GET /auth/google` | | a redirect to the provider with a signed state in a ten-minute cookie; the callback at `/auth/<provider>/callback` exchanges the code, takes the provider's verified email, links it to the account with that email if that account has verified its address (otherwise the sign-in is refused with a page saying to sign in with the password first), or creates one, sets the session, and shows a page that continues to `/`. With `?link=1` from a signed-in session it links the provider to that account instead, whatever email the provider gives. Offered only when the operator configured the provider |
| `GET /verify-email?token=` | | the link sent at registration: marks the address verified and shows a page. A provider sign-in links to a password account only once this has happened |
| `POST /api/verify-email/resend` | `{}` | sends the verification link again; `{ "ok": true, "emailVerified" }` |
| `POST /api/register` | `{ "email", "password" (10+ chars) }` creates the account only (the page then shows the tenant setup) and sends the verification link, answering `{ "email", "tenant": null, "emailVerified": false }`; with `"tenant"` (3–40 chars, `[a-z0-9-]`), `"name"`, `"company"`, `"role"`?, `"phone"`?, `"telegram"`? as well, the tenant is created in the same call, as before |
| `POST /api/onboard` | `{ "tenant", "name", "company", "role"?, "phone"?, "telegram"? }` | the same response as a one-call register; `409` when the account already has a tenant or the id is taken | `{ "tenant", "logId", "plan": "free", "token": "<64 hex, shown once>", "tokenHash": "<12 hex>", "welcome": "<the welcome sheet>", "setup": { "log", "logId", "checkpoints", "keys", "keyid", "env", "config", "verify", "audit", "export" } (the sheet as data; the page shows it as numbered steps, and again under Setup), "exportCommand": "…" }` and a session cookie; with mail configured, one email to the address with the sheet (never the key) and one to the operator with the contact details; `400` on validation, `409` if the email or tenant is taken, `429` after five registrations from one address |
| `POST /api/login` | `{ "email", "password" }` | `{ "email" }` and the cookie; `401` otherwise; throttled per address |
| `POST /api/logout` | `{}` | `{ "ok": true }` |
| `GET /api/me` | | `{ "email", "tenant", "logId", "plan", "used", "quota", "disabled", "billing": true\|false }`; before onboarding, `{ "email", "tenant": null, "profile", "billing" }`; both carry `"emailVerified"`, `"identities"` (the linked providers), `"providers"` (the ones offered), and `"mail"` (whether the portal can send) |
| `GET /api/overview` | | `{ "tenant", "logId", "plan", "used", "quota", "treeSize", "rootHash", "latestCheckpoint": { "treeSize", "signedAt" } \| null, "months": [{ "month": "2026-09", "appends": 37 }, …6], "keys": [{ "label", "hash", "createdAt", "revokedAt" }], "audit": [{ "id", "at", "actor", "action", "tenantId", "detail" }], "billing": { "status" } \| null, "urls": { "log", "keys", "checkpoints" }, "exportCommand", "welcome", "setup" (as on register), "stripe": true\|false }` |
| `GET /api/keys` | | `{ "keys": [...] }` |
| `POST /api/keys` | `{ "label" }` | `{ "token": "<shown once>", "tokenHash": "<12 hex>", "label" }` |
| `POST /api/keys/<hash prefix>/revoke` | `{}` | `{ "revoked": 1 }` |
| `GET /api/policies` | | `{ "policies": [{ "id", "name", "digest", "bytes", "createdAt", "createdBy" }] }`; with `?digest=<64 hex>`, `{ "match": <policy> \| null }`: the published version a receipt's `policyDigest` names |
| `POST /api/policies` | `{ "name", "text" }` (the Cedar file byte for byte as the gateway loads it) | `{ "policy": { "id", "name", "digest", … } }`; `409` when that exact text is already published, naming the version |
| `GET /api/policies/<id>` | | `{ "policy": { …, "text" } }` |
| `POST /api/policies/<id>/remove` | `{}` | `{ "removed": true\|false }`; receipts keep their digests, only the name goes |
| `POST /api/checkout` | `{}` | `{ "url": "https://checkout.stripe.com/…" }`; `409` if not on `free`; `503` when billing is not configured |
| `POST /api/billing-portal` | `{}` | `{ "url": "https://billing.stripe.com/…" }` |
| `POST /stripe/webhook` | Stripe's event, `Stripe-Signature` header | `{ "received": true }`; `400` on a bad or stale signature |
| `GET /health` | | `{ "ok": true, "stripe": true\|false }` |

Every write needs `Content-Type: application/json`; the cookie is `HttpOnly; SameSite=Strict`. Every action is in the tenant's audit trail as `portal:<email>`, and plan changes made by Stripe as `stripe:<event>`.

Two emails follow a registration when the operator has mail configured: the setup sheet at once, and about an hour later a personal note from the founder asking which stack the agents are on and offering to do the integration, sent once by an hourly job (`portal-followup`).

## Policies: names for the digests receipts carry

Enforcement is local: the gateway reads its Cedar file and writes the file's SHA-256 into every receipt as `policyDigest`. The portal's Policies page lets a tenant publish each version they deploy under a name, so a digest reads as "refunds-v3" here, in the match tool (paste a receipt or a digest), and in the export's `policies.json`. Nothing on this page is read by the gateway, and the hosted log never evaluates a policy. Every publish and removal is in the tenant's audit trail.

## Using a tenant

The welcome sheet has the three things a tenant needs; in the gateway or SDK config:

```json
"log": { "url": "https://log.agent-custody.dev/t/acme/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true }
```

Verifiers add `--log-url https://log.agent-custody.dev/ --log-id acme`, which fetches and pins the published keys and requires the tree heads to be this tenant's. The tenant's routes are the [log API](./log-api) under `/t/acme/`; `leaves`, `usage`, and `audit` there answer only to the tenant's token.

## Taking your data

```bash
npx @agent-custody/receipts log-export --log-url https://log.agent-custody.dev/ --tenant acme --token-env AGENT_CUSTODY_LOG_TOKEN --out custody-export/
```

Writes `log.jsonl` (every leaf hash, in the format `verify --log` and `audit --log` read offline), `head.json`, `keys.json`, `checkpoints.json`, `usage.json`, `audit.json`, and `export.json`, after checking that the head and every checkpoint verify against the published keys and that the leaves hash to their roots. Exit 1 and `RESULT: EXPORT DOES NOT ADD UP` if anything does not. Details under [verify](./verify#log-export).

## The operator's side

For whoever runs a log: `agent-custody log-admin --db-env DATABASE_URL tenant add|list|disable|plan`, `token add|list|revoke`, `audit`, `import`; the admin page at `/admin` (or on its own host, `ADMIN_HOST` in the deployment) behind the admin token with the same operations, the registrations list (who signed up through the portal, plan, billing state, appends this month, leaves in total, with totals and a CSV), usage per tenant per month, a CSV for invoicing, and the activity list. The [runbook](https://github.com/svayatta/agent-custody/blob/main/deploy/RUNBOOK.md) is the operating manual.

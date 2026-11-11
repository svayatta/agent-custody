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

The gateway's log client retries a 429 three times with backoff and then treats the append as failed. A pre-committed call and a financial operation are not forwarded: the call returns an error. Any other call is forwarded and returns its real result marked `log-pending`, and its receipt waits in the outbox until the log takes it. In strict mode every call is pre-committed. See [pricing](https://agent-custody.dev/pricing).

## Registering: the portal

`https://app.agent-custody.dev/` is one page. Registering creates the account, the tenant, and its first key, shown once. The page's own API, which any HTTP client may use with the session cookie it sets:

| route | body | response |
| --- | --- | --- |
| `GET /auth/github`, `GET /auth/google` | | a redirect to the provider with a signed state in a ten-minute cookie; the callback at `/auth/<provider>/callback` exchanges the code, takes the provider's verified email, links it to the account with that email if that account has verified its address (otherwise the sign-in is refused with a page saying to sign in with the password first), or creates one, sets the session, and shows a page that continues to `/`. With `?link=1` from a signed-in session it links the provider to that account instead, whatever email the provider gives. Offered only when the operator configured the provider |
| `GET /verify-email?token=` | | the link sent at registration: shows a page that posts the token to `POST /api/verify-email`. Opening the link verifies nothing by itself; without the account's own session the page asks the user to sign in with the password first |
| `POST /api/verify-email` | `{ token }` | needs a session whose user is the token's user (else 403); marks the address verified: `{ "ok": true, "emailVerified": true }`. A provider sign-in links to a password account only once this has happened |
| `GET /unsubscribe?token=` | | the link in the founder's note: a signed token, good for a year. It changes nothing, because a mail scanner opens a link before the person does. It shows a page with one form and a **Stop these emails** button; `400` for a token that is not valid |
| `POST /unsubscribe?token=` | | sets a flag on the account, and answers a page. The hourly job then sends no more automatic messages about getting started to that account. The form of the page posts here, and so does a mail provider's one-click request (RFC 8058: the `List-Unsubscribe` URL, the body `List-Unsubscribe=One-Click`, which the portal does not read). `400` for a token that is not valid. Messages about the account, such as the verification and invite emails, are not affected |
| `POST /api/verify-email/resend` | `{}` | sends the verification link again; `{ "ok": true, "emailVerified" }` |
| `POST /api/register` | `{ "email", "password" (10+ chars) }` creates the account only (the page then shows the tenant setup) and sends the verification link, answering `{ "email", "tenant": null, "emailVerified": false }`; with `"tenant"` (3–40 chars, `[a-z0-9-]`), `"name"`, `"company"`, `"role"`?, `"phone"`?, `"telegram"`? as well, the tenant is created in the same call, as before. The page no longer asks for `phone` and `telegram`; the API still accepts and stores them for older clients |
| `POST /api/onboard` | `{ "tenant", "name", "company", "role"?, "phone"?, "telegram"? }` | the same response as a one-call register; `409` when the account already has a tenant or the id is taken | `{ "tenant", "logId", "plan": "free", "token": "<64 hex, shown once>", "tokenHash": "<12 hex>", "welcome": "<the welcome sheet>", "setup": { "log", "logId", "checkpoints", "keys", "keyid", "env", "config", "verify", "audit", "export" } (the sheet as data; the page shows it as numbered steps, and again under Setup), "exportCommand": "…" }` and a session cookie; with mail configured, one email to the address with the sheet (never the key) and one to the operator with the contact details; `400` on validation, `409` if the email or tenant is taken, `429` after five registrations from one address |
| `POST /api/login` | `{ "email", "password" }` | `{ "email" }` and the cookie; `401` otherwise; throttled per address. When the account has [MFA](#two-step-sign-in) on: `{ "mfa": true }` and a five-minute `custody_mfa` cookie, and no session. Refused for a member of a tenant that enforces [single sign-on](#single-sign-on) |
| `POST /api/login/mfa` | `{ "code" }` | needs the `custody_mfa` cookie; `{ "email" }` and the session cookie; `401` for a wrong or used code; `429` after five tries for the account. A [recovery code](#two-step-sign-in) works once in place of the six-digit code |
| `POST /api/mfa/setup` | `{}` | `{ "secret": "<base32>", "uri": "otpauth://…", "qr": "<svg …>" }` (the `uri` as an inline SVG QR code, made by the portal); `409` when MFA is on already |
| `POST /api/mfa/enable` | `{ "code" }` | `{ "mfa": true, "recoveryCodes": ["xxxx-xxxx-xxxx", …10] }` once the code from the new secret is valid. The codes are shown this one time |
| `POST /api/mfa/disable` | `{ "code" }` | `{ "mfa": false }` with a current code or a recovery code |
| `POST /api/mfa/recovery` | `{ "code" }` | `{ "recoveryCodes": [ …10] }`: ten new codes that replace the old ones; needs a current code or a recovery code; `401` without one |
| `POST /api/password/forgot` | `{ "email" }` | `{ "ok": true }` for every address, with or without an account. With an account, the portal mails a link to `/reset-password?token=`. `400` for a malformed address, `429` after five requests from one client address, `503` when mail is not configured. After three requests for one email address in fifteen minutes, the answer stays the same and no mail goes |
| `GET /reset-password?token=` | | the link in the mail: a page with a field for the new password, which posts to `POST /api/password/reset` |
| `POST /api/password/reset` | `{ "token", "password" (10+ chars) }` | `{ "ok": true }` and no session: the user signs in with the new password, and two-step sign-in still applies. `400` for a short password (the token stays valid), or for a token that is unknown, used, or older than one hour; `403` for a member of a tenant that enforces single sign-on |
| `POST /api/password/change` | `{ "current", "password" (10+ chars) }` | needs a session; `{ "ok": true }` and a new session cookie for this browser. `401` for a wrong current password, `400` for a short new one, `409` in a tenant that enforces single sign-on, `429` after eight tries |
| `POST /api/logout` | `{}` | `{ "ok": true }` |
| `GET /api/me` | | `{ "email", "tenant", "role", "logId", "plan", "used", "quota", "disabled", "billing": true\|false }`; before onboarding, `{ "email", "tenant": null, "profile", "billing" }`; the second also carries `"invites"` (`[{ "tenant", "role" }]`); both carry `"emailVerified"`, `"identities"` (the linked providers), `"providers"` (the ones offered), `"mail"` (whether the portal can send), `"mfa"`, and `"recoveryCodes"` (the number of unused recovery codes) |
| `GET /api/members` | | `{ "members": [{ "id", "email", "role", "joinedAt", "mfa" }], "invites": [{ "email", "role", "invitedBy", "createdAt" }] }` |
| `POST /api/members` | `{ "email", "role" }` | invites the address and sends it the invite email, which has an **Accept the invite** button that opens the portal: `{ "invited", "role", "emailSent" }`. `emailSent` is `false` when mail is not configured or the provider refused the message; the invite stays saved, and the page tells the inviter to send the address to the person another way. The response never holds the provider's error text. `403` when a non-owner grants `owner` |
| `POST /api/members/<userId>/role` | `{ "role" }` | `{ "role" }`; `403` when a non-owner touches an owner; `409` for the last owner |
| `POST /api/members/<userId>/remove` | `{}` | `{ "removed": true }`; `403` when a non-owner removes an owner; `409` for the last owner |
| `POST /api/invites/remove` | `{ "email" }` | `{ "removed": true\|false }` |
| `POST /api/invites/accept` | `{ "tenant" }` | for an account with no tenant and a verified address: `{ "tenant", "role" }`; `403` for an unverified address, `404` for no invite or one older than seven days, `409` when the account has a tenant already |
| `GET /api/overview` | | `{ "tenant", "logId", "plan", "used", "quota", "treeSize", "rootHash", "latestCheckpoint": { "treeSize", "signedAt" } \| null, "months": [{ "month": "2026-09", "appends": 37 }, …6], "keys": [{ "label", "hash", "createdAt", "revokedAt", "lastUsedAt" }], "audit": [{ "id", "at", "actor", "action", "tenantId", "detail" }] (the newest 50), "billing": { "status" } \| null, "urls": { "log", "keys", "checkpoints" }, "exportCommand", "welcome", "setup" (as on register), "stripe": true\|false }` |
| `GET /api/audit?limit=&before=` | | the tenant's audit trail, newest first: `{ "entries": [{ "id", "at", "actor", "action", "tenantId", "detail" }], "next": <id> \| null }`. `limit` is 1 to 100 (25 if not given). To get the next page, send `next` as `before`. `400` on a bad `limit` or `before` |
| `GET /api/keys` | | `{ "keys": [{ "label", "hash", "createdAt", "revokedAt", "lastUsedAt" }] }`. `lastUsedAt` is the time of the last append with the key, correct to about one minute, or `null` when the key has no recorded use |
| `POST /api/keys` | `{ "label" }` | `{ "token": "<shown once>", "tokenHash": "<12 hex>", "label" }` |
| `POST /api/keys/<hash prefix>/revoke` | `{}` | `{ "revoked": 1 }` |
| `GET /api/policies` | | `{ "policies": [{ "id", "name", "digest", "bytes", "createdAt", "createdBy" }] }`; with `?digest=<64 hex>`, `{ "match": <policy> \| null }`: the published version a receipt's `policyDigest` names |
| `POST /api/policies` | `{ "name", "text" }` (the Cedar file byte for byte as the gateway loads it) | `{ "policy": { "id", "name", "digest", … } }`; `409` when that exact text is already published, naming the version |
| `GET /api/policies/<id>` | | `{ "policy": { …, "text" } }` |
| `POST /api/policies/<id>/remove` | `{}` | `{ "removed": true\|false }`; receipts keep their digests, only the name goes |
| `POST /api/checkout` | `{}` | `{ "url": "https://checkout.stripe.com/…" }`; `409` if not on `free`; `503` when billing is not configured |
| `POST /api/billing-portal` | `{}` | `{ "url": "https://billing.stripe.com/…" }` |
| `POST /stripe/webhook` | Stripe's event, `Stripe-Signature` header | `{ "received": true }`; `{ "received": true, "duplicate": true }` for an event id applied already; `400` on a bad or stale signature, or an event without `id` and `created`. An event whose `created` is older than the event that set the stored billing state is acknowledged and not applied |
| `GET /health` | | `{ "ok": true, "stripe": true\|false }` |

Every write needs `Content-Type: application/json`; the cookie is `HttpOnly; SameSite=Strict`. A body over 64 KB is answered `413`, a write without the JSON content type or with a body that does not parse `400`, and any other failure a plain `500 { "error": "internal error" }`, with the detail in the portal's log. Every action is in the tenant's audit trail as `portal:<email>`, and plan changes made by Stripe as `stripe:<event>`.

### Roles

Every member of a tenant has one role. A role includes the roles above it in this table.

| role | may |
| --- | --- |
| `readonly` | every `GET`, and the routes of the member's own account: `/api/password/change`, `/api/mfa/setup`, `/api/mfa/enable`, `/api/mfa/disable`, and `/api/mfa/recovery` |
| `reviewer` | also publish and remove policy versions |
| `admin` | also mint and revoke API keys, invite, cancel invites, change a member's role, and remove a member, but never touch an owner and never grant `owner` |
| `owner` | everything, billing included |

A write route that is not in this table needs `admin`. The last owner of a tenant cannot be removed or demoted. An invite lasts seven days. An account belongs to one tenant. A removed member loses access at once, also in a tenant with single sign-on. The members page of the portal shows the same operations. It names each role with a label (Read-only, Reviewer, Admin, Owner) and a description; the stored and API values stay as in the table. Remove, Revoke, Cancel invite, and a role change ask for confirmation in a dialog that names the member or key. The last owner row shows no Change or Remove action.

### Portal navigation

The sidebar has three groups. Monitor holds Overview, Usage, and Activity. Log holds Setup, API keys, Policies, and Export. Organisation holds Members and Billing. The top bar shows the logo, the tenant (quiet text after a thin separator), the plan (a pill), and three quiet links to the guide, the docs, and the receipt verifier. The Account button at the right shows an avatar with the first letter of the address. On a wide screen it also shows the address and a chevron. Its accessible name is "Account menu for" followed by the address. The Account menu is one list of rows: a header with the address, the tenant, and the role; Security (two-step sign-in); the theme control, which shows On or Off; and Sign out. On a narrow screen the sidebar is a drawer that the menu button opens. The drawer ends with a Help group that holds the three links, so the top bar is one row: the menu button, the logo, and the avatar. The Account menu header then also shows the plan. The sign-in, onboarding, and welcome screens show no avatar, and the Account button there holds only the theme control.

The address bar names the view: `/#policies` opens Policies after sign-in, and the Back and Forward buttons of the browser change the view. An unknown name opens Overview.

### Two-step sign-in

An account can turn on MFA with a time-based one-time password (TOTP, RFC 6238: 6 digits, 30-second step) from any authenticator app. Setup is `POST /api/mfa/setup`, then `POST /api/mfa/enable` with the first code. After that, a password, GitHub, or Google sign-in ends with a code step, `POST /api/login/mfa`. The `custody_mfa` cookie that the first step sets lasts five minutes and is never a session. A code works once. Wrong codes are throttled per address and per account. The setup shows the secret as a QR code, which the portal draws itself (no outside request), and as text. Turning MFA on gives ten recovery codes, shown one time. The portal keeps only their SHA-256 hashes. Each recovery code works one time in place of a code, at sign-in and to turn MFA off, and counts against the same limit as a code. `POST /api/mfa/recovery` with a current code replaces all ten. An operator turns MFA off for an account that lost its authenticator and its recovery codes with `log-admin user mfa-reset <email>` (see [the operator's side](#the-operators-side)). That also deletes the recovery codes.

### Password reset and password change

A user who forgot the password asks for a link on the sign-in page (`POST /api/password/forgot`). The page shows the "Forgot password?" link only when the portal can send mail. The answer is the same for every address, and the portal looks up the address after it answers, so neither the answer nor its time tells whether an account exists. Requests are limited per client address and per email address. The token in the link is 256 random bits, works one time, and expires after one hour. The portal stores only its SHA-256 hash.

A reset sets the new password and ends every session and every half-signed-in `custody_mfa` cookie of the account. It does not sign the user in. The user signs in with the new password, and two-step sign-in still applies. A reset proves control of the mailbox. If the address was not verified, the reset marks it verified and removes each GitHub or Google identity linked to the account, because whoever held the old password linked it before anyone proved the address. This keeps the rule that a provider sign-in links only to a verified address.

An account that a GitHub, Google, or single sign-on sign-in created has a random password that nobody knows. A reset sets its first password, because the mailbox owner already controls the account through the provider. A member of a tenant that enforces single sign-on gets no reset mail, a reset link is refused (`403`), and a change is refused (`409`), so enforcement has no password back door.

A signed-in user changes the password on the Account page with the current password (`POST /api/password/change`). The change ends every other session of the account and keeps the session of the browser that made it.

Sessions carry the time they were signed. Each account has a "sessions valid after" time, which a reset or a change moves to now. A session or a `custody_mfa` cookie signed before that time is refused.

### Single sign-on

An enterprise tenant can sign in through its own identity provider (IdP). Only the operator sets it up, with `log-admin sso set`. A tenant has OIDC (authorization code with PKCE) or SAML 2.0. A domain belongs to one tenant.

| route | response |
| --- | --- |
| `GET /auth/sso?email=` | finds the tenant that owns the domain of the address and starts its sign-in |
| `GET /auth/sso/<tenant>` | starts the sign-in at the tenant's IdP |
| `GET /auth/sso/<tenant>/callback` | OIDC: exchanges the code, checks the `id_token` signature against the IdP's JWKS (RS256 or ES256 only), the issuer, the audience, the nonce, and the expiry, then signs the user in |
| `GET /auth/sso/<tenant>/saml` | the service provider metadata to give to the IdP |
| `POST /auth/sso/<tenant>/saml/acs` | SAML: reads only the signed assertion, whose bearer `SubjectConfirmationData` must answer the request id in the cookie, then signs the user in |

A sign-in creates the account or links it, and joins it to the tenant with the tenant's default role. The email domain must be one of the tenant's. The IdP proves the address, so a password account that never verified it loses the address: the sign-in deletes that account with its password, sessions, memberships, and linked providers, and a tenant that it created stays for the operator. Registering an address first, with or without a tenant, or linking a provider to it, never blocks the person at the IdP. There are two exceptions. An unverified member of the same tenant signs in with the password and verifies the address first. An unverified member of another tenant that has other members is refused (`403`), so that tenant keeps its members. A removal applies to the email address. A member that an admin removed from the tenant does not rejoin through the IdP on its own, also when the address was never verified. A new account with that address, or a later holder of the same address, is refused too. An admin must invite the address again, and the person then joins with the invited role. A rejoin by invite does not clear the removal record. The record has no effect while the person is a member: only the single sign-on sign-in reads it, and only when the person's home tenant is another tenant. The portal skips its own MFA, because the IdP owns it. SAML needs the optional package `@node-saml/node-saml` beside the CLI.

With `--enforce`, members of the tenant cannot sign in with a password, GitHub, or Google. The sessions that members had before end. Invites are refused, because members join through the IdP. An owner whose address is not verified cannot sign in then, so each owner must verify the address or sign in through the IdP before you turn enforcement on.

Two emails follow a registration when the operator has mail configured: the setup sheet at once, and about an hour later a personal note asking which stack the agents are on and offering to do the integration, sent once by an hourly job (`portal-followup`). The note carries an opt-out link and a `List-Unsubscribe` header. The signer is a setting (`--signer` and `--signer-role`; the default is "The agent-custody team"). With a signer, the note is in the first person (for example "I am Ada, the founder"); without one, it says "we". Every email the portal sends has an HTML part and a plain-text part that hold the same words: the logo (a PNG that the public site serves), the product name as text, one button for the one action, and the same link as plain text below it. `--mail-reply-to` (`MAIL_REPLY_TO`) sets the address that a reply goes to.

## Policies: names for the digests receipts carry

Enforcement is local: the gateway reads its Cedar file and writes the file's SHA-256 into every receipt as `policyDigest`. The portal's Policies page lets a tenant publish each version they deploy under a name, so a digest reads as "refunds-v3" here, in the match tool (paste a receipt or a digest), and in the export's `policies.json`. Nothing on this page is read by the gateway, and the hosted log never evaluates a policy. Every publish and removal is in the tenant's audit trail.

The portal's Activity page shows the audit trail as sentences, such as "You created the key 'first key'", in the reader's time zone, with the UTC time on hover. The Billing page shows the three plans of the [pricing page](https://agent-custody.dev/pricing), and a test keeps their names, prices, and limits equal to that page and to the server's plan limits.

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

For whoever runs a log: `agent-custody log-admin --db-env DATABASE_URL tenant add|list|disable|plan`, `token add|list|revoke`, `audit`, `import`, `user mfa-reset <email>`, `sso set|show|remove`; the admin page at `/admin` (or on its own host, `ADMIN_HOST` in the deployment) behind the admin token with the same operations, the registrations list (who signed up through the portal, plan, billing state, appends this month, leaves in total, with totals and a CSV), usage per tenant per month, a CSV for invoicing, and the activity list. The [runbook](https://github.com/svayatta/agent-custody/blob/main/deploy/RUNBOOK.md) is the operating manual.

Single sign-on for a tenant, set by the operator only:

```bash
agent-custody log-admin --db-env DATABASE_URL sso set acme --oidc-issuer https://idp.example.com --oidc-client-id <id> --oidc-secret-env ACME_OIDC_SECRET --domains acme.com,acme.io --default-role readonly --enforce
agent-custody log-admin --db-env DATABASE_URL sso set acme --saml-entry-point https://idp.example.com/sso --saml-cert idp.pem --saml-idp-issuer <id> --domains acme.com
agent-custody log-admin --db-env DATABASE_URL sso show acme
agent-custody log-admin --db-env DATABASE_URL sso remove acme
```

`sso set` reads the client secret from the named environment variable at that moment and stores it in the portal's table. `--default-role` is the role of a new member (`readonly` if unset, never `owner`). `sso set` replaces the whole setting, so give every flag each time. `--enforce` turns on the rules in [Single sign-on](#single-sign-on). The redirect URI to register at the IdP is `https://<PORTAL_HOST>/auth/sso/<tenant>/callback`. `user mfa-reset <email>` turns MFA off for one portal account; it prints an error when the address has no account. `sso set`, `sso remove`, and `user mfa-reset` write an entry in the audit trail (`sso.set`, `sso.remove`, `user.mfa-reset`) with the actor `cli:<user>@<host>`; the entry never holds a secret. `tenancy.audit()` and `log-admin audit` list it.

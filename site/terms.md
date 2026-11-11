---
sidebar: false
aside: false
---

# Terms of service

Version 0.2, 2026-09-26. These are the terms on which Charioteer Consulting Ltd ("we") gives early-access tenants ("you") the use of the hosted log at log.agent-custody.dev. They are written in plain language and have not yet been reviewed by counsel; a tenant who needs a signed agreement gets one, and where the two differ the signed one wins. The packages themselves are Apache-2.0 and these terms do not touch them.

## What you get

1. A tenant on the hosted log: a log id, one or more access tokens, appends at your tenant's path, signed tree heads, published checkpoints, and the endpoints the verifier and the audit command use.
2. Your data back at any time, with your own token, through the export command, in a form the verifier reads with no server.
3. Our answer within two working days to any question about the service, and the written record of any incident that affected your log.

## What we ask

1. Send leaf hashes only. The service is designed for `hashOnly`; a tenant who sends whole receipts has chosen to place their contents with us, and we will disable that tenant's tokens and say why.
2. Keep your tokens to yourselves and tell us when one may have leaked; we revoke it and mint another.
3. Use the service for logging your own agents' receipts, within the rate limits, and not to probe or load other tenants' paths.
4. Pay for what you use. The Free plan is ten thousand appends a calendar month at no charge. The Team plan is $50 a month, billed monthly in advance by card through Stripe, for a million appends a month; it renews until you cancel from the billing page, and a cancellation takes effect at the end of the paid month, after which the tenant is on Free and the log is untouched. A month already paid is not refunded, except where the service was unavailable for most of it, in which case we credit it. Enterprise is invoiced under a signed agreement. Prices may change with thirty days' notice by email; a change never applies to a month already paid.

## What we do not promise

1. **Availability.** One machine, no failover, no service level yet. The design fails closed: when the log is unreachable your gateway withholds pre-committed calls rather than acting without evidence. That is a denial of service on your agents, and it is the intended behaviour.
2. **A witness.** We are not one and cannot be; a second, independent operator is being sought. Until then a verifier who requires a witness signature will not find one.
3. **Certification.** No SOC 2, ISO 27001, or penetration test yet. The [security questionnaire](/security) says exactly what is and is not in place.

## Data

The [privacy page](/privacy) says what we hold and where. Your log's leaves are yours; we keep them for the life of your tenant, disable rather than delete on offboarding so your receipts keep verifying, and delete entirely on your written request, which is irreversible.

## Ending it

Either side can end early access with thirty days' notice by email. We disable your tenant on the day it ends and keep your log readable for ninety days so you can export it, unless you ask for deletion sooner.

## Liability

Early access is provided as is. To the extent the law allows, our liability to you under these terms is limited to the amount you have paid for the service, which during early access is nothing. Nothing here limits liability that cannot be limited by law.

## Law

These terms are governed by the law of England and Wales.

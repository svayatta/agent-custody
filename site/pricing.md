---
title: Pricing
sidebar: false
aside: false
pageClass: wide
---

# Pricing

Everything you run yourself, the gateway, the SDK, the ledger, the verifier, is open source under Apache-2.0 and free. What is priced is the [hosted log](/hosted-log), a log run by someone who is not you, so a stranger can accept your receipts. It counts appends, one per receipt, per calendar month.

<PricingPlans />

## Compare the plans

Every plan includes export of everything at any time, every action on your tenant in the audit trail, and as many API keys as you need. The rows below are the ones that differ.

| | Free | Team | Enterprise |
| --- | --- | --- | --- |
| **Price** | $0 | $50 a month | by conversation |
| **Appends a month** | 10,000 | 1,000,000 | no allowance |
| **Tenants** | one | one | as many as you need |
| **Dedicated log, your own signing key, your region** | — | — | ✓ |
| **API keys managed by your own operators** | — | — | ✓ |
| **Email support within two working days** | — | ✓ | ✓ |
| **Named contact, stated response time** | — | — | ✓ |
| **Signed agreement and data processing agreement** | — | — | ✓ |
| **Witness** | none yet | none yet | run your own, or we help you find an operator |

✓ included, — not included. All plans are on the [terms of service](/terms).

## How appends add up

One append per receipt, one receipt per tool call, allowed or denied. A call to a tool in `precommit`, or a financial operation, uses two: the signed authorization before the call and the receipt after it.

For example, ten support agents, each doing 40 tasks a day with 6 tool calls per task, five days a week, make about 50,000 appends a month: past the Free allowance, well inside Team. A coding agent under the Claude Code hook, at 300 tool calls a working day, makes about 6,500 and stays on Free. The [dashboard](https://app.agent-custody.dev/) shows your appends against the allowance by month.

## At the allowance

An append past the month's allowance is refused with a clear message and the date it resets. The gateway withholds pre-committed calls and financial operations until then, and keeps the receipts of ordinary calls in its outbox until the log takes them. Upgrade from the Billing page and the next append lands. Nothing already logged is affected.

## Paying

Team is billed monthly by card through Stripe, from the dashboard, and cancelled there too. The plan drops to Free at the end of the paid period, and your log stays where it was. We never see the card. Enterprise is invoiced.

No plan carries an availability commitment yet: [status and limits](/status) says what that means and what is being done about it.

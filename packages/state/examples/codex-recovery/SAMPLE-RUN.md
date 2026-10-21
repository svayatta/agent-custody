# Recorded live run: 19 October 2026

This result came from a real `codex exec` run with codex-cli 0.163.0 and the existing ChatGPT login. The runner supplied a customer request, the business policy, and the gateway's MCP tools. It did not make the support calls on the model's behalf.

## What Codex actually did

The gateway recorded five calls, in this order:

| Call | Observed result |
| --- | --- |
| `memory.read` | The account's imported plan was `enterprise` |
| `billing.account` | No existing incident credit |
| `memory.write` | `discount_percent = 20` |
| `memory.write` | `support_tier = priority` |
| `billing.credit` | One simulated GBP 25 credit for INC-42 |

Codex's final answer:

> Alex, your recorded plan is Enterprise. I recorded your 20% discount and priority support benefits. After confirming no existing credit, I applied a simulated £25 service credit for INC-42.

The agent followed its supplied business policy using an incorrect source belief. This was not an invented arithmetic mistake or a scripted model response.

## Correction and review

The operator introduced the CRM sync correction, retired the support grant, retracted `plan = enterprise`, and recorded `plan = free`. The analysis verified the existing receipts, then proposed the following plan. This block summarizes the plan's contents; it is not the literal program output.

```text
retract: discount_percent = 20
retract: support_tier = priority
write:   discount_percent = 0
write:   support_tier = standard
reverse: the simulated 2500-pence credit
```

Both writes and the credit were made after the session had been shown the wrong fact. That is evidence of possible dependency; it does not establish the model's reasoning or causation. The operator reviewed the concrete actions and ran the recovery command with the plan's digest.

## Verified outcome

This block summarizes the fields of the verified report and the final line; it is not the literal program output.

```text
ok: true
receiptsVerified: 13
current:
  plan = free
  discount_percent = 0
  support_tier = standard
billing:
  original credit amount = 2500 pence
  original credit status = reversed
  original and reversal receipt IDs preserved
agentCalls: 5
exposed: true

OK: recovery complete; evidence verified.
```

The 13 receipts cover one initial CRM-memory import, five Codex calls, two operator correction calls, and five recovery calls. Billing calls have authorizations committed before forwarding, and memory and billing results carry upstream signatures. Verification also compares the mutable ledger and billing files with their signed tool results.

This demonstrates traceable recovery in the local simulated service. It does not establish that every real financial action can be undone, that a verified belief is true, or that the model will choose the same calls on another run. The generated evidence stays under the gitignored `examples-out/` directory; this document records the observed result rather than checking private demo keys into Git.

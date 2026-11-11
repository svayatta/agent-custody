---
title: Status and limits
description: "What runs today, what is not in place yet, and where to check the hosted log's state: availability, the witness, the chain anchor, certifications, and the terms."
---

# Status and limits

What agent-custody does not do yet, in one place, so no page has to say it in passing. Each line says what is missing, what that means for you, and where the work stands.

**Live status.** A probe on machines that are not ours verifies the hosted log every ten minutes: the [monitor workflow](https://github.com/svayatta/agent-custody/actions/workflows/monitor.yml). Its badge is the status page.

| | today | what it means for you |
| --- | --- | --- |
| **Availability** | One machine, no failover, no service level on any plan. | When the log cannot be reached, a gateway withholds pre-committed calls rather than acting without evidence: the design fails closed, so an outage stops those calls. |
| **Independent witness** | The witness software exists; no independent operator runs it for the hosted log yet. | A verifier who requires a witness signature does not find one. Run your own witness ([deploy/witness](https://github.com/svayatta/agent-custody/tree/main/deploy/witness)), or ask us about an operator. |
| **Chain anchor** | Anchoring works; it does not run on mainnet for the hosted log yet. | Rewriting the log is caught by checkpoints and a witness, not by a public chain ([anchoring](/receipts/anchoring)). |
| **Certifications** | No SOC 2, no ISO 27001, no penetration test yet. | The [security questionnaire](/security) says exactly what is and is not in place. |
| **Terms** | Written in plain language; not yet reviewed by counsel. | A tenant who needs a signed agreement gets one, and it wins where the two differ ([terms](/terms)). |

What a receipt proves, and against whom, is a separate question: [how verification works](/receipts/verification) and the [threat model](/receipts/threat-model) answer it.

---
title: Logs are claims. Receipts are evidence.
description: Why an agent's audit trail cannot be the agent's own log, and what a record has to carry before a stranger can rely on it.
---

# Logs are claims. Receipts are evidence.

*Partha, 6 October 2026*

When an AI agent does something wrong, the first question is what it did. The second is who said it could. Today both are answered from the same place: the log the agent's own process wrote. The process that made the mistake is also the author of the record of it, and the team that ran the agent holds the file. Read that log and you are trusting its author, which is exactly the party under question.

This is not a complaint about logging. Logs are how you debug. It is a statement about what a log can prove to someone outside the team: nothing. An auditor, a customer, or a regulator who is handed an agent's trace is handed a claim.

## What a record needs before it is evidence

Four things, and each one has to be true of the same record.

**Made outside the agent.** The decision to allow or deny a call has to be taken by a process the agent does not control, on facts that process fetched itself. If the agent supplies the facts, the agent supplies the verdict.

**Authorized by a person, visibly.** Somewhere a human scoped what this agent may do, for how long. That scope must be in the record, signed by the human's key, not referenced by a ticket number in another system.

**Honest about what it knows.** A record that says "amount: 50000" should say whether the value was attested by a signature, observed by the gateway, or merely claimed by the agent. Most audit formats sign the whole blob and let you assume the best.

**Impossible to rewrite quietly.** The record's hash has to live somewhere the operator cannot edit alone: a Merkle log whose heads are signed by a key the operator does not hold, with checkpoints published where a third party can keep a copy.

Strip any one of these and you are back to a claim with a signature on it.

## What that looks like in practice

agent-custody puts a gateway between the agent and its tools. Every call is checked against a grant a person signed and a policy evaluated on facts the gateway fetched, then forwarded or denied, and a signed receipt is issued either way. The receipt labels every field attested, observed, or claimed. Its hash goes to a transparency log whose signed heads are published on a second host. Anyone with the public keys verifies a receipt offline, in a browser, with no account.

The home page shows one: a £50,000 refund the policy refused before it reached the payment provider. Open it in the verifier and read what each check proves. The receipt format is published with 29 conformance vectors, so a second implementation is held to the same standard.

## The honest limit

Not every receipt is evidence of the same strength. A receipt issued by an SDK inside the agent's own process is tamper-evident after the fact, but the agent could have lied to the SDK, and the verifier's report says so in plain words. For a stranger to accept the record, the decision has to be made outside the agent. That is the gateway, and it is the thing worth paying for.

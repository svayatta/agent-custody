---
title: Hosted log
description: "A transparency log run by someone who is not you, so a stranger can accept your receipts: what a tenant gets, what it does not get yet, and how to sign up."
---

# Hosted log

Everything else on this site runs on your own machines. The one thing you cannot run yourself is a log that is not yours: a transparency log operated by someone who is not the agent's operator, whose key signs the tree heads, so an auditor, a customer, or a regulator can accept a receipt without trusting you.

<p><a class="btn" href="https://app.agent-custody.dev/#register">Sign up</a></p>

That log is running at `log.agent-custody.dev` ([status](https://github.com/svayatta/agent-custody/actions/workflows/monitor.yml): a probe from machines that are not ours verifies it every ten minutes). It holds no receipts, only their hashes, and its keys are published at [/.well-known/agent-custody-log.json](https://log.agent-custody.dev/.well-known/agent-custody-log.json) for verifiers to pin.

**What a tenant gets:** a log of its own at `/t/<tenant>/`, an API key per fleet, a log id its tree heads carry, a welcome sheet with the one config line and the two verifier commands, and a dashboard showing appends against the plan, API keys, the latest checkpoint, and every action taken on the tenant.

**What a tenant does not get yet:** a second, independent signer (the witness), and an availability commitment. [Status and limits](/status) lists each, with what is being done about it.

The plans and what each costs are on [pricing](/pricing). Prefer to run it yourself? The same server is a [container, a compose file, and Kubernetes manifests](https://github.com/svayatta/agent-custody/tree/main/deploy), and everything the hosted one does, yours does too.

Everything else, the gateway, the SDK, the ledger, the verifier, stays open source under Apache-2.0 and needs no account. [Get started](/guide/getting-started) with that today.

For your security team: the [security questionnaire](/security), the [threat model](/receipts/threat-model), and the [compliance mapping](/receipts/compliance).

---
title: How it works
description: "How agent-custody records a call: the hook and the gateway, the film, the refund demo, the flow from grant to receipt, the policies, how receipts compare with logs, and the frameworks it covers."
---

<script setup>
import Demo from './.vitepress/theme/Demo.vue'
</script>

# How it works

The front page covers one job: stop a coding agent such as Claude Code from running destructive commands, and keep a signed record that a reviewer can check. This page shows how the rest works: the gateway, grants and policy, and what a receipt proves that a log does not. Each section links to the page that covers it in full.

## The two ways to record a call

The Claude Code hook runs in the agent's own process. It can deny a call that the agent makes through its tools, and it writes a receipt. The receipt is the agent's own report: every field is `claimed`.

The gateway is a separate process between the agent and its tools. It checks a grant that a person signed, evaluates a policy on facts that it fetches itself, forwards or denies the call, and issues a signed receipt either way. The agent cannot skip it for the tools behind it. A credential in the agent's own environment still goes around it: [credential custody and egress lockdown](/guide/credential-custody) take that route away, and under lockdown the egress witness receipts each connection the agent makes around the gateway, by destination and byte count, never by content. The [threat model](/receipts/threat-model) lists what each part defends.

- [Components](/guide/pieces): each component, the failure it prevents, and when you need it.
- [Getting started](/guide/getting-started): the SDK path and the gateway path.
- [The gateway](/receipts/usage) and [configuring the gateway](/receipts/configuration).
- [Architecture](/guide/architecture) and [deployment](/guide/deployment).

## Product overview film

A 30-second narrated film with captions. Priya, an AML lead, tells the story. The AML alert and the policy in the film are illustrative.

<video controls playsinline preload="none" poster="/promo-poster.jpg" width="1080" height="1080" style="display: block; width: 100%; max-width: 640px; height: auto; aspect-ratio: 1 / 1; margin: 0 auto; border-radius: 12px;" aria-label="A 30-second narrated film: an AI agent clears an AML alert and its own log can be edited. Replayed through agent-custody, the same call is denied, the refusal is signed, and an auditor verifies it offline.">
  <source src="/promo.mp4" type="video/mp4" />
  <track kind="captions" src="/promo.vtt" srclang="en" label="English" />
</video>

| time | chapter | what it shows |
| --- | --- | --- |
| 0:00 | Tuesday | An AI agent clears an AML alert. The auditor asks why. |
| 0:06 | The log | The only record is the agent's own log, and anyone can edit it. |
| 0:12 | Tuesday, replayed | The policy checks the same call before it runs. The call is denied, and the refusal is signed and logged. |
| 0:19 | The audit | The auditor verifies the receipt offline, with public keys. A changed word makes the check fail. |
| 0:25 | The close | "Now I don't explain what our agents did. I prove it." |

## The problem

The record of an agent's actions is the log that its own process wrote. Nobody outside the team can check it.

- **Made-up authority.** The agent refunds £50,000. Its log says the customer asked. Nobody signed anything that allowed it.
- **A log that can be edited.** The team that ran the agent holds the log. After the incident, the entry that matters is gone or different.
- **Evidence nobody else can check.** Traces sit in a vendor account. The auditor gets a screenshot and a promise.

## The refund demo

`bun run demo` runs a support agent against a test Stripe server. Each call writes a signed receipt to your disk. Then the demo verifies the receipts and edits one.

```bash
git clone https://github.com/svayatta/agent-custody && cd agent-custody && bun install && bun run demo
```

It needs Node 22 and Bun. It runs four calls through the gateway, three refunds and a payout, and verifies each receipt.

<Demo />

## How it works

Every call through the gateway goes through the same five steps.

1. **Authorize.** A person signs a grant: which agent, which tools, for how long.
2. **Gate.** The gateway fetches the facts itself, evaluates the policy, and forwards or denies.
3. **Record.** One signed receipt per call: who authorized it, what was asked, what was checked, what happened.
4. **Log.** The receipt's hash goes to a Merkle log with signed heads. A rewrite is detectable by anyone who kept a checkpoint.
5. **Verify.** Anyone with the public keys checks a receipt, in the shell or the browser, offline.

<Flow />

## Policies

Policies are written in Cedar and evaluated on facts that the gateway fetches itself. Each receipt records the policy digest. Nine more policies, each run by the test suite, are in [Writing policies](/receipts/policies).

**Limits.** A ceiling per call, in minor units. No floats, no rounding.

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 100000 };
```

**Facts, not claims.** The gateway looks the customer up itself before it decides. The agent's own arguments are never enough.

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when { context.facts.customer.verified
    && context.args.customer_id == context.facts.customer.id };
```

**Allowed targets.** A short list of accounts, hosts, and paths. Anything else is refused before it leaves.

```cedar
permit(principal, action == Action::"payout.send", resource)
when { ["acct_treasury", "acct_payroll"].contains(context.args.to) };
```

**Human approval.** A larger change needs a person that the gateway can see approved it, in the system of record.

```cedar
permit(principal, action == Action::"pr.merge", resource)
when { context.facts.checks.all_green
    && context.facts.reviews.human_count >= 1 };
```

**Boundaries.** Where an agent may write, and what it must say when it does.

```cedar
permit(principal, action == Action::"kb.write", resource)
when { context.args.path like "notes/*"
    && context.args has source };
```

**Evidence before effect.** Name a tool as consequential, and the authorization is logged before the call is forwarded. If the log refuses, nothing happens.

```json
"precommit": ["stripe.refund", "pr.merge", "deploy.promote"]
```

## Receipts compared with logs and traces

Receipts export to OpenTelemetry and Splunk, so you keep your current tools. The exports are in [the SDK reference](/reference/sdk-typescript) and [the gateway reference](/reference/gateway). Tutorials 18 and 19 run them.

| | Application log | Trace | Gateway receipt |
| --- | --- | --- | --- |
| Written by | the agent's process | the agent's process | a gateway, with its own key |
| Allowed or denied before the tool ran | no | no | yes, and a denial is a receipt |
| Who authorized it | not recorded | not recorded | the grant a person signed |
| A rewrite is detectable | no | no | yes, by anyone who kept a checkpoint |
| Who can check it | log access holders | the tracing account | anyone with the public keys |

Measured on a laptop (lower is better):

| what | median |
| --- | --- |
| a policy decision | 0.04 ms |
| a full gateway call | 0.7 ms |
| verifying a receipt | 0.15 ms |
| a receipt (the log gets 32 bytes) | 5.7 KB |

Medians, Apple M5, macOS, Node 22, 9 November 2026, from [scripts/bench.ts](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/scripts/bench.ts). You can run it. [What a receipt costs](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/docs/performance.md) times each step.

## Use cases

Each use case has a runnable example, or says that it has none.

- **Payments and refunds.** A refund within a limit, for a customer that the gateway verified. [The refund demo](#the-refund-demo), and [example 17: a REST upstream](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/17-rest-upstream.ts).
- **Agents that write code.** Risk-tiered merges, and change-management evidence for SOC 2 and ISO 27001. [Risk-tiered merges, with evidence](/blog/risk-tiered-merges-with-evidence), and [example 24: the merge gate](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts).
- **Knowledge bases.** Read anything, and write just under `notes/`, with a source. [A 22-second film](/demo-langchain-kb.mp4), and [example 23: LangChain](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts).
- **Your own repository.** Every Claude Code shell command, file edit, and MCP tool call as a receipt. [This repository](/custody), and [the hook](/reference/claude-code).

More, by kind of team, each with its policy: [Use cases](/use-cases).

## Other frameworks and languages

The Claude Code hook has the same input and output as the Claude Agent SDK, so one handler serves both. These frameworks have an adapter:

| framework | how | where |
| --- | --- | --- |
| Any MCP host | the gateway as an MCP server | [The gateway](/receipts/usage) |
| OpenAI Agents SDK | `wrapTools` | [Getting started](/guide/getting-started) |
| LangChain, LangGraph | `issuer.wrap` and a callback handler | [Getting started](/guide/getting-started) |
| Vercel AI SDK | `wrapTools` | [Getting started](/guide/getting-started) |
| Google ADK | tool callbacks | [Getting started](/guide/getting-started) |
| OpenClaw | the `before_tool_call` hook | [The SDK page](/receipts/sdk) |
| DeepSeek Harness, Hermes, CrewAI | a plugin or an adapter | [The SDK page](/receipts/sdk), [the Python client](/python/) |
| Python | the Python client of the sidecar | [The Python client](/python/) |
| Go, Java, Rust | the HTTP sidecar | [The sidecar](/receipts/sdk#other-languages-the-sidecar), [the client examples](https://github.com/svayatta/agent-custody/tree/main/packages/receipts/examples/languages) |

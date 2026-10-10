# Tutorials

One runnable example per aspect of the code. Each prints what it is doing, step by step, and ends with `OK`. The test suite runs all of them, so what you read here is what the code does today.

```bash
node examples/01-keys-and-signing.ts
```

Suggested reading order is the numbering. Output lands in `examples-out/`, which is gitignored.

| # | aspect | file | you will see | source |
| --- | --- | --- | --- | --- |
| 01 | identities and signatures | [01-keys-and-signing.ts](../examples/01-keys-and-signing.ts) | key generation, keyids, a DSSE envelope, verification with the public key, a tampered payload rejected | `src/crypto.ts` |
| 02 | delegated authority | [02-delegation-grant.ts](../examples/02-delegation-grant.ts) | a principal signs a grant, a stranger's key is rejected, validity windows, scopes | `src/delegation.ts` |
| 03 | policies | [03-policies.ts](../examples/03-policies.ts) | a Cedar policy evaluated against eight calls: reads, limits, gateway facts versus agent claims, forbid, floats, default deny, the policy digest | `src/policy.ts` |
| 04 | the transparency log | [04-merkle-log.ts](../examples/04-merkle-log.ts) | appends, inclusion proofs, recomputing the root from the file, an edited line detected | `src/log.ts` |
| 05 | the gateway | [05-gateway.ts](../examples/05-gateway.ts) | an MCP client connects to the gateway over stdio, sees filtered tools, gets one execution and one denial with receipt ids | `src/gateway.ts`, `src/cli.ts` |
| 06 | verification and auditing | [06-verify-and-audit.ts](../examples/06-verify-and-audit.ts) | the full check list, with and without a log copy, a tampered receipt, an untrusted key, checks as data for CI | `src/verify.ts` |
| 07 | the in-process SDK | [07-sdk-wrap.ts](../examples/07-sdk-wrap.ts) | wrap a function, allowed and denied and errored calls, the decide/record primitives, an SDK receipt's report | `src/sdk/index.ts` |
| 08 | Claude Code and Agent SDK hooks | [08-claude-code-hook.ts](../examples/08-claude-code-hook.ts) | the settings.json entry, PreToolUse allow and deny, PostToolUse, the real command over stdin, Agent SDK hooks | `src/sdk/claude.ts` |
| 09 | OpenAI Agents SDK | [09-openai-agents.ts](../examples/09-openai-agents.ts) | a real Runner with a scripted model, enforcement via wrapped tools, what the model sees on deny, record-only via lifecycle events | `src/sdk/openai-agents.ts` |
| 10 | Vercel AI SDK | [10-vercel-ai.ts](../examples/10-vercel-ai.ts) | a real generateText loop over the SDK's mock model, a denial as a tool-error part | `src/sdk/vercel-ai.ts` |
| 11 | LangChain | [11-langchain.ts](../examples/11-langchain.ts) | the callback handler, tool_call ids, enforcement by wrapping the function | `src/sdk/langchain.ts` |
| 12 | inside a receipt | [12-read-a-receipt.ts](../examples/12-read-a-receipt.ts) | the bundle's three parts, the in-toto statement, every predicate field with its provenance, the tree head | `src/receipt.ts` |
| 13 | a log run by someone else | [13-remote-log.ts](../examples/13-remote-log.ts) | the reference log server on a free port, an SDK config that logs to it, a tree head signed by the log's key, verification failing without that key and passing with it, the root endpoint, a refused token | `src/log-sink.ts` |
| 14 | proving history was not rewritten | [14-audit-history.ts](../examples/14-audit-history.ts) | three receipts and a kept tree head, a consistency proof that passes, the operator rewriting one leaf and appending a fourth call, the audit failing while the fourth receipt still verifies alone | `src/log.ts`, `src/verify.ts` |
| 15 | agents in other languages | [15-sidecar.ts](../examples/15-sidecar.ts) | the sidecar on a free port, a client written as a Python or Go program would write it: decide, run, record; a denial recorded without running the tool; both receipts verified | `src/sidecar.ts` |
| 16 | consequential tools, committed first | [16-precommit.ts](../examples/16-precommit.ts) | a refund named in `precommit`: the authorization leaf before the receipt leaf, the five authorization checks in the report, and the same call withheld when the log refuses | `src/gateway.ts`, `src/issue.ts`, `src/verify.ts` |
| 17 | a REST API as an upstream | [17-rest-upstream.ts](../examples/17-rest-upstream.ts) | a stand-in payments API described as two tools, the token from the environment, a refund allowed on the gateway's own lookup and one denied before reaching the API, the receipt verified | `src/rest.ts`, `src/gateway.ts` |
| 18 | OpenTelemetry export | [18-opentelemetry.ts](../examples/18-opentelemetry.ts) | a stand-in OTLP collector, `otel` in the config, one span per receipt with the receipt id as trace id, the collector going away and the next receipt still issued | `src/otel.ts`, `src/issue.ts` |
| 19 | Splunk export | [19-splunk.ts](../examples/19-splunk.ts) | a stand-in HTTP Event Collector, `splunk` in the config with the token from the environment, one event per receipt with the receipt id and log position as fields, the collector going away and the next receipt still issued | `src/splunk.ts`, `src/otel.ts` |
| 20 | one gateway for many agents, over HTTP | [20-http-gateway.ts](../examples/20-http-gateway.ts) | a gateway host served over Streamable HTTP, two agents connecting with their own grants and seeing their own tools, receipts naming the right agent, a refusal by grant, and a stranger's grant getting no session | `src/gateway-http.ts`, `src/gateway.ts` |
| 21 | OpenClaw plugin hooks | [21-openclaw.ts](../examples/21-openclaw.ts) | the two hooks driven with OpenClaw's event shapes: an allowed call gets no result, a denied one is blocked with the receipt id, executed and failed calls are recorded, every receipt verifies | `src/sdk/openclaw.ts` |
| 22 | DeepSeek Harness plugin | [22-deepseek-harness.ts](../examples/22-deepseek-harness.ts) | the module as a plugin, applied by a stand-in context; pre-execute delegating an allowed call and denying one with the receipt id; post-execute recording executed and failed calls; every receipt verifying with the harness's session and call ids | `src/sdk/deepseek-harness.ts` |
| 23 | a LangChain agent under custody, end to end | [23-langchain-kb-agent.ts](../examples/23-langchain-kb-agent.ts) | a docs agent on LangChain's `createAgent` reading a runbook, refused when it edits one, writing a note that cites its source; three receipts verified with the public key and the log copy; the auditor's report for the refused write. Scripted model, no API key. [23-langchain-kb-agent.tape](../examples/23-langchain-kb-agent.tape) renders it as a film with vhs | `src/sdk/index.ts`, `src/verify.ts` |
| 24 | an agentic CI/CD merge gate with evidence | [24-agentic-cicd-merge-gate.ts](../examples/24-agentic-cicd-merge-gate.ts) | a release agent merging pull requests through the gateway against a stand-in git host: the risk tier is a policy on facts the gateway fetched itself (diff size, sensitive paths, gate results, human approvals); low merges alone, medium needs a CODEOWNER, high is refused for any agent, production promotion refused; merges pre-committed to the log; an evidence index from the receipts alone, every line verified | `src/gateway.ts`, `src/rest.ts`, `src/verify.ts` |
| 25 | an agent delegating to an agent over A2A | [25-a2a-delegation.ts](../examples/25-a2a-delegation.ts) | a stand-in document agent speaking A2A 1.0, the gateway serving A2A in front of it with the document agent's card at its own address, an engagement agent delegating twice as an A2A client: one task allowed and answered with the receipt id in its metadata, one refused as a rejected task because it names a privileged matter, the policy deciding on the card the gateway fetched itself; both receipts verified, the allowed one carrying the card as a fact and the authorization logged before the task went out | `src/a2a.ts`, `src/gateway.ts` |

## How policies are defined, in one paragraph

A policy is a Cedar file. The gateway turns each tool call into a Cedar request: the principal is `Agent::"<agent id from the grant>"`, the action and resource are the tool name, and the context has three parts. `context.args` is what the agent sent and is only ever claimed. `context.facts` is what the gateway fetched itself before deciding, configured per tool in `gateway.json`, and is observed. `context.grant` is the signed delegation and is attested. Nothing matches means deny. A `forbid` beats every `permit`. An evaluation error, such as a missing attribute or a float, is a deny and is written into the receipt. The receipt also carries the sha256 of the policy text, so a verifier knows exactly which policy decided. Example 03 runs one; [policies.md](policies.md) has nine more, each executed by the test suite.

## Where each guide goes deeper

- [usage.md](usage.md): gateway setup and wiring into hosts
- [sdk.md](sdk.md): the interceptor and every adapter
- [policies.md](policies.md): the Cedar mapping, evaluation rules, tested examples, gotchas
- [verification.md](verification.md): every check and what a verified receipt does and does not prove

# A real Codex agent, a wrong plan, and recovery

The model handles a support request using MCP tools behind the custody gateway. The CRM import deliberately says `enterprise` when the account is actually on `free`. Codex decides whether to record benefits and issue a simulated service credit. An operator then introduces the correction, traces potentially affected actions and beliefs, reviews a recovery plan, and explicitly approves compensation.

The support calls come from `codex exec`, not a handwritten tool sequence. The correction and recovery are operator commands. Billing is a persistent local stand-in, not Stripe; a reversal compensates a simulated credit and preserves the original record. No real money moves.

See the [recorded live run](../../state/examples/codex-recovery/SAMPLE-RUN.md) for an actual result, including the final verification of 13 receipts.

## Before running

Use Node 22 with native TypeScript support (or later), Bun, and a Codex CLI that supports `exec`, MCP, `--ignore-user-config`, and `--ephemeral`. Tested with Node 24 and codex-cli 0.163.0. Codex needs working authentication and model access; use `codex login` if needed. An existing ChatGPT login works; an API key is not required when that login is available. Live runs consume the account's normal model usage and require network access to the model.

From the repository root:

```sh
bun install --frozen-lockfile
bun run build
codex login status
```

## Run the support task

```sh
cd packages/state
node examples/codex-recovery/run.ts run
```

Optionally select a model your Codex account supports:

```sh
node examples/codex-recovery/run.ts run --model <model>
```

The runner creates a fresh `examples-out/codex-recovery-*/case/` directory and prints its path. It imports the wrong plan, launches Codex with a task and business policy, waits up to three minutes, then simulates the operator learning about the CRM bug. The operator revokes the support grant, retracts the wrong plan, and writes `plan = free`. The runner verifies the receipts and prints a proposed recovery plan. It stops before applying that plan.

The expected story is:

```text
CRM import: enterprise
  → Codex reads the account memory
  → Codex may record discount 20 / priority support and issue a 2500-pence credit
  → Operator corrects the plan to free and retires the support grant
  → Review possible dependencies and proposed recovery
  → Explicit approval: correct stale benefits and reverse the simulated credit
  → Check current state and all signed receipts
```

The agent can decline, perform fewer actions, or encounter an error. Read `agent-answer.txt` and `codex-events.jsonl` to see what actually happened. The runner does not retry until the desired mistake appears or replace a failed model run with scripted calls. The plan reports `agentCalls` and `exposed`; zero gateway activity is explicitly labelled as not demonstrating an agent workflow. A credit without an observed dependency on the plan requires manual review rather than automatic recovery.

## Review and recover

Read `recovery-plan.json`. It names the exact beliefs to retract, corrected values to write, and simulated credits to reverse. The plan digest binds approval to those actions and the observed state. Changes after review invalidate it.

Copy the `recover` command printed by the runner, or use:

```sh
node examples/codex-recovery/run.ts recover \
  --dir /absolute/path/to/case \
  --approve <printed-plan-digest>
```

For the typical enterprise-to-free run, expect:

- Current plan: `free`; discount: `0`; support tier: `standard`.
- Original simulated credit: preserved, with status `reversed` and its reversal receipt ID.
- Original beliefs: retained in history, with receipted retractions.
- `receiptsVerified` includes the original calls, correction, and recovery.
- The command ends with `OK: recovery complete; evidence verified.`

Repeat verification without issuing tool calls:

```sh
node examples/codex-recovery/run.ts verify --dir /absolute/path/to/case
```

To refresh a plan after intervening activity or a partially completed recovery:

```sh
node examples/codex-recovery/run.ts inspect --dir /absolute/path/to/case
```

If Codex fails, its artifacts remain. Check `codex-stderr.log` and `codex-events.jsonl`. To continue an operator investigation of that failed run, use `correct --dir /absolute/path/to/case`, then inspect its actual evidence. A new `run` always creates a separate case. Demo grants last 24 hours; after expiration, inspect/verify still work, but recovery needs newly issued operator authority.

## Demo commands and flags

These commands belong to the example runner, not the published `agent-custody` or `agent-custody-memory` CLI. Run them from `packages/state` as `node examples/codex-recovery/run.ts <command>`.

| Command | Flags | Behavior |
| --- | --- | --- |
| `run` | optional `--model <model>` | Creates a fresh case, runs Codex, introduces the operator correction, and saves a recovery plan; stops before recovery |
| `correct` | required `--dir <case>` | Revokes support authority, retracts the wrong plan, records the corrected plan, and saves a recovery plan; useful after a failed agent run |
| `inspect` | required `--dir <case>` | Verifies existing evidence and saves a fresh plan and approval digest without issuing tool calls |
| `recover` | required `--dir <case>` and `--approve <digest>` | Rejects a changed plan or state; applies the reviewed recovery, saves the verification report, and prints `OK` on success |
| `verify` | required `--dir <case>` | Checks evidence and current recovery state without issuing tool calls; prints the report and exits nonzero if recovery is incomplete |
| `help` | none | Lists the example runner's commands |

Here `--approve` is an explicit confirmation by the local operator running the command. The digest covers the reviewed plan and snapshot; it is not a separate cryptographically signed human-approval artifact. The gateway's [payload-bound human approvals](approvals.md) are a different feature. Recovery calls still use the operator's signed delegation grant and receive signed gateway receipts; the recovery-plan digest is included in retraction and credit-reversal reasons.

## What to inspect

| Artifact | What it tells you |
| --- | --- |
| `prompt.txt`, `codex-command.json` | The actual task and Codex invocation |
| `codex-events.jsonl`, `agent-answer.txt`, `agent-run.json` | Model events, final answer, and whether the live process completed |
| `ledger.jsonl` | Original beliefs, corrections, and retractions |
| `receipts/`, `log.jsonl`, `keys/*.pub` | Signed calls, precommitted billing authorizations, and verification material |
| `billing.json` | Simulated credits and compensation, linked to receipt IDs |
| `recovery-plan.json`, `approval.json`, `verification.json` | Reviewed actions, explicit approval, and final verification result |

The verifier checks receipt signatures, delegation, inclusion in the local log, signed upstream results, and consistency of the demo stores with those receipts. All demo keys and the log live on the same machine: this is a workflow demonstration, not evidence against a malicious operator controlling that machine.

## Boundaries

- Blast radius records prior exposure in a gateway session. It does not prove that the model reasoned from a fact or that the fact caused an action.
- A verified receipt authenticates recorded evidence, not the truth of the customer's plan or correctness of a business decision.
- The gateway caps credits and confines writes to this account's benefits. Entitlement is intentionally left to the agent in this incident; a production policy could independently check it and prevent the credit.
- Codex runs with read-only shell sandbox settings, shell tools disabled, web search disabled, and user-configured apps/plugins disabled. Its MCP server is required and configured for this invocation only. Calls to this local demo server are preapproved in Codex; the gateway still enforces the grant and Cedar policy. The gateway owns the signing keys and the billing service; the model is not given them as tool data. These settings demonstrate controlled tool access, not adversarial OS isolation of an untrusted process.
- Recovery is deliberately limited to the two benefit predicates and simulated service credits in this case. Real refunds, customer communications, downstream caches, and model context need their own recovery decisions.
- Run operator commands sequentially for one case. The plan freshness check is not a transactional lock against concurrent operators.

## Offline regression coverage

The regular suite never calls Codex or the network. It drives the same MCP servers and recovery functions with scripted calls, clearly labelled as scripted:

```sh
node examples/08-support-recovery.ts
bun run test test/codex-recovery.test.ts test/examples.test.ts
```

The checks cover approval, stale plans, revoked support authority, duplicate-credit prevention, receipt tampering, store/evidence consistency, missing observed dependencies, and runs without agent activity.

Codex integration references: [non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode), [MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

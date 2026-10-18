# Payload-bound human approvals

A delegation lets an agent use a tool. A human approval authorizes one exact call: this principal, this agent, this tool, and every argument, until a short expiry. The gateway requires the signed approval before forwarding a protected call. A flag such as `approved: true` in the arguments has no authority.

The approval is a DSSE envelope signed with an approver's Ed25519 key. Its payload carries `approvalId`, `principal`, `agent`, `tool`, a SHA-256 digest of the complete arguments, `issuedAt`, `expiresAt`, and the action's `amount`, `currency`, and `beneficiary` when those fields exist. Money is an integer in minor units: `2500` means £25.00 for `GBP`, never `25.00`. Extra arguments are covered by the digest too; changing a note or adding a field invalidates the approval.

## Configure the gateway

Generate approver keys with `agent-custody keygen --dir keys --name approver`, keep their private halves with the people approving actions, and add their public halves to the gateway:

```json
{
  "approvals": {
    "trustedKeys": ["keys/approver.pub", "keys/second-approver.pub"],
    "usedDir": "approvals-used",
    "tools": [
      { "tool": "stripe.refund", "minApprovers": 2 }
    ]
  }
}
```

This is an addition to the [gateway config](usage.md#setup-step-by-step), with paths relative to that file. `minApprovers` is `1` by default, or `2` for two distinct trusted signing keys. A repeated signature or the same key listed twice counts once. The operator must assign those keys to distinct people; signatures establish possession of keys, not independent human identities.

`tool: "*"` protects every agent call, with an exact tool rule taking precedence. Wildcard rules do not require approvals for the gateway's internal fact lookups. A named fact-lookup tool cannot also have an exact approval rule: startup rejects that configuration. The gateway does not start with an empty trust list, an empty tools list, or duplicate tool rules.

The default action argument names are `amount`, `currency`, and `beneficiary`. For a refund whose recipient is `customer_id`, map it explicitly:

```json
{ "tool": "stripe.refund", "minApprovers": 1, "fields": { "beneficiary": "customer_id" } }
```

Pass the same `fields` when creating the approval. These are top-level argument names, not dot paths. Each present amount must be a safe integer; a present currency or beneficiary must be a nonempty string. An omitted action field is still covered by the complete argument digest, but the approval cannot establish a business meaning for a differently named field unless it is mapped.

## Sign the exact action and send it

Use the TypeScript API from the process where the human reviews the action. Show the complete arguments before signing, including any fields beyond the displayed amount and recipient.

```ts
import {
  APPROVAL_META_KEY, createApproval, dsseCountersign, loadPrivateKey,
} from "@agent-custody/receipts";

const args = { customer_id: "cust_123", amount: 2500, currency: "GBP" };
const fields = { beneficiary: "customer_id" };
const first = createApproval(loadPrivateKey("keys/approver.key"), {
  principal: "user_456",
  agent: "support-agent",
  tool: "stripe.refund",
  args,
  fields,
  expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
});
// For a two-person rule, the second person reviews and signs the same payload.
const approved = dsseCountersign(first, loadPrivateKey("keys/second-approver.key"));
const result = await agent.callTool({
  name: "stripe.refund",
  arguments: args,
  _meta: { [APPROVAL_META_KEY]: approved },
});
```

`createApproval` supplies a UUID `approvalId` and the current `issuedAt` unless given explicitly. `expiresAt` is required and must follow `issuedAt`. The window is half open: the approval is valid at issuance and invalid at expiry. `dsseCountersign` preserves the payload and adds a signature; it does not issue a different approval.

The gateway reads `agent-custody/approval` from the call's `_meta` and removes that key before forwarding. It checks the trusted signatures, threshold, validity window, principal, agent, tool, complete argument digest, and action fields before fact lookups and Cedar evaluation. Missing, malformed, expired, or mismatched approval denies the call even in observe mode. A valid approval still needs a valid grant and an allowing policy.

After facts and any pre-commit authorization have completed, the gateway checks the approval again and atomically consumes its id immediately before forwarding. An approval that expired during those waits, or lost a concurrent race to use the same id, leaves the call `withheld`. Every refusal gets a signed receipt with its reason.

## Consumption and failure recovery

`usedDir` is part of the enforcement boundary. Keep it persistent across restarts and share the same directory between all gateway processes that accept the same approvals. The filesystem must support exclusive file creation consistently across those processes, and durable file and directory synchronization. A synchronization failure withholds the call. Separate directories let each gateway consume the same approval once.

Consumption is conservative: the id is burned before forwarding. A crash, a log error, or an unknown upstream outcome after consumption does not release it. Obtain a fresh approval after checking the upstream's actual state; retry and exactly-once outcome handling are separate work. Do not delete consumption records while their approvals can still be valid. There is no automatic pruning.

An offline receipt verifier checks the signed action and the gateway's recorded consumption time. It cannot prove that another gateway never used that approval: single use depends on this shared persistent store and the gateway enforcing it.

## Verify the evidence

The receipt's optional `approval` record embeds the envelope, the required threshold, checked time, status, observed signer keyids, configured field mapping when any, and consumption time when consumed. A missing, malformed, or untrusted approval envelope on a refused call is omitted. Only signature entries that verify against trusted approval keys are retained in an embedded envelope. Its provenance is `observed`: the gateway records what it checked; the embedded envelope supplies the independent approver signatures.

```bash
agent-custody verify receipts/<id>.json \
  --issuer-key keys/gateway.pub --principal-key keys/principal.pub \
  --approval-key keys/approver.pub --approval-key keys/second-approver.pub
```

In code, give `verifyBundle` an `approvalKeys` array of `PublicKeyRef`s, separate from `issuerKeys` and `principalKeys`. Those other keys never implicitly authorize an approval. For a forwarded call carrying an approval record, verification requires trusted approval signatures, the exact action binding, validity at the recorded check and consumption times, and an approved, consumed record. A denied or withheld call can verify as an authentic refusal even though the approval was invalid; verification does not turn its approval into an authorization.

`verifyApproval(envelope, trustedKeys, binding, { at?, minApprovers? })` checks an envelope directly and returns either `{ ok: true, approval, approverKeyids }` or `{ ok: false, error }`. It does not consume it. `consumeApproval(usedDir, approvalId, receiptId, at)` creates the exclusive consumption marker and throws if the id has already been used. The gateway combines these steps; callers building another enforcement boundary must preserve their order.

## Privacy limits

The approval envelope stays in clear even under a private capture rule, so a reviewer can verify the human signatures. It exposes the amount, currency, beneficiary, and an **unsalted digest of the full arguments**. A reviewer who can guess the arguments can confirm that guess against this digest. Capture encryption and salted receipt commitments do not hide information in the independently signed approval. Use approval-protected tools only when that disclosure is acceptable; a forwarded call with any arguments still withheld fails the full approval binding check. Restoring those arguments with a capture key or disclosure lets the verifier recompute it; the browser verifier cannot restore them.

[Tutorial 28](../examples/28-payload-bound-approvals.ts) runs a real gateway with two approvers, refuses changed arguments, an expired approval and an insufficient threshold, forwards the exact approved call, refuses its replay, and verifies every receipt.

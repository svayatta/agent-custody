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
    "maxLifetimeSeconds": 900,
    "tools": [
      { "tool": "stripe.refund", "minApprovers": 2 }
    ]
  }
}
```

This is an addition to the [gateway config](usage.md#setup-step-by-step), with paths relative to that file. `maxLifetimeSeconds` caps the approval lifetime, `expiresAt` minus `issuedAt`. The default is `3600`. The signer chooses the expiry, so the gateway refuses an approval with a longer lifetime, in every mode. This keeps an unused approval, which the agent holds, from staying usable for years. `minApprovers` is `1` by default, or `2` for two distinct trusted signing keys. A repeated signature or the same key listed twice counts once. The operator must assign those keys to distinct people; signatures establish possession of keys, not independent human identities.

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

The gateway reads `agent-custody/approval` from the call's `_meta` and removes that key before forwarding. It checks the trusted signatures, threshold, lifetime cap, validity window, principal, agent, tool, complete argument digest, and action fields before fact lookups and Cedar evaluation. Missing, malformed, expired, or mismatched approval denies the call even in observe mode. A valid approval still needs a valid grant and an allowing policy.

After facts and any pre-commit authorization have completed, the gateway checks the approval again and atomically consumes its id immediately before forwarding. An approval that expired during those waits, or lost a concurrent race to use the same id, leaves the call `withheld`. Every refusal gets a signed receipt with its reason.

## Consumption and failure recovery

`usedDir` is part of the enforcement boundary. Keep it persistent across restarts and share the same directory between all gateway processes that accept the same approvals. The filesystem must support exclusive file creation consistently across those processes, and durable file and directory synchronization. A synchronization failure withholds the call. Separate directories let each gateway consume the same approval once.

Consumption is conservative: the id is burned before forwarding. A crash, a log error, or an unknown upstream outcome after consumption does not release it. Obtain a fresh approval after checking the upstream's actual state; retry and exactly-once outcome handling are separate work. Do not delete consumption records while their approvals can still be valid. There is no automatic pruning.

An offline receipt verifier checks the signed action and the gateway's recorded consumption time. It cannot prove that another gateway never used that approval: single use depends on this shared persistent store and the gateway enforcing it.

## Verify the evidence

The receipt's optional `approval` record embeds the envelope, the required threshold, checked time, status, observed signer keyids, configured field mapping when any, and consumption time when consumed. A missing, malformed, or untrusted approval envelope on a refused call is omitted. Only signature entries that verify against trusted approval keys are retained in an embedded envelope. Under a private capture rule the envelope and the reason are withheld as commitments; see [Privacy](#privacy-limits). Its provenance is `observed`: the gateway records what it checked; the embedded envelope supplies the independent approver signatures.

```bash
agent-custody verify receipts/<id>.json \
  --issuer-key keys/gateway.pub --principal-key keys/principal.pub \
  --approval-key keys/approver.pub --approval-key keys/second-approver.pub
```

In code, give `verifyBundle` an `approvalKeys` array of `PublicKeyRef`s, separate from `issuerKeys` and `principalKeys`. Those other keys never implicitly authorize an approval. For a forwarded call carrying an approval record, verification requires trusted approval signatures, the exact action binding, validity at the recorded check and consumption times, and an approved, consumed record. A call that the gateway did not forward needs none of these, and so needs no approval key. This covers a call that Cedar denied, a call outside the grant, and a call withheld after consumption, even when the approval was valid. The record of such a call is an authentic refusal. Verification does not turn its approval into an authorization.

`verifyApproval(envelope, trustedKeys, binding, { at?, minApprovers?, maxLifetimeSeconds? })` checks an envelope directly and returns either `{ ok: true, approval, approverKeyids }` or `{ ok: false, error }`. It does not consume it. `consumeApproval(usedDir, approvalId, receiptId, at)` creates the exclusive consumption marker and throws if the id has already been used. The gateway combines these steps; callers building another enforcement boundary must preserve their order.

## Privacy limits

The approval envelope arrives in the agent's `_meta`. It carries the amount, currency, beneficiary, and an **unsalted digest of the full arguments**. Under a private capture rule the receipt withholds the whole envelope as one commitment at `approval.envelope`. It is salted, and encrypted in mode `encrypted`. The precommit authorization carries the same commitment. A refusal `reason` can quote the statement, so it is withheld too. Without this, the receipt would publish the action fields, and the digest would confirm a guess of the arguments (issue #126).

The record keeps the gateway's own observations in clear: the status, the required threshold, the check and consumption times, the signer key ids, and the configured field mapping. A reviewer sees that an approval was checked and when. To check the signatures and the binding, the reviewer restores the envelope and the arguments with the capture key or a disclosure (`approval.envelope` and `request.args.$rest` in the disclosure file). Without them, the verifier passes the approval checks as committed, as it does for `request args digest`, and says so. A tool with a private rule and an approval therefore proves the approval only to a reviewer who holds the key. The browser verifier cannot restore them.

Under a clear rule the receipt shows the arguments, so the envelope stays in clear.

[Tutorial 28](../examples/28-payload-bound-approvals.ts) runs a real gateway with two approvers, refuses changed arguments, an expired approval and an insufficient threshold, forwards the exact approved call, refuses its replay, and verifies every receipt.

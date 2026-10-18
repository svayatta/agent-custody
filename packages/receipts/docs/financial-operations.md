# Safe financial operations

An API response is evidence of an API call. Settlement is a separate outcome. Configure `operations` on the gateway to give each payment a durable identity, reserve its amount before forwarding, and close uncertain outcomes with a signed provider reconciliation receipt. [Example 29](../examples/29-financial-operations.ts) runs a payments stand-in, drops a response after acceptance, restarts the gateway, and verifies the reconciliation.

## Configuration

Add this to a gateway config whose upstream advertises `stripe.refund` and the read-only `refund.lookup`:

```json
{
  "operations": {
    "database": "operations/operations.sqlite",
    "budgets": [{ "id": "refunds", "currency": "GBP", "limit": 100000 }],
    "tools": [{
      "tool": "stripe.refund",
      "budget": "refunds",
      "amountField": "amount",
      "currencyField": "currency",
      "idempotencyHeader": "Idempotency-Key",
      "reconcile": {
        "tool": "refund.lookup",
        "args": { "key": "$operation.idempotencyKey" },
        "statusPath": "status",
        "identityPath": "idempotencyKey",
        "confirmed": ["succeeded"],
        "failed": ["failed"],
        "pending": ["pending"]
      }
    }]
  }
}
```

Amounts and limits are safe integers in minor units; an amount must be positive. Currency must match the budget's three-letter uppercase code. The amount and currency field defaults are `amount` and `currency`. The default REST header is `Idempotency-Key`; `identityPath` defaults to `idempotencyKey`, and `pending` defaults to an empty list. Other fields above are required. Tool names and budget ids must be unique, and reconciliation status lists must be disjoint.

The database path resolves relative to the config. Its parent directory must be owner-only (`0700`); the gateway creates a missing directory and creates/tightens the database to `0600`. The database contains recovery data, provider responses, and private commitment salts. Keep it private and durable alongside the signing key. Never delete operation records to implement retention or reset a budget: those records prevent old calls from being forwarded again. Financial operations load `node:sqlite` lazily and need Node 22 with that module available.

All sessions and gateway processes sharing a budget must use the same SQLite database on the same machine, with the same budget configuration. Use a remote log for multiple gateway processes; a local receipt log has one writer. Budgets cover UTC calendar days. Unknown, submitted, pending, and confirmed operations continue to count in their original day; a retry never moves a reservation into a new day. A new day gets its own daily limit.

## Provider contract

The provider must honor the supplied idempotency key. REST financial tools receive it in the configured header, overriding any static header of that name. MCP financial tools receive `_meta["agent-custody/operation"] = { id, idempotencyKey }` and must pass the key to their payment provider. A2A financial upstreams are refused because they have no payment idempotency contract.

Reconciliation is a read from the provider's authoritative operation record. A REST reconciliation tool must use GET. Its arguments may substitute only `$operation.idempotencyKey`, beside configured constants. The template cannot copy `$operation.id`: the agent chose that UUID, and it must not reach a receipt. The result must contain JSON in its first text item. `statusPath` and `identityPath` traverse own properties using dot-separated names. The identity must equal the operation's idempotency key; a missing or unrelated record cannot close a reservation. The configured `failed` states must mean a terminal provider failure that cannot later settle. An absent record, a transport failure, and an HTTP error are uncertain outcomes and must never be mapped to terminal failure.

The write upstream, read upstream, and reconciliation configuration are bound into the durable operation. Reconciliation refuses a changed provider configuration. Its lookup arguments, identity path, and terminal mappings are also committed in the original signed authorization. The gateway observes the provider read; this is not an independent provider signature.

## Calling and retrying

Generate and persist one lowercase UUID before a consequential call, then retain it across transport failures and restarts:

```ts
import { randomUUID } from "node:crypto";
import { OPERATION_META_KEY } from "@agent-custody/receipts";

const operationId = randomUUID(); // persist with the business operation before sending
const call = {
  name: "stripe.refund",
  arguments: { amount: 2500, currency: "GBP", customer_id: "cust_123" },
  _meta: { [OPERATION_META_KEY]: operationId },
};
const result = await client.callTool(call);
```

The first use atomically binds the UUID to the principal, agent, tool, destination, full argument digest, and budget, and reserves the amount before the authorization or forward. Reusing it for different arguments or identity is refused. Identical calls with distinct UUIDs are separate business operations, so generating a fresh UUID after a timeout defeats retry protection.

A retry still checks the current grant and policy. It returns the existing logical operation's result, receipt id, and current operation metadata; it never forwards again or reserves again. A retry that policy allows gets a receipt of its own: `execution.status` is `withheld` (the call was not forwarded again), and `operation.originalReceiptId` names the receipt of the first call. The answer carries its id at `_meta["agent-custody/retry-receipt"]`, and `_meta["agent-custody/receipt"]` stays the receipt that holds the outcome. If the gateway died after authorization but before its outcome receipt, the retry reports `unknown` and returns the original signed authorization under `_meta["agent-custody/authorization"]`. There may be no `<originalReceiptId>.json` in that case; the authorization is sufficient for reconciliation.

The signed receipt's `execution.status` describes the API call. Its separate `operation.status` records the financial lifecycle:

| outcome | meaning | budget |
| --- | --- | --- |
| `submitted` | durable reservation exists; forwarding may still be in progress | held |
| `pending` | API answered; settlement awaits an authoritative read | held |
| `unknown` | provider acceptance or settlement is uncertain | held |
| `confirmed` | reconciliation read confirms final success | consumed in the original day |
| `failed` | reconciliation read confirms terminal failure, or the gateway proves it withheld the forward | released |

An initial success response remains `pending` until reconciliation. An HTTP error or thrown call becomes financially `unknown`, even if API execution is `failed` or `error`. Financial authorization logging fails closed in observe mode too; observe suspends Cedar enforcement, never idempotency, budget enforcement, or the required authorization append.

## Reconciling

An operator holding the config and signing key runs:

```bash
agent-custody reconcile --config gateway.json --operation <uuid>
```

The command prints JSON with `operation`, terminal `status`, and the receipt file path. A pending/unknown record causes a nonzero exit and keeps the reservation; run the command again after the provider record changes. Repeated completed reconciliations return the same bundle. The operator can reconcile after the original agent's grant expires or is revoked, because this reads an existing operation and sends no new payment.

In code, `await host.reconcile(operationId)` returns the bundle. This method is on `GatewayHost` and is never advertised as an agent tool. To recover operation ids after a crash, open the configured `OperationStore` and inspect `store.list()`; close the connection when finished. A submitted operation owned by a live process is refused until that forward returns. After a killed process, its submitted authorization can be reconciled. The gateway stores the creator's PID with its kernel start time (`/proc/<pid>/stat`, or `/bin/ps` with the time zone pinned to UTC where there is no `/proc`, because `ps` prints local time). A live process with the same PID and another start time is not the creator, so a gateway that is PID 1 in a restarted container does not block recovery. When the gateway cannot read a start time, it treats the PID as the creator and recovery waits: it never releases the budget of a live forward. The check needs the creator and the operator to share one PID namespace, such as `docker exec` into the gateway container. A second container on the same volume sees other PIDs and must not run `reconcile` while a gateway can still be forwarding.

The gateway saves the signed authorization before it forwards. A submitted operation with a dead creator and no saved authorization therefore proves that the call was never sent. `reconcile` closes it with a receipt, with `execution.status: "withheld"` and `operation.status: "failed"`, and then releases the reservation. It makes no provider read. A wrong liveness answer cannot cause a double forward: the creator saves its authorization with a compare-and-set, and it refuses to forward once recovery has closed the operation. Recovery in turn refuses to close the call when an authorization was saved meanwhile. A retry of a closed call is told that the call was not sent and that a new operation id is needed. The recovery store keeps the call's request values until then, so keep the database private.

The reconciliation embeds the original receipt or pre-forward authorization, preserves operation identity, and records the configured provider read as `execution.result`. It commits the exact signed/captured receipt and private salts in the recovery store before appending it. Only after the log accepts that receipt does a terminal failure release budget. A log outage or process crash retains the amount; retry uses the same signed bytes and salts. Concurrent recovery can append identical evidence more than once, but cannot choose conflicting terminal outcomes or duplicate a payment.

Verify it with the usual `agent-custody verify` command and the gateway/principal public keys. Both verifiers check the original signature and inclusion proof, operation linkage, precommitted lookup, provider record identity and final status, result digest, and log order. Capture rules apply to the reconciliation result too: withheld provider details verify as committed until disclosed or decrypted. The operation metadata never copies the payment amount into clear fields. Under a private capture rule, `operation.id` is withheld too, as one commitment, because the agent chose it. Receipts link by the gateway-derived `idempotencyKey`, which stays in clear.

A reconciliation receipt records a provider read. The gateway evaluated no policy for it, and it did not run the payment tool again. Its `policy.reasons` say so. The OpenTelemetry span and the Splunk event mark it: the span has `agent_custody.reconciliation` and `agent_custody.operation.status`, no policy decision, and the status `reconciled`. The span status is an error when the provider reports the operation as failed. A dashboard therefore never counts it as a second allowed call. `explain` and `review` also show it as a provider read (`reconciled`), not as an allowed execution of the tool.

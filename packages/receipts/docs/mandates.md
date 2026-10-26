# Payment mandates and agent identity: AP2, Visa TAP, Mastercard Agent Pay

Design, not yet built. It tracks issues #185 and #186: fitting the grant and the receipt to the payment networks' standards, so that the networks define the authority and agent-custody keeps the evidence of what was done under it.

Sources read on 26 October 2026: AP2 v0.2 ([google-agentic-commerce/AP2](https://github.com/google-agentic-commerce/AP2), `docs/ap2/specification.md` and `agent_authorization.md`), and Visa's Trusted Agent Protocol ([visa/trusted-agent-protocol](https://github.com/visa/trusted-agent-protocol)). Mastercard Agent Pay has no public specification that we could find; what follows on it comes from secondary sources.

## What AP2 v0.2 defines

- **Mandates are SD-JWT verifiable credentials.** A `vct` claim names the type and version: `mandate.checkout.1`, `mandate.payment.1`, and the open variants `mandate.checkout.open.1` and `mandate.payment.open.1`.
  - An **open** mandate carries `constraints` and the agent's key in `cnf` (RFC 7800).
  - A **closed** mandate is bound to one transaction by the agent's key-binding JWT.
  - Verifiers always receive a closed mandate, sometimes with the open mandate it came from.
- **Two modes.** In human-present mode, the user signs the closed mandate directly. In human-not-present mode, the user signs an open mandate and the agent signs the closed one under its constraints.
- **Payment constraints:** recurrence, allowed payees, allowed instruments, allowed payment initiation service providers, an amount range, a budget, the checkout reference, and an execution date. An unknown constraint fails.
- **Mandate receipts.** Every verifier returns a signed Mandate Receipt JWT on acceptance *and* on rejection: `iss` (the verifier), `result` (`success` or `error`), `reference` (a hash of the mandate it received, computed like `sd_hash`), and, on an error, an `error` code (`invalid_credential`, `unresolved_constraint`, `invalid_mandate`, `mandates_not_supported`) with an optional `error_description`. In the autonomous flow, an agent may not present another open mandate until the previous one has a rejection receipt.
- **Not only payments.** `agent_authorization.md` is a general framework: new mandate types and constraint types MAY be defined, named with an rDNS prefix.
- **What AP2 leaves open: dispute evidence.** The mandates and receipts "provide a non-repudiable picture of the transaction", but *retention and retrieval are outside the scope of this specification*. That gap is exactly agent-custody's job.

## How agent-custody maps onto it

| AP2 | agent-custody today | What changes |
|---|---|---|
| Open mandate, user-signed, with `cnf` = the agent's key and `constraints` | Grant: principal-signed DSSE, with `agentKey`, `scopes`, and a time window | Accept an open AP2 mandate as a grant. Define our own mandate type for non-payment tools, so a grant can be issued as an AP2 SD-JWT VC. |
| Closed mandate, user-signed (human present) | Payload-bound approval: principal-side keys sign the exact tool, arguments, amount and beneficiary | Accept a closed AP2 payment mandate as the approval for a payment tool. |
| Closed mandate, agent-signed under an open mandate (human not present) | A call checked against the grant and the Cedar policy | The gateway verifies the chain and evaluates every constraint before the policy runs. A failed constraint is a denial with a receipt, and an AP2 rejection receipt goes back to the agent. |
| Verifier | The gateway | The gateway becomes an AP2 verifier for the actions it gates. |
| Mandate Receipt JWT (`iss`, `result`, `reference`) | The signed receipt | Each receipt carries the mandate's `reference` and the outcome. For every mandate presented, whether accepted or rejected, the gateway also returns a standard Mandate Receipt JWT, so an AP2 party reads our answer in its own format. |
| Dispute evidence, retention out of scope | The transparency log, chain anchoring, retention, the verifiers | The mandate chain and its receipts are logged and anchored, and are retrievable by `transaction_id`. |
| One open mandate presented at a time | Single-use approvals (`usedDir`) | Track open-mandate presentations the same way, for recurrence and budget constraints. |

**The line for the deck:** AP2 defines who authorised what; agent-custody proves what was then done with it, and keeps the proof where nobody can change it.

## Visa Trusted Agent Protocol

TAP is an identity layer between an agent and a merchant.
- The agent signs each HTTP request with RFC 9421 message signatures, bound to the merchant's domain and the operation, with a timestamp and a nonce.
- Merchants verify the key against Visa's directory.
- It doesn't move money and doesn't carry a mandate.

The fit is at the gateway's outbound side. The gateway already sits between the agent and the merchant. With the agent's TAP key held by the gateway, ideally in the TEE (#179), it signs the outbound request, and the receipt records the signature parameters. The merchant then sees a trusted agent, and the receipt shows exactly which request carried that identity.

## Mastercard Agent Pay

Reported to work through agentic tokens: MDES tokens scoped to an agent, a merchant and a consent policy, with spending limits held by the issuer. No public specification was found. Until one exists, the plan is limited to recording the token reference and its scope in the receipt, as a fact the gateway observed.

## Plan, in order

1. **Record AP2 mandates in receipts.**
   - Verify an SD-JWT VC mandate chain (ES256 and RFC 7800 `cnf`), with issuer keys pinned in the gateway config.
   - Evaluate the payment constraints.
   - Record the `vct`, the `reference`, each constraint's result, and the issuer's key id in the receipt.
   - Under a capture rule, undisclosed claims stay out, and the disclosed ones are treated like arguments.
   - This needs vectors, and both verifiers (`src/verify.ts` and `site/verifier/verify-web.ts`) change together.
2. **Return Mandate Receipts, on acceptance and on rejection.** For every mandate presented with a call, the gateway returns an AP2 Mandate Receipt JWT in `_meta`, bound to the agent-custody receipt id, including when the mandate is refused. A rejection is what lets an AP2 agent retry, fall back, or present its next open mandate, so a refusal must never produce only our own denial receipt.

   | Gateway outcome | `result` | `error` |
   | --- | --- | --- |
   | Chain and constraints verify, and the call is allowed | `success` | |
   | The SD-JWT, its key binding or the chain fails, the issuer isn't trusted, or the mandate has expired | `error` | `invalid_credential` |
   | An unknown constraint type, or a constraint the gateway can't evaluate | `error` | `unresolved_constraint` |
   | Constraints evaluate false, or the mandate doesn't cover this tool or these arguments | `error` | `invalid_mandate` |
   | The tool has no mandate configuration, or the presented `vct` isn't supported | `error` | `mandates_not_supported` |

   - **Authorization, not outcome.** The JWT's `result` is the authorization decision only. Whether the tool then ran, failed, or was withheld, and how a payment later settles, are recorded in the agent-custody receipt (`execution`, `operation`, `reconciliation`), never in the mandate receipt.
   - **Logged.** The mandate receipt's digest is recorded in our receipt, so the rejection evidence is logged too.
   - **No leaks.** `error_description` never carries a withheld value or a policy's internal reason.
   - **One mandate in flight.** An open mandate counts as in flight from its presentation until its receipt, whichever the result.
3. **An agent-custody mandate type for tools.**
   - Name: `dev.agent-custody.mandate.tool.1`.
   - Constraints: allowed tools, an argument range, an amount range, payees, and a window.
   - A principal can then issue an AP2-format open mandate in place of a DSSE grant, and the gateway accepts both.
4. **The TAP signer.** RFC 9421 signatures on outbound requests to configured merchants, with the key held by the gateway, and the signature parameters recorded in the receipt.
5. **Dispute retrieval.** Look a receipt up by AP2 `transaction_id`, and produce an evidence pack with the mandate chain, the AP2 receipts, our receipt, the inclusion proof and the anchor.

## Open questions

- **SD-JWT implementation.** Use an existing library (the OpenWallet Foundation's `@sd-jwt/*`), or write a small verifier ourselves, the way the rest of the verifier is dependency-light? The browser verifier needs it too.
- **Delegation chains.** AP2 uses the Delegate SD-JWT draft for chains, which is not yet stable. Pin to the draft revision that AP2 v0.2's reference implementation uses, and test against its fixtures.
- **Keys.** Mandates are ES256, while our receipts are Ed25519. The gateway verifies ES256 and keeps signing with Ed25519, so no format change is needed. ML-DSA (#11) is unaffected.
- **Privacy.** A mandate's undisclosed claims must never reach a receipt in clear. Disclosed payee and instrument details follow the capture rule, and the capture canary test gets a mandate path.
- **A refusal by the gateway's own policy.** If the mandate verifies but the operator's Cedar policy, an approval rule, or strict mode refuses the call, which code applies? `invalid_mandate` would wrongly blame the mandate. Our recommendation is a namespaced code, `dev.agent-custody.policy_denied`, with a short public reason, if AP2 allows codes beyond the four it defines. Otherwise `invalid_mandate`, with the cause in `error_description`. Confirm with the AP2 maintainers.
- **Which party we are.** In AP2 terms the gateway is a verifier for the actions it gates, not a Credential Provider or a Network. Say so in the docs, so nobody reads agent-custody as a payment network component.

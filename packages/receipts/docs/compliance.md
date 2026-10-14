# What the evidence satisfies

Auditors ask for controls by their names. This page maps the requirements they cite most to the artefacts agent-custody produces, so a security questionnaire can be answered with a file rather than a paragraph. It is a map, not a certificate: the artefacts are evidence that a control operated, and the control itself, the policy, the grant, the retention window, the person who reviews an alarm, is yours.

Two rules keep the answers honest. First, say which producer made the receipt: a gateway receipt was enforced outside the agent's process, an SDK receipt is the agent's own report, and the receipt's `issuer.kind` says which. Second, say where the log runs: with the default local log the operator can rewrite history, with a log run by someone else they cannot, and with a witness neither operator can. The [proof table](../README.md#what-a-receipt-proves-and-what-it-does-not) has the full list of claims and against whom each holds.

## The artefacts

| artefact | what it is | how to produce it |
| --- | --- | --- |
| receipt | one signed record per tool call: who authorized it, what the agent saw, what it did, the policy decision, its position in the log | issued by the gateway or the SDK; `receipts/<id>.json` |
| authorization | the same, committed to the log before a consequential call was forwarded | `precommit` in the gateway config |
| verification report | the check list a third party gets from the receipt and public keys alone | `agent-custody verify` |
| audit | proof that the log at a later size extends its earlier state | `agent-custody audit` between any two tree heads or checkpoints |
| checkpoint | a signed tree head published on a schedule, countersigned by a witness where one runs | the log's checkpoints host, the witness's host |
| action pack | one receipt explained and packed with every downstream receipt, signed | `agent-custody-memory explain --out --sign` |
| custody pack | one fact's history, receipts, blast radius, holds, and forget certificate, signed | `agent-custody-memory pack` |
| forget certificate | the receipt of the call that erased a value from the ledger and the stores, with each store's answer | `memory.forget` through the gateway |
| eval report | scores for stale reads, contradictions, and blast radius after retraction, signed | `agent-custody-memory eval --sign` |
| usage | appends per tenant per month on the hosted log | `/admin/usage.csv` |

## SOC 2, Trust Services Criteria

| criterion | what it asks | what answers it |
| --- | --- | --- |
| CC6.1, logical access | access to systems is restricted to authorized users | the delegation grant: a human-signed statement of which agent may call which tools, for how long, embedded in every gateway receipt and re-checked by the verifier |
| CC6.3, authorization changes | access is granted, modified, and removed by authorized parties | grants have validity windows and are signed by a principal key the gateway is configured to trust; a new grant is a new signed file; `agent-custody revoke` revokes a grant, and every session under it or under a grant delegated from it refuses its next call |
| CC7.2, monitoring for anomalies | the entity monitors system components for anomalies | every call has a receipt, allowed or denied, and `explain` answers who, why, and what depended on it; the OpenTelemetry and Splunk exports carry each receipt into the existing SIEM |
| CC7.3, evaluation of security events | events are evaluated to determine whether they are incidents | the action pack: one receipt with every downstream receipt, verifiable by the evaluator without access to the system |
| CC7.4, incident response | incidents are contained and remediated | blast radius names every action and belief that depended on a wrong fact; retract and forget are receipted calls, so the remediation has its own evidence |
| CC8.1, change management | changes are authorized and tracked | the policy digest in every receipt identifies the exact policy that decided the call, so a policy change is visible in the receipts; for changes made by agents, the merge gate below gives per-change evidence of tier, approval, and authority on either side of it |

## ISO/IEC 27001:2022, Annex A

| control | what it asks | what answers it |
| --- | --- | --- |
| A.5.15, access control | rules for access based on business requirements | the grant and the Cedar policy, with the policy decision on facts the gateway fetched itself |
| A.5.28, collection of evidence | evidence is collected in a form that stands up | receipts are signed, hashed into a Merkle log, and verifiable offline; the audit proves nothing was rewritten between two points; the packs are single signed artefacts for a case file |
| A.8.10, information deletion | information is deleted when no longer required | forget erases a value from the ledger and the adapted stores and the receipt is the certificate, with each store's own answer; retention sweeps run as receipted calls; a legal hold refuses both |
| A.8.15, logging | logs are produced, stored, protected, and analysed | the transparency log, append-only and hashed, with a log run by someone else where the operator must not be trusted |
| A.8.16, monitoring activities | networks, systems, and applications are monitored | `log-check` from a machine that is not the log's, and the per-receipt spans in the SIEM |
| A.8.32, change management | changes are subject to change management | the policy digest, the grant's window, and the receipts either side of a change; for agent-made changes, the merge gate below |

## EU AI Act, obligations on high-risk systems and their deployers

| article | what it asks | what answers it |
| --- | --- | --- |
| Article 12, record-keeping | automatic recording of events over the system's lifetime, enabling traceability | one receipt per tool call, in a tamper-evident log, with the facts the agent was shown and the beliefs it wrote; `explain` traces any action to its causes and consequences |
| Article 14, human oversight | humans can understand, oversee, and intervene | the grant is a human's signature over what the agent may do; the policy decides on facts the agent did not supply; retract and forget are the intervention, receipted |
| Article 19, retention of logs | logs are kept for a period appropriate to the purpose | retention windows per space in the memory server; `prune` on the receipt log keeps every proof valid while the content is gone; a legal hold overrides both |
| Article 26, deployer obligations | deployers keep logs and monitor operation | the same receipts and the same monitor; a tenant on the hosted log has its own log id and checkpoints an auditor can fetch |

## UK GDPR

| provision | what it asks | what answers it |
| --- | --- | --- |
| Article 5(2), accountability | the controller demonstrates compliance | signed receipts and packs demonstrate what was done and why, to a party who has no access to the controller's systems |
| Article 17, right to erasure | personal data is erased on request | the forget certificate, including `stillIndexed` when a store has not caught up, which is what an honest response to a data subject says |
| Article 30, records of processing | records of processing activities are kept | the receipts, and the memory ledger's history of every fact with its source receipt |
| Article 32, security of processing | appropriate technical measures | the hosted log holds hashes only, and receipts stay with the controller |

## Agent-made changes: the merge gate

Teams whose agents open pull requests hit two problems at once. Volume: SOC 2 and ISO 27001 ask that changes are authorized, tested, and approved under a defined process, and a human on every PR does not scale. Accountability: a pipeline's own audit trail, including an "evidence store" at the end of it, is written by the pipeline that made the decisions. Risk-tiered review solves the first only if the tier decision itself is evidence.

[Example 24](../examples/24-agentic-cicd-merge-gate.ts) is that gate. A release agent merges through the gateway; the risk tier is a Cedar policy over facts the gateway fetches from the git host itself, never from the agent: the diff size, whether sensitive paths are touched, the deterministic gate results, which humans approved. Low risk merges on the agent's own authority, medium needs a CODEOWNER's approval the gateway can see, high has no permit for any agent and goes to two humans in the host, and production promotion is refused. Every merge is pre-committed to the log before it is forwarded. The receipts give, per change: the tier, the decision, the approvers as the gateway saw them, the policy digest, the human whose signed grant authorized the agent, and the log positions showing authorization preceded execution, each line verifiable with public keys and no account with us. That is what the two controls above ask for, produced by a key the agent does not hold, instead of a trail the pipeline wrote about itself.

## What no artefact here claims

That the agent's arguments were correct, that the model named in a receipt produced the call, that the upstream executed the action unless it signed the result or a provider delivery is embedded, or that an SDK receipt was enforced outside the agent. The [proof table](../README.md#what-a-receipt-proves-and-what-it-does-not) says so, and a questionnaire answer that repeats it will survive the reviewer who checks.

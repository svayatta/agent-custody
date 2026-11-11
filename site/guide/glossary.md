# Glossary

One name for each thing. The site, the docs, the dashboard, and the CLI use these words in these senses.

## Products and places

| term | meaning |
| --- | --- |
| **Components** | The parts of agent-custody: the gateway, the door, the egress witness, the SDK hooks, the log, and the rest. [Components](/guide/pieces) says which you need. |
| **Dashboard** | The web app at app.agent-custody.dev where you sign up, create API keys, and see your usage. |
| **Gateway console** | The local admin page for one gateway: its checks, its policy, and the audit of changes ([gateway console](/receipts/console)). |
| **Hosted log** | The log we run for you, one tenant per customer ([hosted log](/reference/hosted)). |
| **Verify a receipt** | Check a receipt offline with public keys, on the command line or in [the browser](/verify). |

## Accounts and keys

| term | meaning |
| --- | --- |
| **API key** | The secret your gateway presents to append to your tenant on the hosted log. It is shown once and stored only as a hash. |
| **Sign in**, **Sign up** | Open the dashboard with an existing account, or create one. |
| **Tenant** | One customer's log on the hosted log, with its own API keys, plan, and audit. |

## Receipts and evidence

| term | meaning |
| --- | --- |
| **Bundle** | A receipt with the tree head and inclusion proof that place it in the log: the file a verifier checks. |
| **Capture rule**, **commitment** | A rule that keeps a field out of the receipt. A commitment is the salted hash left in its place, which proves the value later without revealing it. |
| **DSSE** | Dead Simple Signing Envelope: the signed wrapper around each receipt, so any change to it breaks the signature. |
| **Issuer** | What signed a receipt: a gateway, a door, an egress witness, an SDK hook, or a guardian. The verifier says first what each kind is worth ([verification](/receipts/verification)). |
| **Provenance** | The label on each field of a receipt: `attested` (signed by someone other than the issuer), `observed` (seen by the issuer itself), or `claimed` (the agent's word). |
| **Receipt** | A signed record of one tool call: who made it, for whom, with which arguments, what the policy decided, and what happened. |

## Authority and policy

| term | meaning |
| --- | --- |
| **Cedar** | The policy language the gateway uses by default to allow or deny each call. Rego, from Open Policy Agent, is the other one it reads ([policies](/receipts/policies)). |
| **Grant** | A statement, signed by the principal, of what an agent may do and until when. The gateway checks it on every call. |
| **Observe mode** | The policy decides and the decision is recorded, but nothing is blocked. Use it until the policy is right. |
| **Policy digest** | The SHA-256 of the policy file, written into every receipt, so a verifier knows which policy decided. |
| **Principal** | The person or organisation an agent acts for, and whose key signs its grant. |

## The log

| term | meaning |
| --- | --- |
| **Anchor** | A checkpoint's root written to a public blockchain, so that rewriting the log would mean rewriting the chain too ([anchoring](/receipts/anchoring)). |
| **Append** | Writing one receipt's hash to the log. Plans count appends. |
| **Checkpoint** | A tree head published apart from the log at intervals, so anyone can check later that the log was never rewritten. |
| **Inclusion proof** | The hashes that show one leaf is in the log under a given tree head. |
| **Leaf** | One entry in the log: the hash of one receipt. |
| **Log** | An append-only Merkle tree of receipt hashes (RFC 9162), the way Certificate Transparency keeps certificates. |
| **Tree head** | The log's size and root hash, signed with the log's key. |
| **Witness** | An independent party that checks each new checkpoint extends the last one, then cosigns it. |

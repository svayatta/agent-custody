# Security questionnaire

Where the data goes, in plain words, is on the [FAQ](/faq): what a receipt contains, what reaches the hosted log, how secrets are handled.

The answers a procurement or security team asks for, written once, dated, and kept honest. Every "no" is a no. Where a control is planned, the answer says planned, not done. Last reviewed 2026-09-27; the [changelog](/changelog) records what has changed since.

The scope is two things: the **packages** (`@agent-custody/receipts`, `@agent-custody/state`, `agent-custody` on PyPI), which run on your machines, and the **hosted log** at log.agent-custody.dev, which we run. Receipts, arguments, results, and the memory ledger never leave your machines in either case; the hosted log receives leaf hashes.

## The organisation

| question | answer |
| --- | --- |
| Who operates the service, and who is the contracting entity? | Charioteer Consulting Ltd, reachable at partha@charioteerconsulting.com. One operator today; a second, independent operator is being sought for the witness, which by design must not be us. |
| Is there a security contact and disclosure policy? | Yes: [SECURITY.md](https://github.com/svayatta/agent-custody/blob/main/SECURITY.md), acknowledgement within two working days, assessment within seven. |
| Do you hold SOC 2, ISO 27001, or Cyber Essentials? | No. The [compliance mapping](/receipts/compliance) says which of your controls our artefacts are evidence for; it makes no claim about our own certification. |
| Has the service had an independent penetration test? | No. A [threat model](/receipts/threat-model) is published and is the scope we would give a tester. |
| Is the source open? | Yes, Apache-2.0, at [github.com/svayatta/agent-custody](https://github.com/svayatta/agent-custody), the same code that runs the hosted log. Anyone can run the log themselves from [deploy/](https://github.com/svayatta/agent-custody/tree/main/deploy). |

## Data

| question | answer |
| --- | --- |
| What data does the hosted log hold about a tenant? | Leaf hashes (SHA-256 of a receipt envelope), their append times, the tenant id and log id, token hashes with a label, signed tree heads and checkpoints, and the audit trail of administrative actions. Nothing in it identifies a person, a tool call, or an argument. |
| Can the log operator read receipts? | No. The hosted log refuses a full leaf at append and accepts only leaf hashes, so no receipt reaches its process even from a misconfigured gateway or a stolen token; with `hashOnly` in the client config, which the welcome sheet and runbook require, the receipt never leaves the tenant's machine at all. |
| Where is the data? | Helsinki, Finland (Hetzner), in the EU. One region. Backups are on the same machine and, once a destination is configured, mirrored to EU object storage. |
| Is data encrypted in transit? | Yes, TLS 1.2 or later on every endpoint, certificates from Let's Encrypt via Caddy. The signer is reachable only inside the container network. |
| Is data encrypted at rest? | The disk is not encrypted by us; the data it holds is hashes and public signatures. Tenant tokens are stored as SHA-256 hashes. The log's private key is on the volume and read only by the signer process. |
| Retention and deletion? | Leaves are kept for the life of the tenant's log, since removing one changes every later root and breaks the tenant's own evidence. On offboarding the tenant is disabled and their log stays readable so their receipts keep verifying; deletion of the whole log is available on written request and is irreversible. Backups are kept thirty days. |
| Can a tenant take their data? | Yes, any time, with their own token: `agent-custody log-export` fetches every leaf hash, the signed head, the published keys, the checkpoints, their usage, and their audit rows, checks that they add up, and writes a log copy the verifier reads offline. |
| Subprocessors | Hetzner Online GmbH (hosting, Finland); GitHub (source, CI, container images, the website, the outside monitor); npm and PyPI (package distribution); Let's Encrypt (certificates); GoDaddy (DNS); Stripe Payments Europe Ltd (card payments for the Team plan; card details never reach us). No analytics or telemetry in the packages, the log, or the portal. |

## Access control

| question | answer |
| --- | --- |
| Who can administer the hosted log? | The operator, with the admin token, through the admin page or the command line on the server. The admin token is a single shared secret; the page asks for a name that is recorded with every action. There is no SSO or per-user credential yet. |
| Is administrative access logged? | Yes. Every tenant created or disabled and every token minted or revoked is recorded with who, from where, what, and when, never the token; tenants see the rows that concern them in their export. |
| How do tenants authenticate? | A bearer token per fleet, shown once, stored hashed, revocable individually, rate-limited per token. Tenants cannot see or affect other tenants. The portal, where tenants register and manage keys, uses an email and a password hashed with scrypt, a signed session cookie (HttpOnly, SameSite=Strict, fourteen days), and throttled sign-in; there is no multi-factor authentication or SSO on it yet. |
| How is the server accessed? | SSH with a key; root password login is disabled. Password authentication for other accounts is currently enabled by the OS default and is being turned off. Ports open: 22, 80, 443. |
| Multi-factor authentication? | Publishing to npm requires it on the publishing account. The admin page has none beyond the token and the recorded name. |

## Operations

| question | answer |
| --- | --- |
| Monitoring | A probe from GitHub's machines every ten minutes verifies the head against the published keys, that checkpoints keep up, and that the head extends them; failures email the operator. [Status](https://github.com/svayatta/agent-custody/actions/workflows/monitor.yml). |
| Availability commitment | None contractually yet. The design fails closed: a pre-committed call is withheld when the log is unreachable, so an outage is a denial of service on the agent, not a loss of evidence. One VM, no failover. |
| Backups and restore | Nightly: the key volume and a database dump, kept thirty days. A restore drill script in the [runbook](https://github.com/svayatta/agent-custody/blob/main/deploy/RUNBOOK.md) restores a night's backups beside the live service and checks the restored log against the live key; first run 2026-09-09, passed, to be repeated quarterly. |
| Patching | Ubuntu unattended upgrades; the application image is rebuilt per release from the published package; Dependabot opens updates weekly for npm, pip, GitHub Actions, and the image base. |
| Incident response | The runbook covers a leaked admin or signer token, a compromised host, and every monitor failure. Affected tenants receive the written record of what was noticed, when, and what was done. No formal SLA on notification time yet; the intent is 72 hours. |
| Key management | Ed25519. The log's private key is held only by the signer process; the log process facing the internet has no key. Keys are published at a well-known URL and pinned by verifiers; rotation keeps old public keys published so old heads keep verifying; yearly rotation and on suspicion. No HSM. |
| Change management | Every change is a commit on the public repository, tested by CI before push, released as a versioned package, and recorded in the changelog. Deployment is a version bump in the server's environment. |

## Software supply chain

| question | answer |
| --- | --- |
| Dependencies | Small and pinned: the receipts package depends on Cedar, the MCP SDK, and zod at runtime; Postgres support uses the `pg` driver as an optional peer. The lockfile is frozen in CI. |
| Build integrity | The container images (the log and the gateway) are built by GitHub Actions on native runners, smoke-tested before they are pushed, and carry a provenance attestation and an SBOM. Each is signed with cosign, keyless, by the workflow's identity on main, so a pulled image can be checked against the workflow that built it, and a workflow run cannot point a version tag at anything but the tagged release commit (the commands are in `deploy/README.md`). Base images are pinned by digest and every third-party GitHub Action by commit. A release image is built from the published package and tagged by version; a build from main is tagged `edge`. The packages' transitive dependencies are resolved at image build time, not frozen by a lockfile, and the SBOM records what was installed. Packages to date were published by hand from the maintainer's machine with a scoped token; publishing through the release workflow with provenance attestations and no long-lived token is set up in the repository and waits on the registries being told to trust it. |
| Secrets in code | None. Every secret reaches the software through a named environment variable, checked at startup; the repository has a gitignored `.npmrc` and `.env`. |
| Vulnerability handling | Private report to the security contact; fix in the packages and the hosted log before disclosure; credit in the changelog. |

## What we would tell a reviewer to look at first

1. The [threat model](/receipts/threat-model): which defences are properties of the evidence and which depend on the deployment.
2. The [verification guide](/receipts/verification): what each check proves, and the browser verifier that runs them on a receipt with no server.
3. The [runbook](https://github.com/svayatta/agent-custody/blob/main/deploy/RUNBOOK.md): what the operator does, and what is not yet done.

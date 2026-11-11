---
sidebar: false
aside: false
---

# Privacy

What Charioteer Consulting Ltd, the operator of agent-custody.dev and the hosted log at log.agent-custody.dev, collects, and what it does with it. Last reviewed 2026-09-09. Questions to partha@charioteerconsulting.com.

## This website

The site is static pages served by GitHub Pages. We run no analytics, set no cookies, and load nothing from third parties except the pages themselves. GitHub, as the host, keeps its own access logs under [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

The browser verifier at [/verify](/verify) runs entirely in your browser. A receipt you drop on it never leaves your machine.

## The early-access form

The form has no backend. Submitting it opens your own mail client with your answers filled in, addressed to partha@charioteerconsulting.com; nothing is sent until you send it. The mail then contains what you wrote: your work email, what agents you run and on what data, which stores you use, and whether you have been asked to prove an agent's actions. We use it to reply to you and to decide who to onboard, keep it in the mailbox for as long as we are in contact, and delete it on request. It is shared with nobody.

## The hosted log

A tenant of the hosted log sends it leaf hashes: the SHA-256 of a receipt envelope, sixty-four hexadecimal characters that identify a receipt without revealing anything in it. The log stores, per tenant, those hashes with the time they arrived, the tenant's id and log id, the SHA-256 hash of each access token with a label the tenant chose, signed tree heads and checkpoints, and an audit trail of administrative actions naming the operator who took them. The log never receives receipts, tool arguments, results, or the memory ledger; those stay on the tenant's machines by design, and the tenant's configuration (`hashOnly`) is what enforces it.

The log's web server records the requesting IP address and the request path in its logs for rate limiting and incident handling; those logs are kept on the server for thirty days.

The log runs on a server in Helsinki, Finland, operated by Hetzner Online GmbH. Backups of the database are kept for thirty days on the same server and, once configured, on EU object storage. Data is not transferred outside the EU or the UK except to a tenant who exports it.

A tenant can export everything the log holds about them at any time with their own token, and can ask for their log to be disabled or deleted; deletion is irreversible and breaks the inclusion proofs in the tenant's own receipts, which the [runbook](https://github.com/svayatta/agent-custody/blob/main/deploy/RUNBOOK.md) explains.

## The dashboard

Signing up at app.agent-custody.dev stores your name, your company or organisation, your role if you gave one, your email address, your phone number and Telegram username if you gave them, a scrypt hash of your password (never the password), the tenant id you chose, and the time; we use the contact details to reach you about your tenant and for nothing else, and the operator sees them on the admin page; registering sends you two emails through Resend, Inc., your setup sheet at once (never your key) and, about an hour later, a note from the founder asking about your setup, whose [privacy policy](https://resend.com/legal/privacy-policy) covers what it holds in transit, and sends the operator a note with the details you entered; signing in sets a session cookie that carries nothing but a signed user id and expires in fourteen days. Every action you take on your tenant, minting or revoking a key, changing a plan, is recorded in the tenant's audit trail with your email as the actor, and you see those rows in your export. The portal's web server records the requesting IP address for rate limiting, kept thirty days. There is no password reset until an email provider is configured; write to us and we verify you another way.

Paying for the Team plan goes through Stripe Payments Europe Ltd: the card and billing details are entered on Stripe's pages and never reach us; we store Stripe's customer and subscription identifiers against your tenant and the subscription's status, and Stripe's own [privacy policy](https://stripe.com/privacy) covers what it holds.

## The packages

`@agent-custody/receipts`, `@agent-custody/state`, and `agent-custody` on PyPI run on your infrastructure and send nothing to us. The only network calls they make are the ones you configure: to your own upstreams, to the log you name, and to the exporters you turn on.

## Your rights

Under the UK GDPR and the EU GDPR you can ask what personal data we hold about you, have it corrected or deleted, and object to its use. Write to partha@charioteerconsulting.com. If you are not satisfied with the answer you can complain to the UK Information Commissioner's Office or to your local supervisory authority.

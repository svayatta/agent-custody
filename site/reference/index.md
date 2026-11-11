# Reference

Every feature of agent-custody, how to use it, and the exact request and response of every function and endpoint. The narrative guides on [agent-custody.dev](https://agent-custody.dev/guide/getting-started) explain why; these pages say what goes in and what comes out.

## Reference pages

What each component is for, and when you need it, is on [Components](/guide/pieces). Each one has a reference page:

| component | package | reference |
| --- | --- | --- |
| Gateway | `@agent-custody/receipts` | [gateway](./gateway) |
| Egress witness | `@agent-custody/receipts` | [egress](./egress) |
| ACS Guardian | `@agent-custody/receipts` | [acs](./acs) |
| Door | `@agent-custody/receipts` | [door](./door) |
| SDK | `@agent-custody/receipts` | [TypeScript SDK](./sdk-typescript) |
| Sidecar | `@agent-custody/receipts` | [sidecar](./sidecar) |
| Python | `agent-custody` on PyPI | [Python](./python) |
| Claude Code | `@agent-custody/receipts` | [Claude Code](./claude-code) |
| Log | `@agent-custody/receipts` | [log API](./log-api) |
| Verifier | `@agent-custody/receipts` | [verify and audit](./verify) |
| Hosted log | log.agent-custody.dev | [hosted](./hosted) |
| Memory | `@agent-custody/state` | [memory](./memory) |
| Explain, review, pack | `@agent-custody/state` | [explain and packs](./state-tools) |
| Command line | both packages | [CLI](./cli) |

## Install

```bash
npm install @agent-custody/receipts @agent-custody/state
pip install agent-custody
```

The packages run on Node 22 or later and Python 3.10 or later. Nothing phones home; the only network calls are the ones you configure.

## Conventions on these pages

- **Request** and **Response** blocks are JSON exactly as sent and received. Fields marked *optional* may be omitted; fields marked *env* name an environment variable and never carry the secret itself.
- Every signed object is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope: `{ "payloadType", "payload" (base64), "signatures": [{ "keyid", "sig" }] }`. The `keyid` is the SHA-256 of the signer's public key in SPKI DER, so a verifier matches keys without being told which is which.
- `provenance` on a receipt field is one of `attested` (signed by a key other than the issuer's), `observed` (the issuer saw it itself), or `claimed` (the agent said so). The [proof table](https://agent-custody.dev/receipts/#what-a-receipt-proves-and-what-it-does-not) says what each is worth.
- Money is integer minor units everywhere. Timestamps are ISO 8601, UTC.

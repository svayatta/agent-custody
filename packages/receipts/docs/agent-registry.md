# The agent registry

An organisation that runs agents registers each one on the portal, and the portal signs it a **passport**. A site whose [door](door.md) trusts the registry's key admits that agent as `verified`. The site needs nothing per agent, and the door asks the registry nothing when a request arrives.

## What a passport is

A passport is a DSSE envelope of type `application/vnd.agent-custody.passport+json`, signed by the registry's key:

```json
{
  "version": "0.1",
  "registry": "https://app.agent-custody.dev/",
  "agentId": "agt_5325ae63b111bdcb",
  "agent": "did:key:z6Mkn6Tz2tjzcb8f…",
  "name": "Carted shopper",
  "owner": "carted",
  "contact": "agents@carted.example",
  "capabilities": ["refunds"],
  "issuedAt": "2026-11-23T09:00:00.000Z",
  "expiresAt": "2026-11-24T09:00:00.000Z"
}
```

- `agent` is the agent's own Ed25519 key, written as a [did:key](https://w3c-ccg.github.io/did-key-spec/). The agent holds the private key; the registry never sees it.
- `owner` is the portal tenant that registered the agent. `contact` is how a site reaches the agent's operator.
- `capabilities` are the organisation's own words for what the agent does: lowercase letters, digits, and `. _ : -`, at most 32. The registry does not check them. A site's policy decides what they are worth.
- A passport lives for a day by default (`--passport-seconds`, from 60 seconds to 7 days), and never past the registration's own expiry.
- `erc8004`, when the agent is [linked to an ERC-8004 identity](#link-an-erc-8004-identity): `{ agentRegistry, agentId, owner, block }`, as the registry last checked it on chain.

**A passport is public.** It proves nothing without a signature by the agent's key on the same request, so the registry serves one to anyone who asks, like a certificate.

## Register an agent

The portal runs the registry when it starts with a registry key, and `--portal-url`, which names the registry in every passport:

```bash
agent-custody keygen --dir keys --name registry
export REGISTRY_KEY="$(cat keys/registry.key)"
agent-custody portal --db-env DATABASE_URL --secret-env PORTAL_SECRET --public-url https://log.example/ \
  --portal-url https://app.example/ --registry-key-env REGISTRY_KEY
```

The registry key is its own, never the log's. To keep it out of the process that faces the internet, hold it in a signer, `agent-custody signer --key keys/registry.key --port 8791 --token-env REGISTRY_SIGNER_TOKEN`, and start the portal with `--registry-signer-url http://signer:8791/ --registry-signer-token-env REGISTRY_SIGNER_TOKEN` instead.

An admin of a tenant registers an agent with the agent's did:key, a contact, its capabilities, and an expiry at most 366 days out:

```bash
curl -b session.txt -H 'content-type: application/json' https://app.example/api/agents \
  -d '{ "name": "Carted shopper", "contact": "agents@carted.example", "capabilities": ["refunds"],
        "agent": "did:key:z6Mk…", "expiresAt": "2027-02-21T00:00:00Z" }'
```

The answer has the registry entry and a first passport. Every key belongs to one agent, and a tenant has at most 100 active agents. `POST /api/agents/<id>` changes the name, contact, capabilities, key, or expiry, and `POST /api/agents/<id>/revoke` revokes the agent for good. Each is in the tenant's audit trail. The [hosted reference](../../../site/reference/hosted.md) lists every route.

In code, `didKeyOf(publicKey)` gives a key's did:key.

## Link an ERC-8004 identity

An agent that already has a token in an [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) Identity Registry can carry it in its passport. The registry vouches for the agent, as before; the link adds the agent's portable on-chain identity, so a site can require one. ERC-8004 is still a draft, and only its `registration-v1` file is read.

The portal reads a chain only with an RPC URL for it, from the environment:

```bash
export BASE_RPC="https://…"   # a provider's URL often carries its key
agent-custody portal … --registry-key-env REGISTRY_KEY --erc8004-rpc-env 8453=BASE_RPC [--ipfs-gateway https://ipfs.io]
```

The owner adds `"erc8004": { "agentRegistry": "eip155:8453:0x…", "agentId": "7" }` to `POST /api/agents` or `POST /api/agents/<id>`. `agentId` is the token id in decimal. Before it stores the link, the registry reads, at one block:

1. `ownerOf(agentId)`: the token exists and has an owner.
2. `tokenURI(agentId)`: where the registration file is. It fetches the file: an inline `data:application/json` URI, `https://` (never from an internal address, following no redirect, within 5 seconds and 64 KiB), or `ipfs://` through `--ipfs-gateway`.
3. The file: its `type` is `registration-v1`, `active` is true, `registrations` lists this `agentRegistry` and `agentId`, and `services` has `{ "name": "DID", "endpoint": "<the agent's did:key>" }`.

So the agent's owner publishes its did:key in the token's registration file first. Anything that does not agree is refused with the reason. The entry records the owner address, the block, the file's sha256, and when it was checked. A new key while a link stands is checked against the file again, so rotate the key in the file first. `"erc8004": null` unlinks.

A link is checked again before a passport carries it, when the last check is older than `--erc8004-recheck-seconds` (an hour by default), at most once a minute per agent. When that check fails, for example because the owner marked the agent inactive or moved the token to a file that no longer lists the key, passports carry no link until a check succeeds, and the entry shows the error.

The door reads no chain. It records the link from the passport in `arrival.passport.erc8004`, and a policy can require it:

```cedar
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport has erc8004 &&
  context.facts.arrival.passport.erc8004.agentRegistry == "eip155:8453:0x…"
};
```

What the link does not do: it reads the ERC-8004 Identity Registry only, not its Reputation or Validation registries; it does not make anyone's token trustworthy (anyone can register one for gas, which is why the registry still vouches); and a door that trusts ERC-8004 registries directly, with no portal, is not built.

## What the registry publishes

| path | what |
| --- | --- |
| `GET /.well-known/agent-custody-registry.json` | the registry's key document: its URL, the passport type and header, how long a passport lives, the chain ids whose ERC-8004 registries it reads (`erc8004Chains`), and its keys (`keyid`, `alg`, `publicKeyPem`, `validFrom`) |
| `GET /registry/agents/<id>` | the agent's entry: name, owner, contact, capabilities, its key as a did:key and as an Ed25519 JWK (`kid` is the did:key, `exp` the registration's expiry), `status` (`active`, `revoked`, or `expired`), and `erc8004`, the linked identity as last checked (with `error` when the last check failed) or null |
| `GET /registry/agents/<id>/passport` | a fresh passport for an active agent; `410` for a revoked or expired one |

The agent fetches a fresh passport before the one it holds expires. It needs no session for that.

## Admit registered agents at a door

Put the registry's public key in a file, list it in `trustedRegistryKeys`, and configure `webBotAuth`, which checks the agent's signature. Its `agents` may be empty, because a did:key carries its own key and the door fetches nothing:

```json
{
  "trustedRegistryKeys": ["keys/registry.pub"],
  "webBotAuth": { "authorities": ["shop.example"] }
}
```

The door refuses to start with `trustedRegistryKeys` and no `webBotAuth`. In a Worker the keys are the `TRUSTED_REGISTRY_KEYS` variable.

The agent sends the passport as base64url JSON in `X-Agent-Custody-Passport`, and signs the request as for [Web Bot Auth](door.md#a-did-key-signature): RFC 9421, Ed25519, `tag="web-bot-auth"`, `@authority` covered, a nonce, and `keyid` set to its did:key. With no grant in the request, the door then records:

- `class: "verified"`, and `subject` the agent's did:key, which is the Cedar `principal`;
- `arrival.passport`, with `outcome: "verified"`, the registry, the registry's keyid, the agent's id, did:key, name, owner, capabilities, expiry, the passport's digest, and the passport itself (`envelope`).

A policy reads the registry's word as a fact. Test that the field is there first, since an arrival without a passport has none:

```cedar
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.capabilities.contains("refunds") &&
  context.args.body.amount <= 5000
};
```

| what arrived | `passport.outcome` | `class` |
| --- | --- | --- |
| a passport from a trusted registry, in its window, under a signature by its did:key | `verified` | `verified` |
| the same passport under another key's signature, or with no signature | `wrong-sender` | `claimed` |
| a passport from another registry, edited, expired, or a header that is not a passport | `invalid` | `claimed` |
| a passport at a door with no `trustedRegistryKeys` | `unchecked` | `claimed` |
| a grant and a passport | recorded | decided by the grant alone |

A replayed request is refused as any Web Bot Auth signature is: the nonce is kept for the passport's did:key, so the second use is `invalid`, and the arrival is `claimed`.

## What the receipt shows

The receipt names the agent as `observed`, never `attested`: `agent: { id: "did:key:z6Mk…", provenance: "observed" }`, and the principal is `claimed`, as for any arrival admitted by its signature alone. A reader can check the recorded passport again under the registry's key (`verifyPassport(envelope, [registryKey], timestamp)`), but cannot repeat the check of the request's signature, which the receipt does not carry.

## What it does not do

- **Revocation reaches the door when the passport expires.** Revoking an agent stops new passports. The passport the agent already holds works until its `expiresAt`, because the door asks the registry nothing. `--passport-seconds` is that delay; shorten it if a day is too long.
- **A key rotation is the same.** A passport for the old key works until it expires.
- **Capabilities are the owner's claim.** The registry records what the organisation says the agent does, and signs that it said so. It does not check it.
- **A passport says who, not on whose behalf.** It does not name a principal or a route. For that, the agent presents a [grant](door.md#presenting-a-passport) from a principal the site trusts, and the door decides by the grant.
- **Admission lists** (allow these registered agents, block those) and a search of the registry by capability are not built yet.

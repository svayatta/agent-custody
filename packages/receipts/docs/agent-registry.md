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

An admin of a tenant registers an agent with the agent's did:key, a proof that whoever registers it holds that key, a contact, its capabilities, and an expiry at most 366 days out. The agent's operator makes the proof with the agent's private key:

```bash
agent-custody registry proof --key agent.key --registry https://app.example/ --tenant carted
# {"agent":"did:key:z6Mk…","proof":"…"}
curl -b session.txt -H 'content-type: application/json' https://app.example/api/agents \
  -d '{ "name": "Carted shopper", "contact": "agents@carted.example", "capabilities": ["refunds"],
        "agent": "did:key:z6Mk…", "proof": "…", "expiresAt": "2027-02-21T00:00:00Z" }'
```

The proof is the key's Ed25519 signature over the registry's URL, the tenant, and the did:key (`registrationProof` in code), so it registers that key with that tenant at that registry only. Without it, a tenant could register a did:key it saw in a grant or a signature and choose that agent's capabilities. A key rotation needs the new key's proof.

The answer has the registry entry and a first passport. Every key belongs to one live agent, which the database enforces, and a tenant has at most 100 agents that are not revoked. An expired agent counts until it is revoked. `POST /api/agents/<id>` changes the name, contact, capabilities, key, or expiry, and `POST /api/agents/<id>/revoke` revokes the agent for good. Each is in the tenant's audit trail. The [hosted reference](../../../site/reference/hosted.md) lists every route.

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
2. `tokenURI(agentId)`: where the registration file is. It fetches the file: an inline `data:application/json` URI, `https://` (never from an internal address, following no redirect, within 5 seconds and 64 KiB), or `ipfs://` through `--ipfs-gateway`, as a CID and plain path segments that stay under the gateway's `/ipfs/<cid>/`; a `.` or `..` segment is refused.
3. The file: its `type` is `registration-v1`, `active` is true, `registrations` lists this `agentRegistry` and `agentId`, and `services` has `{ "name": "DID", "endpoint": "<the agent's did:key>" }`.

So the agent's owner publishes its did:key in the token's registration file first. Anything that does not agree is refused with the reason. The entry records the owner address, the block, the file's sha256, and when it was checked. A new key while a link stands is checked against the file again, so rotate the key in the file first. `"erc8004": null` unlinks.

A link is checked again before a passport carries it, when the last check is older than `--erc8004-recheck-seconds` (an hour by default, 60 to 86400), at most once a minute per agent. When that check fails, for example because the owner marked the agent inactive or moved the token to a file that no longer lists the key, passports carry no link until a check succeeds, and the entry shows the error. A check that finishes after the owner changed the link or rotated the key is not stored: it was for a link the agent no longer has.

The door reads no chain. It records the link from the passport in `arrival.passport.erc8004`, only when the passport is `verified`, bound to the request by the agent's signature; a passport under another key carries no link into the policy. A policy can require it, testing the outcome too:

```cedar
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.outcome == "verified" &&
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
| `GET /registry/agents?capability=&owner=&limit=&after=` | the active agents that hold a capability (or belong to an owner), by id, a page of up to 100 at a time; see [admission lists](admission-lists.md#find-agents-in-the-registry) |
| `GET /registry/agents/<id>/passport` | a fresh passport for an active agent; `410` for a revoked or expired one |

These reads need no session. Each address gets a burst of 120 of them (search, entries, and passports together) and then one every 2 seconds; past that the registry answers `429` with `Retry-After`.

The agent fetches a fresh passport before the one it holds expires. It needs no session for that.

## Admit registered agents at a door

Put the registry's public key in a file, list it in `trustedRegistryKeys` with the registry's URL (the `registry` of its key document), and configure `webBotAuth`, which checks the agent's signature. Its `agents` may be empty, because a did:key carries its own key and the door fetches nothing:

```json
{
  "trustedRegistryKeys": [{ "key": "keys/registry.pub", "registry": "https://app.agent-custody.dev/" }],
  "webBotAuth": { "authorities": ["shop.example"] }
}
```

A key bound to a registry admits only passports that name that registry, in any spelling of its URL; a passport it signed that names another registry is `invalid`. A registry writes its own URL into its passports, so without the binding a door that trusts two registries lets either one vouch for the other's agents. A bare path, `"keys/registry.pub"`, is still accepted and trusts the key for any registry; `agent-custody check` warns when more than one registry key is trusted and any is bare.

The door refuses to start with `trustedRegistryKeys` and no `webBotAuth`. In a Worker the keys are the `TRUSTED_REGISTRY_KEYS` variable: SPKI PEM keys, each trusted for any registry, or a JSON list of `{ "publicKeyPem", "registry" }`, the `keys` of the key document with the registry's URL added to each. In the list, `registry` is required, and a JSON object, such as the whole key document, is refused: its key would otherwise be read bare. One key listed twice, for two registries or bound and also bare, stops the door at start.

The agent sends the passport as base64url JSON in `X-Agent-Custody-Passport`, and signs the request as for [Web Bot Auth](door.md#a-did-key-signature): RFC 9421, Ed25519, `tag="web-bot-auth"`, a nonce, and `keyid` set to its did:key. For the passport to count, the signature also covers what binds it to this one request:

- `@authority`, `@method`, `@path`, `@query` (the query string, or `?` when there is none), and `x-agent-custody-passport`;
- on any method but GET, HEAD, and OPTIONS, `content-digest`: a `Content-Digest` field (RFC 9530, `sha-256` or `sha-512`) that the door checks against the body it read.

```
Signature-Input: sig1=("@authority" "@method" "@path" "@query" "x-agent-custody-passport" "content-digest");created=…;expires=…;keyid="did:key:z6Mk…";alg="ed25519";nonce="…";tag="web-bot-auth"
```

A passport is public, so without that a signature the agent made for one request, or before it held a passport the door would take, could be sent again with the passport attached. A door in authz mode does not see the body, so it admits a passport on a safe method only. With no grant in the request, the door then records:

- `class: "verified"`, and `subject` the agent's did:key, which is the Cedar `principal`;
- `arrival.passport`, with `outcome: "verified"`, the registry, the registry's keyid, the agent's id, did:key, name, owner, capabilities, expiry, the passport's digest, and the passport itself (`envelope`).

Only a `verified` passport puts the registry's entry in the fact. Any other outcome records the outcome, the error, and at most the registry and the did:key the passport names, so a passport the signer is not bound to cannot carry another agent's capabilities into the policy, even on an arrival that a grant or a signature verified.

A policy reads the registry's word as a fact. Test that the field is there and that the passport was verified, since an arrival without a passport has none:

```cedar
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.outcome == "verified" &&
  context.facts.arrival.passport.capabilities.contains("refunds") &&
  context.args.body.amount <= 5000
};
```

| what arrived | `passport.outcome` | `class` |
| --- | --- | --- |
| a passport from a trusted registry, in its window, under a signature by its did:key that covers all of the above | `verified` | `verified` |
| the same, with a signature that leaves out a component above, or a `Content-Digest` that is not of the body | `unbound` | `claimed` |
| the same passport under another key's signature, or with no signature | `wrong-sender` | `claimed` |
| a passport from another registry, edited, expired, or a header that is not a passport | `invalid` | `claimed` |
| a passport at a door with no `trustedRegistryKeys` | `unchecked` | `claimed` |
| a grant and a passport | recorded | decided by the grant alone |

A replayed request is refused as any Web Bot Auth signature is: the nonce is kept for the passport's did:key, whatever grant the request also carries, so the second use is `invalid`, and the arrival is `claimed`. The nonce is kept too for a passport that is not yet valid at the door, because the registry's clock is ahead, so the request cannot be sent again once its window opens. The signature covers `@query`, so the request cannot be sent again with another query either.

## What the receipt shows

The receipt names the agent as `observed`, never `attested`: `agent: { id: "did:key:z6Mk…", provenance: "observed" }`, and the principal is `claimed`, as for any arrival admitted by its signature alone. A reader can check the recorded passport again under the registry's key (`verifyPassport(envelope, [registryKey], timestamp)`), but cannot repeat the check of the request's signature, which the receipt does not carry.

## What it does not do

- **Revocation reaches the door when the passport expires.** Revoking an agent stops new passports. The passport the agent already holds works until its `expiresAt`, because the door asks the registry nothing. `--passport-seconds` is that delay; shorten it if a day is too long.
- **A key rotation is the same.** A passport for the old key works until it expires.
- **Capabilities are the owner's claim.** The registry records what the organisation says the agent does, and signs that it said so. It does not check it.
- **A passport says who, not on whose behalf.** It does not name a principal or a route. For that, the agent presents a [grant](door.md#presenting-a-passport) from a principal the site trusts, and the door decides by the grant.
- **Who a site admits is the site's own list.** The registry answers a search by capability (`GET /registry/agents?capability=`), and a site lists the agents it admits or blocks in its door's [admission lists](admission-lists.md).

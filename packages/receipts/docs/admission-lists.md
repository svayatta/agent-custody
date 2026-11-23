# Admission lists

A site keeps its own named lists of agents, such as `partners` or `blocked`. Its [door](door.md) records in each arrival fact which lists the arrival's agent is on, and its Cedar policy decides what each list means. The decision is a receipt that names the lists and the digest of the lists in force, so a reader knows which version of the lists the door used.

To fill a list, a site can search an [agent registry](agent-registry.md) by capability.

## Find agents in the registry

The registry answers a search without a session:

```bash
curl 'https://app.agent-custody.dev/registry/agents?capability=refunds&limit=50'
# { "registry": "https://app.agent-custody.dev/", "agents": [ <entry>, … ], "next": "agt_…" | null }
```

It lists active agents only, never a revoked or expired one, ordered by id. `capability` filters by one capability and `owner` by one tenant. `limit` is 1 to 100 (50 by default); any other value is a `400`. To get the next page, send `after=<next>`. `registry` is the registry's URL as its passports name it: copy it into a list entry. Each entry is the one `GET /registry/agents/<id>` publishes, without `contact` or `history`: id, name, owner, capabilities, its key as a did:key and a JWK, and its ERC-8004 link when it has one. A search finds agents; it is not a directory of contacts. An agent's contact is on its own entry and in its passport, which reaches every site the agent visits.

The registry's public reads (the search, an agent's entry, and its passport) allow each address a burst of 120 and then one every 2 seconds; past that they answer `429` with `Retry-After`.

The registry signs nothing about a search. A site that lists an agent from a search names it by the entry's registry and id, and the door then admits the agent only on a passport the registry signed.

## Write the lists

The lists are a JSON file beside the door config:

```json
{
  "lists": {
    "partners": [
      { "registry": "https://app.agent-custody.dev/", "agentId": "agt_d0cdd11e729cf856" },
      { "erc8004": { "agentRegistry": "eip155:8453:0x…", "agentId": "7" } }
    ],
    "crawlers": [{ "agent": "https://crawler.example" }],
    "blocked": [{ "agent": "did:key:z6Mk…" }]
  }
}
```

```json
{ "admissionLists": "admission.json" }
```

A list name is lowercase letters, digits, and `. _ -`, at most 64 characters. There are at most 64 lists, of at most 10,000 entries each. An entry names an agent in one of three ways, by what the door checks:

| entry | matches a `verified` arrival | survives a key rotation |
| --- | --- | --- |
| `{ "registry", "agentId", "version"? \| "versions"? }` | whose [passport](agent-registry.md#admit-registered-agents-at-a-door) is `verified`, from that registry, for that agent id | yes |
| `{ "erc8004": { "agentRegistry", "agentId" } }` | whose `verified` passport carries that [ERC-8004 link](agent-registry.md#link-an-erc-8004-identity), which the registry checked on chain | yes, while the token's file names the new key |
| `{ "agent" }` | whose `subject` is that value: a did:key, a Web Bot Auth signature agent's origin, or the agent a trusted grant names | no, for a did:key |

A registry entry may also name the agent's versions: `"version": "1.4.0"` for one, or `"versions": { "from": "1.2.0", "below": "2.0.0" }` for a range (`from` included, `below` not, either may be left out). Versions compare as numbers, so 1.10.0 is above 1.2.0. An entry with a version matches only a `verified` passport that carries a version in it; an agent whose owner registered no version is not on the list by that entry. When the agent arrives at a version the list does not name, the receipt shows `passport.agentVersion` and lists without that name, so the site sees the change before it admits it.

The registry's URL is part of a registry entry because an agent id is unique only within one registry. A URL or origin is compared in one spelling, so `https://APP.example.test:443` and `https://app.example.test/` name the same registry, and `https://Crawler.Example/` the agent `https://crawler.example`; a did:key is compared exactly.

**Bind each registry key to its registry.** A passport's `registry` is written by the registry that signs it. A door that trusts the keys of two registries, each as a bare path, lets either one issue a passport that names the other's URL and an agent id from it, and so put its own agent on a list entry meant for the other's agent. Give each key the one registry it speaks for, `{ "key": "keys/registry.pub", "registry": "https://app.agent-custody.dev/" }` ([the agent registry](agent-registry.md#admit-registered-agents-at-a-door)), and a passport that names any other registry is `invalid`. `agent-custody check` warns when more than one registry key is trusted and any is bound to no URL. The binding protects `{ registry, agentId }` entries. An `{ erc8004 }` entry names no registry, so it trusts the ERC-8004 check of every registry whose key the door trusts. Prefer registry entries for registered agents, because they survive a key rotation. Use `agent` for an agent with no registry, or to block one key whatever registry vouches for it.

The door reads the file when it starts, and refuses to start if the file is not valid. It reads the file again whenever it changes. A changed file that cannot be read, or is not valid, leaves the lists in force and prints `ADMISSION LISTS NOT RELOADED`. Emptying the lists instead would also empty a block list. `agent-custody check --config door.json` checks the file. In a Worker, the lists are the `ADMISSION_LISTS` variable, and a change is a deploy.

## Use them in a policy

The door adds `admission` to every arrival fact when it has lists:

```json
{ "admission": { "lists": ["partners"], "digest": "c34ef919ab97…" } }
```

`lists` holds the names of the lists the agent is on, sorted, and is empty when it is on none. `digest` is the sha256 of the lists file in force. The names mean what the policy makes of them:

```cedar
// a refund is for a verified partner, and never for a blocked agent
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has admission &&
  context.facts.arrival.admission.lists.contains("partners")
};
forbid(principal, action == Action::"refund", resource)
when { context.facts.arrival has admission && context.facts.arrival.admission.lists.contains("blocked") };
```

A `forbid` beats a `permit`, so an agent that is a partner by its registry entry and blocked by its key is refused. Test `has admission`, because a door without lists, or a receipt from before the lists, has no such field.

## What puts an agent on a list

Only what the door checked. An arrival that is not `verified` is on no list. A passport under another key's signature, or under a signature that does not bind it to the request, does not put the registry's agent on a list, even when the arrival is verified as itself by its own grant. A claim therefore cannot add an agent to an allow list. A policy that blocks with `forbid` must not rely on a claimed arrival being listed: such an arrival is on no list, so refuse it some other way, for example by permitting only `verified` arrivals, as above.

## What it does not do

- **Lists live in the door's config, not the registry.** The registry holds agents; each site keeps its own lists in its own file, so no one else can change who a site admits. There is no shared list service.
- **Lists do not deny or allow on their own.** Every meaning comes from the policy.
- **The digest names a version of the lists, not the lists themselves.** To read what a receipt's lists said, keep each version of the file, for example in version control.

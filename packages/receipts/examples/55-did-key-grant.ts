// Aspect: a grant that names its agent by a did:key, the identifier of the agent's Ed25519 key. Source: src/did-key.ts, src/door.ts
// Run:    node examples/55-did-key-grant.ts
//
// An agent without a name of its own is named by its key: did:key:z6Mk... A shop's principal signs a grant for that
// identifier, and the door in front of the shop checks it as any grant, and checks the identifier too: it must decode to
// an Ed25519 key, and must be the key the grant's agentKey names. A grant that checks is verified; one that names no
// key, or two different keys, is claimed; an arrival with nothing is unknown. Each is a receipt that verifies.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, publicKeyToPem, type Envelope } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { didKeyOf, publicKeyFromDidKey } from "../src/did-key.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

step(1, "the agent's key, and its did:key: the identifier is the key, so anyone can read the key back from it");
const agent = generateKeyPair();
const did = didKeyOf(agent.publicKey);
console.log(`   ${did}`);
console.log(`   decodes to the agent's key: ${publicKeyFromDidKey(did).keyid === agent.keyid}`);

step(2, "a shop behind the door; the shop's principal signs a refund grant for the did:key");
const origin = await startOrigin();
const fx = buildDoorFixture(out("55-did-key-grant"), origin.url);
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });
const grant = (agentId: string, agentKey?: string) => createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: agentId, scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString(), ...(agentKey ? { agentKey } : {}) });

step(3, "four arrivals ask for a refund: the grant, a garbled did:key, a grant naming two keys, and nothing at all");
let ok = true;
const statuses: number[] = [];
for (const [label, g] of [
  ["did:key grant      ", grant(did, publicKeyToPem(agent.publicKey))],
  ["garbled did:key    ", grant("did:key:z6Mk0bad")],
  ["two different keys ", grant(did, publicKeyToPem(generateKeyPair().publicKey))],
  ["nothing presented  ", undefined],
] as [string, Envelope | undefined][]) {
  const res = await fetch(`${door.url}/refunds`, { method: "POST", headers: { "content-type": "application/json", ...(g ? { authorization: `Bearer ${grantHeader(g)}` } : {}) }, body: JSON.stringify({ order: "o_1", amount: 100 }) });
  await res.text();
  statuses.push(res.status);
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
  const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
  const a = p.facts[ARRIVAL_FACT]!.value as Arrival;
  const verified = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile }).ok;
  ok &&= verified;
  console.log(`   ${label} HTTP ${res.status}, ${a.class}, grant ${a.grant}${a.grantError ? ` (${a.grantError})` : ""}; agent ${p.agent.provenance}; receipt ${verified ? "verified" : "FAILED"}`);
}

await door.close();
await host.close();
await origin.close();
if (!ok || statuses.join() !== "200,403,403,403") throw new Error("the did:key grant was not classified as described");
console.log("\nOK");

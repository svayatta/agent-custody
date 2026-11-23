// Aspect: the agent registry: register an agent, receive a passport, and be admitted by a door that holds only the registry's key. Source: src/registry.ts, src/portal.ts, src/door-core.ts
// Run:    node examples/62-agent-registry.ts
//
// An agent-commerce company signs up on the portal and registers its shopping agent: the agent's own Ed25519 key as a
// did:key, a contact, the capability "refunds", and an expiry. The portal signs a passport for it. A shop's door
// trusts the registry's key, which it reads from the registry's key document, and nothing else: no principal key, no
// signature agent, no entry per agent. The agent sends its passport and signs the request with its key; the door
// admits it as verified, and the shop's policy reads the registry's capabilities. The same passport under another
// key's signature is refused. Postgres runs in-process through PGlite; everything listens on loopback.
import { createHash, sign as edSign } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, type Envelope, type KeyPair } from "../src/crypto.ts";
import { didKeyOf } from "../src/did-key.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival } from "../src/door.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { servePortal } from "../src/portal.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { PASSPORT_HEADER, REGISTRY_DOCUMENT_PATH, passportHeader, registrationProof } from "../src/registry.ts";
import { localSigner } from "../src/signer.ts";
import { verifyBundle } from "../src/verify.ts";
import { parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
import { buildDoorFixture } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

const SHOP = "shop.example";

step(1, "the portal runs the agent registry, with a signing key of its own");
const db = new PGlite();
const portal = await servePortal({ tenancy: new PostgresTenancy(db), client: db, secret: "an-example-session-secret-of-32-chars", publicUrl: "https://log.example.test/", portalUrl: "https://app.example.test/", registry: { signer: localSigner(generateKeyPair()), passportSeconds: 3600 }, log: () => {} }, { port: 0 });
let cookie = "";
const call = async (method: string, path: string, body?: unknown) => {
  const res = await fetch(new URL(path, portal.url), { method, headers: { ...(cookie ? { cookie } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const set = res.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0]!;
  return { status: res.status, json: (await res.json()) as any };
};
const doc = (await call("GET", REGISTRY_DOCUMENT_PATH)).json as { registry: string; keys: { keyid: string; publicKeyPem: string }[] };
console.log(`   ${REGISTRY_DOCUMENT_PATH}: registry ${doc.registry}, key ${doc.keys[0]!.keyid.slice(0, 16)}…`);

step(2, "an agent-commerce company signs up and registers its shopping agent by the agent's own key, with the key's proof that it holds it");
await call("POST", "/api/register", { email: "ops@carted.example", password: "a-long-enough-password", tenant: "carted", name: "Ana", company: "Carted" });
const agent: KeyPair = generateKeyPair();
const registered = await call("POST", "/api/agents", { name: "Carted shopper", contact: "agents@carted.example", capabilities: ["refunds"], ...registrationProof(agent, doc.registry, "carted"), expiresAt: new Date(Date.now() + 90 * 86_400_000).toISOString() });
const passport = registered.json.passport as Envelope;
console.log(`   agent ${registered.json.agent.id}, key ${didKeyOf(agent.publicKey).slice(0, 24)}…, capabilities [${registered.json.agent.capabilities}], ${registered.json.agent.status}`);
const published = (await call("GET", `/registry/agents/${registered.json.agent.id}`)).json;
console.log(`   anyone can read the entry: owner ${published.owner}, contact ${published.contact}, ${published.keys.length} key`);

step(3, "a shop puts a door in front of its refunds API that trusts the registry's key and nothing else");
const received: string[] = [];
const site = createServer((req, res) => { received.push(`${req.method} ${req.url}`); res.writeHead(200, { "content-type": "application/json" }); res.end('{"refunded":true}'); });
await new Promise<void>((r) => site.listen(0, "127.0.0.1", r));
const dir = out("62-agent-registry");
const fx = buildDoorFixture(dir, `http://127.0.0.1:${(site.address() as AddressInfo).port}`, { trustedPrincipalKeys: [], trustedRegistryKeys: ["keys/registry.pub"], webBotAuth: { authorities: [SHOP] } });
writeFileSync(join(fx.dir, "keys", "registry.pub"), doc.keys[0]!.publicKeyPem);
writeFileSync(join(fx.dir, "policy.cedar"), `// A refund is for an agent the door verified by its passport, whose registry entry gives it "refunds", up to £50.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.outcome == "verified" &&
  context.facts.arrival.passport.capabilities.contains("refunds") &&
  context.args.body.amount <= 5000
};
`);
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });

let n = 0;
const bodyOf = (amount: number) => JSON.stringify({ order: "o_77", amount });
// the signature covers the passport, the method, the path, and a digest of the body, which bind the passport to this one request
const signedBy = (key: KeyPair, amount: number) => {
  const fields: Record<string, string> = { [PASSPORT_HEADER]: passportHeader(passport), "content-digest": `sha-256=:${createHash("sha256").update(bodyOf(amount)).digest("base64")}:` };
  const created = Math.floor(Date.now() / 1000);
  const input = `sig1=("@authority" "@method" "@path" "@query" "${PASSPORT_HEADER}" "content-digest");created=${created};expires=${created + 60};keyid="${didKeyOf(key.publicKey)}";alg="ed25519";nonce="example-${++n}";tag="web-bot-auth"`;
  const base = signatureBase({ method: "POST", target: "/refunds", authority: SHOP, header: (name) => (fields[name] !== undefined ? [fields[name]!] : undefined) }, parseDictionary(input).get("sig1") as SfInnerList);
  return { ...fields, "signature-input": input, signature: `sig1=:${edSign(null, Buffer.from(base), key.privateKey).toString("base64")}:` };
};
const refund = (headers: Record<string, string>, amount: number) => new Promise<{ status: number; arrival: Arrival; verified: boolean }>((resolve, reject) => {
  const u = new URL(door.url);
  const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path: "/refunds", headers: { host: SHOP, "content-type": "application/json", ...headers } }, (res) => {
    res.resume();
    res.on("end", () => {
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers[RECEIPT_HEADER]}.json`), "utf8")) as ReceiptBundle;
      const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement;
      resolve({ status: res.statusCode!, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, verified: verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok });
    });
  });
  req.on("error", reject);
  req.end(bodyOf(amount));
});
const show = (label: string, r: Awaited<ReturnType<typeof refund>>) => console.log(`   ${label}: ${r.status}, ${r.arrival.class}, passport ${r.arrival.passport?.outcome}${r.arrival.passport?.owner ? ` (owner ${r.arrival.passport.owner}, [${r.arrival.passport.capabilities}])` : ""}, receipt ${r.verified ? "verified" : "FAILED"}`);

step(4, "the agent asks for a £12 refund with its passport, signed by its own key: verified, and refunded");
const admitted = await refund(signedBy(agent, 1200), 1200);
show("the agent", admitted);

step(5, "someone who copied the passport signs with their own key: the passport was handed on, and the refund is refused");
const copied = await refund(signedBy(generateKeyPair(), 1200), 1200);
show("a copy", copied);

step(6, "the company revokes the agent: the registry issues it no more passports");
await call("POST", `/api/agents/${registered.json.agent.id}/revoke`, {});
const after = await call("GET", `/registry/agents/${registered.json.agent.id}/passport`);
console.log(`   a new passport: ${after.status}, ${after.json.error}; the one it holds lasts out its hour`);

await door.close();
await host.close();
site.close();
await portal.close();
await db.close();
if (admitted.status !== 200 || admitted.arrival.class !== "verified" || admitted.arrival.passport?.outcome !== "verified" || !admitted.verified ||
  copied.status !== 403 || copied.arrival.class !== "claimed" || copied.arrival.passport?.outcome !== "wrong-sender" || !copied.verified ||
  after.status !== 410 || received.length !== 1) throw new Error("the registry did not behave as described");
console.log("\nOK");

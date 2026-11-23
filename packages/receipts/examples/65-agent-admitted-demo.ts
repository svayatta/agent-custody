// Aspect: Demo 3, agent admitted: an agent-commerce company registers its agent, gets a passport, and is admitted by a marketplace that had been blocking it. Source: src/registry.ts, src/admission.ts, src/door-core.ts
// Run:    node examples/65-agent-admitted-demo.ts
//
// A marketplace puts the door in front of its order API and admits only the agents on its "partners" list. Carted, an
// agent-commerce company, sends its shopping agent with a signature and nothing else, and the door blocks it: anyone can
// make a key. Carted signs up at the registry, registers the agent with proof that it holds the key, and gets a
// passport. The door now knows who the agent is and who owns it, and still blocks it, because the marketplace has not
// listed it. The marketplace searches the registry for agents that place orders, finds Carted's, and lists it by its
// registry entry; the door reads the changed list on the next request, without a restart. The order goes through.
// Then the merchant reads its own receipts, with the door's public key and nothing else: who each agent was, who owns
// it, and what it did. To reach the agent's operator, it looks up the registry entry that the passport names. Postgres
// runs in-process through PGlite; everything listens on loopback.
import { createHash, sign as edSign } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
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

const MARKETPLACE = "bazaar.example";
const REGISTRY = "https://app.example.test/";
// one directory per run: the run of every example and the cold-twice test may run this at the same time
const dir = out(`65-agent-admitted-demo/${process.pid}`);

// The marketplace's order API: every order that reaches it is kept, so the run can show what got through.
const orders: { path: string; body: string }[] = [];
const api = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    orders.push({ path: req.url ?? "/", body });
    res.writeHead(201, { "content-type": "application/json" });
    res.end(JSON.stringify({ order: `ord_${orders.length}`, status: "placed" }));
  });
});
await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));

const db = new PGlite();
const portal = await servePortal({ tenancy: new PostgresTenancy(db), client: db, secret: "an-example-session-secret-of-32-chars", publicUrl: "https://log.example.test/", portalUrl: REGISTRY, registry: { signer: localSigner(generateKeyPair()) }, log: () => {} }, { port: 0 });

step(1, "the marketplace puts the door in front of its order API: only agents on its partners list may order");
const fx = buildDoorFixture(dir, `http://127.0.0.1:${(api.address() as AddressInfo).port}`, {
  routes: [{ name: "order", methods: ["POST"], path: "/orders" }],
  trustedPrincipalKeys: [],
  trustedRegistryKeys: ["keys/registry.pub"],
  webBotAuth: { authorities: [MARKETPLACE] },
  admissionLists: "admission.json",
});
const registryDoc = (await (await fetch(new URL(REGISTRY_DOCUMENT_PATH, portal.url))).json()) as { registry: string; keys: { publicKeyPem: string }[] };
writeFileSync(join(fx.dir, "keys", "registry.pub"), registryDoc.keys[0]!.publicKeyPem);
const lists = (partners: unknown[]) => writeFileSync(join(fx.dir, "admission.json"), JSON.stringify({ lists: { partners } }, null, 2));
lists([]);
writeFileSync(join(fx.dir, "policy.cedar"), `// Orders: a verified agent on the partners list, for at most £500.
permit(principal, action == Action::"order", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has admission &&
  context.facts.arrival.admission.lists.contains("partners") &&
  context.args.body.total <= 50000
};
`);
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });
console.log(`   door ${door.url}, trusting the registry ${registryDoc.registry}; partners: none yet`);

// Carted's shopping agent: its own key, and, once it has one, the passport. It signs each order as the registry's
// passports require: the method, path, query, passport, and a digest of the body, under its did:key.
const agentKey: KeyPair = generateKeyPair();
let passport: Envelope | undefined;
let n = 0;
const order = (total: number) => new Promise<{ status: number; arrival: Arrival; decision?: string; receipt: string }>((resolve, reject) => {
  const body = JSON.stringify({ item: "sku_4411", quantity: 2, total });
  const fields: Record<string, string> = { "content-digest": `sha-256=:${createHash("sha256").update(body).digest("base64")}:`, ...(passport ? { [PASSPORT_HEADER]: passportHeader(passport) } : {}) };
  const covered = ["@authority", "@method", "@path", "@query", ...(passport ? [PASSPORT_HEADER] : []), "content-digest"];
  const created = Math.floor(Date.now() / 1000);
  const input = `sig1=(${covered.map((c) => `"${c}"`).join(" ")});created=${created};expires=${created + 60};keyid="${didKeyOf(agentKey.publicKey)}";alg="ed25519";nonce="demo3-${process.pid}-${++n}";tag="web-bot-auth"`;
  const base = signatureBase({ method: "POST", target: "/orders", authority: MARKETPLACE, header: (name) => (fields[name] !== undefined ? [fields[name]!] : undefined) }, parseDictionary(input).get("sig1") as SfInnerList);
  const u = new URL(door.url);
  const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path: "/orders", headers: { host: MARKETPLACE, "content-type": "application/json", "x-agent-custody-agent": "carted-shopper", ...fields, "signature-input": input, signature: `sig1=:${edSign(null, Buffer.from(base), agentKey.privateKey).toString("base64")}:` } }, (res) => {
    res.resume();
    res.on("end", () => {
      const receipt = String(res.headers[RECEIPT_HEADER]);
      const st = JSON.parse(Buffer.from((JSON.parse(readFileSync(join(fx.receiptsDir, `${receipt}.json`), "utf8")) as ReceiptBundle).envelope.payload, "base64").toString()) as ReceiptStatement;
      resolve({ status: res.statusCode!, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, ...(st.predicate.policy ? { decision: st.predicate.policy.decision } : {}), receipt });
    });
  });
  req.on("error", reject);
  req.end(body);
});
const show = (r: Awaited<ReturnType<typeof order>>) => console.log(`   order: ${r.status}, ${r.arrival.class}${r.arrival.passport ? `, passport ${r.arrival.passport.outcome}` : ", no passport"}, lists [${r.arrival.admission?.lists.join(", ")}], ${r.decision}`);

step(2, "Carted's agent orders with only its signature: blocked, because anyone can make a key");
const unknown = await order(4200);
show(unknown);

step(3, "Carted signs up at the registry, registers the agent with proof it holds the key, and gets a passport");
let cookie = "";
const call = async (path: string, body: unknown) => {
  const res = await fetch(new URL(path, portal.url), { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const set = res.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0]!;
  return (await res.json()) as any;
};
await call("/api/register", { email: "ops@carted.example", password: "a-long-enough-password", tenant: "carted", name: "Ops", company: "Carted" });
const registered = await call("/api/agents", { name: "Carted shopper", contact: "agents@carted.example", capabilities: ["orders"], ...registrationProof(agentKey, REGISTRY, "carted"), expiresAt: new Date(Date.now() + 90 * 86_400_000).toISOString() });
const agentId = registered.agent.id as string;
passport = registered.passport as Envelope;
console.log(`   ${agentId}: "${registered.agent.name}", owner ${registered.agent.owner}, capabilities ${registered.agent.capabilities.join(", ")}`);

step(4, "it orders again with the passport: the door now knows who it is and who owns it, and still blocks it, as it is not a partner");
const known = await order(4200);
show(known);

step(5, "the marketplace searches the registry for agents that place orders, and lists Carted's by its registry entry");
const found = (await (await fetch(new URL("/registry/agents?capability=orders", portal.url))).json()) as { registry: string; agents: { id: string; name: string; owner: string }[] };
for (const a of found.agents) console.log(`   found ${a.id} "${a.name}", owner ${a.owner}`);
lists([{ registry: found.registry, agentId: found.agents[0]!.id }]);
console.log("   admission.json: partners = that entry; the door reads it on the next request, with no restart");

step(6, "Carted's agent orders again: admitted, and the order is placed");
const admitted = await order(4200);
show(admitted);

step(7, "the merchant reads its receipts, with the door's public key alone: who came, who owns them, and what they did");
const doorKey = loadPublicKey(fx.doorPub);
const rows: { verified: boolean; at: string; arrival: Arrival; decision?: string; did: string }[] = [];
// one receipt per arrival, `<id>.json`; an allowed write also left `<id>.authorization.json`, the decision committed before the order was relayed
for (const file of readdirSync(fx.receiptsDir).filter((f) => /^[0-9a-f-]{36}\.json$/.test(f))) {
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, file), "utf8")) as ReceiptBundle;
  const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement;
  const arrival = st.predicate.facts[ARRIVAL_FACT]!.value as Arrival;
  rows.push({ verified: verifyBundle(bundle, { issuerKeys: [doorKey], principalKeys: [], logFile: fx.logFile }).ok, at: st.predicate.timestamp, arrival, ...(st.predicate.policy ? { decision: st.predicate.policy.decision } : {}), did: `${arrival.method} ${arrival.path} ${JSON.stringify((st.predicate.request.args as { body?: unknown }).body)} → ${st.predicate.execution.status}` });
}
rows.sort((a, b) => a.at.localeCompare(b.at));
for (const r of rows) {
  const p = r.arrival.passport?.outcome === "verified" ? r.arrival.passport : undefined;
  const who = p ? `"${p.name}" (${p.agentId}), owner ${p.owner}` : `claims "${r.arrival.declared}", unidentified`;
  console.log(`   ${r.verified ? "verified" : "FAILED  "} receipt: ${who}, lists [${r.arrival.admission?.lists.join(", ")}]\n      ${r.did}`);
}
// the passport names the registry and the agent's id there, so the merchant can look the agent up and reach its operator
const entry = (await (await fetch(new URL(`/registry/agents/${agentId}`, portal.url))).json()) as { contact: string; status: string };
console.log(`   the registry's entry for ${agentId}: ${entry.status}, contact ${entry.contact}`);
console.log(`   orders that reached the API: ${orders.length}, ${orders.map((o) => o.body).join(", ")}`);

await door.close();
await host.close();
api.close();
await portal.close();
await db.close();
const ok =
  unknown.status === 403 && unknown.arrival.class === "claimed" && unknown.arrival.passport === undefined &&
  known.status === 403 && known.arrival.class === "verified" && known.arrival.passport?.outcome === "verified" && known.arrival.passport.owner === "carted" && known.arrival.admission?.lists.length === 0 &&
  found.agents.length === 1 && found.agents[0]!.id === agentId &&
  admitted.status === 201 && admitted.arrival.admission?.lists.join() === "partners" && admitted.decision === "allow" &&
  rows.length === 3 && rows.every((r) => r.verified) && orders.length === 1 && entry.contact === "agents@carted.example";
if (!ok) throw new Error("Demo 3 did not behave as described");
console.log("\nOK");

// Aspect: admission lists: a site finds agents in the registry by capability, lists the ones it admits and the one it blocks, and its policy reads the lists. Source: src/admission.ts, src/registry.ts, src/door-core.ts
// Run:    node examples/64-admission-lists.ts
//
// Two agent-commerce companies register shopping agents with the capability "refunds". A shop searches the registry
// for that capability, puts one company's agent on its "partners" list by its registry entry, and blocks the other's
// by its key. Its door trusts the registry's key, reads the lists from a file, and records in each arrival fact the
// lists the agent is on. The policy permits a refund for a partner and forbids it for a blocked agent. Each decision is
// a receipt that names the lists and the digest of the lists in force. Postgres runs in-process through PGlite;
// everything listens on loopback.
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
const REGISTRY = "https://app.example.test/";

step(1, "two companies register shopping agents with the capability \"refunds\"");
const db = new PGlite();
const portal = await servePortal({ tenancy: new PostgresTenancy(db), client: db, secret: "an-example-session-secret-of-32-chars", publicUrl: "https://log.example.test/", portalUrl: REGISTRY, registry: { signer: localSigner(generateKeyPair()) }, log: () => {} }, { port: 0 });
const company = async (tenant: string, key: KeyPair) => {
  let cookie = "";
  const call = async (path: string, body: unknown) => {
    const res = await fetch(new URL(path, portal.url), { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
    const set = res.headers.get("set-cookie");
    if (set) cookie = set.split(";")[0]!;
    return (await res.json()) as any;
  };
  await call("/api/register", { email: `ops@${tenant}.example`, password: "a-long-enough-password", tenant, name: "Ops", company: tenant });
  const r = await call("/api/agents", { name: `${tenant} shopper`, contact: `agents@${tenant}.example`, capabilities: ["refunds"], ...registrationProof(key, REGISTRY, tenant), expiresAt: new Date(Date.now() + 90 * 86_400_000).toISOString() });
  return { key, id: r.agent.id as string, passport: r.passport as Envelope };
};
const carted = await company("carted", generateKeyPair());
const grabby = await company("grabby", generateKeyPair());

step(2, "the shop searches the registry for agents that do refunds");
const found = (await (await fetch(new URL("/registry/agents?capability=refunds", portal.url))).json()) as { agents: { id: string; owner: string; agent: string }[] };
for (const a of found.agents) console.log(`   ${a.id}  owner ${a.owner}  key ${a.agent.slice(0, 24)}…`);

step(3, "it lists Carted's agent as a partner by its registry entry, blocks Grabby's by its key, and its door reads the lists");
const received: string[] = [];
const site = createServer((req, res) => { received.push(`${req.method} ${req.url}`); res.writeHead(200, { "content-type": "application/json" }); res.end('{"refunded":true}'); });
await new Promise<void>((r) => site.listen(0, "127.0.0.1", r));
const fx = buildDoorFixture(out("64-admission-lists"), `http://127.0.0.1:${(site.address() as AddressInfo).port}`, { trustedPrincipalKeys: [], trustedRegistryKeys: ["keys/registry.pub"], webBotAuth: { authorities: [SHOP] }, admissionLists: "admission.json" });
const doc = (await (await fetch(new URL(REGISTRY_DOCUMENT_PATH, portal.url))).json()) as { keys: { publicKeyPem: string }[] };
writeFileSync(join(fx.dir, "keys", "registry.pub"), doc.keys[0]!.publicKeyPem);
const grabbyKey = found.agents.find((a) => a.owner === "grabby")!.agent;
writeFileSync(join(fx.dir, "admission.json"), JSON.stringify({ lists: { partners: [{ registry: REGISTRY, agentId: carted.id }], blocked: [{ agent: grabbyKey }] } }, null, 2));
writeFileSync(join(fx.dir, "policy.cedar"), `// A refund is for a verified partner, up to £50, and never for a blocked agent.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has admission &&
  context.facts.arrival.admission.lists.contains("partners") &&
  context.args.body.amount <= 5000
};
forbid(principal, action == Action::"refund", resource)
when { context.facts.arrival has admission && context.facts.arrival.admission.lists.contains("blocked") };
`);
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });

let n = 0;
const body = JSON.stringify({ order: "o_9", amount: 1500 });
const refund = (agent: { key: KeyPair; passport: Envelope }) => new Promise<{ status: number; arrival: Arrival; decision?: string; verified: boolean }>((resolve, reject) => {
  const fields: Record<string, string> = { [PASSPORT_HEADER]: passportHeader(agent.passport), "content-digest": `sha-256=:${createHash("sha256").update(body).digest("base64")}:` };
  const created = Math.floor(Date.now() / 1000);
  const input = `sig1=("@authority" "@method" "@path" "@query" "${PASSPORT_HEADER}" "content-digest");created=${created};expires=${created + 60};keyid="${didKeyOf(agent.key.publicKey)}";alg="ed25519";nonce="example-${++n}";tag="web-bot-auth"`;
  const base = signatureBase({ method: "POST", target: "/refunds", authority: SHOP, header: (name) => (fields[name] !== undefined ? [fields[name]!] : undefined) }, parseDictionary(input).get("sig1") as SfInnerList);
  const u = new URL(door.url);
  const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path: "/refunds", headers: { host: SHOP, "content-type": "application/json", ...fields, "signature-input": input, signature: `sig1=:${edSign(null, Buffer.from(base), agent.key.privateKey).toString("base64")}:` } }, (res) => {
    res.resume();
    res.on("end", () => {
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers[RECEIPT_HEADER]}.json`), "utf8")) as ReceiptBundle;
      const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement;
      resolve({ status: res.statusCode!, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, ...(st.predicate.policy ? { decision: st.predicate.policy.decision } : {}), verified: verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok });
    });
  });
  req.on("error", reject);
  req.end(body);
});
const show = (label: string, r: Awaited<ReturnType<typeof refund>>) => console.log(`   ${label}: ${r.status}, ${r.arrival.class}, on [${r.arrival.admission?.lists.join(", ")}], ${r.decision}, lists ${r.arrival.admission?.digest.slice(0, 12)}…, receipt ${r.verified ? "verified" : "FAILED"}`);

step(4, "Carted's agent asks for a £15 refund: a partner, admitted");
const admitted = await refund(carted);
show("Carted", admitted);

step(5, "Grabby's agent asks: verified as itself, blocked, and refused");
const blocked = await refund(grabby);
show("Grabby", blocked);

await door.close();
await host.close();
site.close();
await portal.close();
await db.close();
if (found.agents.length !== 2 || admitted.status !== 200 || admitted.arrival.admission?.lists.join() !== "partners" || !admitted.verified ||
  blocked.status !== 403 || blocked.arrival.class !== "verified" || blocked.arrival.admission?.lists.join() !== "blocked" || !blocked.verified || received.length !== 1) throw new Error("the admission lists did not behave as described");
console.log("\nOK");

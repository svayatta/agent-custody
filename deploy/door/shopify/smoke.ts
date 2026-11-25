// Smoke test, run BY HAND against a real Shopify development store. CI does not run it: it needs a store and a token.
//   (cd deploy/door/shopify && npm install)     # once: the server loads the published door
//   SHOPIFY_SHOP=x.myshopify.com SHOPIFY_ADMIN_TOKEN=shpat_... SMOKE_VARIANT_ID=<a variant id of the store> node deploy/door/shopify/smoke.ts
// (or SHOPIFY_CLIENT_ID with SHOPIFY_CLIENT_SECRET instead of the token). It makes a registry key, a passport, and an agent;
// starts the server on a free port with a copy of the shipped config; places one order as the agent; shows that an agent
// with no passport is refused; and verifies each receipt. It leaves one draft order in the store, tagged agent-custody.
import { spawn } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "../../../packages/receipts/src/crypto.ts";
import { didKeyOf } from "../../../packages/receipts/src/did-key.ts";
import { issuePassport, type AgentEntry } from "../../../packages/receipts/src/registry.ts";
import { localSigner } from "../../../packages/receipts/src/signer.ts";
import { verifyBundle } from "../../../packages/receipts/src/verify.ts";
import { agentHeaders } from "../../../packages/receipts/scripts/door-fixture.ts";
import type { ReceiptBundle } from "../../../packages/receipts/src/receipt.ts";

const variant = process.env.SMOKE_VARIANT_ID;
if (!process.env.SHOPIFY_SHOP || !variant) throw new Error("set SHOPIFY_SHOP, SMOKE_VARIANT_ID, and SHOPIFY_ADMIN_TOKEN (or SHOPIFY_CLIENT_ID with SHOPIFY_CLIENT_SECRET)");
const here = import.meta.dirname;
const dir = mkdtempSync(join(tmpdir(), "agent-custody-shopify-smoke-"));
const port = 18790;
const authority = `127.0.0.1:${port}`;

const registry = generateKeyPair();
writeKeyPair(registry, join(dir, "keys"), "registry");
const doorKey = writeKeyPair(generateKeyPair(), join(dir, "data", "keys"), "door");
copyFileSync(join(here, "policy.cedar"), join(dir, "policy.cedar"));
const config = JSON.parse(readFileSync(join(here, "door.json"), "utf8"));
config.webBotAuth.authorities = [authority];
writeFileSync(join(dir, "door.json"), JSON.stringify(config));

const agent = generateKeyPair();
const entry: AgentEntry = { id: "agt_00000000000000a1", owner: "smoke", name: "smoke agent", contact: "smoke@example.com", capabilities: ["orders"], agent: didKeyOf(agent.publicKey), createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86_400_000).toISOString(), revokedAt: null };
const registryUrl = "https://registry.example.test/";
const passport = await issuePassport(localSigner(registry), registryUrl, entry, 3600);
writeFileSync(join(dir, "admission.json"), JSON.stringify({ lists: { agents: [{ registry: registryUrl, agentId: entry.id }] } }));

const server = spawn("node", [join(here, "start.ts")], { env: { ...process.env, DOOR_CONFIG: join(dir, "door.json"), PORT: String(port) }, stdio: ["ignore", "inherit", "inherit"] });
try {
  for (let i = 0; i < 50; i++) {
    if (await fetch(`http://${authority}/`, { method: "POST" }).then(() => true, () => false)) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  let n = 0;
  const order = async (who: "agent" | "stranger") => {
    const body = JSON.stringify({ lines: [{ variant_id: variant, quantity: 1 }], email: "smoke@example.com" });
    const key = who === "agent" ? agent : generateKeyPair();
    const res = await fetch(`http://${authority}/orders`, { method: "POST", headers: { "content-type": "application/json", ...agentHeaders(key, { method: "POST", target: "/orders", authority, body, ...(who === "agent" ? { passport } : {}), nonce: `smoke-${Date.now()}-${++n}` }) }, body });
    return { status: res.status, body: await res.json(), receipt: res.headers.get("x-agent-custody-receipt")! };
  };
  const admitted = await order("agent");
  console.log(`agent with a passport: ${admitted.status}`, admitted.body);
  if (admitted.status !== 201) throw new Error("the agent was not admitted");
  const refused = await order("stranger");
  console.log(`agent with no passport: ${refused.status}`);
  if (refused.status !== 403) throw new Error("an agent with no passport was not refused");
  await new Promise((r) => setTimeout(r, 500));
  const files = readdirSync(join(dir, "data", "receipts")).filter((f) => /^[0-9a-f-]{36}\.json$/.test(f));
  for (const f of files) {
    const r = verifyBundle(JSON.parse(readFileSync(join(dir, "data", "receipts", f), "utf8")) as ReceiptBundle, { issuerKeys: [loadPublicKey(doorKey.pubFile)], principalKeys: [], logFile: join(dir, "data", "log.jsonl") });
    if (!r.ok) throw new Error(`receipt ${f} does not verify: ${r.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")}`);
  }
  console.log(`smoke: OK (${files.length} receipts verified, in ${dir})`);
} finally {
  server.kill();
}

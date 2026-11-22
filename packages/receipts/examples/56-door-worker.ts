// Aspect: the door as a Cloudflare Worker. Source: src/door-worker.ts, src/door-core.ts, src/object-issuer.ts,
// scripts/build-door-worker.ts, deploy/door/cloudflare-worker/
// The door's own decision loop, built for workerd the way `wrangler deploy` builds it, and run locally in workerd
// (Miniflare): the signing key is a secret binding, the policy and config are variables, receipts go to an R2 bucket and
// to a log over HTTP. An order with no grant is refused before it reaches the origin; an order under a grant is
// committed to the log first, then relayed. Both receipts verify with the Worker's public key and the log's.
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { buildDoorWorker } from "../scripts/build-door-worker.ts";
import { generateKeyPair, publicKeyToPem } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { grantHeader } from "../src/grant-header.ts";
import { serveLog } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { out, step } from "./_out.ts";

const dir = out("56-door-worker");
step(1, "build the Worker: one ES module and the Cedar WebAssembly, as wrangler.toml's build command does");
const built = await buildDoorWorker(join(dir, "dist"));
console.log(`   ${built.bytes} bytes of JavaScript, plus ${built.wasm.split("/").pop()}`);

step(2, "the keys, a log run elsewhere, and the bindings: secrets for the key and the token, variables for the rest");
const door = generateKeyPair();
const principal = generateKeyPair();
const logKey = generateKeyPair();
const log = await serveLog(join(dir, "log.jsonl"), logKey, { port: 0, tokens: ["log-token"] });
const reached: string[] = [];
const mf = new Miniflare({
  // Miniflare's stand-in request.cf, not Cloudflare's cf.json fetched from the network
  cf: false,
  modules: true,
  scriptPath: built.script,
  modulesRoot: join(dir, "dist"),
  modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
  compatibilityDate: "2025-11-01",
  compatibilityFlags: ["nodejs_compat"],
  r2Buckets: ["RECEIPTS"],
  bindings: {
    DOOR_CONFIG: JSON.stringify({ routes: [{ name: "catalogue", path: "/products/*", methods: ["GET"] }, { name: "orders", path: "/orders", methods: ["POST"] }], precommit: ["orders"] }),
    DOOR_POLICY: `permit(principal, action == Action::"catalogue", resource);\npermit(principal, action == Action::"orders", resource) when { context.facts.arrival.class == "verified" };`,
    ORIGIN_URL: "https://origin.example",
    LOG_URL: "https://log.example/",
    LOG_KEYS: publicKeyToPem(logKey.publicKey),
    TRUSTED_PRINCIPAL_KEYS: publicKeyToPem(principal.publicKey),
    DOOR_KEY: door.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    LOG_TOKEN: "log-token",
  },
  // the Worker's subrequests: the log is the local one above, the origin a stand-in shop
  outboundService: async (request: Request) => {
    const u = new URL(request.url);
    if (u.hostname === "log.example") {
      const body = request.method === "POST" ? await request.text() : undefined;
      return fetch(new URL(u.pathname.slice(1), log.url), { method: request.method, headers: { "content-type": "application/json", authorization: request.headers.get("authorization") ?? "" }, ...(body !== undefined ? { body } : {}) });
    }
    reached.push(`${request.method} ${u.pathname}`);
    return new Response(JSON.stringify({ order: "o-1", status: "placed" }), { headers: { "content-type": "application/json" } });
  },
});

const bucket = await mf.getR2Bucket("RECEIPTS");
const show = async (label: string, method: string, headers: Record<string, string> = {}) => {
  const res = await mf.dispatchFetch("https://shop.example/orders", { method, headers: { "content-type": "application/json", ...headers }, body: '{"sku":"tea","qty":1}' });
  await res.text();
  const id = res.headers.get("x-agent-custody-receipt");
  const bundle = JSON.parse(await (await bucket.get(`${id}.json`))!.text()) as ReceiptBundle;
  const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
  const ok = verifyBundle(bundle, { issuerKeys: [door], principalKeys: [principal], logKeys: [logKey] }).ok;
  console.log(`   ${label} HTTP ${res.status}, ${res.headers.get("x-agent-custody-class")}, ${p.execution.status}; authorization ${p.authorization ? "committed first" : "none"}; receipt ${ok ? "verified" : "FAILED"}`);
  return { status: res.status, ok };
};

step(3, "an order with no grant, then an order under a grant for \"orders\"");
const refused = await show("no grant:   ", "POST");
const allowed = await show("with grant: ", "POST", { "x-agent-custody-grant": grantHeader(createDelegation(principal, { version: "0.1", principal: "shop-owner", agent: "buyer-bot", scopes: ["orders"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() })) });
console.log(`   the origin saw: ${reached.join(", ") || "nothing"}`);

await mf.dispose();
await log.close();
if (refused.status !== 403 || allowed.status !== 200 || !refused.ok || !allowed.ok || reached.join() !== "POST /orders") throw new Error("the Worker did not decide and receipt as described");
console.log("\nOK");

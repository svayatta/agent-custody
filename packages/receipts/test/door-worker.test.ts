// The door as a Cloudflare Worker, run in workerd (Miniflare) from the bundle the build script makes for `wrangler
// deploy`. A site that moves its door to the edge must get the same decision and the same evidence: an arrival the
// policy refuses never reaches the origin, a request that can change something reaches it only once the log holds its
// authorization, a forged or replayed signature is no passport, and a receipt from the Worker verifies exactly as one
// from the Node door does. The origin, the hosted log, and the crawler's key directory are local stand-ins; nothing
// leaves the machine.
import { generateKeyPairSync, sign, verify as edVerify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildDoorWorker } from "../scripts/build-door-worker.ts";
import { generateKeyPair, publicKeyToPem, writeKeyPair } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import type { Arrival } from "../src/door-core.ts";
import { grantHeader } from "../src/grant-header.ts";
import { serveLog, type RunningLog } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, jwkThumbprint, parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";

const CRAWLER = "https://crawler.test";
const SITE = "shop.test";
const door = generateKeyPair();
const principal = generateKeyPair();
const logKey = generateKeyPair();
const crawler = generateKeyPairSync("ed25519");
const crawlerX = crawler.publicKey.export({ format: "jwk" }).x!;
const directory = JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", x: crawlerX }] });

const POLICY = `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"orders", resource) when { context.facts.arrival.class == "verified" };
permit(principal, action == Action::"api", resource) when { context.facts.arrival.class == "verified" };`;
const CONFIG = {
  routes: [
    { name: "catalogue", path: "/products/*", methods: ["GET", "HEAD"] },
    { name: "orders", path: "/orders", methods: ["POST"] },
    { name: "api", path: "/api/*", methods: ["GET"] },
  ],
  precommit: ["orders"],
  webBotAuth: { agents: [CRAWLER], authorities: [SITE] },
};

let dir: string;
let log: RunningLog;
let mf: Miniflare;
let logDown = false;
const reached: string[] = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "door-worker-"));
  const built = await buildDoorWorker(join(dir, "dist"));
  log = await serveLog(join(dir, "log.jsonl"), logKey, { port: 0, tokens: ["log-token"] });
  mf = new Miniflare({
    modules: true,
    scriptPath: built.script,
    modulesRoot: join(dir, "dist"),
    modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
    compatibilityDate: "2025-11-01",
    compatibilityFlags: ["nodejs_compat"],
    r2Buckets: ["RECEIPTS"],
    bindings: {
      DOOR_CONFIG: JSON.stringify(CONFIG),
      DOOR_POLICY: POLICY,
      ORIGIN_URL: "https://origin.test",
      LOG_URL: "https://log.test/",
      LOG_KEYS: publicKeyToPem(logKey.publicKey),
      TRUSTED_PRINCIPAL_KEYS: publicKeyToPem(principal.publicKey),
      DOOR_KEY: door.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      LOG_TOKEN: "log-token",
    },
    // every subrequest the Worker makes lands here: the hosted log, the origin, and the crawler's directory
    outboundService: async (request: Request) => {
      const u = new URL(request.url);
      if (u.hostname === "log.test") {
        if (logDown) return new Response("down for maintenance", { status: 503 });
        const body = request.method === "POST" ? await request.text() : undefined;
        const headers: Record<string, string> = {};
        for (const h of ["content-type", "authorization"]) { const v = request.headers.get(h); if (v) headers[h] = v; }
        return fetch(new URL(u.pathname.slice(1) + u.search, log.url), { method: request.method, headers, ...(body !== undefined ? { body } : {}) });
      }
      if (u.hostname === "origin.test") {
        reached.push(`${request.method} ${u.pathname}`);
        return new Response(JSON.stringify({ ok: true, path: u.pathname }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (u.origin === CRAWLER && u.pathname === DIRECTORY_PATH) return new Response(directory, { headers: { "content-type": DIRECTORY_MEDIA_TYPE } });
      return new Response(`not stood in: ${request.url}`, { status: 502 });
    },
  });
}, 60_000);

afterAll(async () => {
  await mf?.dispose();
  await log?.close();
});

let nonce = 0;
/** a crawler's RFC 9421 signature over the authority and its Signature-Agent, with a fresh nonce unless one is given */
function signedHeaders(path: string, key = crawler.privateKey, n = `worker-${process.pid}-${++nonce}`): Record<string, string> {
  const created = Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = { "signature-agent": `crawler="${CRAWLER}"` };
  headers["signature-input"] = `sig1=("@authority" "signature-agent";key="crawler");created=${created};expires=${created + 60};keyid="${jwkThumbprint(crawlerX)}";alg="ed25519";nonce="${n}";tag="web-bot-auth"`;
  const base = signatureBase({ method: "GET", target: path, authority: SITE, header: (h) => (Object.hasOwn(headers, h) ? [headers[h]!] : undefined) }, parseDictionary(headers["signature-input"]).get("sig1") as SfInnerList);
  headers.signature = `sig1=:${sign(null, Buffer.from(base), key).toString("base64")}:`;
  return headers;
}

const grant = (scopes: string[]) => grantHeader(createDelegation(principal, { version: "0.1", principal: "shop-owner", agent: "buyer-bot", scopes, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() }));

async function send(method: string, path: string, headers: Record<string, string> = {}, body?: string, cf?: Record<string, unknown>) {
  const res = await mf.dispatchFetch(`https://${SITE}${path}`, { method, headers, ...(body !== undefined ? { body } : {}), ...(cf ? { cf } : {}) });
  const text = await res.text();
  return { status: res.status, receipt: res.headers.get("x-agent-custody-receipt"), klass: res.headers.get("x-agent-custody-class"), pending: res.headers.get("x-agent-custody-log-pending"), text };
}

async function stored(key: string): Promise<string | null> {
  const bucket = await mf.getR2Bucket("RECEIPTS");
  const obj = await bucket.get(key);
  return obj ? obj.text() : null;
}

async function bundleOf(receiptId: string | null): Promise<ReceiptBundle> {
  const text = await stored(`${receiptId}.json`);
  expect(text, `no bundle for ${receiptId} in the bucket`).not.toBeNull();
  return JSON.parse(text!) as ReceiptBundle;
}

const statement = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const arrivalOf = (b: ReceiptBundle) => statement(b).predicate.facts.arrival!.value as Arrival;
const verified = (b: ReceiptBundle) => verifyBundle(b, { issuerKeys: [door], principalKeys: [principal], logKeys: [logKey] });

describe("the door as a Cloudflare Worker", () => {
  it("refuses an unknown arrival on a protected route, never reaches the origin, and receipts the refusal", async () => {
    const before = reached.length;
    const r = await send("POST", "/orders", { "content-type": "application/json" }, '{"sku":"tea","qty":1}');
    expect(r.status).toBe(403);
    expect(r.klass).toBe("unknown");
    expect(reached.length).toBe(before);
    const b = await bundleOf(r.receipt);
    expect(verified(b).ok).toBe(true);
    expect(statement(b).predicate).toMatchObject({ issuer: { kind: "door", framework: "cloudflare-worker" }, tool: { name: "orders" }, execution: { status: "denied" } });
  });

  it("allows a verified Web Bot Auth arrival, relays it, and its receipt verifies", async () => {
    const r = await send("GET", "/api/orders", signedHeaders("/api/orders"));
    expect(r.status).toBe(200);
    expect(r.klass).toBe("verified");
    expect(reached).toContain("GET /api/orders");
    const b = await bundleOf(r.receipt);
    expect(verified(b).ok).toBe(true);
    expect(arrivalOf(b)).toMatchObject({ class: "verified", subject: CRAWLER, signature: "verified", signatureAgent: CRAWLER });
    expect(statement(b).predicate.agent).toMatchObject({ id: CRAWLER, provenance: "observed" });
  });

  it("does not verify a forged signature, or the same signature a second time", async () => {
    const forged = await send("GET", "/api/orders", signedHeaders("/api/orders", generateKeyPairSync("ed25519").privateKey));
    expect(forged.status).toBe(403);
    expect(arrivalOf(await bundleOf(forged.receipt)).signature).toBe("invalid");

    const once = signedHeaders("/api/orders");
    expect((await send("GET", "/api/orders", once)).status).toBe(200);
    const replayed = await send("GET", "/api/orders", once);
    expect(replayed.status).toBe(403);
    const arrival = arrivalOf(await bundleOf(replayed.receipt));
    expect(arrival.signature).toBe("invalid");
    expect(arrival.signatureError).toMatch(/nonce/);
  });

  it("checks a grant at the edge, and commits the authorization to the log before the order reaches the origin", async () => {
    const r = await send("POST", "/orders", { "content-type": "application/json", "x-agent-custody-grant": grant(["orders"]) }, '{"sku":"tea","qty":1}');
    expect(r.status).toBe(200);
    expect(reached).toContain("POST /orders");
    const b = await bundleOf(r.receipt);
    expect(verified(b).ok).toBe(true);
    expect(statement(b).predicate).toMatchObject({ principal: { id: "shop-owner", provenance: "attested" }, agent: { id: "buyer-bot", provenance: "attested" }, execution: { status: "executed" } });
    expect(statement(b).predicate.authorization).toBeDefined();
    expect(await stored(`${r.receipt}.authorization.json`)).not.toBeNull();
  });

  it("does not relay a precommit request when the log will not take its authorization", async () => {
    logDown = true;
    try {
      const before = reached.length;
      const r = await send("POST", "/orders", { "content-type": "application/json", "x-agent-custody-grant": grant(["orders"]) }, '{"sku":"tea","qty":2}');
      expect(r.status).toBe(503);
      expect(JSON.parse(r.text)).toMatchObject({ error: "not relayed" });
      expect(reached.length).toBe(before);
    } finally {
      logDown = false;
    }
  });

  it("relays a safe request while the log is down, keeps its receipt in the bucket's outbox, and the cron appends it", async () => {
    logDown = true;
    let r: Awaited<ReturnType<typeof send>>;
    try {
      r = await send("GET", "/products/tea");
      expect(r.status).toBe(200);
      expect(r.pending).toBe("true");
      expect(await stored(`outbox/${r.receipt}.json`)).not.toBeNull();
      expect(await stored(`${r.receipt}.json`)).toBeNull();
    } finally {
      logDown = false;
    }
    const worker = await mf.getWorker();
    await worker.scheduled({ cron: "* * * * *" });
    const b = await bundleOf(r.receipt);
    expect(verified(b).ok).toBe(true);
    expect(await stored(`outbox/${r.receipt}.json`)).toBeNull();
  });

  it("records Cloudflare Bot Management from the request's cf object as an observed fact", async () => {
    const scored = await send("GET", "/products/tea", {}, undefined, { botManagement: { score: 3, verifiedBot: false } });
    const fact = statement(await bundleOf(scored.receipt)).predicate.facts.cloudflare;
    expect(fact).toMatchObject({ tool: "cloudflare.botManagement", value: { score: 3, verifiedBot: false }, provenance: "observed" });
  });

  it("signs exactly as Node does: the Worker's Ed25519 signature is the one Node makes over the same bytes", async () => {
    const r = await send("GET", "/products/tea");
    const b = await bundleOf(r.receipt);
    const payload = Buffer.from(b.envelope.payload, "base64");
    const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(b.envelope.payloadType)} ${b.envelope.payloadType} ${payload.length} `), payload]);
    // Ed25519 is deterministic: the same key over the same bytes gives one signature, so equal means the same algorithm and encoding
    expect(sign(null, pae, door.privateKey).toString("base64")).toBe(b.envelope.signatures[0]!.sig);
    expect(edVerify(null, pae, door.publicKey, Buffer.from(b.envelope.signatures[0]!.sig, "base64"))).toBe(true);
  });

  it("gives a receipt that `agent-custody verify` accepts with the Worker's public key and the log's", async () => {
    const r = await send("POST", "/orders", { "content-type": "application/json", "x-agent-custody-grant": grant(["orders"]) }, '{"sku":"tea","qty":3}');
    const keys = join(dir, "keys");
    const doorPub = writeKeyPair(door, keys, "door").pubFile;
    const logPub = writeKeyPair(logKey, keys, "log").pubFile;
    const principalPub = writeKeyPair(principal, keys, "principal").pubFile;
    const file = join(dir, `${r.receipt}.json`);
    writeFileSync(file, JSON.stringify(await bundleOf(r.receipt)));
    const cli = spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "verify", file, "--issuer-key", doorPub, "--principal-key", principalPub, "--log-key", logPub], { encoding: "utf8" });
    expect(cli.status, cli.stderr + cli.stdout).toBe(0);
  });

  it("answers its key id and policy digest, and refuses a config that names a file, relaying nothing", async () => {
    const info = await mf.dispatchFetch(`https://${SITE}/.well-known/agent-custody-door`);
    expect(await info.json()).toMatchObject({ keyid: door.keyid, version: expect.any(String) });
    const broken = new Miniflare({
      modules: true,
      scriptPath: join(dir, "dist", "index.js"),
      modulesRoot: join(dir, "dist"),
      modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
      compatibilityDate: "2025-11-01",
      compatibilityFlags: ["nodejs_compat"],
      r2Buckets: ["RECEIPTS"],
      bindings: { DOOR_CONFIG: JSON.stringify({ ...CONFIG, policyFile: "policy.cedar" }), DOOR_POLICY: POLICY, ORIGIN_URL: "https://origin.test", LOG_URL: "https://log.test/", LOG_KEYS: publicKeyToPem(logKey.publicKey), DOOR_KEY: door.privateKey.export({ type: "pkcs8", format: "pem" }).toString() },
      outboundService: () => new Response("nothing should be fetched", { status: 599 }),
    });
    try {
      const res = await broken.dispatchFetch(`https://${SITE}/products/tea`);
      expect(res.status).toBe(500);
      expect(await res.json()).toMatchObject({ error: "the door is not configured, so nothing was relayed", detail: expect.stringMatching(/policyFile.*DOOR_POLICY variable/) });
    } finally {
      await broken.dispose();
    }
  });
});

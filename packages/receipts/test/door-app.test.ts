// The door in-process. The decision is the proxy's own (one code path), so these tests are about what differs when the
// door runs inside the app: the app, not an origin, runs an allowed request; the body the policy read must reach the
// app's own body parser unchanged; the grant must never reach the app; a request that can change something is in the
// log before the app runs; and the receipt records what the app answered, or says it could not see it.
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { request as httpRequest, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkDoorConfig, isDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { door, MIDDLEWARE_FRAMEWORK, ROUTE_FRAMEWORK, type InProcessDoor } from "../src/door-app.ts";
import { ARRIVAL_FACT, CLASS_HEADER, RECEIPT_HEADER, createDoorHost, type Arrival } from "../src/door.ts";
import { GRANT_HEADER, grantHeader } from "../src/gateway-http.ts";
import type { LogSink } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, jwkThumbprint, parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
import { buildDoorFixture, type DoorFixture } from "../scripts/door-fixture.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const appFixture = (name: string, extra: Record<string, unknown> = {}) => buildDoorFixture(mkdtempSync(join(tmpdir(), `agent-custody-door-app-${name}-`)), "http://unused.invalid", { origin: undefined, ...extra });
const grantFor = (fx: DoorFixture, agent: string, scopes: string[]) => createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent, scopes, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
/** The receipt of an answer the app gave is written after it, so a test waits for the file. */
const receiptOf = async (fx: DoorFixture, id: string | null): Promise<ReceiptStatement["predicate"]> => {
  const file = join(fx.receiptsDir, `${id}.json`);
  for (let i = 0; i < 200 && !existsSync(file); i++) await new Promise((r) => setTimeout(r, 10));
  return decode(JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle).predicate;
};
const verifies = (fx: DoorFixture, id: string | null) => verifyBundle(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });

describe("the in-process door's config", () => {
  it("names no origin: a config with one is refused here, and the proxy refuses a config without one", async () => {
    const proxyFx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-app-origin-")), "http://127.0.0.1:9");
    expect(() => door(proxyFx.configFile)).toThrow("names no origin");
    const fx = appFixture("no-origin");
    await expect(createDoorHost(loadDoorConfig(fx.configFile))).rejects.toThrow("the door proxy needs origin.url");
    const d = door(fx.configFile, { autoFlush: false });
    expect(d.keyid).toMatch(/^[0-9a-f]+$/);
    d.close();
    // `check` must still treat it as a door config, not a gateway config with no upstream
    expect(isDoorConfig(fx.configFile)).toBe(true);
    const findings = checkDoorConfig(fx.configFile);
    expect(findings.filter((f) => f.level === "error")).toEqual([]);
    expect(findings).toContainEqual(expect.objectContaining({ level: "ok", check: "origin", message: expect.stringContaining("in-process") }));
  });
});

describe("the door as Express middleware", () => {
  let fx: DoorFixture;
  let guard: InProcessDoor;
  let server: Server;
  let base: string;
  const ran: { path: string; headers: IncomingMessage["headers"]; rawHeaders: string[]; distinct: IncomingMessage["headersDistinct"]; body: unknown; authorizationOnDisk: boolean }[] = [];
  const refusing: LogSink = { kind: "file", where: "refusing", append: async () => { throw new Error("the log is full"); } };
  let refusingGuard: InProcessDoor;

  beforeAll(async () => {
    fx = appFixture("express", { maxBodyBytes: 2048 });
    guard = door(fx.configFile, { autoFlush: false });
    refusingGuard = door(fx.configFile, { autoFlush: false, log: refusing });
    const app = express();
    app.use((req, res, next) => (req.headers["x-test-log"] === "full" ? refusingGuard : guard)(req, res, next));
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    const note = (req: express.Request) => {
      const id = req.headers[RECEIPT_HEADER] as string;
      ran.push({ path: req.url ?? "", headers: { ...req.headers }, rawHeaders: [...req.rawHeaders], distinct: req.headersDistinct, body: req.body, authorizationOnDisk: existsSync(join(fx.receiptsDir, `${id}.authorization.json`)) });
    };
    app.get("/catalogue/:item", (req, res) => { note(req); res.json({ item: "shoes", price: 4500 }); });
    app.post("/refunds", (req, res) => { note(req); res.json({ refunded: (req.body as { amount: number }).amount }); });
    app.post("/api/form", (req, res) => { note(req); res.json({ got: req.body }); });
    app.get("/api/broken", (req, res) => { note(req); res.status(500).json({ error: "the app failed" }); });
    app.get("/api/hangup", (req, res) => { note(req); res.writeHead(200, { "content-type": "text/plain" }); res.write("half"); setTimeout(() => res.destroy(), 20); });
    app.post("/api/raw", (req, res) => {
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        res.json({ bytes: Buffer.concat(chunks).toString("utf8") });
      })();
    });
    await new Promise<void>((r) => { server = app.listen(0, "127.0.0.1", () => r()); });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    guard?.close();
    refusingGuard?.close();
    server?.closeAllConnections();
    await new Promise<void>((r) => server?.close(() => r()));
  });

  it("passes an allowed arrival to the app with the receipt id and class, and the receipt records what the app answered, byte for byte", async () => {
    const res = await fetch(`${base}/catalogue/shoes`, { headers: { [RECEIPT_HEADER]: "spoofed", [CLASS_HEADER]: "verified" } });
    const text = await res.text();
    const id = res.headers.get(RECEIPT_HEADER);
    expect(res.status).toBe(200);
    expect(res.headers.get(CLASS_HEADER)).toBe("unknown");
    // the app reads the door's word, never a header the client sent under the same name
    const seen = ran.find((r) => r.path === "/catalogue/shoes")!;
    expect(seen.headers[RECEIPT_HEADER]).toBe(id);
    expect(seen.headers[CLASS_HEADER]).toBe("unknown");
    expect(seen.rawHeaders.filter((h) => h.toLowerCase() === CLASS_HEADER)).toHaveLength(1);
    const p = await receiptOf(fx, id);
    expect(p.issuer).toMatchObject({ kind: "door", framework: MIDDLEWARE_FRAMEWORK });
    expect(p.tool.name).toBe("catalogue");
    expect(p.execution).toMatchObject({ status: "executed", result: { status: 200, contentType: expect.stringContaining("application/json"), bodyBytes: Buffer.byteLength(text), bodyDigest: sha(text) } });
    expect(verifies(fx, id).ok).toBe(true);
  });

  it("refuses what the policy denies before the app runs: 403, a denied receipt, nothing at the app", async () => {
    const before = ran.length;
    const res = await fetch(`${base}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_1", amount: 1000 }) });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "refused by the door's policy", receipt: res.headers.get(RECEIPT_HEADER) });
    expect(ran.length).toBe(before);
    expect((await receiptOf(fx, res.headers.get(RECEIPT_HEADER))).execution.status).toBe("denied");
  });

  it("a verified refund reaches express.json() with the body the policy read, without the grant, and only after its authorization is in the log", async () => {
    const res = await fetch(`${base}/refunds`, { method: "POST", headers: { authorization: `Bearer ${grantHeader(grantFor(fx, "shopping-agent", ["refund"]))}`, "content-type": "application/json", [CLASS_HEADER]: "spoofed", [RECEIPT_HEADER]: "spoofed" }, body: JSON.stringify({ order: "o_2", amount: 4500 }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ refunded: 4500 });
    const seen = ran.find((r) => r.path === "/refunds")!;
    expect(seen.body).toEqual({ order: "o_2", amount: 4500 });
    expect(seen.headers.authorization).toBeUndefined();
    expect(seen.rawHeaders.map((h) => h.toLowerCase())).not.toContain("authorization");
    expect(seen.headers[CLASS_HEADER]).toBe("verified");
    // headersDistinct is built from rawHeaders: it must match the rewritten headers, not the client's
    expect(seen.distinct[CLASS_HEADER]).toEqual(["verified"]);
    expect(seen.distinct[RECEIPT_HEADER]).toEqual([res.headers.get(RECEIPT_HEADER)]);
    expect(seen.distinct.authorization).toBeUndefined();
    expect(seen.authorizationOnDisk).toBe(true);
    const p = await receiptOf(fx, res.headers.get(RECEIPT_HEADER));
    expect(p.agent).toMatchObject({ id: "shopping-agent", provenance: "attested" });
    expect(p.authorization).toBeDefined();
    expect(verifies(fx, res.headers.get(RECEIPT_HEADER)).ok).toBe(true);
  });

  it("a form body and a raw stream read after the door get the bytes the door read; the grant header is stripped", async () => {
    const grant = { [GRANT_HEADER]: grantHeader(grantFor(fx, "shopping-agent", ["api"])) };
    const form = await fetch(`${base}/api/form`, { method: "POST", headers: { ...grant, "content-type": "application/x-www-form-urlencoded" }, body: "name=ada&amount=12" });
    expect(await form.json()).toEqual({ got: { name: "ada", amount: "12" } });
    expect(ran.find((r) => r.path === "/api/form")!.headers[GRANT_HEADER]).toBeUndefined();
    const raw = await fetch(`${base}/api/raw`, { method: "POST", headers: { ...grant, "content-type": "application/octet-stream" }, body: "exact bytes" });
    expect(await raw.json()).toEqual({ bytes: "exact bytes" });
  });

  it("an allowed body above maxBodyBytes is 413 and never reaches the app; a refused one is 403 whatever its size", async () => {
    const before = ran.length;
    const big = JSON.stringify({ pad: "x".repeat(4096) });
    const allowed = await fetch(`${base}/api/form`, { method: "POST", headers: { [GRANT_HEADER]: grantHeader(grantFor(fx, "shopping-agent", ["api"])), "content-type": "application/json" }, body: big });
    expect(allowed.status).toBe(413);
    const refused = await fetch(`${base}/api/form`, { method: "POST", headers: { "content-type": "application/json" }, body: big });
    expect(refused.status).toBe(403);
    expect(ran.length).toBe(before);
  });

  it("when the log will not commit a refund, the app never runs: 503 and a withheld receipt", async () => {
    const before = ran.length;
    const res = await fetch(`${base}/refunds`, { method: "POST", headers: { "x-test-log": "full", authorization: `Bearer ${grantHeader(grantFor(fx, "shopping-agent", ["refund"]))}`, "content-type": "application/json" }, body: JSON.stringify({ amount: 100 }) });
    expect(res.status).toBe(503);
    expect(res.headers.get("x-agent-custody-log-pending")).toBe("true");
    expect(ran.length).toBe(before);
  });

  it("an app 5xx is a failed receipt; a connection the app drops mid-answer is an error that says the app may have acted", async () => {
    const grant = { [GRANT_HEADER]: grantHeader(grantFor(fx, "shopping-agent", ["api"])) };
    const broken = await fetch(`${base}/api/broken`, { headers: grant });
    expect(broken.status).toBe(500);
    expect((await receiptOf(fx, broken.headers.get(RECEIPT_HEADER))).execution).toMatchObject({ status: "failed", result: { status: 500 } });
    const hangup = await fetch(`${base}/api/hangup`, { headers: grant });
    const id = hangup.headers.get(RECEIPT_HEADER);
    await hangup.text().catch(() => undefined);
    expect((await receiptOf(fx, id)).execution).toMatchObject({ status: "error", error: expect.stringContaining("the app may have acted") });
  });
});

describe("the door as a route-handler wrapper (Next.js App Router)", () => {
  let fx: DoorFixture;
  let guard: InProcessDoor;
  beforeAll(() => {
    fx = appFixture("route");
    guard = door(fx.configFile, { autoFlush: false });
  });
  afterAll(() => guard?.close());
  const at = (path: string, init: RequestInit = {}) => new Request(`http://shop.example${path}`, init);

  it("runs the handler for an allowed arrival, with the door's headers on the request and the answer, and records the app's status and body digest", async () => {
    const seen: Request[] = [];
    const GET = guard.route(async (req: Request, ctx: { params: Promise<{ item: string }> }) => {
      seen.push(req);
      return Response.json({ item: (await ctx.params).item });
    });
    const res = await GET(at("/catalogue/shoes", { headers: { [CLASS_HEADER]: "verified" } }), { params: Promise.resolve({ item: "shoes" }) });
    const text = await res.text();
    const id = res.headers.get(RECEIPT_HEADER);
    expect(res.status).toBe(200);
    expect(JSON.parse(text)).toEqual({ item: "shoes" });
    expect(seen[0]!.headers.get(RECEIPT_HEADER)).toBe(id);
    expect(seen[0]!.headers.get(CLASS_HEADER)).toBe("unknown");
    const p = await receiptOf(fx, id);
    expect(p.issuer.framework).toBe(ROUTE_FRAMEWORK);
    expect(p.execution).toMatchObject({ status: "executed", result: { status: 200, bodyBytes: Buffer.byteLength(text), bodyDigest: sha(text) } });
    // a fetch request has no socket: without trustProxy the door does not guess an address
    expect((p.facts[ARRIVAL_FACT]!.value as Arrival).remote).toBe("unknown");
    expect(verifies(fx, id).ok).toBe(true);
  });

  it("does not run the handler for a refused arrival, and the handler reads the body the door read, without the grant", async () => {
    let calls = 0;
    const bodies: unknown[] = [];
    const POST = guard.route(async (req: Request) => {
      calls += 1;
      bodies.push({ body: await req.json(), authorization: req.headers.get("authorization") });
      return Response.json({ ok: true });
    });
    const denied = await POST(at("/refunds", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ amount: 1000 }) }));
    expect(denied.status).toBe(403);
    expect(calls).toBe(0);
    const ok = await POST(at("/refunds", { method: "POST", headers: { authorization: `Bearer ${grantHeader(grantFor(fx, "shopping-agent", ["refund"]))}`, "content-type": "application/json" }, body: JSON.stringify({ amount: 4500 }) }));
    expect(ok.status).toBe(200);
    await ok.text();
    expect(bodies).toEqual([{ body: { amount: 4500 }, authorization: null }]);
    const p = await receiptOf(fx, ok.headers.get(RECEIPT_HEADER));
    expect(p.authorization).toBeDefined();
    expect(verifies(fx, ok.headers.get(RECEIPT_HEADER)).ok).toBe(true);
  });

  it("when the framework seals the request's headers, the handler gets a request without the grant all the same, body intact", async () => {
    const req = at("/refunds", { method: "POST", headers: { authorization: `Bearer ${grantHeader(grantFor(fx, "shopping-agent", ["refund"]))}`, "content-type": "application/json" }, body: JSON.stringify({ amount: 100 }) });
    const sealed = new Headers(req.headers);
    for (const m of ["set", "delete", "append"] as const) sealed[m] = () => { throw new TypeError("immutable"); };
    Object.defineProperty(req, "headers", { value: sealed });
    const got: { authorization: string | null; class: string | null; body: unknown }[] = [];
    const POST = guard.route(async (r: Request) => {
      got.push({ authorization: r.headers.get("authorization"), class: r.headers.get(CLASS_HEADER), body: await r.json() });
      return Response.json({ ok: true });
    });
    const res = await POST(req);
    await res.text();
    expect(got).toEqual([{ authorization: null, class: "verified", body: { amount: 100 } }]);
  });

  it("a streamed answer reaches the client as it streams, and the receipt is the digest of every byte; a handler that throws is an error receipt and the throw reaches the framework", async () => {
    const grant = { [GRANT_HEADER]: grantHeader(grantFor(fx, "shopping-agent", ["api"])) };
    const GET = guard.route(async () => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("one,")); c.enqueue(new TextEncoder().encode("two")); c.close(); } }), { headers: { "content-type": "text/plain" } }));
    const res = await GET(at("/api/stream", { headers: grant }));
    expect(await res.text()).toBe("one,two");
    expect((await receiptOf(fx, res.headers.get(RECEIPT_HEADER))).execution).toMatchObject({ status: "executed", result: { bodyBytes: 7, bodyDigest: sha("one,two"), contentType: "text/plain" } });
    const THROWS = guard.route(async () => { throw new Error("database down"); });
    await expect(THROWS(at("/api/throws", { headers: grant }))).rejects.toThrow("database down");
    const thrown = readdirSync(fx.receiptsDir).filter((f) => /^[0-9a-f-]{36}\.json$/.test(f)).map((f) => decode(JSON.parse(readFileSync(join(fx.receiptsDir, f), "utf8")) as ReceiptBundle).predicate).find((p) => (p.request.args as { path?: string }).path === "/api/throws");
    expect(thrown?.execution).toMatchObject({ status: "error", error: expect.stringContaining("the handler threw: database down; the app may have acted") });
  });
});

// The signature check is part of the decision the in-process door shares with the proxy: a request signed per Web Bot
// Auth, with no grant, must reach the app as `verified`, its agent observed, through the middleware and the wrapper alike.
describe("the in-process door checks Web Bot Auth signatures", () => {
  const CRAWLER = "https://crawler.example";
  const SITE = "shop.example";
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x!;
  const keyid = jwkThumbprint(x);
  const stub = (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url !== `${CRAWLER}${DIRECTORY_PATH}`) throw new Error(`the test fetched ${url}`);
    return new Response(JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", x }] }), { headers: { "content-type": DIRECTORY_MEDIA_TYPE } });
  }) as typeof fetch;
  let n = 0;
  const signedHeaders = (target: string) => {
    const created = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = { "signature-agent": `crawler="${CRAWLER}"` };
    headers["signature-input"] = `sig1=("@authority" "signature-agent";key="crawler");created=${created};expires=${created + 60};keyid="${keyid}";alg="ed25519";nonce="app-${process.pid}-${++n}";tag="web-bot-auth"`;
    const base = signatureBase({ method: "GET", target, authority: SITE, header: (h) => (Object.hasOwn(headers, h) ? [headers[h]!] : undefined) }, parseDictionary(headers["signature-input"]).get("sig1") as SfInnerList);
    headers.signature = `sig1=:${sign(null, Buffer.from(base), privateKey).toString("base64")}:`;
    return headers;
  };
  let fx: DoorFixture;
  let guard: InProcessDoor;
  let server: Server;
  const seen: (string | undefined)[] = [];
  beforeAll(async () => {
    fx = appFixture("wba", { webBotAuth: { agents: [CRAWLER], authorities: [SITE] } });
    guard = door(fx.configFile, { autoFlush: false, fetch: stub });
    const app = express();
    app.use(guard);
    app.get("/api/orders", (req, res) => { seen.push(req.get(CLASS_HEADER)); res.json({ orders: [] }); });
    await new Promise<void>((r) => { server = app.listen(0, "127.0.0.1", () => r()); });
  });
  afterAll(async () => {
    guard?.close();
    server?.closeAllConnections();
    await new Promise<void>((r) => server?.close(() => r()));
  });
  const expectSignedAgent = async (id: string | null) => {
    const p = await receiptOf(fx, id);
    expect(p.facts[ARRIVAL_FACT]!.value).toMatchObject({ class: "verified", subject: CRAWLER, grant: "absent", signature: "verified", signatureAgent: CRAWLER, signatureKeyid: keyid });
    expect(p.agent).toEqual({ id: CRAWLER, provenance: "observed" });
    expect(p.execution.status).toBe("executed");
    expect(verifies(fx, id).ok).toBe(true);
  };

  it("through the Express middleware: a signed request with no grant is verified as its signature agent", async () => {
    // node:http, because fetch will not send a Host of the test's choosing, and the Host is the authority the signature covers
    const res = await new Promise<{ status: number; id: string | null }>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port: (server.address() as AddressInfo).port, path: "/api/orders", headers: { host: SITE, ...signedHeaders("/api/orders") } }, (r) => {
        r.resume();
        r.on("end", () => resolve({ status: r.statusCode!, id: (r.headers[RECEIPT_HEADER] as string | undefined) ?? null }));
      });
      req.on("error", reject);
      req.end();
    });
    expect(res.status).toBe(200);
    expect(seen).toEqual(["verified"]);
    await expectSignedAgent(res.id);
  });

  it("through the route wrapper: the same, with the authority taken from the request's URL", async () => {
    const GET = guard.route(async (req: Request) => Response.json({ class: req.headers.get(CLASS_HEADER) }));
    const res = await GET(new Request(`https://${SITE}/api/orders`, { headers: signedHeaders("/api/orders") }));
    expect(await res.json()).toEqual({ class: "verified" });
    await expectSignedAgent(res.headers.get(RECEIPT_HEADER));
    // the wrapper is not what admitted it: the same route without a signature is unknown, and refused
    const unsigned = await GET(new Request(`https://${SITE}/api/orders`));
    expect(unsigned.status).toBe(403);
  });
});

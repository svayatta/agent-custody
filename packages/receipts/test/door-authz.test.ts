// The door answering a proxy's authz check (nginx auth_request, Envoy ext_authz) instead of relaying. Why each case
// matters: the proxy relays on a 2xx and refuses on anything else, so the door must answer 200 only for a decision it
// recorded, and a request that can change something only once its authorization is in the log; the door never sees the
// body or the origin's answer, so its receipt must say it records a decision and must never claim a result; and the
// original request comes from the proxy's headers, never from the check request's own method and path.
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkDoorConfig, isDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { dsseSign, digestOf, loadPrivateKey, loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { ARRIVAL_FACT, AUTHZ_ALLOWED_REASON, CLASS_HEADER, ORIGINAL_METHOD_HEADER, ORIGINAL_URI_HEADER, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { LogSink } from "../src/log-sink.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, jwkThumbprint, parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
import { publicKeyFromPem, verifyBundle as webVerify } from "../../../site/verifier/verify-web.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

/** The body is the proxy's, never the door's: a refund rule cannot read an amount here, only who arrived. */
const AUTHZ_POLICY = `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"refund", resource) when { context.facts.arrival.class == "verified" };
`;

let origin: Origin;
let fx: DoorFixture;
let host: DoorHost;
let door: RunningDoor;

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const receiptIn = (dir: string, id: string | null) => JSON.parse(readFileSync(join(dir, `${id}.json`), "utf8")) as ReceiptBundle;
const keysOf = (f: DoorFixture) => ({ issuerKeys: [loadPublicKey(f.doorPub)], principalKeys: [loadPublicKey(f.principalPub)], logFile: f.logFile });
const grant = (scopes: string[], f = fx) => createDelegation(f.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
const authzFixture = (extra: Record<string, unknown> = {}) => {
  const f = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-authz-")), origin.url, { authz: true, trustProxy: true, ...extra });
  writeFileSync(join(f.dir, "policy.cedar"), AUTHZ_POLICY);
  return f;
};

/** A check as the proxy sends it: its own method and path, the original request in X-Original-*, and the client's headers. */
const check = async (url: string, dir: string, checkPath: string, original: { method: string; uri: string }, headers: Record<string, string> = {}, checkMethod = "GET") => {
  const res = await fetch(`${url}${checkPath}`, { method: checkMethod, headers: { [ORIGINAL_METHOD_HEADER]: original.method, [ORIGINAL_URI_HEADER]: original.uri, "x-forwarded-for": "203.0.113.7", ...headers } });
  const body = (await res.json()) as Record<string, unknown>;
  const id = res.headers.get(RECEIPT_HEADER);
  const bundle = receiptIn(dir, id);
  const p = decode(bundle).predicate;
  return { res, body, id, bundle, p, arrival: p.facts[ARRIVAL_FACT]!.value as Arrival };
};

beforeAll(async () => {
  origin = await startOrigin();
  fx = authzFixture();
  host = await createDoorHost(loadDoorConfig(fx.configFile));
  door = await serveDoor(host, { port: 0, log: () => {} });
}, 60_000);

afterAll(async () => {
  await door?.close();
  await host?.close();
  await origin?.close();
});

describe("the door answering authz checks", () => {
  it("nginx: an allowed read is answered 200 with the receipt and class headers for the proxy to pass upstream, and the door relays nothing", async () => {
    const r = await check(door.url, fx.receiptsDir, "/_custody", { method: "GET", uri: "/catalogue/shoes?colour=red" }, { "user-agent": "browser/1" });
    expect(r.res.status).toBe(200);
    expect(r.body).toEqual({ allowed: true, receipt: r.id });
    expect(r.res.headers.get(CLASS_HEADER)).toBe("unknown");
    expect(origin.seen).toHaveLength(0);
    // the decision on the original request, not on the check request's GET /_custody
    expect(r.p.tool.name).toBe("catalogue");
    expect(r.p.request.args).toMatchObject({ method: "GET", path: "/catalogue/shoes", query: { colour: "red" }, headers: { "user-agent": "browser/1" } });
    // no body was seen, so none is claimed: no size, no digest
    expect(r.p.request.args).not.toHaveProperty("bodyBytes");
    expect(r.p.request.args).not.toHaveProperty("bodyDigest");
    expect(r.arrival.remote).toBe("203.0.113.7");
    expect(r.p.issuer).toMatchObject({ kind: "door", framework: "authz" });
    expect(r.p.execution).toEqual({ status: "withheld", reason: AUTHZ_ALLOWED_REASON, provenance: "observed" });
    const v = verifyBundle(r.bundle, keysOf(fx));
    expect(v.ok).toBe(true);
    expect(v.checks).toContainEqual(expect.objectContaining({ name: "door authz decided, relayed nothing", ok: true }));
    const report = formatReport(v);
    expect(report).toContain("the receipt records the decision, not the result");
    expect(report).not.toContain("the log would not commit it");
  });

  it("Envoy: the check arrives with the original method and a prefixed path; an unknown refund is refused 403 and a verified one is committed to the log before the 200", async () => {
    const refused = await check(door.url, fx.receiptsDir, "/authz/refunds", { method: "POST", uri: "/refunds" }, {}, "POST");
    expect(refused.res.status).toBe(403);
    expect(refused.p.execution.status).toBe("denied");
    expect(refused.p.tool.name).toBe("refund");
    expect(existsSync(join(fx.receiptsDir, `${refused.id}.authorization.json`))).toBe(false);

    const allowed = await check(door.url, fx.receiptsDir, "/authz/refunds", { method: "POST", uri: "/refunds" }, { authorization: `Bearer ${grantHeader(grant(["refund"]))}` }, "POST");
    expect(allowed.res.status).toBe(200);
    expect(allowed.res.headers.get(CLASS_HEADER)).toBe("verified");
    expect(allowed.p.agent).toEqual({ id: "shopping-agent", provenance: "attested" });
    // a POST can change something at the origin: its authorization is in the log before the proxy is told to relay it
    expect(allowed.p.authorization).toBeDefined();
    expect(existsSync(join(fx.receiptsDir, `${allowed.id}.authorization.json`))).toBe(true);
    const v = verifyBundle(allowed.bundle, keysOf(fx));
    expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")).toBe(true);
    expect(origin.seen).toHaveLength(0);
  });

  it("a check that does not name the original request is refused 400 with no receipt, never decided on the check request itself", async () => {
    const before = readdirSync(fx.receiptsDir).length;
    const incomplete: Record<string, string>[] = [{}, { [ORIGINAL_METHOD_HEADER]: "GET" }, { [ORIGINAL_URI_HEADER]: "/catalogue/shoes" }, { [ORIGINAL_METHOD_HEADER]: "GET", [ORIGINAL_URI_HEADER]: "http://elsewhere/catalogue" }];
    for (const headers of incomplete) {
      const res = await fetch(`${door.url}/catalogue/shoes`, { headers });
      expect(res.status).toBe(400);
      expect(res.headers.get(RECEIPT_HEADER)).toBeNull();
    }
    expect(readdirSync(fx.receiptsDir).length).toBe(before);
  });

  it("a path the origin would read differently is never allowed, even by a policy that permits everything: 400 and a withheld receipt", async () => {
    const f = authzFixture();
    writeFileSync(join(f.dir, "policy.cedar"), "permit(principal, action, resource);");
    const h = await createDoorHost(loadDoorConfig(f.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const r = await check(d.url, f.receiptsDir, "/_custody", { method: "GET", uri: "/catalogue/a%2fb" });
      expect(r.res.status).toBe(400);
      expect(r.p.execution.status).toBe("withheld");
      expect(r.p.execution).not.toMatchObject({ reason: AUTHZ_ALLOWED_REASON });
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("when the log refuses the authorization, a POST is not allowed: 503, which nginx and Envoy both treat as a refusal", async () => {
    const f = authzFixture();
    const refusing: LogSink = { kind: "file", where: "refusing", append: async () => { throw new Error("the log is full"); } };
    const h = await createDoorHost(loadDoorConfig(f.configFile), { log: refusing });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/_custody`, { headers: { [ORIGINAL_METHOD_HEADER]: "POST", [ORIGINAL_URI_HEADER]: "/refunds", "x-forwarded-for": "203.0.113.7", authorization: `Bearer ${grantHeader(grant(["refund"], f))}` } });
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ error: "not relayed", reason: expect.stringContaining("the log did not commit the authorization") });
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("observe mode answers 200 for a denial and records that it was not enforced", async () => {
    const f = authzFixture({ mode: "observe" });
    const h = await createDoorHost(loadDoorConfig(f.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const r = await check(d.url, f.receiptsDir, "/_custody", { method: "POST", uri: "/refunds" });
      expect(r.res.status).toBe(200);
      expect(r.p.policy).toMatchObject({ decision: "deny", enforced: false });
      expect(r.p.execution).toMatchObject({ status: "withheld", reason: expect.stringContaining("Observe mode") });
      expect(verifyBundle(r.bundle, keysOf(f)).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("an authz receipt re-signed to claim the door saw the origin's answer fails, in the CLI and the browser verifier alike", async () => {
    const r = await check(door.url, fx.receiptsDir, "/_custody", { method: "GET", uri: "/catalogue/shoes" });
    const st = decode(r.bundle);
    const result = { status: 200, bodyBytes: 2, bodyDigest: "0".repeat(64) };
    st.predicate.execution = { status: "executed", result, resultDigest: digestOf(result), provenance: "observed" };
    const forged = { ...r.bundle, envelope: dsseSign(RECEIPT_TYPE, st, loadPrivateKey(join(fx.dir, "keys", "door.key"))) };
    // the re-signed leaf is also not the one the log took; that check fails too, and is not what this case is about
    const v = verifyBundle(forged, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [] });
    expect(v.ok).toBe(false);
    expect(v.checks.filter((c) => !c.ok).map((c) => c.name)).toContain("door authz decided, relayed nothing");
    const pem = readFileSync(fx.doorPub, "utf8");
    const web = await webVerify(forged, { issuerKeys: [await publicKeyFromPem(pem)], principalKeys: [] });
    expect(web.checks.filter((c) => !c.ok).map((c) => c.name)).toContain("door authz decided, relayed nothing");
    const honest = await webVerify(r.bundle, { issuerKeys: [await publicKeyFromPem(pem)], principalKeys: [] });
    expect(honest.ok).toBe(true);
    expect(honest.issuerNote).toContain("the receipt records the decision, not the result");
  });
});

// Web Bot Auth is part of the decision the authz door shares with the proxy and the in-process door. A signature covers
// the request the agent sent, which the door knows only from X-Original-*: verified against the check request's own
// method and path (nginx's GET /_custody), every signed agent behind a proxy would be refused, and a signature for one
// path would pass for another.
describe("the authz door checks Web Bot Auth signatures on the original request", () => {
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
  /** what the agent sends: a signature over the method, path, and authority of the request it makes, not of any check */
  const signedHeaders = (method: string, target: string) => {
    const created = Math.floor(Date.now() / 1000);
    const headers: Record<string, string> = { "signature-agent": `crawler="${CRAWLER}"` };
    headers["signature-input"] = `sig1=("@method" "@path" "@authority" "signature-agent";key="crawler");created=${created};expires=${created + 60};keyid="${keyid}";alg="ed25519";nonce="authz-${process.pid}-${++n}";tag="web-bot-auth"`;
    const base = signatureBase({ method, target, authority: SITE, header: (h) => (Object.hasOwn(headers, h) ? [headers[h]!] : undefined) }, parseDictionary(headers["signature-input"]).get("sig1") as SfInnerList);
    headers.signature = `sig1=:${sign(null, Buffer.from(base), privateKey).toString("base64")}:`;
    return headers;
  };
  let f: DoorFixture;
  let wbaHost: DoorHost;
  let wbaDoor: RunningDoor;
  beforeAll(async () => {
    f = authzFixture({ webBotAuth: { agents: [CRAWLER], authorities: [SITE] } });
    wbaHost = await createDoorHost(loadDoorConfig(f.configFile), { fetch: stub });
    wbaDoor = await serveDoor(wbaHost, { port: 0, log: () => {} });
  });
  afterAll(async () => {
    await wbaDoor?.close();
    await wbaHost?.close();
  });
  /** nginx's check: its own GET to a fixed location, the original request in X-Original-*, the client's Host and headers. node:http, because fetch will not send a Host of the test's choosing */
  const nginxCheck = (original: { method: string; uri: string }, headers: Record<string, string>) =>
    new Promise<{ status: number; id: string | null; cls: string | undefined }>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port: Number(new URL(wbaDoor.url).port), path: "/_custody", headers: { host: SITE, [ORIGINAL_METHOD_HEADER]: original.method, [ORIGINAL_URI_HEADER]: original.uri, "x-forwarded-for": "203.0.113.9", ...headers } }, (r) => {
        r.resume();
        r.on("end", () => resolve({ status: r.statusCode!, id: (r.headers[RECEIPT_HEADER] as string | undefined) ?? null, cls: r.headers[CLASS_HEADER] as string | undefined }));
      });
      req.on("error", reject);
      req.end();
    });

  it("a signed refund with no grant is verified as its signature agent, committed to the log, and allowed", async () => {
    const res = await nginxCheck({ method: "POST", uri: "/refunds" }, signedHeaders("POST", "/refunds"));
    expect(res).toMatchObject({ status: 200, cls: "verified" });
    const p = decode(receiptIn(f.receiptsDir, res.id)).predicate;
    expect(p.facts[ARRIVAL_FACT]!.value).toMatchObject({ class: "verified", subject: CRAWLER, grant: "absent", signature: "verified", signatureAgent: CRAWLER, signatureKeyid: keyid, method: "POST", path: "/refunds" });
    expect(p.agent).toEqual({ id: CRAWLER, provenance: "observed" });
    expect(p.issuer.framework).toBe("authz");
    expect(p.execution).toMatchObject({ status: "withheld", reason: AUTHZ_ALLOWED_REASON });
    expect(existsSync(join(f.receiptsDir, `${res.id}.authorization.json`))).toBe(true);
    expect(verifyBundle(receiptIn(f.receiptsDir, res.id), keysOf(f)).ok).toBe(true);
  });

  it("the same signature presented for another original request does not verify, and the arrival is refused as a claim", async () => {
    // the agent signed a catalogue read; the proxy asks about a refund
    const res = await nginxCheck({ method: "POST", uri: "/refunds" }, signedHeaders("GET", "/catalogue/shoes"));
    expect(res).toMatchObject({ status: 403, cls: "claimed" });
    const p = decode(receiptIn(f.receiptsDir, res.id)).predicate;
    expect(p.facts[ARRIVAL_FACT]!.value).toMatchObject({ class: "claimed", signature: "invalid" });
    expect(p.execution.status).toBe("denied");
  });
});

describe("authz config", () => {
  const write = (cfg: Record<string, unknown>) => {
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-door-authz-cfg-"));
    const file = join(dir, "door.json");
    writeFileSync(file, JSON.stringify({ identity: { keyFile: "k" }, policyFile: "p.cedar", receiptsDir: "r", logFile: "l.jsonl", ...cfg }));
    return file;
  };
  it("needs no origin, and needs trustProxy: every check comes from the proxy, and the arrival's address is the one it appended", () => {
    expect(loadDoorConfig(write({ authz: true, trustProxy: true })).origin).toBeUndefined();
    expect(() => loadDoorConfig(write({ authz: true }))).toThrow(/authz needs trustProxy/);
  });
  it("check recognises an authz door and says the receipts record the decision", () => {
    expect(isDoorConfig(fx.configFile)).toBe(true);
    const noOrigin = write({ authz: true, trustProxy: true });
    expect(isDoorConfig(noOrigin)).toBe(true);
    expect(checkDoorConfig(fx.configFile)).toContainEqual(expect.objectContaining({ level: "ok", check: "authz" }));
  });
});

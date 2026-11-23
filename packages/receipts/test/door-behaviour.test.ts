// The door's behavioural and fingerprint signals in each Node host. A door without `behaviour` must record the arrival
// exactly as before, or every existing receipt changes meaning. With it, the signals must be in the receipt the policy
// decided on, a policy must be able to read a signal and to test for one that is absent, the door itself must refuse
// nothing because of a signal, and a client must not be able to supply the TLS fingerprint that only a proxy can see.
// Requests go over node:http with their headers in a fixed order; nothing leaves the machine.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { door as inProcessDoor } from "../src/door-app.ts";
import { ARRIVAL_FACT, ORIGINAL_METHOD_HEADER, ORIGINAL_URI_HEADER, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import { FORM_REPORT_HEADER } from "../src/door-signals.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
// shaped as a JA4, with hashes that are plainly not a real client's
const ja4 = (a: string) => `${a}_000000000000_111111111111`;
/** The refund route is refused to a write that follows no page load, and every route to a stated browser whose TLS says otherwise. Both rules read a signal; the second tests for it first. */
const POLICY = `permit(principal, action, resource);
forbid(principal, action == Action::"refund", resource) when { context.facts.arrival.behaviour.navigation.directWrite };
forbid(principal, action, resource) when { context.facts.arrival.fingerprint has tls && context.facts.arrival.fingerprint.tls.mismatch };
`;

let origin: Origin;
const open: { close(): Promise<void> | void }[] = [];

/** One request with exactly these headers, in this order. */
const send = (base: string, method: string, path: string, headers: [string, string][] = [], body?: string) => new Promise<{ status: number; receipt: string | null }>((resolve, reject) => {
  const u = new URL(base);
  const all = [["host", u.host], ...headers, ...(body !== undefined ? [["content-length", String(Buffer.byteLength(body))]] : []), ["connection", "close"]];
  const req = httpRequest({ host: u.hostname, port: u.port, method, path, headers: all.flat() }, (res) => {
    res.resume();
    res.on("end", () => resolve({ status: res.statusCode ?? 0, receipt: (res.headers[RECEIPT_HEADER] as string | undefined) ?? null }));
  });
  req.on("error", reject);
  req.end(body);
});
const bundleOf = async (fx: DoorFixture, id: string | null) => {
  const file = join(fx.receiptsDir, `${id}.json`);
  // the in-process door writes the receipt after the app has answered
  await expect.poll(() => { try { return readFileSync(file, "utf8").length > 0; } catch { return false; } }).toBe(true);
  return JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
};
const arrivalOf = async (fx: DoorFixture, id: string | null) => ((JSON.parse(Buffer.from((await bundleOf(fx, id)).envelope.payload, "base64").toString()) as ReceiptStatement).predicate.facts[ARRIVAL_FACT]!.value as Arrival);
const proxyDoor = async (name: string, extra: Record<string, unknown>, policy = POLICY) => {
  const fx = buildDoorFixture(mkdtempSync(join(tmpdir(), `agent-custody-door-behaviour-${name}-`)), origin.url, extra);
  writeFileSync(join(fx.dir, "policy.cedar"), policy);
  const host: DoorHost = await createDoorHost(loadDoorConfig(fx.configFile));
  const running: RunningDoor = await serveDoor(host, { port: 0, log: () => {} });
  open.push(running, host);
  return { fx, url: running.url };
};

beforeAll(async () => {
  origin = await startOrigin();
}, 60_000);
afterAll(async () => {
  for (const o of open) await o.close();
  await origin?.close();
});

describe("a door without behaviour configured", () => {
  it("records the arrival fact with the fields it always had, reads no TLS or form header, and relays both as any other header", async () => {
    const { fx, url } = await proxyDoor("off", { trustProxy: true }, "permit(principal, action, resource);\n");
    const r = await send(url, "GET", "/catalogue/shoes", [["user-agent", CHROME], ["x-forwarded-for", "203.0.113.1"], ["x-ja4", ja4("t12d1516h2")], [FORM_REPORT_HEADER, "v=2;ms=0;k=0;p=0;paste=0;trusted=1;mv=0;ks=0;rd=0"]]);
    expect(r.status).toBe(200);
    expect(await arrivalOf(fx, r.receipt)).toEqual({ class: "unknown", subject: "unknown", grant: "absent", signature: "absent", remote: "203.0.113.1", method: "GET", path: "/catalogue/shoes", route: "catalogue", rate: { by: "remote", burst: 1, minute: 1 } });
    expect(origin.seen.at(-1)!.headers[FORM_REPORT_HEADER]).toBe("v=2;ms=0;k=0;p=0;paste=0;trusted=1;mv=0;ks=0;rd=0");
  });
});

describe("the door proxy with behaviour configured", () => {
  let fx: DoorFixture;
  let url: string;
  beforeAll(async () => {
    ({ fx, url } = await proxyDoor("proxy", { trustProxy: true, behaviour: { tlsHeader: "X-JA4" } }));
  });
  const from = (address: string): [string, string] => ["x-forwarded-for", address];

  it("puts the fingerprint and the behaviour in the arrival fact of a receipt that verifies", async () => {
    const r = await send(url, "GET", "/catalogue/shoes", [["user-agent", "curl/8.7.1"], ["accept", "*/*"], from("203.0.113.10"), ["x-ja4", ja4("t13d3112h2")]]);
    expect(r.status).toBe(200);
    const arrival = await arrivalOf(fx, r.receipt);
    expect(arrival.fingerprint).toEqual({
      headers: { order: expect.stringMatching(/^[0-9a-f]{16}$/), count: 5, client: "tool", family: "curl", mismatch: false, hintsMismatch: false, fetchInvalid: false },
      tls: { ja4: ja4("t13d3112h2"), malformed: false, protocol: "tcp", version: "13", sni: true, ciphers: 31, extensions: 12, alpn: "h2", mismatch: false, knownTool: false },
      seen: 1,
    });
    expect(arrival.behaviour).toEqual({ timing: { gaps: 0, regular: false }, navigation: { pageLoaded: false, referer: "absent", origin: "absent", directWrite: false } });
    expect(verifyBundle(await bundleOf(fx, r.receipt), { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile }).ok).toBe(true);

    // the same headers in another order are another fingerprint; the same order is the same one; the second arrival has a gap
    const again = await arrivalOf(fx, (await send(url, "GET", "/catalogue/hats", [["user-agent", "curl/8.7.1"], ["accept", "*/*"], from("203.0.113.10"), ["x-ja4", ja4("t13d3112h2")]])).receipt);
    const reordered = await arrivalOf(fx, (await send(url, "GET", "/catalogue/hats", [["accept", "*/*"], ["user-agent", "curl/8.7.1"], from("203.0.113.10"), ["x-ja4", ja4("t13d3112h2")]])).receipt);
    expect(again.fingerprint!.headers.order).toBe(arrival.fingerprint!.headers.order);
    expect(reordered.fingerprint!.headers.order).not.toBe(arrival.fingerprint!.headers.order);
    expect(again.behaviour!.timing.gaps).toBe(1);
    expect(Number.isSafeInteger(again.behaviour!.timing.medianGapMs)).toBe(true);
  });

  it("a policy reads a signal: a refund with no page load before it is refused by the operator's rule, and one after a page load passes", async () => {
    const refund: [string, string][] = [["content-type", "application/json"]];
    const cold = await send(url, "POST", "/refunds", [...refund, from("203.0.113.20")], '{"amount":100}');
    expect(cold.status).toBe(403);
    expect((await arrivalOf(fx, cold.receipt)).behaviour!.navigation).toEqual({ pageLoaded: false, referer: "absent", origin: "absent", directWrite: true });

    const page = await send(url, "GET", "/catalogue/returns", [["accept", "text/html,application/xhtml+xml"], from("203.0.113.21")]);
    expect(page.status).toBe(200);
    const filled = await send(url, "POST", "/refunds", [...refund, from("203.0.113.21")], '{"amount":100}');
    expect(filled.status).toBe(200);
    expect((await arrivalOf(fx, filled.receipt)).behaviour!.navigation).toMatchObject({ pageLoaded: true, directWrite: false });

    // a form on a page of this site, by its referer; the host is the one the proxy says the client named
    const referred = await send(url, "POST", "/refunds", [...refund, from("203.0.113.22"), ["x-forwarded-host", "shop.example"], ["referer", "https://shop.example/returns"], ["sec-fetch-site", "same-origin"], ["sec-fetch-mode", "cors"], ["sec-fetch-dest", "empty"]], '{"amount":100}');
    expect(referred.status).toBe(200);
    expect((await arrivalOf(fx, referred.receipt)).behaviour!.navigation).toEqual({ pageLoaded: false, referer: "same-origin", origin: "absent", site: "same-origin", mode: "cors", dest: "empty", directWrite: false });
  });

  it("a policy tests for a signal that may be absent: no TLS fingerprint passes, a browser's passes, and a stated browser with a ClientHello no browser sends is refused", async () => {
    const browser: [string, string][] = [["user-agent", CHROME], ["accept-language", "en-GB,en;q=0.9"]];
    const none = await send(url, "GET", "/catalogue/a", [...browser, from("203.0.113.30")]);
    expect(none.status).toBe(200);
    expect((await arrivalOf(fx, none.receipt)).fingerprint).not.toHaveProperty("tls");
    expect((await send(url, "GET", "/catalogue/a", [...browser, from("203.0.113.30"), ["x-ja4", ja4("t13d1516h2")]])).status).toBe(200);
    const old = await send(url, "GET", "/catalogue/a", [...browser, from("203.0.113.30"), ["x-ja4", ja4("t12d1516h2")]]);
    expect(old.status).toBe(403);
    expect((await arrivalOf(fx, old.receipt)).fingerprint!.tls).toMatchObject({ version: "12", mismatch: true });
    // the same ClientHello under a tool's own name is no mismatch
    expect((await send(url, "GET", "/catalogue/a", [["user-agent", "python-requests/2.32.3"], from("203.0.113.30"), ["x-ja4", ja4("t12d1516h2")]])).status).toBe(200);
  });

  it("refuses nothing itself: an arrival with every flag the door can raise is relayed when the policy does not read them", async () => {
    const lenient = await proxyDoor("lenient", { trustProxy: true, behaviour: { tlsHeader: "x-ja4" } }, "permit(principal, action, resource);\n");
    const r = await send(lenient.url, "POST", "/refunds", [["user-agent", CHROME], ["x-forwarded-proto", "https"], from("203.0.113.40"), ["x-ja4", ja4("t12d151600")], [FORM_REPORT_HEADER, "v=2;ms=0;k=0;p=0;paste=0;trusted=0;mv=0;ks=0;rd=0"], ["content-type", "application/json"]], "{}");
    expect(r.status).toBe(200);
    const a = await arrivalOf(lenient.fx, r.receipt);
    expect(a.fingerprint).toMatchObject({ headers: { mismatch: true, missing: "accept-language origin sec-fetch-site sec-fetch-mode sec-fetch-dest sec-ch-ua" }, tls: { mismatch: true } });
    expect(a.behaviour).toMatchObject({ navigation: { directWrite: true }, form: { report: "claimed", noInput: true, trusted: false } });
    // the form report is the door's to read, not the origin's
    expect(origin.seen.at(-1)!.headers).not.toHaveProperty(FORM_REPORT_HEADER);
  });

  it("records a hostile TLS or form header as malformed and goes on", async () => {
    // a proxy that appends to the client's header, and a report that is not one
    const r = await send(url, "GET", "/catalogue/a", [["user-agent", CHROME], from("203.0.113.50"), ["x-ja4", ja4("t13d1516h2")], ["x-ja4", ja4("t13d1516h2")], [FORM_REPORT_HEADER, "v=1;ms=-5;k=x".repeat(200)]]);
    expect(r.status).toBe(200);
    const a = await arrivalOf(fx, r.receipt);
    expect(a.fingerprint!.tls).toEqual({ malformed: true, mismatch: false, knownTool: false });
    expect(a.behaviour!.form).toEqual({ report: "malformed", fast: false, noInput: false });
  });
});

describe("the TLS fingerprint header belongs to the operator's proxy", () => {
  it("is not read when the config does not name it, and a config that names it without trustProxy does not load", async () => {
    const { fx, url } = await proxyDoor("no-tls-header", { behaviour: {} });
    const r = await send(url, "GET", "/catalogue/a", [["user-agent", CHROME], ["accept-language", "en"], ["x-ja4", ja4("t12d1516h2")], ["ja4", ja4("t12d1516h2")]]);
    expect(r.status).toBe(200);
    expect((await arrivalOf(fx, r.receipt)).fingerprint).not.toHaveProperty("tls");

    const bad = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-behaviour-bad-")), origin.url, { behaviour: { tlsHeader: "x-ja4" } });
    expect(() => loadDoorConfig(bad.configFile)).toThrow(/behaviour\.tlsHeader needs trustProxy/);
    expect(checkDoorConfig(bad.configFile)).toContainEqual({ level: "error", check: "config", message: expect.stringMatching(/^behaviour\.tlsHeader: .*needs trustProxy/) });
  });

  it("check says what the signals are, warns that the proxy must overwrite the header, and refuses a mistyped setting", () => {
    const fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-behaviour-check-")), origin.url, { trustProxy: true, behaviour: { tlsHeader: "x-ja4" } });
    const findings = checkDoorConfig(fx.configFile);
    expect(findings.filter((f) => f.level === "error")).toEqual([]);
    expect(findings).toContainEqual({ level: "ok", check: "behaviour", message: expect.stringContaining("the door refuses nothing because of them") });
    expect(findings).toContainEqual({ level: "warn", check: "behaviour", message: expect.stringContaining("overwrites it on every request") });
    const typo = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-behaviour-typo-")), origin.url, { trustProxy: true, behaviour: { tlsheader: "x-ja4" } });
    expect(checkDoorConfig(typo.configFile).filter((f) => f.level === "error").map((f) => f.message).join("\n")).toMatch(/behaviour.*tlsheader/);
  });
});

describe("the door answering authz checks with behaviour configured", () => {
  it("fingerprints no header set, since the proxy chose it, and reads the rest from the original request", async () => {
    const { fx, url } = await proxyDoor("authz", { authz: true, trustProxy: true, behaviour: { tlsHeader: "x-ja4" } }, "permit(principal, action, resource);\n");
    const r = await send(url, "GET", "/authz", [[ORIGINAL_METHOD_HEADER, "POST"], [ORIGINAL_URI_HEADER, "/refunds"], ["user-agent", CHROME], ["x-forwarded-for", "203.0.113.60"], ["x-forwarded-proto", "https"], ["x-ja4", ja4("t13d1516h2")]]);
    expect(r.status).toBe(200);
    const a = await arrivalOf(fx, r.receipt);
    // the check carries no accept-language, and that says nothing about the client
    expect(a.fingerprint!.headers).toEqual({ client: "browser", family: "chromium", version: 126, mismatch: false, hintsMismatch: false, fetchInvalid: false });
    expect(a.fingerprint!.tls).toMatchObject({ ja4: ja4("t13d1516h2"), mismatch: false });
    expect(a.behaviour!.navigation).toMatchObject({ directWrite: true });
    expect(checkDoorConfig(fx.configFile)).toContainEqual({ level: "ok", check: "behaviour", message: expect.stringContaining("authz mode") });
  });
});

describe("the in-process door with behaviour configured", () => {
  let fx: DoorFixture;
  let guard: ReturnType<typeof inProcessDoor>;
  let server: Server;
  let base: string;
  beforeAll(async () => {
    fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-behaviour-app-")), "http://unused.invalid", { origin: undefined, behaviour: {} });
    writeFileSync(join(fx.dir, "policy.cedar"), POLICY);
    guard = inProcessDoor(fx.configFile, { autoFlush: false });
    server = createServer((req, res) => guard(req, res, () => res.end("app")));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server?.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    guard?.close();
  });

  it("the middleware sees the header order, and the policy's rule on a signal refuses before the app runs", async () => {
    const read = await send(base, "GET", "/catalogue/shoes", [["user-agent", "Go-http-client/1.1"], ["accept-encoding", "gzip"]]);
    expect(read.status).toBe(200);
    expect((await arrivalOf(fx, read.receipt)).fingerprint!.headers).toEqual({ order: expect.stringMatching(/^[0-9a-f]{16}$/), count: 4, client: "tool", family: "go-http-client", mismatch: false, hintsMismatch: false, fetchInvalid: false });
    const write = await send(base, "POST", "/refunds", [["content-type", "application/json"]], "{}");
    expect(write.status).toBe(403);
    expect((await arrivalOf(fx, write.receipt)).behaviour!.navigation.directWrite).toBe(true);
  });

  it("the route wrapper cannot see the header order, so it records none rather than guess", async () => {
    let ran = 0;
    const handler = guard.route(async () => { ran += 1; return new Response("ok"); });
    const res = await handler(new Request("https://shop.example/catalogue/shoes", { headers: { "user-agent": CHROME, "accept-language": "en", "x-ja4": ja4("t12d1516h2") } }));
    expect(res.status).toBe(200);
    expect(ran).toBe(1);
    const a = await arrivalOf(fx, res.headers.get(RECEIPT_HEADER));
    expect(a.fingerprint).toEqual({ headers: { count: 4, client: "browser", family: "chromium", version: 126, mismatch: false, hintsMismatch: false, fetchInvalid: false } });
  });
});

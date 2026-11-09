// The egress witness in front of a locked-down agent. Why each case matters: a direct call to a payment provider must be
// refused and still leave a signed record of the attempt; an agent is named only by a credential the witness checked, so
// a guessed id or a missing credential cannot satisfy a rule about that agent and is never relayed; an allowed tunnel is
// relayed byte for byte and its receipt says where it went and how much, never what; a plain HTTP request never carries
// the agent's proxy secret to the destination; observe mode relays and records the deny; an unreachable destination, the
// in-flight limit, the idle timeout, and a witness that stops each end in a receipt or say plainly why there is none.
// Every receipt verifies with public keys alone.
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import { createServer as createTcpServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadEgressConfig } from "../src/config.ts";
import { loadPublicKey, sha256Hex } from "../src/crypto.ts";
import { RECEIPT_HEADER } from "../src/door.ts";
import { DESTINATION_FACT, checkProxyCredential, createEgressHost, destinationName, normalizeHost, parseAuthority, serveEgress, type Destination, type EgressResult } from "../src/egress.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { EGRESS_AGENT, EGRESS_SECRET, buildEgressFixture, connectThrough, proxyAuth, startEcho, type EchoServer, type EgressFixture } from "../scripts/egress-fixture.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const good = proxyAuth(EGRESS_AGENT, EGRESS_SECRET);

async function waitForReceipt(fx: EgressFixture, id: string): Promise<ReceiptBundle> {
  const file = join(fx.receiptsDir, `${id}.json`);
  for (let i = 0; i < 200 && !existsSync(file); i++) await new Promise((r) => setTimeout(r, 25));
  return JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
}
const verified = (fx: EgressFixture, b: ReceiptBundle) => verifyBundle(b, { issuerKeys: [loadPublicKey(fx.witnessPub)], principalKeys: [], logFile: fx.logFile });
const failing = (r: ReturnType<typeof verifyBundle>) => r.checks.filter((c) => !c.ok).map((c) => c.name);

async function start(extra: Record<string, unknown> = {}, policy?: string) {
  const fx = buildEgressFixture(mkdtempSync(join(tmpdir(), "egress-")), extra, policy);
  const host = await createEgressHost(loadEgressConfig(fx.configFile));
  const running = await serveEgress(host, { port: 0, log: () => {} });
  const port = Number(new URL(running.url).port);
  return { fx, host, running, port, async stop() { await host.close(); await running.close(); } };
}

describe("parsing what the agent asked for", () => {
  it("reads a CONNECT authority and refuses anything that is not host:port", () => {
    expect(parseAuthority("API.Stripe.com.:443")).toEqual({ host: "api.stripe.com", port: 443 });
    expect(parseAuthority("[::1]:8443")).toEqual({ host: "::1", port: 8443 });
    for (const bad of ["api.stripe.com", "api.stripe.com:0", "api.stripe.com:70000", "a b:443", "[nothost]:443", "user@host:443", "host:443/path", ":443", "a..b:443"]) expect(parseAuthority(bad), bad).toBeNull();
    expect(destinationName("::1", 443)).toBe("[::1]:443");
    expect(normalizeHost("Example.COM")).toBe("example.com");
  });

  it("names an agent only when its secret matches; a guessed id is a claim", () => {
    const agents = new Map([[EGRESS_AGENT, Buffer.from(sha256Hex(EGRESS_SECRET), "hex")]]);
    expect(checkProxyCredential(good, agents)).toEqual({ credential: "verified", agent: EGRESS_AGENT });
    expect(checkProxyCredential(proxyAuth(EGRESS_AGENT, "guess"), agents)).toEqual({ credential: "invalid", declared: EGRESS_AGENT });
    expect(checkProxyCredential(proxyAuth("nobody", EGRESS_SECRET), agents)).toEqual({ credential: "invalid", declared: "nobody" });
    expect(checkProxyCredential("Bearer abc", agents)).toEqual({ credential: "invalid" });
    expect(checkProxyCredential(undefined, agents)).toEqual({ credential: "absent" });
  });
});

describe("the witness, enforcing", () => {
  let w: Awaited<ReturnType<typeof start>>;
  let echo: EchoServer;
  beforeAll(async () => { w = await start(); echo = await startEcho(); });
  afterAll(async () => { await w.stop(); await echo.close(); });

  it("refuses a direct call to a payment provider and receipts the attempt, without opening a connection", async () => {
    const a = await connectThrough(w.port, "api.stripe.com:443", good);
    expect(a.status).toBe(403);
    expect(JSON.parse(a.body).error).toBe("refused by the egress policy");
    a.socket.destroy();
    const b = await waitForReceipt(w.fx, a.headers[RECEIPT_HEADER]!);
    const p = decode(b).predicate;
    expect(p.issuer).toMatchObject({ kind: "egress", framework: "connect" });
    expect(p.agent).toEqual({ id: EGRESS_AGENT, provenance: "observed" });
    expect(p.tool).toEqual({ name: "api.stripe.com:443", provenance: "observed" });
    expect(p.execution.status).toBe("denied");
    expect(p.facts[DESTINATION_FACT]!.value).toMatchObject({ host: "api.stripe.com", port: 443, scheme: "connect", credential: "verified" });
    const r = verified(w.fx, b);
    expect(failing(r)).toEqual([]);
    expect(r.checks.find((c) => c.name === "egress destination observed")?.detail).toContain("not a record of what was sent");
  });

  it("relays an allowed tunnel byte for byte and records where it went and how much, not what", async () => {
    const a = await connectThrough(w.port, `127.0.0.1:${echo.port}`, good);
    expect(a.status).toBe(200);
    const reply = await new Promise<string>((resolve) => { a.socket.once("data", (c) => resolve(c.toString())); a.socket.write("hello"); });
    expect(reply).toBe("echo:hello");
    a.socket.end();
    const b = await waitForReceipt(w.fx, a.headers[RECEIPT_HEADER]!);
    const p = decode(b).predicate;
    expect(p.execution.status).toBe("executed");
    const result = (p.execution as { result: EgressResult }).result;
    expect(result).toMatchObject({ peer: "127.0.0.1", bytesUp: 5, bytesDown: 10, end: "closed" });
    expect(JSON.stringify(p)).not.toContain("hello");
    expect(failing(verified(w.fx, b))).toEqual([]);
  });

  it("refuses with 407 when no credential is sent, and the receipt names nobody", async () => {
    const a = await connectThrough(w.port, `127.0.0.1:${echo.port}`);
    expect(a.status).toBe(407);
    expect(a.headers["proxy-authenticate"]).toBe('Basic realm="agent-custody egress"');
    a.socket.destroy();
    const b = await waitForReceipt(w.fx, a.headers[RECEIPT_HEADER]!);
    const p = decode(b).predicate;
    expect(p.agent).toEqual({ id: "unknown", provenance: "claimed" });
    expect(p.execution.status).toBe("denied");
    expect(failing(verified(w.fx, b))).toEqual([]);
  });

  it("a guessed secret cannot satisfy a rule about the agent it names: refused, the name kept only as a claim", async () => {
    const a = await connectThrough(w.port, `127.0.0.1:${echo.port}`, proxyAuth(EGRESS_AGENT, "guess"));
    expect(a.status).toBe(407);
    a.socket.destroy();
    const p = decode(await waitForReceipt(w.fx, a.headers[RECEIPT_HEADER]!)).predicate;
    expect(p.agent).toEqual({ id: "unknown", provenance: "claimed" });
    expect((p.facts[DESTINATION_FACT]!.value as Destination)).toMatchObject({ credential: "invalid", declared: EGRESS_AGENT });
    expect(p.policy?.decision).toBe("deny");
  });

  it("records an unreachable destination as an error, since no byte reached it", async () => {
    const closed = createTcpServer();
    const port = await new Promise<number>((r) => closed.listen(0, "127.0.0.1", () => r((closed.address() as AddressInfo).port)));
    await new Promise<void>((r) => closed.close(() => r()));
    const a = await connectThrough(w.port, `127.0.0.1:${port}`, good);
    expect(a.status).toBe(502);
    a.socket.destroy();
    const b = await waitForReceipt(w.fx, a.headers[RECEIPT_HEADER]!);
    expect(decode(b).predicate.execution).toMatchObject({ status: "error" });
    expect(failing(verified(w.fx, b))).toEqual([]);
  });

  it("relays plain HTTP without the agent's proxy secret, with the Host the policy decided on", async () => {
    let seen: Record<string, string | string[] | undefined> = {};
    const origin: Server = createServer((req, res) => { seen = req.headers; req.resume(); res.end("plain answer"); });
    const oport = await new Promise<number>((r) => origin.listen(0, "127.0.0.1", () => r((origin.address() as AddressInfo).port)));
    const answer = await new Promise<{ status: number; id: string; body: string }>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: w.port, method: "POST", path: `http://127.0.0.1:${oport}/docs?q=1`, headers: { "proxy-authorization": good, host: "evil.example", "content-type": "text/plain" } }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode!, id: res.headers[RECEIPT_HEADER] as string, body }));
      });
      req.on("error", reject);
      req.end("abc");
    });
    await new Promise<void>((r) => origin.close(() => r()));
    expect(answer).toMatchObject({ status: 200, body: "plain answer" });
    expect(seen["proxy-authorization"]).toBeUndefined();
    expect(seen.host).toBe(`127.0.0.1:${oport}`);
    const b = await waitForReceipt(w.fx, answer.id);
    const p = decode(b).predicate;
    expect(p.issuer.framework).toBe("http");
    expect(p.request.args).toEqual({ method: "POST", host: "127.0.0.1", port: oport });
    expect((p.execution as { result: EgressResult }).result).toMatchObject({ status: 200, bytesUp: 3, bytesDown: 12, end: "closed" });
    expect(failing(verified(w.fx, b))).toEqual([]);
  });

  it("answers for itself in origin form and refuses https:// in a plain request", async () => {
    const wk = await fetch(`${w.running.url}/.well-known/agent-custody-egress`).then((r) => r.json()) as { keyid: string };
    expect(wk.keyid).toBe(w.host.keyid);
    const status = await new Promise<number>((resolve) => {
      request({ host: "127.0.0.1", port: w.port, path: "https://api.stripe.com/v1/charges", headers: { "proxy-authorization": good } }, (res) => { res.resume(); resolve(res.statusCode!); }).end();
    });
    expect(status).toBe(400);
  });
});

describe("the witness's limits and modes", () => {
  it("observe mode relays a denied destination and records the deny as not enforced", async () => {
    const echo = await startEcho();
    const w = await start({ mode: "observe" }, "forbid(principal, action, resource);\n");
    try {
      const a = await connectThrough(w.port, `127.0.0.1:${echo.port}`, good);
      expect(a.status).toBe(200);
      a.socket.end();
      const b = await waitForReceipt(w.fx, a.headers[RECEIPT_HEADER]!);
      expect(decode(b).predicate.policy).toMatchObject({ decision: "deny", enforced: false });
      expect(failing(verified(w.fx, b))).toEqual([]);
    } finally { await w.stop(); await echo.close(); }
  });

  it("past maxInFlight answers 503 and writes no receipt; an idle tunnel is closed and receipted as idle", async () => {
    const echo = await startEcho();
    const w = await start({ maxInFlight: 1, idleTimeoutMs: 300 });
    try {
      const first = await connectThrough(w.port, `127.0.0.1:${echo.port}`, good);
      expect(first.status).toBe(200);
      const second = await connectThrough(w.port, `127.0.0.1:${echo.port}`, good);
      expect(second.status).toBe(503);
      expect(second.headers[RECEIPT_HEADER]).toBeUndefined();
      second.socket.destroy();
      const b = await waitForReceipt(w.fx, first.headers[RECEIPT_HEADER]!);
      expect((decode(b).predicate.execution as { result: EgressResult }).result.end).toBe("idle-timeout");
    } finally { await w.stop(); await echo.close(); }
  });

  it("a witness that stops closes its tunnels and receipts each as witness-stopped before it returns", async () => {
    const echo = await startEcho();
    const w = await start();
    try {
      const a = await connectThrough(w.port, `127.0.0.1:${echo.port}`, good);
      expect(a.status).toBe(200);
      await w.host.close();
      const file = join(w.fx.receiptsDir, `${a.headers[RECEIPT_HEADER]}.json`);
      expect(existsSync(file)).toBe(true);
      const p = decode(JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle).predicate;
      expect((p.execution as { result: EgressResult }).result.end).toBe("witness-stopped");
    } finally { await w.running.close(); await echo.close(); }
  });

  it("refuses to start without an agent's secret in the environment", async () => {
    const fx = buildEgressFixture(mkdtempSync(join(tmpdir(), "egress-")), { agents: [{ id: "other", secretEnv: "EGRESS_TEST_UNSET_VARIABLE" }] });
    delete process.env.EGRESS_TEST_UNSET_VARIABLE;
    await expect(createEgressHost(loadEgressConfig(fx.configFile))).rejects.toThrow(/EGRESS_TEST_UNSET_VARIABLE is not set/);
  });
});

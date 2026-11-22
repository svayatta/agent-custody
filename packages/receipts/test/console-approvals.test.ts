// The console's Approvals tab. What an operator relies on: the console signs nothing and never sees a key; the page signs
// in the browser, and the console stores a signature only if it verifies with a trusted approver key over this exact
// call, so the gateway then forwards that call once. The page's own signing code is run here under Node's WebCrypto.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { APPROVAL_REQUEST_META_KEY } from "../src/approval-requests.ts";
import { loadConfig } from "../src/config.ts";
import { serveConsole, type RunningConsole } from "../src/console.ts";
import { CONSOLE_SCRIPT } from "../src/console-page.ts";
import { generateKeyPair, writeKeyPair } from "../src/crypto.ts";
import { createGateway } from "../src/gateway.ts";
import { buildFixture } from "../scripts/fixture.ts";

const TOKEN = "console-approvals-token";
const approver = generateKeyPair();
const second = generateKeyPair();
const stranger = generateKeyPair();
let fx: ReturnType<typeof buildFixture>;
let con: RunningConsole;
let files: Record<"approver" | "second" | "stranger", string>;

const call = async (path: string, body?: unknown) => {
  const r = await fetch(new URL(path, con.url), { method: body === undefined ? "GET" : "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: r.status, body: (await r.json()) as any };
};
const refund = async (amount: number) => {
  const gw = await createGateway(loadConfig(fx.configFile));
  try {
    return await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount } });
  } finally {
    await gw.close();
  }
};
const requestOf = (r: { _meta?: Record<string, unknown> }) => (r._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string }).requestId;

// the page's signWith, exactly as it ships, run against Node's WebCrypto and File
const pageSign: (file: File, pae: string) => Promise<{ keyid: string; sig: string }> = (() => {
  const start = CONSOLE_SCRIPT.indexOf("  function b64bytes");
  const end = CONSOLE_SCRIPT.indexOf("\n  }\n", CONSOLE_SCRIPT.indexOf("function signWith")) + 4;
  return vm.runInNewContext(`${CONSOLE_SCRIPT.slice(start, end)}\nsignWith`, { atob, btoa, crypto: globalThis.crypto, Uint8Array, Promise, Array });
})();
const keyFile = (path: string) => new File([readFileSync(path, "utf8")], "approver.key");
async function approveInPage(requestId: string, path: string, expiresInSeconds = 600) {
  const prepared = await call("/api/approvals/prepare", { requestId, expiresInSeconds });
  expect(prepared.status, JSON.stringify(prepared.body)).toBe(200);
  const s = await pageSign(keyFile(path), prepared.body.pae);
  return call("/api/approvals/sign", { requestId, payload: prepared.body.payload, keyid: s.keyid, sig: s.sig });
}

beforeAll(async () => {
  fx = buildFixture(join(mkdtempSync(join(tmpdir(), "console-approvals-")), "fx"));
  files = {
    approver: writeKeyPair(approver, join(fx.dir, "keys"), "approver").keyFile,
    second: writeKeyPair(second, join(fx.dir, "keys"), "second-approver").keyFile,
    stranger: writeKeyPair(stranger, join(fx.dir, "keys"), "stranger").keyFile,
  };
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
  cfg.approvals = { trustedKeys: ["keys/approver.pub", "keys/second-approver.pub"], usedDir: "approvals-used", maxLifetimeSeconds: 900, requests: { dir: "approval-requests" }, tools: [{ tool: "stripe.refund" }] };
  writeFileSync(fx.configFile, JSON.stringify(cfg));
  con = await serveConsole({ configFile: fx.configFile, token: TOKEN, port: 0, log: () => {} });
});
afterAll(async () => {
  await con.close();
});

describe("the console's approvals", () => {
  it("lists a waiting request with its exact arguments, and needs the token", async () => {
    const requestId = requestOf(await refund(2500));
    const { body } = await call("/api/approvals");
    expect(body).toMatchObject({ configured: true, maxLifetimeSeconds: 900, trustedKeyids: [approver.keyid, second.keyid] });
    expect(body.requests.find((r: { requestId: string }) => r.requestId === requestId)).toMatchObject({ status: "pending", agent: "support-agent", tool: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 }, signedBy: [] });
    expect((await fetch(new URL("/api/approvals", con.url))).status).toBe(401);
  });

  it("stores the page's signature with a trusted key, after which the gateway forwards that call once", async () => {
    const requestId = requestOf(await refund(1200));
    const signed = await approveInPage(requestId, files.approver);
    expect(signed.status, JSON.stringify(signed.body)).toBe(200);
    expect(signed.body.status).toBe("approved");
    const ok = await refund(1200);
    expect(ok.isError, JSON.stringify(ok.content)).toBeFalsy();
    expect((await refund(1200)).isError).toBe(true);
    const audit = (await call("/api/audit")).body.entries;
    expect(audit[0]).toMatchObject({ action: "approval.sign", requestId, keyid: approver.keyid, status: "approved" });
  });

  it("refuses a signature from a key the gateway does not trust, or over another payload, and stores nothing", async () => {
    const requestId = requestOf(await refund(1300));
    const untrusted = await approveInPage(requestId, files.stranger);
    expect(untrusted.status).toBe(409);
    expect(untrusted.body.error).toContain("the signature was not accepted");
    const prepared = await call("/api/approvals/prepare", { requestId, expiresInSeconds: 600 });
    const other = await call("/api/approvals/prepare", { requestId: requestOf(await refund(1301)), expiresInSeconds: 600 });
    const s = await pageSign(keyFile(files.approver), other.body.pae);
    const swapped = await call("/api/approvals/sign", { requestId, payload: other.body.payload, keyid: s.keyid, sig: s.sig });
    expect(swapped.status).toBe(409);
    expect(swapped.body.error).toContain("does not match this call");
    const forged = await call("/api/approvals/sign", { requestId, payload: prepared.body.payload, keyid: approver.keyid, sig: Buffer.alloc(64).toString("base64") });
    expect(forged.status).toBe(409);
    expect((await call("/api/approvals")).body.requests.find((r: { requestId: string }) => r.requestId === requestId).status).toBe("pending");
    expect((await refund(1300)).isError).toBe(true);
  });

  it("refuses an expiry longer than the gateway accepts, and records a denial that the gateway reports without its free text", async () => {
    const requestId = requestOf(await refund(1400));
    expect((await call("/api/approvals/prepare", { requestId, expiresInSeconds: 3600 })).status).toBe(400);
    const denied = await call("/api/approvals/deny", { requestId, reason: "duplicate of an earlier refund" });
    expect(denied.status).toBe(200);
    const again = await refund(1400);
    expect((again.content as { text: string }[])[0]!.text).toContain(`an approver denied request ${requestId}`);
    expect((again.content as { text: string }[])[0]!.text).not.toContain("duplicate of an earlier refund");
    expect((await call("/api/approvals/prepare", { requestId, expiresInSeconds: 600 })).status).toBe(409);
  });
});

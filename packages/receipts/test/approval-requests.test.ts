// Human in the loop over signed approvals. What must hold: the request store only carries requests and signed
// envelopes, so nothing written to it can make the gateway forward a call that no trusted approver signed for exactly.
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { createApproval, type ApprovalBinding } from "../src/approval.ts";
import { APPROVAL_REQUEST_META_KEY, approvalRequestId, approveApprovalRequest, denyApprovalRequest, listApprovalRequests, readApprovalRequest } from "../src/approval-requests.ts";
import { loadConfig, type GatewayConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair, type Envelope } from "../src/crypto.ts";
import { createGatewayHost, RECEIPT_META_KEY, type Gateway, type GatewayHost } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";

const args = (amount = 2500) => ({ amount, currency: "GBP", beneficiary: "cust_123", customer_id: "cust_123" });
const binding = (a: Record<string, unknown> = args()): ApprovalBinding => ({ principal: "user_456", agent: "support-agent", tool: "stripe.refund", args: a });
const approver = generateKeyPair();
const second = generateKeyPair();
const stranger = generateKeyPair();
const in10m = () => new Date(Date.now() + 600_000).toISOString();

let server: Server;
let url: string;
let refunds: unknown[] = [];
const hosts: GatewayHost[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") refunds.push(JSON.parse(body));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(req.method === "GET" ? { id: "cust_123", verified: true } : { refund_id: "re_1" }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterEach(async () => {
  for (const h of hosts.splice(0)) await h.close();
  refunds = [];
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

async function gateway(opts: { minApprovers?: 1 | 2; requests?: boolean } = {}) {
  const fx: Fixture = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-approval-requests-")));
  writeKeyPair(approver, join(fx.dir, "keys"), "approver");
  writeKeyPair(second, join(fx.dir, "keys"), "second-approver");
  const raw = JSON.parse(readFileSync(fx.configFile, "utf8"));
  raw.upstream = { rest: { baseUrl: url, tools: [{ name: "customer.lookup", path: "/customer/{customer_id}" }, { name: "stripe.refund", method: "POST", path: "/refund" }] } };
  raw.approvals = {
    trustedKeys: ["keys/approver.pub", "keys/second-approver.pub"],
    usedDir: "used-approvals",
    maxLifetimeSeconds: 900,
    ...(opts.requests === false ? {} : { requests: { dir: "approval-requests" } }),
    tools: [{ tool: "stripe.refund", minApprovers: opts.minApprovers ?? 1 }],
  };
  writeFileSync(fx.configFile, JSON.stringify(raw));
  writeFileSync(join(fx.dir, "policy.cedar"), "permit(principal, action, resource);");
  const cfg: GatewayConfig = loadConfig(fx.configFile);
  const host = await createGatewayHost(cfg);
  hosts.push(host);
  const gw: Gateway = host.open(JSON.parse(readFileSync(cfg.grantFile!, "utf8")) as Envelope);
  const send = (a: Record<string, unknown> = args()) => gw.handleCall({ name: "stripe.refund", arguments: a });
  const bundleOf = (r: Awaited<ReturnType<Gateway["handleCall"]>>) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const predicate = (r: Awaited<ReturnType<Gateway["handleCall"]>>): ReceiptPredicate => (JSON.parse(Buffer.from(bundleOf(r).envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
  const dir = join(fx.dir, "approval-requests");
  return { fx, cfg, send, bundleOf, predicate, dir };
}
const textOf = (r: { content?: unknown }) => (r.content as { text: string }[])[0]!.text;

describe("human in the loop: approval requests", () => {
  it("refuses a protected call without an approval, leaves a request for it, and names the request to the agent", async () => {
    const { send, dir } = await gateway();
    const r = await send();
    const requestId = approvalRequestId(binding());
    expect(r.isError).toBe(true);
    expect(textOf(r)).toContain(`request ${requestId} is waiting for an approver`);
    expect(r._meta?.[APPROVAL_REQUEST_META_KEY]).toEqual({ requestId, status: "pending" });
    expect(refunds).toEqual([]);
    const request = readApprovalRequest(dir, requestId)!;
    expect(request).toMatchObject({ status: "pending", requiredApprovers: 1, binding: binding(), receiptId: r._meta?.[RECEIPT_META_KEY] });
    // the same call refused again names the same request, and does not open a second one
    await send();
    expect(listApprovalRequests(dir)).toHaveLength(1);
  });

  it("forwards the same call once after an approver signs it, with an approval the verifier accepts, and only once", async () => {
    const { send, dir, bundleOf, predicate, fx } = await gateway();
    const requestId = (await send())._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
    expect(approveApprovalRequest(dir, requestId.requestId, approver, { expiresAt: in10m() }).status).toBe("approved");
    const ok = await send();
    expect(ok.isError, textOf(ok)).toBeFalsy();
    expect(refunds).toEqual([args()]);
    expect(predicate(ok).approval).toMatchObject({ status: "approved", approverKeyids: [approver.keyid] });
    const v = verifyBundle(bundleOf(ok), { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], approvalKeys: [approver, second] });
    expect(v.ok, JSON.stringify(v.checks.filter((c) => !c.ok))).toBe(true);
    // the approval was consumed: the same call again is refused and opens a new request, saying why
    const again = await send();
    expect(again.isError).toBe(true);
    expect(textOf(again)).toContain("the last approval for this call has been used");
    expect(refunds).toHaveLength(1);
    expect(readApprovalRequest(dir, requestId.requestId)!.status).toBe("pending");
  });

  it("does not use an approval for a call with any other argument, which is its own request", async () => {
    const { send, dir } = await gateway();
    const first = (await send())._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
    approveApprovalRequest(dir, first.requestId, approver, { expiresAt: in10m() });
    const changed = await send(args(2501));
    expect(changed.isError).toBe(true);
    expect((changed._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string }).requestId).not.toBe(first.requestId);
    expect(refunds).toEqual([]);
  });

  it("never forwards on an envelope in the store that no trusted key signed, or that signs another call", async () => {
    const { send, dir } = await gateway();
    const { requestId } = (await send())._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
    const file = join(dir, `${requestId}.json`);
    const forge = (envelope: Envelope) => writeFileSync(file, JSON.stringify({ ...readApprovalRequest(dir, requestId), status: "approved", envelope }));
    forge(createApproval(stranger, { ...binding(), expiresAt: in10m() }));
    const r1 = await send();
    expect(textOf(r1)).toContain("the last approval for this call was not accepted");
    forge(createApproval(approver, { ...binding(args(1)), expiresAt: in10m() }));
    const r2 = await send();
    expect(textOf(r2)).toContain("approval argsDigest does not match this call");
    writeFileSync(file, "not json");
    expect((await send()).isError).toBe(true);
    expect(refunds).toEqual([]);
  });

  it("needs two approvers with distinct keys under a two-person rule", async () => {
    const { send, dir } = await gateway({ minApprovers: 2 });
    const { requestId } = (await send())._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
    expect(approveApprovalRequest(dir, requestId, approver, { expiresAt: in10m() }).status).toBe("pending");
    expect(() => approveApprovalRequest(dir, requestId, approver, { expiresAt: in10m() })).toThrow(/different key/);
    expect((await send()).isError).toBe(true);
    expect(refunds).toEqual([]);
    expect(approveApprovalRequest(dir, requestId, second, { expiresAt: in10m() }).status).toBe("approved");
    expect((await send()).isError).toBeFalsy();
    expect(refunds).toHaveLength(1);
  });

  it("keeps refusing a call an approver denied, and says so", async () => {
    const { send, dir } = await gateway();
    const { requestId } = (await send())._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
    denyApprovalRequest(dir, requestId, { reason: "the customer was refunded by phone" });
    const r = await send();
    expect(textOf(r)).toContain(`an approver denied request ${requestId}: the customer was refunded by phone`);
    expect(r._meta?.[APPROVAL_REQUEST_META_KEY]).toEqual({ requestId, status: "denied" });
    expect(() => approveApprovalRequest(dir, requestId, approver, { expiresAt: in10m() })).toThrow(/already denied/);
    expect(refunds).toEqual([]);
  });

  it("leaves no request when approvals.requests is not configured", async () => {
    const { send, dir } = await gateway({ requests: false });
    const r = await send();
    expect(r.isError).toBe(true);
    expect(r._meta?.[APPROVAL_REQUEST_META_KEY]).toBeUndefined();
    expect(existsSync(dir)).toBe(false);
  });

  it("the approvals command lists, shows, and approves a request, refusing an expiry the gateway would not accept", async () => {
    const { send, dir, fx } = await gateway();
    const { requestId } = (await send())._meta?.[APPROVAL_REQUEST_META_KEY] as { requestId: string };
    const cli = (...a: string[]) => spawnSync(process.execPath, ["--import", "tsx", join(import.meta.dirname, "../src/cli.ts"), "approvals", ...a], { encoding: "utf8", timeout: 30_000 });
    const list = cli("list", "--config", fx.configFile);
    expect(list.status, list.stderr).toBe(0);
    expect(list.stdout).toContain(`${requestId}  pending`);
    const show = cli("show", requestId, "--config", fx.configFile);
    expect(JSON.parse(show.stdout)).toMatchObject({ requestId, tool: "stripe.refund", arguments: args() });
    const tooLong = cli("approve", requestId, "--config", fx.configFile, "--key", join(fx.dir, "keys/approver.key"), "--expires", "1h");
    expect(tooLong.status).not.toBe(0);
    expect(tooLong.stderr).toContain("longer than the gateway accepts");
    const ok = cli("approve", requestId, "--config", fx.configFile, "--key", join(fx.dir, "keys/approver.key"), "--expires", "5m");
    expect(ok.status, ok.stderr).toBe(0);
    expect(readApprovalRequest(dir, requestId)!.status).toBe("approved");
    expect((await send()).isError).toBeFalsy();
  });
});

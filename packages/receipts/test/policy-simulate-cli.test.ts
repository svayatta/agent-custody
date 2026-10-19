import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildFixture, buildSdkFixture, SDK_POLICY, type SdkFixture } from "../scripts/fixture.ts";
import { pathKey } from "../src/capture.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { APPROVAL_META_KEY, createApproval } from "../src/approval.ts";
import { dsseSign, generateKeyPair, loadPrivateKey, writeKeyPair } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { policyDigest } from "../src/policy.ts";
import { RECEIPT_TYPE, TREEHEAD_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer, receiptIdOf } from "../src/sdk/index.ts";
import type { SimulationReport } from "../src/simulate.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const proposed = `permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 1000 || context.args.amount >= 100000 };
`;
let dir: string;
let fx: SdkFixture;
let policyFile: string;
let ids: string[];

const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 30_000 });
const simulate = (...args: string[]) => run("policy", "simulate", "--policy", policyFile, "--receipts", fx.receiptsDir, "--issuer-key", fx.appPub, ...args);
const decode = (bundle: ReceiptBundle) => JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString("utf8")) as ReceiptStatement;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "policy-simulate-cli-"));
  fx = buildSdkFixture(join(dir, "sdk"));
  policyFile = join(dir, "proposed.cedar");
  writeFileSync(policyFile, proposed);
  const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
  ids = [];
  for (const amount of [100, 5000, 150000]) {
    const event = { tool: "stripe.refund", args: { amount } };
    const decision = sdk.decide(event)!;
    const outcome = decision.decision === "allow" ? { status: "executed" as const, result: { refunded: amount } } : { status: "denied" as const, reason: "over limit" };
    ids.push(receiptIdOf(await sdk.record(event, outcome, decision)));
  }
  // The salts directory is a normal issuer side directory, not a receipt bundle, and must not enter the replay.
  mkdirSync(join(fx.receiptsDir, "salts"));
  writeFileSync(join(fx.receiptsDir, "salts", "private.json"), "not receipt JSON");
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("policy simulate CLI on plain Node", () => {
  it("reports both decision changes, keeps baseline digests, and writes its full JSON report owner-only", () => {
    const out = join(dir, "simulation.json");
    writeFileSync(out, "old report");
    chmodSync(out, 0o644);
    const result = simulate("--json", "--out", out);
    expect(result.status, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout) as SimulationReport;
    expect(report).toMatchObject({ total: 3, evaluated: 3, unchanged: 1, complete: true, policyDigest: policyDigest(proposed), previousPolicyDigests: [policyDigest(SDK_POLICY)] });
    expect(report.changes.map((change) => change.receiptId).sort()).toEqual([ids[1], ids[2]].sort());
    expect(report.changes.find((change) => change.receiptId === ids[1])).toMatchObject({ previous: { decision: "allow" }, proposed: { decision: "deny" } });
    expect(report.changes.find((change) => change.receiptId === ids[2])).toMatchObject({ previous: { decision: "deny" }, proposed: { decision: "allow" } });
    expect(report.runId).toMatch(/^[0-9a-f-]{36}$/);
    expect(new Date(report.timestamp).toISOString()).toBe(report.timestamp);
    expect(report.skipped).toEqual([]);
    expect(report.groups.flatMap((group) => group.receiptIds).sort()).toEqual([ids[1], ids[2]].sort());
    expect(JSON.parse(readFileSync(out, "utf8"))).toEqual(report);
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  it("prints grouped receipt IDs for a human and keeps --out in JSON", () => {
    const out = join(dir, "human-report.json");
    const result = simulate("--out", out);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("stripe.refund");
    expect(result.stdout).toContain(ids[1]);
    expect(result.stdout).toContain(ids[2]);
    expect(JSON.parse(readFileSync(out, "utf8")).policyDigest).toBe(policyDigest(proposed));
  });

  it("verifies gateway delegation and replays recorded facts after the gateway has closed", async () => {
    const gatewayFixture = buildFixture(join(dir, "gateway"));
    const cfg = loadConfig(gatewayFixture.configFile);
    cfg.precommit = ["stripe.refund"];
    const gateway = await createGateway(cfg);
    let id: string;
    try {
      const result = await gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 500 } });
      expect(result.isError).toBeFalsy();
      id = String(result._meta?.[RECEIPT_META_KEY]);
    } finally {
      await gateway.close();
    }
    const proposedFile = join(dir, "facts.cedar");
    writeFileSync(proposedFile, `permit(principal, action, resource) when { context.facts.customer.verified == false };`);
    const args = ["policy", "simulate", "--policy", proposedFile, "--receipts", gatewayFixture.receiptsDir, "--issuer-key", gatewayFixture.gatewayPub];
    const untrusted = run(...args, "--json");
    expect(untrusted.status).toBe(1);
    expect(untrusted.stderr).toContain("delegation signature (principal key)");
    const result = run(...args, "--principal-key", gatewayFixture.principalPub, "--json");
    expect(result.status, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout) as SimulationReport;
    expect(report).toMatchObject({ total: 1, evaluated: 1, complete: true });
    expect(report.changes.map((change) => change.receiptId)).toEqual([id]);
  });

  it("rejects a tampered receipt before producing or saving a replay report", () => {
    const receipts = join(dir, "tampered");
    mkdirSync(receipts);
    const file = join(receipts, "tampered.json");
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${ids[0]}.json`), "utf8")) as ReceiptBundle;
    const statement = decode(bundle);
    statement.predicate.request.args.amount = 9000;
    bundle.envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    writeFileSync(file, JSON.stringify(bundle));
    const result = simulate("--receipts", receipts, "--json");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(file);
    expect(result.stderr).toContain("receipt signature (issuer key)");
    expect(result.stdout).toBe("");
  });

  it("requires the supplied trust key for a separately signed log head", () => {
    const receipts = join(dir, "independent-log");
    mkdirSync(receipts);
    const logKey = generateKeyPair();
    const logFiles = writeKeyPair(logKey, join(dir, "keys"), "log");
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${ids[0]}.json`), "utf8")) as ReceiptBundle;
    const treeHead = JSON.parse(Buffer.from(bundle.treeHead.payload, "base64").toString("utf8"));
    bundle.treeHead = dsseSign(TREEHEAD_TYPE, treeHead, logKey);
    writeFileSync(join(receipts, "receipt.json"), JSON.stringify(bundle));
    expect(simulate("--receipts", receipts).status).toBe(1);
    const trusted = simulate("--receipts", receipts, "--log-key", fx.appPub, "--log-key", logFiles.pubFile, "--json");
    expect(trusted.status, trusted.stderr).toBe(0);
    expect(JSON.parse(trusted.stdout)).toMatchObject({ total: 1, evaluated: 1, complete: true });
  });

  it("rejects a trusted signature over the wrong predicate type", () => {
    const receipts = join(dir, "wrong-type");
    mkdirSync(receipts);
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${ids[0]}.json`), "utf8")) as ReceiptBundle;
    const statement = { ...decode(bundle), predicateType: "https://example.com/not-a-receipt" };
    bundle.envelope = dsseSign(RECEIPT_TYPE, statement, loadPrivateKey(join(fx.dir, "keys", "app.key")));
    writeFileSync(join(receipts, "wrong-type.json"), JSON.stringify(bundle));
    const result = simulate("--receipts", receipts);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("receipt payload type");
    expect(result.stdout).toBe("");
  });

  it("fails on malformed receipt JSON in filename order instead of silently skipping it", () => {
    const receipts = join(dir, "malformed");
    mkdirSync(receipts);
    writeFileSync(join(receipts, "z.json"), "not JSON");
    writeFileSync(join(receipts, "a.json"), "not JSON");
    copyFileSync(join(fx.receiptsDir, `${ids[0]}.json`), join(receipts, "b.json"));
    const result = simulate("--receipts", receipts);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(join(receipts, "a.json"));
    expect(result.stdout).toBe("");
  });

  it("marks withheld replay inputs incomplete, writes that report, and exits 1", async () => {
    const privateFixture = buildSdkFixture(join(dir, "private"));
    const cfg = loadSdkConfig(privateFixture.configFile);
    cfg.capture = { "*": { args: { mode: "digest" } } };
    const sdk = createSdkIssuer(cfg);
    const event = { tool: "stripe.refund", args: { amount: 100 } };
    const bundle = await sdk.record(event, { status: "executed", result: "ok" }, sdk.decide(event));
    const out = join(dir, "incomplete.json");
    const result = simulate("--receipts", privateFixture.receiptsDir, "--issuer-key", privateFixture.appPub, "--out", out, "--json");
    expect(result.status, result.stderr).toBe(1);
    const report = JSON.parse(result.stdout) as SimulationReport;
    expect(report).toMatchObject({ complete: false, total: 1, evaluated: 0 });
    expect(report.skipped).toHaveLength(1);
    expect(report.skipped[0]?.receiptId).toBe(receiptIdOf(bundle));
    expect(report.skipped[0]?.reason).toMatch(/withheld/i);
    expect(JSON.parse(readFileSync(out, "utf8"))).toEqual(report);
  });

  it("reports a call whose receipt is missing but whose authorization survives, instead of dropping it", async () => {
    const gatewayFixture = buildFixture(join(dir, "orphan"));
    const cfg = loadConfig(gatewayFixture.configFile);
    cfg.precommit = ["stripe.refund"];
    const gateway = await createGateway(cfg);
    const made: string[] = [];
    try {
      for (const amount of [500, 40000]) {
        const result = await gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount } });
        made.push(String(result._meta?.[RECEIPT_META_KEY]));
      }
    } finally {
      await gateway.close();
    }
    // The gateway died after it forwarded the second call: the authorization is on disk and the receipt is not.
    rmSync(join(gatewayFixture.receiptsDir, `${made[1]}.json`));
    const tighter = join(dir, "orphan.cedar");
    writeFileSync(tighter, `permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 1000 };`);
    const args = ["policy", "simulate", "--policy", tighter, "--receipts", gatewayFixture.receiptsDir, "--issuer-key", gatewayFixture.gatewayPub, "--principal-key", gatewayFixture.principalPub, "--json"];
    const result = run(...args);
    expect(result.status, result.stderr).toBe(1);
    const report = JSON.parse(result.stdout) as SimulationReport;
    expect(report).toMatchObject({ total: 2, evaluated: 1, unchanged: 1, complete: false, skipped: [{ receiptId: made[1], tool: "stripe.refund", reason: expect.stringContaining("authorization") }] });
    // An authorization that does not verify fails the command, as a receipt that does not verify does.
    const file = join(gatewayFixture.receiptsDir, `${made[1]}.authorization.json`);
    const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
    bundle.inclusion.leafIndex += 1;
    writeFileSync(file, JSON.stringify(bundle));
    const forged = run(...args);
    expect(forged.status).toBe(1);
    expect(forged.stderr).toContain(file);
    expect(forged.stdout).toBe("");
  });

  it("replays receipts under a capture rule with the capture key or a disclosure", async () => {
    const privateFixture = buildSdkFixture(join(dir, "keyed"));
    const cfg = JSON.parse(readFileSync(privateFixture.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "encrypted" } } };
    cfg.captureKeyEnv = "SIMULATE_CAPTURE_KEY";
    writeFileSync(privateFixture.configFile, JSON.stringify(cfg));
    process.env.SIMULATE_CAPTURE_KEY = randomBytes(32).toString("hex");
    const sdk = createSdkIssuer(loadSdkConfig(privateFixture.configFile));
    const event = { tool: "stripe.refund", args: { amount: 100 } };
    await sdk.record(event, { status: "executed", result: "ok" }, sdk.decide(event));
    const keyed = (...more: string[]) => simulate("--receipts", privateFixture.receiptsDir, "--issuer-key", privateFixture.appPub, "--json", ...more);
    expect(keyed().status).toBe(1);
    const wrong = spawnSync(process.execPath, [cli, "policy", "simulate", "--policy", policyFile, "--receipts", privateFixture.receiptsDir, "--issuer-key", privateFixture.appPub, "--capture-key-env", "SIMULATE_CAPTURE_KEY_UNSET"], { encoding: "utf8" });
    expect(wrong.status).toBe(1);
    expect(wrong.stderr).toContain("SIMULATE_CAPTURE_KEY_UNSET");
    const result = keyed("--capture-key-env", "SIMULATE_CAPTURE_KEY");
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ total: 1, evaluated: 1, unchanged: 1, complete: true });

    const digestFixture = buildSdkFixture(join(dir, "disclosed"));
    const digestCfg = loadSdkConfig(digestFixture.configFile);
    digestCfg.capture = { "*": { args: { mode: "digest" }, result: { mode: "clear" }, facts: { mode: "clear" } } };
    const digestSdk = createSdkIssuer(digestCfg);
    const bundle = await digestSdk.record(event, { status: "executed", result: "ok" }, digestSdk.decide(event));
    const statement = decode(bundle);
    const id = statement.predicate.receiptId;
    // The holder fills in the value beside the salt it kept, as reveal --include-salts describes.
    const salts = (JSON.parse(readFileSync(join(digestFixture.receiptsDir, "salts", `${id}.json`), "utf8")) as { salts: Record<string, string> }).salts;
    const path = statement.predicate.capture!.withheld[0]!;
    const disclosureFile = join(dir, "disclosure.json");
    writeFileSync(disclosureFile, JSON.stringify({ receiptId: id, request: { args: { $rest: { $custody: "disclosed", salt: salts[pathKey(path)], value: event.args } } } }));
    const base = ["--receipts", digestFixture.receiptsDir, "--issuer-key", digestFixture.appPub, "--json"];
    expect(simulate(...base).status).toBe(1);
    const disclosed = simulate(...base, "--disclose", disclosureFile);
    expect(disclosed.status, disclosed.stderr).toBe(0);
    expect(JSON.parse(disclosed.stdout)).toMatchObject({ total: 1, evaluated: 1, complete: true });
    // A disclosure that does not match the commitment fails; it never replays a made-up value.
    writeFileSync(disclosureFile, JSON.stringify({ receiptId: id, request: { args: { $rest: { $custody: "disclosed", salt: salts[pathKey(path)], value: { amount: 999999 } } } } }));
    const lying = simulate(...base, "--disclose", disclosureFile);
    expect(lying.status).toBe(1);
    expect(JSON.parse(lying.stdout)).toMatchObject({ evaluated: 0, complete: false, skipped: [{ reason: expect.stringContaining("does not match") }] });
  });

  it("rejects malformed proposed Cedar instead of reporting a successful replay", () => {
    const malformed = join(dir, "invalid.cedar");
    writeFileSync(malformed, "permit(principal, action, resource) when {;");
    const result = simulate("--policy", malformed, "--json");
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/policy|cedar/i);
    expect(result.stdout).toBe("");
  });

  it("explains missing command inputs and refuses an empty receipts directory", () => {
    const unknown = run("policy", "publish");
    expect(unknown.status).toBe(1);
    expect(unknown.stderr).toContain("simulate subcommand");
    const missing = run("policy", "simulate", "--policy", policyFile);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("--receipts");
    const receipts = join(dir, "empty");
    mkdirSync(receipts);
    const empty = simulate("--receipts", receipts);
    expect(empty.status).toBe(1);
    expect(empty.stderr).toContain("no receipt bundles found");
  });
});

describe("policy simulate with human approvals", () => {
  it("needs the approval keys to verify an approved call, and does not replay an approval refusal as a policy change", async () => {
    const afx = buildFixture(join(dir, "approvals"));
    const human = generateKeyPair();
    const humanFiles = writeKeyPair(human, join(afx.dir, "keys"), "human");
    const cfg = loadConfig(afx.configFile);
    cfg.approvals = { trustedKeys: [humanFiles.pubFile], usedDir: join(afx.dir, "used-approvals"), tools: [{ tool: "stripe.refund", minApprovers: 1 }] };
    const gw = await createGateway(cfg);
    const args = { customer_id: "cust_123", amount: 2500, currency: "GBP", beneficiary: "acct_42" };
    const approval = createApproval(human, { principal: "user_456", agent: "support-agent", tool: "stripe.refund", args, expiresAt: new Date(Date.now() + 60_000).toISOString() });
    const approved = await gw.handleCall({ name: "stripe.refund", arguments: args, _meta: { [APPROVAL_META_KEY]: approval } });
    const refused = await gw.handleCall({ name: "stripe.refund", arguments: args });
    await gw.close();
    expect(approved.isError).toBeFalsy();
    expect(refused.isError).toBe(true);
    // the recorded policy itself, so that nothing in the proposed policy can change a decision
    const base = ["policy", "simulate", "--policy", join(afx.dir, "policy.cedar"), "--receipts", afx.receiptsDir, "--issuer-key", afx.gatewayPub, "--principal-key", afx.principalPub, "--json"];

    const unkeyed = run(...base);
    expect(unkeyed.status).toBe(1);
    expect(unkeyed.stderr).toContain("approval signatures (human keys)");

    const keyed = run(...base, "--approval-key", humanFiles.pubFile);
    const report = JSON.parse(keyed.stdout) as SimulationReport;
    // the refusal is skipped as a non-policy gate, so the report is incomplete; it is not listed as deny -> allow
    expect(report).toMatchObject({ total: 2, evaluated: 1, unchanged: 1, changes: [], complete: false });
    expect(report.skipped).toEqual([{ receiptId: String(refused._meta?.[RECEIPT_META_KEY]), tool: "stripe.refund", reason: expect.stringContaining("approval was refused before Cedar ran") }]);
    expect(keyed.status).toBe(1);
  });
});


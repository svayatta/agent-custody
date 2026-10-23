import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { pathKey, privateView, setAt, withhold } from "../src/capture.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { digestOf } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { evaluate, policyDigest } from "../src/policy.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer, type SdkIssuer } from "../src/sdk/index.ts";
import { formatSimulation, simulatePolicy } from "../src/simulate.ts";
import { buildFixture, buildSdkFixture } from "../scripts/fixture.ts";

const ALLOW = "permit(principal, action, resource);";
const DENY = "forbid(principal, action, resource);";
const OLD = 'permit(principal, action == Action::"refund", resource) when { context.args.amount <= 100 };';
const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "custody-simulate-")); dirs.push(dir); return dir; };
afterAll(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
const decode = (b: ReceiptBundle) => (JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;

function issuer(policy: string = OLD, mode?: "observe"): SdkIssuer {
  const fx = buildSdkFixture(temp(), policy);
  return createSdkIssuer({ ...loadSdkConfig(fx.configFile), ...(mode ? { mode } : {}) });
}

async function record(sdk: SdkIssuer, amount: number, tool = "refund"): Promise<ReceiptPredicate> {
  const ev = { tool, args: { amount } };
  const policy = sdk.decide(ev);
  const outcome = policy?.decision === "deny" && policy.enforced !== false
    ? { status: "denied" as const, reason: [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched" }
    : { status: "executed" as const, result: { success: true } };
  return decode(await sdk.record(ev, outcome, policy));
}

describe("offline policy simulation", () => {
  it("replays real SDK receipts in both directions and leaves the recorded inputs intact", async () => {
    const sdk = issuer();
    const receipts = [await record(sdk, 10), await record(sdk, 150), await record(sdk, 75)];
    const before = JSON.stringify(receipts);
    const proposed = 'permit(principal, action == Action::"refund", resource) when { context.args.amount > 50 && context.args.amount <= 200 };';
    const report = simulatePolicy(proposed, receipts);
    expect(report).toMatchObject({ total: 3, evaluated: 3, unchanged: 1, complete: true, skipped: [] });
    expect(report.changes.map((c) => [c.receiptId, c.previous.decision, c.proposed.decision])).toEqual([
      [receipts[0]!.receiptId, "allow", "deny"], [receipts[1]!.receiptId, "deny", "allow"],
    ]);
    expect(report.changes[0]!.previous.provenance).toBe("claimed");
    expect(report.previousPolicyDigests).toEqual([policyDigest(OLD)]);
    expect(report.policyDigest).toBe(policyDigest(proposed));
    expect(report.runId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(new Date(report.timestamp).toISOString()).toBe(report.timestamp);
    expect(JSON.stringify(receipts)).toBe(before);
    expect(simulatePolicy(proposed + "\n", receipts).policyDigest).not.toBe(report.policyDigest);
  });

  it("uses the observed deny as its baseline even when observe mode executed the tool", async () => {
    const receipt = await record(issuer(DENY, "observe"), 10);
    expect(receipt.execution.status).toBe("executed");
    expect(simulatePolicy(DENY, [receipt])).toMatchObject({ evaluated: 1, unchanged: 1, changes: [], complete: true });
    const [change] = simulatePolicy(ALLOW, [receipt]).changes;
    expect(change).toMatchObject({ previous: { decision: "deny", enforced: false }, proposed: { decision: "allow" } });
  });

  it("keeps real gateway facts and the original grant context after the gateway has closed", async () => {
    const fx = buildFixture(temp());
    const gateway = await createGateway(loadConfig(fx.configFile));
    let receipt: ReceiptPredicate;
    try {
      const result = await gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
      const id = String(result._meta?.[RECEIPT_META_KEY]);
      receipt = decode(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle);
    } finally { await gateway.close(); }
    expect(receipt.facts.customer!.value).toMatchObject({ verified: true });
    const proposed = `permit(principal == Agent::"support-agent", action == Action::"stripe.refund", resource)
      when { context.facts.customer.verified && context.args.amount <= 1000 &&
        context.grant.principal == "user_456" && context.grant.scopes.contains("stripe.refund") };`;
    expect(simulatePolicy(proposed, [receipt])).toMatchObject({ evaluated: 1, complete: true, changes: [{ previous: { decision: "allow" }, proposed: { decision: "deny", errors: [] } }] });
    const lateRevocation = { ...receipt, execution: { status: "withheld" as const, reason: "the delegation grant has been revoked before the call was forwarded", provenance: "observed" as const } };
    expect(simulatePolicy(proposed, [lateRevocation])).toMatchObject({ evaluated: 1, complete: true, changes: [{ previous: { decision: "allow" }, proposed: { decision: "deny", errors: [] } }] });
    const observedDeny = { ...receipt, policy: { ...receipt.policy!, decision: "deny" as const, enforced: false } };
    const permitWithFrozenContext = proposed.replace("<= 1000", "<= 100000");
    expect(simulatePolicy(permitWithFrozenContext, [observedDeny])).toMatchObject({ complete: true, changes: [{ proposed: { decision: "allow", errors: [] } }] });
    // A new policy cannot enlarge a grant or move its original validity window.
    const outOfScope = { ...receipt, tool: { ...receipt.tool, name: "stripe.payout" } };
    const outsideWindow = { ...receipt, timestamp: "2100-01-01T00:00:00.000Z" };
    const gates = simulatePolicy(ALLOW, [outOfScope, outsideWindow]);
    expect(gates).toMatchObject({ complete: false, evaluated: 0, changes: [] });
    expect(gates.skipped.map((s) => s.reason)).toEqual(expect.arrayContaining([expect.stringContaining("scopes"), expect.stringContaining("validity window")]));
    const privateFact = privateView(receipt, { args: { mode: "clear" }, result: { mode: "clear" }, facts: { mode: "digest" } }).predicate;
    expect(simulatePolicy(ALLOW, [privateFact])).toMatchObject({ evaluated: 0, complete: false, skipped: [{ reason: expect.stringContaining("facts.customer.value") }] });
  });

  it("skips actual gateway grant and failed fact-lookup denials instead of turning them into allows", async () => {
    const fx = buildFixture(temp());
    const gateway = await createGateway(loadConfig(fx.configFile));
    const receipts: ReceiptPredicate[] = [];
    try {
      for (const ev of [
        { name: "stripe.payout", arguments: { amount: 1 } },
        { name: "stripe.refund", arguments: { customer_id: "cust_404", amount: 1 } },
        { name: "stripe.refund", arguments: { amount: 1 } },
      ]) {
        const result = await gateway.handleCall(ev);
        const id = String(result._meta?.[RECEIPT_META_KEY]);
        receipts.push(decode(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle));
      }
    } finally { await gateway.close(); }
    const report = simulatePolicy(ALLOW, receipts);
    expect(report).toMatchObject({ total: 3, evaluated: 0, complete: false, changes: [] });
    expect(report.skipped.every((s) => s.reason.startsWith("non-policy gate:"))).toBe(true);
    expect(report.skipped.map((s) => s.receiptId)).toEqual(receipts.map((p) => p.receiptId));
    const hiddenFailure = privateView(receipts[1]!, { args: { mode: "clear" }, result: { mode: "digest" }, facts: { mode: "clear" } }).predicate;
    expect(simulatePolicy(ALLOW, [hiddenFailure])).toMatchObject({ evaluated: 0, complete: false, changes: [], skipped: [{ reason: expect.stringContaining("cannot establish complete Cedar inputs") }] });
    const observedFailure = { ...hiddenFailure, policy: { ...hiddenFailure.policy!, enforced: false }, execution: { status: "executed" as const, result: {}, resultDigest: digestOf({}), provenance: "observed" as const } };
    expect(simulatePolicy(ALLOW, [observedFailure])).toMatchObject({ evaluated: 0, complete: false, changes: [] });
  });

  it("fails closed on evaluation errors and refuses malformed proposed policy text", async () => {
    const receipt = await record(issuer(ALLOW), 10);
    const report = simulatePolicy('permit(principal, action, resource) when { context.args.missing == 1 };', [receipt]);
    expect(report).toMatchObject({ complete: true, evaluated: 1, changes: [{ proposed: { decision: "deny" } }] });
    expect(report.changes[0]!.proposed.errors.length).toBeGreaterThan(0);
    expect(report.groups[0]!.reason).toContain(report.changes[0]!.proposed.errors[0]);
    expect(() => simulatePolicy("invalid Cedar", [receipt])).toThrow("invalid Cedar policy");
    expect(() => simulatePolicy("invalid Cedar", [])).toThrow("invalid Cedar policy");
  });

  it("groups every changed receipt id by tool and reason and pins all previous policy digests", async () => {
    const one = await record(issuer(ALLOW), 1);
    const two = await record(issuer(ALLOW + "\n"), 2);
    const three = await record(issuer(ALLOW), 3, "lookup");
    const report = simulatePolicy("", [two, one, three]);
    expect(report.groups).toEqual([
      { tool: "lookup", reason: "no permit policy matched", receiptIds: [three.receiptId] },
      { tool: "refund", reason: "no permit policy matched", receiptIds: [one.receiptId, two.receiptId].sort() },
    ]);
    expect(report.previousPolicyDigests).toEqual([policyDigest(ALLOW), policyDigest(ALLOW + "\n")].sort());
    const formatted = formatSimulation(report);
    for (const p of [one, two, three]) expect(formatted).toContain(`${p.receiptId}: allow -> deny`);
    expect(formatted).toContain("changed: 3");
    expect(formatted).toContain("RESULT: COMPLETE");
  });

  it("reports withheld required inputs as incomplete while replaying unrelated private fields", async () => {
    const receipt = await record(issuer(ALLOW), 1);
    const privateArgs = privateView(receipt, { args: { mode: "digest" }, result: { mode: "clear" }, facts: { mode: "clear" } }).predicate;
    const skipped = simulatePolicy(DENY, [privateArgs]);
    expect(skipped).toMatchObject({ complete: false, evaluated: 0, changes: [], skipped: [{ reason: expect.stringContaining("request.args") }] });
    expect(formatSimulation(skipped)).toContain("RESULT: INCOMPLETE");
    const oldError = evaluate('permit(principal, action, resource) when { context.args.missing == 1 };', { agentId: receipt.agent.id, tool: receipt.tool.name, context: { args: receipt.request.args, facts: {} } });
    const denied = { ...receipt, policy: { ...oldError, provenance: "claimed" as const } };
    const unrelated = privateView(denied, { args: { mode: "clear" }, result: { mode: "digest" }, facts: { mode: "clear" } }).predicate;
    expect(unrelated.capture?.withheld).toContainEqual(["policy", "errors"]);
    expect(simulatePolicy(ALLOW, [unrelated])).toMatchObject({ complete: true, evaluated: 1, changes: [{ previous: { decision: "deny" }, proposed: { decision: "allow" } }] });
  });

  it("treats commitment-shaped ordinary arguments as data unless the capture note names them", async () => {
    const receipt = await record(issuer(ALLOW), 1);
    const data = withhold("ordinary data").commitment;
    receipt.request.args = { data };
    receipt.request.argsDigest = digestOf(receipt.request.args);
    const proposed = 'permit(principal, action, resource) when { context.args.data["$custody"] == "withheld" };';
    expect(simulatePolicy(proposed, [receipt])).toMatchObject({ complete: true, evaluated: 1, unchanged: 1, changes: [] });
  });

  it("does not invent policy decisions for record-only or malformed receipts", async () => {
    const receipt = await record(issuer(ALLOW), 1);
    const cases = [
      { ...receipt, policy: null },
      { ...receipt, timestamp: "not a date" },
      { ...receipt, facts: { missing: { tool: "lookup", args: {}, resultDigest: "digest", provenance: "observed" } } },
      { ...receipt, capture: { mode: "digest", withheld: [["request", "args", "amount"]] } },
      { ...receipt, capture: { mode: "digest", withheld: "bad" } },
      null,
    ] as unknown as ReceiptPredicate[];
    const report = simulatePolicy(DENY, cases);
    expect(report).toMatchObject({ total: cases.length, evaluated: 0, complete: false, changes: [] });
    expect(report.skipped).toHaveLength(cases.length);
    expect(report.skipped[0]!.reason).toContain("record-only");
    expect(report.skipped[3]!.reason).toContain("no commitment");
    expect(simulatePolicy(ALLOW, [])).toMatchObject({ complete: true, total: 0, evaluated: 0, previousPolicyDigests: [], changes: [], groups: [] });
  });

  it("reads a one-shot iterable once and counts the calls that have no receipt", async () => {
    const sdk = issuer();
    const first = await record(sdk, 10);
    const second = await record(sdk, 150);
    const seen: string[] = [];
    function* lazy() { for (const p of [first, second]) { seen.push(p.receiptId); yield p; } }
    const orphan = { receiptId: "orphan-1", tool: "refund", reason: "only the authorization survives" };
    const report = simulatePolicy(ALLOW, lazy(), { unreplayable: [orphan] });
    expect(seen).toEqual([first.receiptId, second.receiptId]);
    expect(report).toMatchObject({ total: 3, evaluated: 2, complete: false, skipped: [orphan] });
    expect(formatSimulation(report)).toContain("SKIPPED orphan-1 (refund)");
  });

  it("evaluates each receipt before it pulls the next, so a caller can stream a large history", async () => {
    const sdk = issuer();
    const first = await record(sdk, 10);
    const second = await record(sdk, 150);
    const order: string[] = [];
    const watched = { ...first, request: { ...first.request, get args() { order.push("evaluate first"); return first.request.args; } } } as ReceiptPredicate;
    function* source() { yield watched; order.push("pull second"); yield second; }
    simulatePolicy(ALLOW, source());
    expect(order).toContain("evaluate first");
    expect(order.indexOf("evaluate first")).toBeLessThan(order.indexOf("pull second"));
  });

  it("replays withheld inputs with the capture key or a matching disclosure, and no other", async () => {
    const receipt = await record(issuer(ALLOW), 10);
    const key = randomBytes(32);
    const encrypted = privateView(receipt, { args: { mode: "encrypted" }, result: { mode: "clear" }, facts: { mode: "clear" } }, key).predicate;
    expect(simulatePolicy(DENY, [encrypted])).toMatchObject({ evaluated: 0, complete: false, skipped: [{ reason: expect.stringContaining("withheld") }] });
    expect(simulatePolicy(DENY, [encrypted], { captureKey: key })).toMatchObject({ evaluated: 1, complete: true, changes: [{ previous: { decision: "allow" }, proposed: { decision: "deny" } }] });
    expect(simulatePolicy(DENY, [encrypted], { captureKey: randomBytes(32) })).toMatchObject({ evaluated: 0, complete: false, skipped: [{ reason: expect.stringContaining("malformed capture") }] });
    const view = privateView(receipt, { args: { mode: "digest" }, result: { mode: "clear" }, facts: { mode: "clear" } });
    // With no clear list, the whole arguments object is withheld at one path: request.args.$rest.
    expect(view.predicate.capture!.withheld).toEqual([["request", "args", "$rest"]]);
    const path = view.predicate.capture!.withheld[0]!;
    const disclosure = setAt({ receiptId: receipt.receiptId }, path, { $custody: "disclosed", salt: view.salts[pathKey(path)], value: receipt.request.args });
    expect(simulatePolicy(DENY, [view.predicate])).toMatchObject({ evaluated: 0, complete: false });
    expect(simulatePolicy(DENY, [view.predicate], { disclosures: new Map([[receipt.receiptId, disclosure]]) })).toMatchObject({ evaluated: 1, complete: true, changes: [{ proposed: { decision: "deny" } }] });
    expect(simulatePolicy(DENY, [view.predicate], { disclosures: new Map([["another-receipt", disclosure]]) })).toMatchObject({ evaluated: 0, complete: false });
  });
});

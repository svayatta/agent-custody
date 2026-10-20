import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createGateway, createIssuer, digestOf, generateKeyPair, loadConfig, loadPublicKey, RECEIPT_META_KEY, verifyBundle, type CaptureConfig, type ReceiptBundle, type ReceiptPredicate, type ReceiptStatement } from "@agent-custody/receipts";
import { buildFixture } from "../../receipts/scripts/fixture.ts";
import { matchesReceiptSearch, receiptSearchTerms, validateReceiptSearch } from "../src/search.ts";

const decode = (bundle: ReceiptBundle) => (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString("utf8")) as ReceiptStatement).predicate;

function predicate(args: Record<string, unknown> = {}, result: unknown = {}): ReceiptPredicate {
  return {
    receiptId: randomUUID(), timestamp: "2026-10-15T12:00:00.000Z",
    issuer: { kind: "sdk", keyid: "filled-by-issue", version: "0" },
    principal: { id: null, provenance: "claimed" }, agent: { id: "refund-agent", provenance: "claimed" },
    session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" },
    tool: { name: "stripe.refund", provenance: "claimed" },
    request: { args, argsDigest: digestOf(args), provenance: "claimed" }, facts: {}, policy: null,
    execution: { status: "executed", result, resultDigest: digestOf(result), provenance: "claimed" },
  };
}

async function issue(p: ReceiptPredicate, rules?: CaptureConfig) {
  const dir = mkdtempSync(join(tmpdir(), "receipt-search-"));
  const key = generateKeyPair();
  p.issuer.keyid = key.keyid;
  const issuer = createIssuer(key, join(dir, "receipts"), join(dir, "log.jsonl"), { capture: { rules, key: randomBytes(32) } });
  const bundle = await issuer.issue(p);
  expect(verifyBundle(bundle, { issuerKeys: [{ keyid: key.keyid, publicKey: key.publicKey }], principalKeys: [] }).ok).toBe(true);
  return { p: decode(bundle), dir };
}

describe("receipt search", () => {
  it("finds the refund produced by a real gateway and keeps its signed verification intact", async () => {
    const fixture = buildFixture(mkdtempSync(join(tmpdir(), "search-gateway-")));
    const config = loadConfig(fixture.configFile);
    // State's tests run from its own workspace; use Node's native type stripping rather than receipts' tsx peer.
    if (config.upstream && "command" in config.upstream) config.upstream.args = config.upstream.args.slice(2);
    const gateway = await createGateway(config);
    try {
      const result = await gateway.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 500 } });
      expect(result.isError).toBeFalsy();
      const receiptId = String(result._meta?.[RECEIPT_META_KEY]);
      const bundle = JSON.parse(readFileSync(join(fixture.receiptsDir, `${receiptId}.json`), "utf8")) as ReceiptBundle;
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(fixture.gatewayPub)], principalKeys: [loadPublicKey(fixture.principalPub)] }).ok).toBe(true);
      const p = decode(bundle);
      const terms = receiptSearchTerms(p);
      expect(terms.transactionIds).toHaveLength(1);
      expect(terms.transactionIds[0]).toMatch(/^re_/);
      expect(terms.customerIds).toEqual(["cust_123"]);
      expect(matchesReceiptSearch(p, { transaction: terms.transactionIds[0], customer: "cust_123", agent: "support-agent", from: p.timestamp, to: p.timestamp })).toBe(true);
    } finally {
      await gateway.close();
    }
  });

  it("finds named ids in nested public arguments, JSON text, structured results, and facts without substring matches", async () => {
    const p = predicate({
      transaction_id: "tx_request", nested: [{ payment_intent: "pi_request", customer: { id: "customer-expanded" } }],
      transactionId: "tx_camel", customerId: "customer-camel", charge_id: "ch_request", refundId: "re_argument",
      id: "ch_unlabelled_argument", note: "refund re_prose belongs to customer customer-prose",
    }, {
      content: [{ type: "text", text: JSON.stringify({ data: [{ id: "re_result", payment_intent_id: "pi_result", chargeId: "ch_result", customer_id: "customer-result" }], note: "re_unlabelled" }) }, { type: "text", text: "prefix {\"refund_id\":\"re_fragment\"} suffix" }],
      structuredContent: { nested: { transaction: { id: "tx_expanded" }, customer: "customer-structured", id: "pi_structured" }, event: { id: "evt_unrelated" } },
    });
    p.facts = {
      customer: { tool: "customer.lookup", args: { customer_id: "customer-lookup" }, value: { id: "customer-fact", nested: { transactionId: "tx_fact" } }, resultDigest: "unused", provenance: "observed" },
      payment: { tool: "payment.lookup", args: { payment_intent_id: "pi_lookup" }, value: { id: "ch_fact", customer: { id: "customer-fact-nested" } }, resultDigest: "unused", provenance: "observed" },
    };
    const terms = receiptSearchTerms((await issue(p)).p);
    expect(terms).toEqual({
      transactionIds: ["tx_request", "pi_request", "tx_camel", "ch_request", "re_argument", "re_result", "pi_result", "ch_result", "tx_expanded", "pi_structured", "tx_fact", "pi_lookup", "ch_fact"].sort(),
      customerIds: ["customer-expanded", "customer-camel", "customer-result", "customer-structured", "customer-lookup", "customer-fact", "customer-fact-nested"].sort(),
    });
    expect(matchesReceiptSearch(p, { transaction: "re_result", customer: "customer-fact" })).toBe(true);
    expect(matchesReceiptSearch(p, { transaction: "re_res" })).toBe(false);
    expect(matchesReceiptSearch(p, { transaction: "RE_RESULT" })).toBe(false);
    expect(matchesReceiptSearch(p, { customer: "CUSTOMER-RESULT" })).toBe(false);
    expect(matchesReceiptSearch(p, { transaction: "re_prose" })).toBe(false);
  });

  it("combines exact identifiers and agent with inclusive date bounds compared as instants", () => {
    const p = predicate({ transaction_id: "tx_1", customer_id: "customer-1" });
    const query = { transaction: "tx_1", customer: "customer-1", agent: "refund-agent", from: "2026-10-15T14:00:00+02:00", to: "2026-10-15T07:00:00-05:00" };
    expect(matchesReceiptSearch(p, query)).toBe(true);
    expect(matchesReceiptSearch(p, {})).toBe(true);
    expect(matchesReceiptSearch(p, { ...query, transaction: "tx_2" })).toBe(false);
    expect(matchesReceiptSearch(p, { ...query, customer: "customer-2" })).toBe(false);
    expect(matchesReceiptSearch(p, { ...query, agent: "Refund-agent" })).toBe(false);
    expect(matchesReceiptSearch(p, { from: "2026-10-15T12:00:00.001Z" })).toBe(false);
    expect(matchesReceiptSearch(p, { to: "2026-10-15T11:59:59.999Z" })).toBe(false);
  });

  it("rejects invalid, ambiguous, and inverted date filters even when another filter cannot match", () => {
    for (const value of ["", "tomorrow", "2026-10-15", "2026-10-15T12:00:00", "2026-02-30T12:00:00Z", "2026-10-15T25:00:00Z", "2026-10-15T12:00:00+25:00"]) {
      for (const field of ["from", "to"] as const) expect(() => validateReceiptSearch({ [field]: value })).toThrow(`receipt search: ${field}`);
    }
    expect(() => validateReceiptSearch({ from: "2026-10-15T12:00:01Z", to: "2026-10-15T12:00:00Z" })).toThrow("from must be at or before to");
    expect(() => validateReceiptSearch({ from: "2026-10-16T00:00:00+02:00", to: "2026-10-15T23:00:00Z" })).not.toThrow();
    expect(() => matchesReceiptSearch(predicate(), { agent: "another-agent", from: "invalid" })).toThrow("receipt search: from");
  });

  for (const mode of ["digest", "encrypted"] as const) {
    it(`searches only the identifiers retained in the public signed view (${mode})`, async () => {
      const raw = predicate({ transaction_id: "tx_public", customer_id: "customer-public", secret: { refund_id: "re_hidden_argument", customer: "customer-hidden-argument" } }, {
        structuredContent: { id: "re_public_result", customer: "customer-public-result" },
        content: [{ type: "text", text: JSON.stringify({ id: "re_hidden_result", customer_id: "customer-hidden-result" }) }],
      });
      raw.facts = {
        customer: { tool: "customer.lookup", args: { customer_id: "customer-hidden-lookup" }, value: { id: "customer-hidden-fact", refund_id: "re_hidden_fact" }, resultDigest: "unused", provenance: "observed" },
      };
      const { p, dir } = await issue(raw, { "*": { args: { mode, clear: ["transaction_id", "customer_id"] }, result: { mode, clear: ["structuredContent"] } } });
      expect(p.capture?.mode).toBe(mode);
      expect(receiptSearchTerms(p)).toEqual({ transactionIds: ["re_public_result", "tx_public"], customerIds: ["customer-public", "customer-public-result"] });
      for (const transaction of ["re_hidden_argument", "re_hidden_result", "re_hidden_fact"]) {
        expect(matchesReceiptSearch(raw, { transaction })).toBe(true);
        expect(matchesReceiptSearch(p, { transaction })).toBe(false);
      }
      for (const customer of ["customer-hidden-argument", "customer-hidden-result", "customer-hidden-lookup", "customer-hidden-fact"]) {
        expect(matchesReceiptSearch(raw, { customer })).toBe(true);
        expect(matchesReceiptSearch(p, { customer })).toBe(false);
      }
      // A digest capture actually keeps private salts beside the receipts. Searching receives just the signed view.
      if (mode === "digest") expect(readFileSync(join(dir, "receipts", "salts", `${p.receiptId}.json`), "utf8")).toContain("salts");
    });
  }

  it("uses the signed capture paths, including nested values, rather than treating commitment-shaped public data as private", () => {
    const p = predicate({ customer: { id: "customer-hidden", other: { transaction_id: "tx_hidden" } }, public: { $custody: "withheld", sha256: "0".repeat(64), transaction_id: "tx_public" } });
    p.capture = { mode: "digest", withheld: [["request", "args", "customer"]] };
    expect(receiptSearchTerms(p)).toEqual({ transactionIds: ["tx_public"], customerIds: [] });
  });

  it("still hides a withheld path below a nested array, object, or JSON text", () => {
    const p = predicate({ a: { b: [{ transaction_id: "tx_hidden" }, { transaction_id: "tx_shown" }] }, c: JSON.stringify({ d: { customer_id: "customer-hidden" } }) });
    p.capture = { mode: "digest", withheld: [["request", "args", "a", "b", "0"], ["request", "args", "c", "d"]] };
    expect(receiptSearchTerms(p)).toEqual({ transactionIds: ["tx_shown"], customerIds: [] });
  });
});

describe("search cost on hostile input", () => {
  const nest = (depth: number, inner: Record<string, unknown>) => {
    let value = inner;
    for (let i = 0; i < depth; i++) value = { next: value };
    return value;
  };

  it("indexes a deeply nested string argument in under a second", () => {
    const memo = "[".repeat(2000) + "]".repeat(2000);
    const p = predicate({ transaction_id: "tx_public", memo });
    p.capture = { mode: "digest", withheld: [["request", "args", "secret", "deep", "er"]] };
    const started = performance.now();
    const terms = receiptSearchTerms(p);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(terms).toEqual({ transactionIds: ["tx_public"], customerIds: [], truncated: true });
  });

  it("stops at a fixed depth in nested objects and in JSON text, and keeps the ids above it", () => {
    const shallow = nest(10, { customer_id: "customer-shallow" });
    const deep = nest(300,{ customer_id: "customer-deep" });
    const text = JSON.stringify(nest(100, { customer_id: "customer-text" }));
    const long = `[${" ".repeat(70_000)}{"customer_id":"customer-long"}]`;
    const started = performance.now();
    const terms = receiptSearchTerms(predicate({ shallow, deep, text, long }));
    expect(performance.now() - started).toBeLessThan(1000);
    expect(terms.customerIds).toEqual(["customer-shallow"]);
  });

  it("marks a result as truncated when it skipped a deep value or a long JSON text, and only then", () => {
    expect(receiptSearchTerms(predicate({ a: nest(10, { customer_id: "customer-1" }) }))).not.toHaveProperty("truncated");
    expect(receiptSearchTerms(predicate({ note: "x".repeat(100_000) }))).not.toHaveProperty("truncated");
    expect(receiptSearchTerms(predicate({ a: nest(300, {}) })).truncated).toBe(true);
    // JSON text on each side of the depth cap: the text is searched, or the result says that it is not.
    const text = JSON.stringify({ payment_intent: "pi_text" });
    expect(receiptSearchTerms(predicate(nest(60, { note: text })))).toEqual({ transactionIds: ["pi_text"], customerIds: [] });
    for (const depth of [63, 64, 65]) expect(receiptSearchTerms(predicate(nest(depth, { note: text }))).truncated, `string at ${depth}`).toBe(true);
    expect(receiptSearchTerms(predicate(nest(63, { notes: [text] }))).truncated).toBe(true);
    expect(receiptSearchTerms(predicate(nest(64, { note: "plain prose" }))).truncated).toBeUndefined();
    expect(receiptSearchTerms(predicate({}, { content: [{ type: "text", text: `[${" ".repeat(70_000)}]` }] })).truncated).toBe(true);
    expect(receiptSearchTerms(predicate({ memo: "[".repeat(200) + "]".repeat(200) })).truncated).toBe(true);
  });
});

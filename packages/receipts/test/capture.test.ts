// Private evidence (issue #109): the receipt carries only what the capture rule allows, the digests and signatures
// are over the whole call, and the verifier recomputes them when the values are in clear, disclosed, or revealed with
// the customer's key, and says "committed, not recomputed" when they are not.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { captureKeyFrom, captureValue, checkCommitment, isCommitment, restore, reveal, withhold } from "../src/capture.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { digestOf, loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY, type Gateway } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { formatReport, verifyBundle, type VerifyOptions } from "../src/verify.ts";
import { buildFixture, buildSdkFixture, type Fixture } from "../scripts/fixture.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const bundleOf2 = (fx: Fixture, r: { _meta?: Record<string, unknown> }) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
const KEY_HEX = randomBytes(32).toString("hex");
const key = captureKeyFrom(KEY_HEX);
const check = (name: string, r: ReturnType<typeof verifyBundle>) => r.checks.find((c) => c.name === name)!;
const WEBHOOK_SECRET = "whsec_capture_test";

describe("commitments", () => {
  it("withholds a value as a salted digest, optionally with the value encrypted under the key, and checks it back", () => {
    const w = withhold({ reason: "card ending 4242" });
    expect(w.$custody).toBe("withheld");
    expect(checkCommitment(w, { reason: "card ending 4242" })).toBe(true);
    expect(checkCommitment(w, { reason: "card ending 4243" })).toBe(false);
    expect(() => reveal(w, key)).toThrow(/withheld without its value/);
    const e = withhold("phone +44 20 7946 0000", key);
    expect(e.$custody).toBe("encrypted");
    expect(JSON.stringify(e)).not.toContain("7946");
    expect(reveal(e, key)).toBe("phone +44 20 7946 0000");
    expect(() => reveal(e, captureKeyFrom(randomBytes(32).toString("hex")))).toThrow(/not the one given/);
    expect(isCommitment(e)).toBe(true);
    expect(isCommitment({ sha256: "x" })).toBe(false);
    expect(() => captureKeyFrom("too-short")).toThrow(/32 bytes/);
  });

  it("captures an object field by field, keeps the listed fields in clear, and restores from a disclosure or the key", () => {
    const args = { customer_id: "cust_123", amount: 2500, reason: "called from +44 20 7946 0000", note: { card: "4242" } };
    const digest = captureValue(args, { mode: "digest", clear: ["customer_id", "amount"] });
    expect(digest.note).toEqual({ mode: "digest", withheld: ["reason", "note"] });
    expect((digest.view as any).amount).toBe(2500);
    expect(JSON.stringify(digest.view)).not.toMatch(/7946|4242/);
    expect(restore(digest.view, digest.note)).toBeNull();
    expect(restore(digest.view, digest.note, args)!.value).toEqual(args);
    expect(() => restore(digest.view, digest.note, { ...args, reason: "something else" })).toThrow(/does not match/);
    const enc = captureValue(args, { mode: "encrypted", clear: ["amount"] }, key);
    expect(restore(enc.view, enc.note, undefined, key)).toEqual({ value: args, how: "decrypted" });
    expect(restore(enc.view, enc.note, undefined, captureKeyFrom(randomBytes(32).toString("hex")))).toBeNull();
    const whole = captureValue("just a string", { mode: "digest" });
    expect(whole.note).toEqual({ mode: "digest", withheld: ["*"], whole: true });
    expect(restore(whole.view, whole.note, "just a string")!.how).toBe("disclosed");
    // no note: the view is the value, whatever it looks like
    expect(restore({ extra: { $custody: "withheld", sha256: "00", salt: "00" } }, undefined)).toEqual({ value: { extra: { $custody: "withheld", sha256: "00", salt: "00" } }, how: "clear" });
    expect(captureValue(args, { mode: "clear" })).toEqual({ view: args });
    expect(captureValue(args, undefined)).toEqual({ view: args });
    expect(() => captureValue(args, { mode: "encrypted" })).toThrow(/needs captureKeyEnv/);
  });

  it("keeps a field named __proto__ through capture and restoration, and a field literally named * is just a field", () => {
    const args = JSON.parse('{"__proto__":{"secret":"review"},"amount":2500,"*":"star"}') as Record<string, unknown>;
    const enc = captureValue(args, { mode: "encrypted", clear: ["amount"] }, key);
    expect(enc.note).toEqual({ mode: "encrypted", withheld: ["__proto__", "*"] });
    const persisted = JSON.parse(JSON.stringify(enc.view)) as Record<string, unknown>;
    expect(isCommitment(persisted["__proto__"])).toBe(true);
    expect(isCommitment(persisted["*"])).toBe(true);
    const back = restore(persisted, enc.note, undefined, key)!;
    expect(back.how).toBe("decrypted");
    expect(JSON.parse(JSON.stringify(back.value))).toEqual(args);
    expect(digestOf(back.value)).toBe(digestOf(args));
    expect(restore(persisted, enc.note, args)!.how).toBe("disclosed");
    expect(({} as Record<string, unknown>).secret).toBeUndefined();
  });

  it("the note decides what is withheld: a named field that is not a commitment is an error, and commitment-shaped data outside the note is data", () => {
    expect(() => restore({ amount: 1 }, { mode: "digest", withheld: ["reason"] })).toThrow(/no commitment for it/);
    expect(() => restore({ amount: 1 }, { mode: "digest", withheld: ["*"], whole: true })).toThrow(/withheld whole/);
    const view = { amount: 1, extra: { $custody: "withheld", sha256: "00", salt: "00" } };
    expect(restore(view, undefined)).toEqual({ value: view, how: "clear" });
  });
});

describe("private evidence through the gateway", () => {
  let fx: Fixture;
  let gw: Gateway;
  let opts: VerifyOptions;
  const bundleOf = (r: { _meta?: Record<string, unknown> }) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  beforeAll(async () => {
    process.env.TEST_CAPTURE_KEY = KEY_HEX;
    fx = buildFixture(mkdtempSync(join(tmpdir(), "capture-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.capture = {
      "stripe.refund": { args: { mode: "encrypted", clear: ["customer_id", "amount"] }, result: { mode: "digest" }, facts: { mode: "encrypted" } },
      "customer.lookup": { result: { mode: "digest" } },
    };
    cfg.captureKeyEnv = "TEST_CAPTURE_KEY";
    // the fake provider also delivers a signed webhook for every refund, so the delivery body is in play
    cfg.upstream.args.push("--webhook-secret", WEBHOOK_SECRET);
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    gw = await createGateway(loadConfig(fx.configFile));
    opts = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], providerSecrets: { stripe: WEBHOOK_SECRET }, logFile: fx.logFile };
  });
  afterAll(async () => {
    await gw.close();
    delete process.env.TEST_CAPTURE_KEY;
  });

  it("the receipt file carries the amount and the customer id, no reason, no card, and no customer record; the digests are over the whole call", async () => {
    const args = { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000 about card ending 4242" };
    const r = await gw.handleCall({ name: "stripe.refund", arguments: args });
    expect(r.isError).toBeFalsy();
    // the agent still gets the real result
    expect((r.content[0] as { text: string }).text).toContain("succeeded");
    const bundle = bundleOf(r);
    const file = JSON.stringify(bundle);
    expect(file).not.toMatch(/7946|4242|called from/);
    const p = decode(bundle).predicate;
    expect(p.request.args).toMatchObject({ customer_id: "cust_123", amount: 2500 });
    expect(isCommitment(p.request.args.reason)).toBe(true);
    expect(p.request.capture).toEqual({ mode: "encrypted", withheld: ["reason"] });
    expect(p.request.argsDigest).toBe(digestOf(args));
    expect(p.execution.status).toBe("executed");
    const ex = p.execution as { result: { content: unknown; isError?: boolean; _meta?: unknown }; capture?: unknown };
    expect(isCommitment(ex.result.content)).toBe(true);
    expect(ex.result._meta).toBeDefined();
    // the fact the policy decided on is encrypted field by field: the policy saw it, the file does not show it
    const customer = p.facts.customer!.value as Record<string, unknown>;
    expect(Object.values(customer).every(isCommitment)).toBe(true);
    expect(p.facts.customer!.capture).toEqual({ mode: "encrypted", withheld: ["id", "email", "verified"] });
    expect(file).not.toContain('"plan":"pro"');
    expect(p.policy!.decision).toBe("allow");
    // the lookup's arguments are copied from the call: the customer id is in clear there as in the request, and nothing else leaks through them
    expect(p.facts.customer!.args).toEqual({ customer_id: "cust_123" });
    expect(p.facts.customer!.argsCapture).toBeUndefined();
    // the provider's delivery is withheld with the result: its body is a commitment in the evidence, and gone from the metadata copy
    const up = (p.execution as { upstream: { rawBody: unknown; signature: string } }).upstream;
    expect(isCommitment(up.rawBody)).toBe(true);
    expect(typeof up.signature).toBe("string");
    expect(ex.result._meta).not.toHaveProperty("agent-custody/upstream-signature");
    expect(ex.capture).toEqual({ mode: "digest", withheld: ["content", "upstream.rawBody"] });
    expect(file).not.toMatch(/refund_id|re_[0-9a-f]{8}/);
  });

  it("a field withheld from the request does not reappear through the lookup that used it", async () => {
    const fx2 = buildFixture(mkdtempSync(join(tmpdir(), "capture-factargs-")));
    const cfg = JSON.parse(readFileSync(fx2.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "digest" }, result: { mode: "digest" }, facts: { mode: "digest" } } };
    writeFileSync(fx2.configFile, JSON.stringify(cfg));
    const gw2 = await createGateway(loadConfig(fx2.configFile));
    try {
      const r = await gw2.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      const p = decode(bundleOf2(fx2, r)).predicate;
      expect(isCommitment(p.request.args.customer_id)).toBe(true);
      expect(isCommitment(p.facts.customer!.args.customer_id)).toBe(true);
      expect(p.facts.customer!.argsCapture).toEqual({ mode: "digest", withheld: ["customer_id"] });
      expect(readFileSync(join(fx2.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")).not.toContain("cust_123");
      const v = verifyBundle(bundleOf2(fx2, r), { issuerKeys: [loadPublicKey(fx2.gatewayPub)], principalKeys: [loadPublicKey(fx2.principalPub)], logFile: fx2.logFile });
      expect(v.ok, formatReport(v)).toBe(true);
      expect(check("fact customer args", v).detail).toMatch(/committed, not recomputed/);
      const disclosed = verifyBundle(bundleOf2(fx2, r), { issuerKeys: [loadPublicKey(fx2.gatewayPub)], principalKeys: [loadPublicKey(fx2.principalPub)], logFile: fx2.logFile, disclosed: { facts: { customer: { args: { customer_id: "cust_123" } } } } });
      expect(check("fact customer args", disclosed).detail).toMatch(/hold against the disclosed value/);
    } finally {
      await gw2.close();
    }
  });

  it("verifies as committed without the values, in full with the key, in full with a disclosure, and refuses a disclosure that lies", async () => {
    const args = { customer_id: "cust_123", amount: 2600, reason: "duplicate charge" };
    const r = await gw.handleCall({ name: "stripe.refund", arguments: args });
    const bundle = bundleOf(r);
    const bare = verifyBundle(bundle, opts);
    expect(bare.ok, formatReport(bare)).toBe(true);
    expect(check("request args digest", bare).detail).toMatch(/committed, not recomputed: 1 field\(s\) are withheld \(encrypted\)/);
    expect(check("result digest", bare).detail).toMatch(/committed, not recomputed/);
    expect(check("upstream signature not checked", bare)).toBeDefined();
    expect(bare.checks.find((c) => c.name === "upstream signature (upstream key)")).toBeUndefined();

    const withKey = verifyBundle(bundle, { ...opts, captureKey: key });
    expect(withKey.ok, formatReport(withKey)).toBe(true);
    expect(check("request args digest", withKey).detail).toBe("recomputed from decrypted values");
    expect(check("fact customer value", withKey).detail).toMatch(/hold against the decrypted value/);
    // the result was withheld as a digest, not encrypted: the key cannot bring it back
    expect(check("result digest", withKey).detail).toMatch(/committed, not recomputed/);

    const p = decode(bundle).predicate;
    const fullResult = JSON.parse((r.content[0] as { text: string }).text) as { refund_id: string };
    // the full result as the upstream sent it is what the agent received, less the receipt id the gateway adds
    const { "agent-custody/receipt": _receipt, ...originalMeta } = r._meta as Record<string, unknown>;
    const disclosed = { args, result: { ...r, _meta: originalMeta }, upstreamRawBody: (originalMeta["agent-custody/upstream-signature"] as { rawBody: string }).rawBody };
    void p;
    const withDisclosure = verifyBundle(bundle, { ...opts, disclosed });
    expect(withDisclosure.ok, formatReport(withDisclosure)).toBe(true);
    expect(check("request args digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("result digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("upstream signature (provider secret)", withDisclosure).ok).toBe(true);
    expect(fullResult.refund_id).toMatch(/^re_/);

    const lie = verifyBundle(bundle, { ...opts, disclosed: { args: { ...args, amount: 2600, reason: "a different reason" } } });
    expect(lie.ok).toBe(false);
    expect(check("request args digest", lie).detail).toMatch(/"reason" does not match/);
    // a disclosure that lies about the fact the policy decided on fails too, key or no key
    const factLie = verifyBundle(bundle, { ...opts, captureKey: key, disclosed: { facts: { customer: { value: { id: "cust_999", email: "lie@example.com", verified: false } } } } });
    expect(factLie.ok).toBe(false);
    expect(check("fact customer value", factLie).detail).toMatch(/does not match/);
  });

  it("a rule in mode encrypted without a key, or a key variable that is not set, fails at startup", async () => {
    const fx2 = buildFixture(mkdtempSync(join(tmpdir(), "capture-nokey-")));
    const cfg = JSON.parse(readFileSync(fx2.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "encrypted" } } };
    writeFileSync(fx2.configFile, JSON.stringify(cfg));
    await expect(createGateway(loadConfig(fx2.configFile))).rejects.toThrow(/needs captureKeyEnv/);
    cfg.captureKeyEnv = "TEST_CAPTURE_KEY_MISSING";
    writeFileSync(fx2.configFile, JSON.stringify(cfg));
    await expect(createGateway(loadConfig(fx2.configFile))).rejects.toThrow(/TEST_CAPTURE_KEY_MISSING is not set/);
  });
});

describe("private evidence through the SDK", () => {
  it("record applies the same rule and the receipt verifies as committed, then in full with the key", async () => {
    process.env.TEST_CAPTURE_KEY = KEY_HEX;
    const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "capture-sdk-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "encrypted", clear: ["amount"] }, result: { mode: "encrypted" } } };
    cfg.captureKeyEnv = "TEST_CAPTURE_KEY";
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
    const bundle = await sdk.record({ tool: "stripe.refund", args: { amount: 900, customer_id: "cust_9" } }, { status: "executed", result: { refund_id: "re_9", card_last4: "4242" } });
    expect(JSON.stringify(bundle)).not.toMatch(/cust_9|4242/);
    const o = { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile };
    const bare = verifyBundle(bundle, o);
    expect(bare.ok, formatReport(bare)).toBe(true);
    expect(check("result digest", bare).detail).toMatch(/2 field\(s\) are withheld \(encrypted\)/);
    const full = verifyBundle(bundle, { ...o, captureKey: key });
    expect(full.ok).toBe(true);
    expect(check("result digest", full).detail).toBe("recomputed from decrypted values");
    delete process.env.TEST_CAPTURE_KEY;
  });
});

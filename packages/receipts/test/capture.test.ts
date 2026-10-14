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
const KEY_HEX = randomBytes(32).toString("hex");
const key = captureKeyFrom(KEY_HEX);
const check = (name: string, r: ReturnType<typeof verifyBundle>) => r.checks.find((c) => c.name === name)!;

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
    expect(restore(digest.view)).toBeNull();
    expect(restore(digest.view, args)!.value).toEqual(args);
    expect(() => restore(digest.view, { ...args, reason: "something else" })).toThrow(/does not match/);
    const enc = captureValue(args, { mode: "encrypted", clear: ["amount"] }, key);
    expect(restore(enc.view, undefined, key)).toEqual({ value: args, how: "decrypted" });
    expect(restore(enc.view, undefined, captureKeyFrom(randomBytes(32).toString("hex")))).toBeNull();
    const whole = captureValue("just a string", { mode: "digest" });
    expect(whole.note).toEqual({ mode: "digest", withheld: ["*"] });
    expect(restore(whole.view, "just a string")!.how).toBe("disclosed");
    expect(captureValue(args, { mode: "clear" })).toEqual({ view: args });
    expect(captureValue(args, undefined)).toEqual({ view: args });
    expect(() => captureValue(args, { mode: "encrypted" })).toThrow(/needs captureKeyEnv/);
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
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    gw = await createGateway(loadConfig(fx.configFile));
    opts = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], logFile: fx.logFile };
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
    expect(ex.capture).toEqual({ mode: "digest", withheld: ["content"] });
    // the fact the policy decided on is encrypted field by field: the policy saw it, the file does not show it
    const customer = p.facts.customer!.value as Record<string, unknown>;
    expect(Object.values(customer).every(isCommitment)).toBe(true);
    expect(p.facts.customer!.capture).toEqual({ mode: "encrypted", withheld: ["id", "email", "verified"] });
    expect(file).not.toContain('"plan":"pro"');
    expect(p.policy!.decision).toBe("allow");
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
    // the result was withheld as a digest, not encrypted: the key cannot bring it back
    expect(check("result digest", withKey).detail).toMatch(/committed, not recomputed/);

    const p = decode(bundle).predicate;
    const fullResult = JSON.parse((r.content[0] as { text: string }).text);
    const disclosed = { args, result: { content: [{ type: "text", text: JSON.stringify(fullResult) }], _meta: (p.execution as { result: { _meta: unknown } }).result._meta } };
    const withDisclosure = verifyBundle(bundle, { ...opts, disclosed });
    expect(withDisclosure.ok, formatReport(withDisclosure)).toBe(true);
    expect(check("request args digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("result digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("upstream signature (upstream key)", withDisclosure).ok).toBe(true);

    const lie = verifyBundle(bundle, { ...opts, disclosed: { args: { ...args, amount: 2600, reason: "a different reason" } } });
    expect(lie.ok).toBe(false);
    expect(check("request args digest", lie).detail).toMatch(/"reason" does not match/);
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

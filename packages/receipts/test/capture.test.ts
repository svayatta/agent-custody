// Private evidence (issues #109, #76, #126): the receipt carries only what the capture rule allows, decided in one place
// (the issuer's view of the whole statement), the digests and signatures are over the whole call, salted, and the
// verifier recomputes them when the values are in clear, disclosed, or revealed with the customer's key, and says
// "committed, not recomputed" when they are not.
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { captureKeyFrom, checkCommitment, digestSalt, getAt, isCommitment, pathKey, privateView, restorePaths, reveal, ruleFor, setAt, withhold, type CaptureNote, type Path } from "../src/capture.ts";
import { sha256Hex } from "../src/crypto.ts";
import { SALTS_DIR } from "../src/retention.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { digestOf, loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY, type Gateway } from "../src/gateway.ts";
import type { AuthorizationStatement, ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { formatReport, verifyBundle, type VerifyOptions } from "../src/verify.ts";
import { buildFixture, buildSdkFixture, type Fixture } from "../scripts/fixture.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const bundleOf2 = (fx: Fixture, r: { _meta?: Record<string, unknown> }) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
/** Everything a receipt file says, decoded: the statement, the authorization inside it, and the rest. A leak check on the base64 file alone proves nothing. */
const leakText = (b: ReceiptBundle): string => {
  const statement = Buffer.from(b.envelope.payload, "base64").toString();
  const auth = (JSON.parse(statement) as ReceiptStatement).predicate.authorization;
  return statement + (auth ? Buffer.from(auth.envelope.payload, "base64").toString() : "") + JSON.stringify(b);
};
const KEY_HEX = randomBytes(32).toString("hex");
const key = captureKeyFrom(KEY_HEX);
const check = (name: string, r: ReturnType<typeof verifyBundle>) => r.checks.find((c) => c.name === name)!;
const text = (r: { content: { type: string; text?: string }[] }) => (r.content[0] as { text: string }).text;
const withheldPaths = (p: ReceiptPredicate) => (p.capture?.withheld ?? []).map((w) => w.join("."));
/** the salts the issuer kept beside a receipt, never in it: those of digest-only commitments; an encrypted one's salt comes back with the key */
const saltsOf = (receiptsDir: string, id: string) => (JSON.parse(readFileSync(join(receiptsDir, SALTS_DIR, `${id}.json`), "utf8")) as { salts: Record<string, string> }).salts;
const allSalts = (receiptsDir: string, p: ReceiptPredicate, k?: Buffer) => ({ ...saltsOf(receiptsDir, p.receiptId), ...Object.fromEntries(restorePaths(p, p.capture, undefined, k).salts) });
/** the salt a digest over `prefix` was made with, from the kept salts */
const saltFor = (note: CaptureNote | undefined, salts: Record<string, string>, prefix: Path) => digestSalt((note?.withheld ?? []).filter((w) => prefix.every((s, i) => w[i] === s)).map((w) => salts[pathKey(w)]!));
/** a disclosure as the holder of the values and the salts writes it: `{ $custody: "disclosed", salt, value }` at each withheld path the partial predicate covers */
const disclose = (note: CaptureNote | undefined, salts: Record<string, string>, partial: Record<string, unknown>): Record<string, unknown> => {
  let out: Record<string, unknown> = {};
  for (const w of note?.withheld ?? []) {
    const value = getAt(partial, w);
    if (value !== undefined) out = setAt(out, w, { $custody: "disclosed", salt: salts[pathKey(w)], value });
  }
  return out;
};
const WEBHOOK_SECRET = "whsec_capture_test";

/** an SDK-shaped predicate with a value in every place a call can leave one */
const predicate = (over: Partial<ReceiptPredicate> = {}): ReceiptPredicate => ({
  receiptId: "r-1",
  timestamp: "2026-10-15T00:00:00.000Z",
  issuer: { kind: "sdk", keyid: "k", version: "0" },
  principal: { id: "user_456", provenance: "claimed" },
  agent: { id: "bot", provenance: "claimed" },
  session: { id: null, toolUseId: null, provenance: "claimed" },
  model: { id: null, provenance: "claimed" },
  tool: { name: "stripe.refund", provenance: "claimed" },
  request: { args: { customer_id: "cust_123", amount: 2500, reason: "called from +44 20 7946 0000", note: { card: "4242" } }, argsDigest: "x", provenance: "claimed" },
  facts: {},
  policy: { decision: "allow", reasons: ["policy0"], errors: [], policyDigest: "d", provenance: "claimed" },
  execution: { status: "executed", result: { content: [{ type: "text", text: "refund re_1 for cust_123" }], isError: false, _meta: { "x/trace": "cust_123" } }, resultDigest: "y", provenance: "claimed" },
  ...over,
});

describe("the view of a statement under a rule", () => {
  it("withholds a value as a salted digest, optionally with the value encrypted under the key, and checks it back", () => {
    const { commitment: w, salt } = withhold({ reason: "card ending 4242" });
    expect(w).toEqual({ $custody: "withheld", sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(checkCommitment(w, { reason: "card ending 4242" }, salt)).toBe(true);
    expect(checkCommitment(w, { reason: "card ending 4243" }, salt)).toBe(false);
    expect(checkCommitment(w, { reason: "card ending 4242" }, randomBytes(16).toString("hex"))).toBe(false);
    expect(() => reveal(w, key)).toThrow(/withheld without its value/);
    const e = withhold("phone +44 20 7946 0000", key);
    expect(e.commitment.$custody).toBe("encrypted");
    expect(JSON.stringify(e.commitment)).not.toMatch(/7946|salt/);
    expect(reveal(e.commitment, key)).toEqual({ value: "phone +44 20 7946 0000", salt: e.salt });
    expect(() => reveal(e.commitment, captureKeyFrom(randomBytes(32).toString("hex")))).toThrow(/not the one given/);
    expect(isCommitment(e.commitment)).toBe(true);
    expect(isCommitment({ sha256: "x" })).toBe(false);
    expect(isCommitment({ $custody: "withheld" })).toBe(false);
    expect(() => captureKeyFrom("too-short")).toThrow(/32 bytes/);
  });

  it("captures each side field by field, keeps the listed fields, salts the digests, and restores from a disclosure or the key", () => {
    const p = predicate();
    const { predicate: v, salts } = privateView(p, { args: { mode: "digest", clear: ["customer_id", "amount"] }, result: { mode: "digest", clear: ["content"] } });
    expect(v.capture).toEqual({ mode: "digest", withheld: [["request", "args", "reason"], ["request", "args", "note"], ["execution", "result", "_meta"]] });
    expect(v.request.args.amount).toBe(2500);
    expect(isCommitment(v.request.args.reason)).toBe(true);
    expect(JSON.stringify(v)).not.toMatch(/7946|4242|salt/);
    expect(Object.keys(salts).sort()).toEqual(v.capture!.withheld.map(pathKey).sort());
    // the digests are over the full values, salted from the field salts: whoever can restore the values can recompute them
    expect(v.request.argsDigest).toBe(digestOf(p.request.args, saltFor(v.capture, salts, ["request", "args"])));
    expect(v.request.argsDigest).not.toBe(digestOf(p.request.args));
    const ex = v.execution as { resultDigest: string };
    expect(ex.resultDigest).toBe(digestOf((p.execution as { result: unknown }).result, saltFor(v.capture, salts, ["execution", "result"])));
    // nothing comes back without a disclosure or a key
    expect(restorePaths(v, v.capture).missing).toHaveLength(3);
    const back = restorePaths(v, v.capture, disclose(v.capture, salts, { request: { args: { reason: p.request.args.reason, note: p.request.args.note } }, execution: { result: { _meta: { "x/trace": "cust_123" } } } }));
    expect(back.problems).toEqual([]);
    expect(back.missing).toEqual([]);
    expect(back.predicate.request.args).toEqual(p.request.args);
    expect(digestOf(back.predicate.request.args, saltFor(v.capture, salts, ["request", "args"]))).toBe(v.request.argsDigest);
    const lie = restorePaths(v, v.capture, disclose(v.capture, salts, { request: { args: { reason: "something else" } } }));
    expect(lie.problems[0]!.error).toMatch(/disclosed request.args.reason does not match/);
    // a value alone, without its salt, cannot be checked and is said so
    const bare = restorePaths(v, v.capture, { request: { args: { reason: p.request.args.reason } } });
    expect(bare.problems[0]!.error).toMatch(/must be \{ "\$custody": "disclosed", "salt", "value" \}/);
    // a salt alone, as reveal --include-salts writes for the holder to complete, is an unfinished disclosure and fails rather than passing as committed
    expect(restorePaths(v, v.capture, { request: { args: { reason: { $custody: "disclosed", salt: salts[pathKey(["request", "args", "reason"])] } } } }).problems[0]!.error).toMatch(/carries a salt but no value/);
    const enc = privateView(p, { args: { mode: "encrypted", clear: ["amount"] } }, key).predicate;
    const dec = restorePaths(enc, enc.capture, undefined, key);
    expect(dec.missing).toEqual([]);
    expect(dec.predicate.request.args).toEqual(p.request.args);
    expect([...dec.restored.values()].every((h) => h === "decrypted")).toBe(true);
    expect(restorePaths(enc, enc.capture, undefined, captureKeyFrom(randomBytes(32).toString("hex"))).missing.length).toBeGreaterThan(0);
    expect(privateView(p, { args: { mode: "clear" } })).toEqual({ predicate: p, salts: {} });
    expect(privateView(p, undefined).predicate).toBe(p);
    expect(() => privateView(p, { args: { mode: "encrypted" } })).toThrow(/needs captureKeyEnv/);
  });

  it("once a side is private, the sides the rule does not set are withheld whole, every other message is withheld, and a side set to clear stays", () => {
    const p = predicate({
      policy: { decision: "deny", reasons: [], errors: ["no such customer cust_123"], policyDigest: "d", provenance: "claimed" },
      execution: { status: "denied", reason: "no such customer cust_123", provenance: "claimed" },
    });
    const v = privateView(p, { result: { mode: "digest" } }).predicate;
    expect(withheldPaths(v)).toEqual(["request.args.customer_id", "request.args.amount", "request.args.reason", "request.args.note", "policy.errors", "execution.reason"]);
    expect(isCommitment(v.policy!.errors)).toBe(true);
    expect(JSON.stringify(v)).not.toContain("cust_123");
    // a side set to clear is in clear, and an empty error list is structural
    const clear = privateView(predicate(), { args: { mode: "digest" }, result: { mode: "clear" } }).predicate;
    expect(withheldPaths(clear)).toEqual(["request.args.customer_id", "request.args.amount", "request.args.reason", "request.args.note"]);
    expect((clear.execution as { result: { _meta: unknown } }).result._meta).toEqual({ "x/trace": "cust_123" });
    expect(clear.policy!.errors).toEqual([]);
    // the result's error flag is its status and stays; its metadata never does, listed in clear or not
    const meta = privateView(predicate(), { result: { mode: "digest", clear: ["content", "_meta", "isError"] } }).predicate;
    expect(withheldPaths(meta)).toEqual(["request.args.customer_id", "request.args.amount", "request.args.reason", "request.args.note", "execution.result._meta"]);
    expect((meta.execution as { result: { isError: boolean } }).result.isError).toBe(false);
    // a thrown message, and a part of the statement added later, start withheld
    const err = privateView({ ...predicate({ execution: { status: "error", error: "card declined for cust_123", provenance: "claimed" } }), later: { secret: "cust_123" } } as ReceiptPredicate, { args: { mode: "digest", clear: ["customer_id", "amount", "reason", "note"] } }).predicate;
    expect(withheldPaths(err)).toEqual(["execution.error", "later"]);
    expect(JSON.stringify(err)).not.toMatch(/declined|secret/);
    // one mode for what is outside the sides: encrypted as soon as any side is, so the key brings everything back
    const mixed = privateView(p, { args: { mode: "digest" }, result: { mode: "encrypted" } }, key).predicate;
    expect((mixed.request.args.customer_id as { $custody: string }).$custody).toBe("withheld");
    expect((mixed.policy!.errors as { $custody: string }).$custody).toBe("encrypted");
    expect(restorePaths(mixed, mixed.capture, undefined, key).predicate.policy!.errors).toEqual(["no such customer cust_123"]);
  });

  it("keeps a field named __proto__ through capture and restoration, and a field literally named * is just a field", () => {
    const args = JSON.parse('{"__proto__":{"secret":"review"},"amount":2500,"*":"star"}') as Record<string, unknown>;
    const p = predicate({ request: { args, argsDigest: "x", provenance: "claimed" } });
    const { predicate: v, salts } = privateView(p, { args: { mode: "encrypted", clear: ["amount"] } }, key);
    expect(v.capture!.withheld).toEqual([["request", "args", "__proto__"], ["request", "args", "*"], ["execution", "result", "content"], ["execution", "result", "_meta"]]);
    const persisted = JSON.parse(JSON.stringify(v)) as ReceiptPredicate;
    expect(isCommitment(getAt(persisted, ["request", "args", "__proto__"]))).toBe(true);
    expect(isCommitment(getAt(persisted, ["request", "args", "*"]))).toBe(true);
    const back = restorePaths(persisted, persisted.capture, undefined, key);
    expect(back.missing).toEqual([]);
    expect(JSON.parse(JSON.stringify(back.predicate.request.args))).toEqual(args);
    expect(digestOf(back.predicate.request.args, saltFor(v.capture, salts, ["request", "args"]))).toBe(v.request.argsDigest);
    expect(restorePaths(persisted, persisted.capture, disclose(v.capture, salts, { request: { args } })).problems).toEqual([]);
    expect(({} as Record<string, unknown>).secret).toBeUndefined();
  });

  it("the note decides what is withheld: a named path that is not a commitment is a problem, and commitment-shaped data outside the note is data", () => {
    const p = predicate();
    const bad = restorePaths(p, { mode: "digest", withheld: [["request", "args", "reason"]] });
    expect(bad.problems[0]!.error).toMatch(/says request.args.reason is withheld, but the receipt carries no commitment/);
    const shaped = predicate({ request: { args: { extra: { $custody: "withheld", sha256: "00".repeat(32) } }, argsDigest: "x", provenance: "claimed" } });
    const r = restorePaths(shaped, undefined, undefined, key);
    expect(r.predicate).toBe(shaped);
    expect(r.missing).toEqual([]);
  });

  it("a tool or a fact named like an inherited property is looked up by own property, a null is withheld, an incoming note is dropped, and a fact without its full result has its digest withheld", () => {
    // the wildcard rule applies to a tool named constructor: an inherited member is not a rule
    const rule = { "*": { args: { mode: "digest" as const, clear: ["amount"] } } };
    for (const tool of ["constructor", "toString", "hasOwnProperty", "__proto__"]) expect(ruleFor(rule, tool)).toBe(rule["*"]);
    expect(ruleFor({ constructor: { args: { mode: "clear" as const } } }, "constructor")!.args!.mode).toBe("clear");
    expect(ruleFor({ stripe: {} }, "other")).toBeUndefined();
    const p = predicate({
      request: { args: { amount: 2500, reason: null, note: "n" }, argsDigest: "x", provenance: "claimed" },
      facts: { constructor: { tool: "customer.lookup", args: { customer_id: "cust_123" }, value: { id: "cust_123" }, resultDigest: digestOf({ content: [] }), provenance: "observed" as const } },
      capture: { mode: "digest", withheld: [["request", "args", "amount"]] },
    });
    const { predicate: v, salts } = privateView(p, rule["*"] ? { args: { mode: "digest", clear: ["amount"] } } : undefined);
    // the note came from this view, not from the predicate; a null is a value and is withheld; the fact named constructor is handled by own property
    // the result side was not set, so it is withheld too
    expect(withheldPaths(v).sort()).toEqual(["request.args.reason", "request.args.note", "facts.constructor.value.id", "facts.constructor.args.customer_id", "facts.constructor.resultDigest", "execution.result.content", "execution.result._meta"].sort());
    expect(v.request.args.amount).toBe(2500);
    expect(isCommitment(getAt(v, ["facts", "constructor", "resultDigest"]))).toBe(true);
    expect(Object.keys(salts)).toHaveLength(7);
    // with the full lookup result given, the digest is salted instead
    const given = privateView(p, { args: { mode: "digest", clear: ["amount"] } }, undefined, { factResults: { constructor: { content: [] } } }).predicate;
    expect(typeof getAt(given, ["facts", "constructor", "resultDigest"])).toBe("string");
    expect(getAt(given, ["facts", "constructor", "resultDigest"])).not.toBe(digestOf({ content: [] }));
    // the receipt's view built on the authorization's carries the same commitments and salts for the shared parts
    const auth = privateView({ ...p, execution: undefined } as unknown as ReceiptPredicate, { args: { mode: "digest", clear: ["amount"] } });
    const after = privateView(p, { args: { mode: "digest", clear: ["amount"] } }, undefined, {}, auth);
    expect(after.predicate.request).toEqual(auth.predicate.request);
    expect(after.predicate.facts).toEqual(auth.predicate.facts);
    expect(after.predicate.request.argsDigest).toBe(auth.predicate.request.argsDigest);
    expect(withheldPaths(after.predicate)).toEqual([...withheldPaths(auth.predicate), "execution.result.content", "execution.result._meta"]);
    for (const w of auth.predicate.capture!.withheld) expect(after.salts[pathKey(w)]).toBe(auth.salts[pathKey(w)]);
  });

  it("a reviewer who can guess a withheld value cannot confirm the guess from the receipt, in either mode (issue #126)", () => {
    const args = { amount: 2500, reason: "fraud" };
    const guesses = ["fraud", "duplicate", "goodwill", "requested by customer"];
    for (const mode of ["digest", "encrypted"] as const) {
      const { predicate: v, salts } = privateView(predicate({ request: { args, argsDigest: "x", provenance: "claimed" } }), { args: { mode, clear: ["amount"] } }, key);
      const c = v.request.args.reason as { sha256: string };
      // nothing in the receipt is a salt, and no public computation over a guess reaches the commitment or the digest
      expect(JSON.stringify(v)).not.toMatch(/"salt"/);
      for (const guess of guesses) {
        expect(sha256Hex(JSON.stringify(guess))).not.toBe(c.sha256);
        expect(digestOf(guess)).not.toBe(c.sha256);
        expect(digestOf({ amount: 2500, reason: guess })).not.toBe(v.request.argsDigest);
        expect(digestOf({ amount: 2500, reason: guess }, sha256Hex(""))).not.toBe(v.request.argsDigest);
      }
      // with the salt, and only with it, the true value checks and the others do not: the test can fail
      const salt = salts[pathKey(["request", "args", "reason"])]!;
      expect(guesses.filter((g) => checkCommitment(c as never, g, salt))).toEqual(["fraud"]);
      expect(digestOf(args, digestSalt([salt]))).toBe(v.request.argsDigest);
    }
  });
});

describe("private evidence through the gateway", () => {
  let fx: Fixture;
  let gw: Gateway;
  let gwClear: Gateway;
  let opts: VerifyOptions;
  const bundleOf = (r: { _meta?: Record<string, unknown> }) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const clearBundleOf = (r: { _meta?: Record<string, unknown> }) => JSON.parse(readFileSync(join(fx.dir, "receipts-clear", `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
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
    const clearCfg = { ...cfg, capture: {}, receiptsDir: "receipts-clear", logFile: "log-clear.jsonl" };
    writeFileSync(join(fx.dir, "gateway-clear.json"), JSON.stringify(clearCfg));
    gwClear = await createGateway(loadConfig(join(fx.dir, "gateway-clear.json")));
    opts = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], providerSecrets: { stripe: WEBHOOK_SECRET }, logFile: fx.logFile };
  });
  afterAll(async () => {
    await gw.close();
    await gwClear.close();
    delete process.env.TEST_CAPTURE_KEY;
  });

  it("the receipt file carries the amount and the customer id, no reason, no card, and no customer record; the digests are over the whole call", async () => {
    const args = { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000 about card ending 4242" };
    const r = await gw.handleCall({ name: "stripe.refund", arguments: args });
    expect(r.isError).toBeFalsy();
    // the agent still gets the real result
    expect(text(r)).toContain("succeeded");
    const bundle = bundleOf(r);
    const file = leakText(bundle);
    expect(file).not.toMatch(/7946 0000|ending 4242|called from/);
    // and without a rule the same call would show them, so the check can fail
    const clearCall = await gwClear.handleCall({ name: "stripe.refund", arguments: args });
    expect(leakText(clearBundleOf(clearCall))).toMatch(/7946 0000/);
    const p = decode(bundle).predicate;
    expect(p.request.args).toMatchObject({ customer_id: "cust_123", amount: 2500 });
    expect(isCommitment(p.request.args.reason)).toBe(true);
    expect(p.capture!.mode).toBe("encrypted");
    const paths = withheldPaths(p);
    expect(paths).toContain("request.args.reason");
    // the digest is salted from the field salts the issuer kept beside the receipt, never in it, for the owner alone
    expect(file).not.toMatch(/"salt"/);
    const kept = saltsOf(fx.receiptsDir, p.receiptId);
    expect(statSync(join(fx.receiptsDir, SALTS_DIR, `${p.receiptId}.json`)).mode & 0o777).toBe(0o600);
    expect(statSync(join(fx.receiptsDir, SALTS_DIR)).mode & 0o777).toBe(0o700);
    // the file holds the salts of the digest-only commitments and none of the encrypted ones, whose salts the key alone recovers
    const kinds = Object.fromEntries(p.capture!.withheld.map((w) => [pathKey(w), (getAt(p, w) as { $custody: string }).$custody]));
    expect(Object.keys(kept).sort()).toEqual(Object.keys(kinds).filter((k) => kinds[k] === "withheld").sort());
    expect(kinds[pathKey(["request", "args", "reason"])]).toBe("encrypted");
    const salts = allSalts(fx.receiptsDir, p, key);
    expect(p.request.argsDigest).toBe(digestOf(args, saltFor(p.capture, salts, ["request", "args"])));
    expect(p.request.argsDigest).not.toBe(digestOf(args));
    expect(p.execution.status).toBe("executed");
    const ex = p.execution as { result: { content: unknown; isError?: boolean; _meta?: unknown }; resultSalt?: string };
    expect(isCommitment(ex.result.content)).toBe(true);
    expect(isCommitment(ex.result.isError)).toBe(false);
    // the metadata carries the provider's delivery, so it is withheld with the result, and so is the body in the evidence
    expect(isCommitment(ex.result._meta)).toBe(true);
    expect(paths).toContain("execution.result._meta");
    expect(paths).toContain("execution.upstream.rawBody");
    const up = (p.execution as { upstream: { rawBody: unknown; signature: string } }).upstream;
    expect(isCommitment(up.rawBody)).toBe(true);
    expect(typeof up.signature).toBe("string");
    // the fact the policy decided on is encrypted field by field: the policy saw it, the file does not show it
    const customer = p.facts.customer!.value as Record<string, unknown>;
    expect(Object.values(customer).every(isCommitment)).toBe(true);
    expect(paths).toEqual(expect.arrayContaining(["facts.customer.value.id", "facts.customer.value.email", "facts.customer.value.verified"]));
    expect(file).not.toContain('"plan":"pro"');
    expect(p.policy!.decision).toBe("allow");
    // the lookup's arguments are copied from the call: the customer id is in clear there as in the request, and nothing else leaks through them
    expect(p.facts.customer!.args).toEqual({ customer_id: "cust_123" });
    expect(paths.filter((w) => w.startsWith("facts.customer.args"))).toEqual([]);
    expect(file).not.toMatch(/refund_id|re_[0-9a-f]{8}/);
  });

  it("a field withheld from the request does not reappear as the argument of the lookup that used it", async () => {
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
      expect(withheldPaths(p)).toContain("facts.customer.args.customer_id");
      expect(leakText(bundleOf2(fx2, r))).not.toContain("cust_123");
      const o = { issuerKeys: [loadPublicKey(fx2.gatewayPub)], principalKeys: [loadPublicKey(fx2.principalPub)], logFile: fx2.logFile };
      const v = verifyBundle(bundleOf2(fx2, r), o);
      expect(v.ok, formatReport(v)).toBe(true);
      expect(check("fact customer args", v).detail).toMatch(/committed, not recomputed/);
      const disclosed = verifyBundle(bundleOf2(fx2, r), { ...o, disclosed: disclose(p.capture, saltsOf(fx2.receiptsDir, p.receiptId), { facts: { customer: { args: { customer_id: "cust_123" } } } }) });
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
    expect(check("request args digest", bare).detail).toMatch(/committed, not recomputed: 1 value\(s\) withheld \(1 encrypted\)/);
    expect(check("execution result digest", bare).detail).toMatch(/committed, not recomputed/);
    expect(check("withheld execution.upstream.rawBody", bare).detail).toMatch(/committed, not recomputed/);
    expect(check("upstream signature not checked", bare)).toBeDefined();
    expect(bare.checks.find((c) => c.name === "upstream signature (upstream key)")).toBeUndefined();

    const withKey = verifyBundle(bundle, { ...opts, captureKey: key });
    expect(withKey.ok, formatReport(withKey)).toBe(true);
    expect(check("request args digest", withKey).detail).toBe("recomputed from decrypted values");
    expect(check("fact customer value", withKey).detail).toMatch(/hold against the decrypted value/);
    // the result was withheld as a digest, not encrypted: the key cannot bring it back
    expect(check("execution result digest", withKey).detail).toMatch(/committed, not recomputed/);

    // the full result as the upstream sent it is what the agent received, less the receipt id the gateway adds
    const { "agent-custody/receipt": _receipt, ...originalMeta } = r._meta as Record<string, unknown>;
    const result = { ...r, _meta: originalMeta };
    const p = decode(bundle).predicate;
    // the holder of the values discloses them with their salts: from the file for digest-only ones, from the key for encrypted ones
    const salts = allSalts(fx.receiptsDir, p, key);
    const disclosed = disclose(p.capture, salts, { request: { args }, execution: { result, upstream: { rawBody: (originalMeta["agent-custody/upstream-signature"] as { rawBody: string }).rawBody } } });
    const withDisclosure = verifyBundle(bundle, { ...opts, disclosed });
    expect(withDisclosure.ok, formatReport(withDisclosure)).toBe(true);
    expect(check("request args digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("execution result digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("withheld execution.upstream.rawBody", withDisclosure).detail).toBe("holds against the disclosed value");
    expect(check("upstream signature (provider secret)", withDisclosure).ok).toBe(true);
    // key and disclosure together: each part comes back the way it can
    const both = verifyBundle(bundle, { ...opts, captureKey: key, disclosed: disclose(p.capture, salts, { execution: { result } }) });
    expect(both.ok, formatReport(both)).toBe(true);
    expect(check("execution result digest", both).detail).toBe("recomputed from disclosed values");

    const lie = verifyBundle(bundle, { ...opts, disclosed: disclose(p.capture, salts, { request: { args: { reason: "a different reason" } } }) });
    expect(lie.ok).toBe(false);
    expect(check("request args digest", lie).detail).toMatch(/disclosed request.args.reason does not match/);
    // a disclosure that lies about the fact the policy decided on fails too, key or no key
    const factLie = verifyBundle(bundle, { ...opts, captureKey: key, disclosed: disclose(p.capture, salts, { facts: { customer: { value: { id: "cust_999" } } } }) });
    expect(factLie.ok).toBe(false);
    expect(check("fact customer value", factLie).detail).toMatch(/does not match/);
    // a disclosure for another receipt is refused as such
    const other = verifyBundle(bundle, { ...opts, disclosed: { receiptId: "someone-else", ...disclose(p.capture, salts, { request: { args } }) } });
    expect(other.ok).toBe(false);
    expect(check("disclosure names this receipt", other).ok).toBe(false);
  });

  it("a fact argument is withheld by the call argument it copies, whatever it is called, and a constant stays in clear", async () => {
    const fx3 = buildFixture(mkdtempSync(join(tmpdir(), "capture-factsrc-")));
    const cfg = JSON.parse(readFileSync(fx3.configFile, "utf8"));
    cfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref", mode: "full" }, forTools: ["stripe.refund"] }];
    cfg.capture = { "*": { args: { mode: "digest", clear: ["customer_id", "amount"] } } };
    writeFileSync(fx3.configFile, JSON.stringify(cfg));
    const gw3 = await createGateway(loadConfig(fx3.configFile));
    try {
      const r = await gw3.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", account_ref: "cust_123", amount: 2500 } });
      expect(r.isError).toBeFalsy();
      const p = decode(bundleOf2(fx3, r)).predicate;
      expect(p.request.args.customer_id).toBe("cust_123");
      expect(isCommitment(p.request.args.account_ref)).toBe(true);
      // the lookup's customer_id came from account_ref, which is withheld: so it is withheld too, under its own name
      expect(isCommitment(p.facts.customer!.args.customer_id)).toBe(true);
      expect(p.facts.customer!.args.mode).toBe("full");
      expect(withheldPaths(p).filter((w) => w.startsWith("facts.customer.args"))).toEqual(["facts.customer.args.customer_id"]);
    } finally {
      await gw3.close();
    }
  });

  it("the answer of a lookup that failed, marked isError or thrown, is withheld from the receipt under a private rule; the agent gets it", async () => {
    const fx4 = buildFixture(mkdtempSync(join(tmpdir(), "capture-lookupfail-")));
    const cfg = JSON.parse(readFileSync(fx4.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx4.configFile, JSON.stringify(cfg));
    const gw4 = await createGateway(loadConfig(fx4.configFile));
    try {
      for (const id of ["cust_SECRET_777", "cust_throw_SECRET_777"]) {
        const r = await gw4.handleCall({ name: "stripe.refund", arguments: { customer_id: id, amount: 2500 } });
        expect(r.isError).toBe(true);
        expect(text(r)).toContain(id);
        const bundle = bundleOf2(fx4, r);
        const p = decode(bundle).predicate;
        expect(p.execution.status).toBe("denied");
        expect(isCommitment(p.policy!.errors)).toBe(true);
        expect(isCommitment((p.execution as { reason: unknown }).reason)).toBe(true);
        expect(withheldPaths(p)).toEqual(expect.arrayContaining(["policy.errors", "execution.reason"]));
        expect(leakText(bundle)).not.toContain("SECRET_777");
        const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx4.gatewayPub)], principalKeys: [loadPublicKey(fx4.principalPub)], logFile: fx4.logFile });
        expect(v.ok, formatReport(v)).toBe(true);
        expect(check("withheld policy.errors", v).detail).toMatch(/committed, not recomputed/);
      }
    } finally {
      await gw4.close();
    }
    // the same calls through a gateway without a rule: the answers are the errors, as before
    const clear = await gwClear.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_throw_SECRET_777", amount: 2500 } });
    expect((decode(clearBundleOf(clear)).predicate.policy!.errors as string[])[0]).toMatch(/lookup via customer.lookup failed: MCP error .*no customer cust_throw_SECRET_777/);
  });

  it("the message of a forwarded call that throws is withheld under a private rule, comes back with a disclosure, and the agent still gets it", async () => {
    const fx6 = buildFixture(mkdtempSync(join(tmpdir(), "capture-forwardthrow-")));
    const cfg = JSON.parse(readFileSync(fx6.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx6.configFile, JSON.stringify(cfg));
    const gw6 = await createGateway(loadConfig(fx6.configFile));
    try {
      const r = await gw6.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "decline" } });
      expect(r.isError).toBe(true);
      expect(text(r)).toMatch(/Upstream error: MCP error .*refund declined for cust_123/);
      const bundle = bundleOf2(fx6, r);
      const p = decode(bundle).predicate;
      expect(p.execution.status).toBe("error");
      expect(isCommitment((p.execution as { error: unknown }).error)).toBe(true);
      expect(isCommitment(p.request.args.customer_id)).toBe(true);
      // the facts side was not set, so the customer record is withheld too
      expect(Object.values(p.facts.customer!.value as Record<string, unknown>).every(isCommitment)).toBe(true);
      expect(leakText(bundle)).not.toContain("declined");
      expect(leakText(bundle)).not.toContain("cust_123");
      const o = { issuerKeys: [loadPublicKey(fx6.gatewayPub)], principalKeys: [loadPublicKey(fx6.principalPub)], logFile: fx6.logFile };
      const v = verifyBundle(bundle, o);
      expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")).toBe(true);
      expect(check("withheld execution.error", v).detail).toMatch(/committed, not recomputed/);
      const message = text(r).replace(/^Upstream error: /, "").replace(/ \(receipt [^)]+\)$/, "");
      const salts = saltsOf(fx6.receiptsDir, p.receiptId);
      const disclosed = verifyBundle(bundle, { ...o, disclosed: disclose(p.capture, salts, { execution: { error: message } }) });
      expect(check("withheld execution.error", disclosed).detail).toBe("holds against the disclosed value");
      expect(check("withheld execution.error", verifyBundle(bundle, { ...o, disclosed: disclose(p.capture, salts, { execution: { error: "another message" } }) })).ok).toBe(false);
    } finally {
      await gw6.close();
    }
    // without a rule the message is recorded, as before
    const clear = await gwClear.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "decline" } });
    expect((decode(clearBundleOf(clear)).predicate.execution as { error: string }).error).toMatch(/refund declined for cust_123/);
  });

  it("a fact's arguments follow the template of the fact config that was used, not the first config with that name", async () => {
    // fact names are not unique: one `customer` fact for another tool copies a call argument that is in clear, and the
    // `customer` fact for the refund copies one that is withheld; the receipt must withhold the lookup's argument
    const configs = [
      // across tools: the payout's fact comes first in the list
      [
        { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.payout"] },
        { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] },
      ],
      // on the same tool: the later config wins the name, so its template is the one in force
      [
        { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.refund"] },
        { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] },
      ],
    ];
    for (const facts of configs) {
      const fx7 = buildFixture(mkdtempSync(join(tmpdir(), "capture-factdup-")));
      const cfg = JSON.parse(readFileSync(fx7.configFile, "utf8"));
      cfg.facts = facts;
      cfg.capture = { "*": { args: { mode: "digest", clear: ["customer_id", "amount"] } } };
      writeFileSync(fx7.configFile, JSON.stringify(cfg));
      const gw7 = await createGateway(loadConfig(fx7.configFile));
      try {
        const r = await gw7.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", account_ref: "cust_123", amount: 2500 } });
        expect(r.isError).toBeFalsy();
        const p = decode(bundleOf2(fx7, r)).predicate;
        expect(p.request.args.customer_id).toBe("cust_123");
        expect(isCommitment(p.request.args.account_ref)).toBe(true);
        expect(isCommitment(p.facts.customer!.args.customer_id)).toBe(true);
        expect(withheldPaths(p)).toContain("facts.customer.args.customer_id");
      } finally {
        await gw7.close();
      }
    }
  });

  it("a pre-committed call's authorization and receipt carry the same commitments and salts, so the receipt still names the authorization", async () => {
    const fx8 = buildFixture(mkdtempSync(join(tmpdir(), "capture-precommit-")));
    const cfg = JSON.parse(readFileSync(fx8.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] }, facts: { mode: "digest" } } };
    cfg.precommit = ["stripe.refund"];
    writeFileSync(fx8.configFile, JSON.stringify(cfg));
    const gw8 = await createGateway(loadConfig(fx8.configFile));
    try {
      const r = await gw8.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "dup" } });
      expect(r.isError).toBeFalsy();
      const bundle = bundleOf2(fx8, r);
      const p = decode(bundle).predicate;
      const ap = (JSON.parse(Buffer.from(p.authorization!.envelope.payload, "base64").toString()) as AuthorizationStatement).predicate;
      expect(ap.request.argsDigest).toBe(p.request.argsDigest);
      expect(ap.request.args.customer_id).toEqual(p.request.args.customer_id);
      // one salts file, covering the shared parts and the receipt's own
      const salts = saltsOf(fx8.receiptsDir, p.receiptId);
      expect(Object.keys(salts).sort()).toEqual(p.capture!.withheld.map(pathKey).sort());
      expect(p.request.argsDigest).toBe(digestOf({ customer_id: "cust_123", amount: 2500, reason: "dup" }, saltFor(p.capture, salts, ["request", "args"])));
      expect(ap.facts.customer!.value).toEqual(p.facts.customer!.value);
      expect(ap.facts.customer!.resultDigest).toBe(p.facts.customer!.resultDigest);
      expect(ap.capture!.withheld.map((w: Path) => w.join("."))).toEqual(withheldPaths(p).filter((w) => w.startsWith("request.") || w.startsWith("facts.") || w.startsWith("policy.")));
      expect(withheldPaths(p)).toContain("execution.result.content");
      expect(leakText(bundle)).not.toContain("cust_123");
      const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx8.gatewayPub)], principalKeys: [loadPublicKey(fx8.principalPub)], logFile: fx8.logFile });
      expect(v.ok, formatReport(v)).toBe(true);
      expect(check("authorization names this call", v).ok).toBe(true);
    } finally {
      await gw8.close();
    }
  });

  it("reveal writes the salts of values it cannot reveal only when asked, and a file carrying a salt without its value does not verify", async () => {
    const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2700, reason: "fraud" } });
    const bundle = bundleOf(r);
    const p = decode(bundle).predicate;
    const file = join(fx.receiptsDir, `${p.receiptId}.json`);
    const cli = join(import.meta.dirname, "..", "src", "cli.ts");
    const run = (...extra: string[]) => spawnSync(process.execPath, [cli, "reveal", file, "--capture-key-env", "TEST_CAPTURE_KEY", ...extra], { encoding: "utf8", env: { ...process.env, TEST_CAPTURE_KEY: KEY_HEX } });
    // by default: the encrypted values with their salts, nothing for the digest-only ones but their names
    const plain = run();
    expect(plain.status, plain.stderr).toBe(0);
    const disclosure = JSON.parse(plain.stdout) as Record<string, unknown>;
    expect(getAt(disclosure, ["request", "args", "reason"])).toMatchObject({ $custody: "disclosed", value: "fraud" });
    expect(getAt(disclosure, ["execution", "result", "content"])).toBeUndefined();
    expect(plain.stderr).toMatch(/Not revealed.*execution.result.content.*--include-salts/s);
    const ok = verifyBundle(bundle, { ...opts, disclosed: disclosure });
    expect(ok.ok, formatReport(ok)).toBe(true);
    expect(check("request args digest", ok).detail).toBe("recomputed from disclosed values");
    // asked for: the salts go in, and the file fails until the holder fills in the values
    const withSalts = run("--include-salts");
    expect(withSalts.status, withSalts.stderr).toBe(0);
    const unfinished = JSON.parse(withSalts.stdout) as Record<string, unknown>;
    expect(getAt(unfinished, ["execution", "result", "content"])).toEqual({ $custody: "disclosed", salt: expect.stringMatching(/^[0-9a-f]{32}$/) });
    expect(withSalts.stderr).toMatch(/do not hand it over unfinished/);
    const refused = verifyBundle(bundle, { ...opts, disclosed: unfinished });
    expect(refused.ok).toBe(false);
    expect(check("execution result digest", refused).detail).toMatch(/carries a salt but no value/);
    // a receipt id from a bundle never becomes part of a path unchecked
    const st = decode(bundle);
    const forged = { ...bundle, envelope: { ...bundle.envelope, payload: Buffer.from(JSON.stringify({ ...st, predicate: { ...st.predicate, receiptId: "../../etc/passwd" } })).toString("base64") } };
    const forgedFile = join(fx.dir, "forged.json");
    writeFileSync(forgedFile, JSON.stringify(forged));
    const bad = spawnSync(process.execPath, [cli, "reveal", forgedFile, "--capture-key-env", "TEST_CAPTURE_KEY", "--include-salts"], { encoding: "utf8", env: { ...process.env, TEST_CAPTURE_KEY: KEY_HEX } });
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toMatch(/not a valid id/);
  });

  it("a rule in mode encrypted without a key, or a key variable that is not set, fails at startup", async () => {
    const fx5 = buildFixture(mkdtempSync(join(tmpdir(), "capture-nokey-")));
    const cfg = JSON.parse(readFileSync(fx5.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "encrypted" } } };
    writeFileSync(fx5.configFile, JSON.stringify(cfg));
    await expect(createGateway(loadConfig(fx5.configFile))).rejects.toThrow(/needs captureKeyEnv/);
    cfg.captureKeyEnv = "TEST_CAPTURE_KEY_MISSING";
    writeFileSync(fx5.configFile, JSON.stringify(cfg));
    await expect(createGateway(loadConfig(fx5.configFile))).rejects.toThrow(/TEST_CAPTURE_KEY_MISSING is not set/);
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
    expect(leakText(bundle)).not.toMatch(/cust_9|4242/);
    const o = { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile };
    const bare = verifyBundle(bundle, o);
    expect(bare.ok, formatReport(bare)).toBe(true);
    expect(check("execution result digest", bare).detail).toMatch(/2 value\(s\) withheld \(2 encrypted\)/);
    const full = verifyBundle(bundle, { ...o, captureKey: key });
    expect(full.ok).toBe(true);
    expect(check("execution result digest", full).detail).toBe("recomputed from decrypted values");
    delete process.env.TEST_CAPTURE_KEY;
  });

  it("the message of a wrapped tool that throws is withheld under a private rule, through the issuer every adapter uses", async () => {
    const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "capture-sdk-throw-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.capture = { "stripe.refund": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
    const refund = sdk.wrap("stripe.refund", async (a: { customer_id: string; amount: number }) => {
      throw new Error(`card declined for ${a.customer_id}`);
    });
    // the caller gets the error itself
    await expect(refund({ customer_id: "cust_SDK_SECRET", amount: 900 })).rejects.toThrow(/card declined for cust_SDK_SECRET/);
    const files = readdirSync(fx.receiptsDir).filter((f) => f.endsWith(".json") && !f.endsWith(".authorization.json"));
    expect(files).toHaveLength(1);
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, files[0]!), "utf8")) as ReceiptBundle;
    const p = decode(bundle).predicate;
    expect(p.execution.status).toBe("error");
    expect(isCommitment((p.execution as { error: unknown }).error)).toBe(true);
    expect(isCommitment(p.request.args.customer_id)).toBe(true);
    expect(leakText(bundle)).not.toContain("cust_SDK_SECRET");
    expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile }).ok).toBe(true);
    // a tool without a rule records the message, as before
    const clear = await sdk.record({ tool: "stripe.payout", args: { customer_id: "cust_SDK_SECRET" } }, { status: "error", error: "payout declined for cust_SDK_SECRET" });
    expect((decode(clear).predicate.execution as { error: string }).error).toBe("payout declined for cust_SDK_SECRET");
  });
});

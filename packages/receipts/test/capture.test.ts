// Private evidence (issues #109, #76, #126): the receipt carries only what the capture rule allows, decided in one place
// (the issuer's view of the whole statement), the digests and signatures are over the whole call, salted, and the
// verifier recomputes them when the values are in clear, disclosed, or revealed with the customer's key, and says
// "committed, not recomputed" when they are not.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { aadFor, captureKeyFrom, checkCommitment, digestSalt, effectiveRule, getAt, isCommitment, pathKey, privateView, REST, restorePaths, reveal, ruleFor, setAt, withhold, type CaptureNote, type Path } from "../src/capture.ts";
import { dsseSign, generateKeyPair } from "../src/crypto.ts";
import { contentDigest, signResult, UPSTREAM_SIG_META_KEY, UPSTREAM_TYPE } from "../src/upstream.ts";
import { sha256Hex } from "../src/crypto.ts";
import { pruneLog, SALTS_DIR } from "../src/retention.ts";
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
const saltsOf = (receiptsDir: string, id: string) => (existsSync(join(receiptsDir, SALTS_DIR, `${id}.json`)) ? (JSON.parse(readFileSync(join(receiptsDir, SALTS_DIR, `${id}.json`), "utf8")) as { salts: Record<string, string> }).salts : {});
const allSalts = (receiptsDir: string, p: ReceiptPredicate, k?: Buffer) => ({ ...saltsOf(receiptsDir, p.receiptId), ...Object.fromEntries(restorePaths(p, p.capture, undefined, k).salts) });
/** the salt a digest over `prefix` was made with, from the kept salts */
const saltFor = (note: CaptureNote | undefined, salts: Record<string, string>, prefix: Path) => digestSalt((note?.withheld ?? []).filter((w) => prefix.every((s, i) => w[i] === s)).map((w) => salts[pathKey(w)]!));
/**
 * A disclosure as the holder of the values and the salts writes it, from a partial predicate holding the real values:
 * `{ $custody: "disclosed", salt, value }` at each withheld path the partial covers. A `$rest` path takes the object of
 * every field of the real parent that the view does not show in clear, which is what the commitment was made over.
 */
const disclose = (p: ReceiptPredicate, salts: Record<string, string>, partial: Record<string, unknown>): Record<string, unknown> => {
  let out: Record<string, unknown> = {};
  for (const w of p.capture?.withheld ?? []) {
    let value: unknown;
    if (w[w.length - 1] === REST) {
      const real = getAt(partial, w.slice(0, -1));
      const view = getAt(p, w.slice(0, -1)) as Record<string, unknown> | undefined;
      if (!real || typeof real !== "object") continue;
      value = Object.fromEntries(Object.entries(real as Record<string, unknown>).filter(([k]) => k === REST || !view || !Object.hasOwn(view, k)));
    } else value = getAt(partial, w);
    if (value !== undefined) out = setAt(out, w, { $custody: "disclosed", salt: salts[pathKey(w)], value });
  }
  return out;
};
const rest = (p: ReceiptPredicate, parent: Path) => getAt(p, [...parent, REST]);
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
    expect(JSON.stringify(e.commitment)).not.toMatch(/7946 0000|"salt"/);
    expect(reveal(e.commitment, key)).toEqual({ value: "phone +44 20 7946 0000", salt: e.salt });
    expect(() => reveal(e.commitment, captureKeyFrom(randomBytes(32).toString("hex")))).toThrow(/not the one given/);
    expect(isCommitment(e.commitment)).toBe(true);
    expect(isCommitment({ sha256: "x" })).toBe(false);
    expect(isCommitment({ $custody: "withheld" })).toBe(false);
    // the encrypted form carries a 12-byte iv and a 16-byte tag, nothing shorter
    expect(isCommitment({ ...e.commitment, tag: Buffer.alloc(8).toString("base64") })).toBe(false);
    expect(isCommitment({ ...e.commitment, iv: Buffer.alloc(8).toString("base64") })).toBe(false);
    // a key is 64 hex characters or 44 of strict base64: a string with stray characters never decodes to a different key by accident
    expect(() => captureKeyFrom(`${KEY_HEX.slice(0, 63)}g`)).toThrow(/64 hex characters or 44 characters of base64/);
    expect(() => captureKeyFrom(`${Buffer.from(KEY_HEX, "hex").toString("base64").slice(0, 43)}!`)).toThrow(/64 hex/);
    expect(captureKeyFrom(Buffer.from(KEY_HEX, "hex").toString("base64")).equals(key)).toBe(true);
    // an encrypted commitment is bound to its receipt and path: moved elsewhere, it does not decrypt under the right key
    const bound = withhold("patient 0042", key, aadFor("receipt-A", ["request", "args", "reason"]));
    expect(reveal(bound.commitment, key, aadFor("receipt-A", ["request", "args", "reason"])).value).toBe("patient 0042");
    expect(() => reveal(bound.commitment, key, aadFor("receipt-B", ["request", "args", "reason"]))).toThrow();
    expect(() => reveal(bound.commitment, key, aadFor("receipt-A", ["execution", "result", "note"]))).toThrow();
    expect(() => reveal(bound.commitment, key)).toThrow();
  });

  it("captures a side as the listed fields beside one commitment over the rest, so no field name chosen by the agent or the upstream appears; salts the digests; restores from a disclosure or the key", () => {
    const p = predicate();
    const { predicate: v, salts } = privateView(p, { args: { mode: "digest", clear: ["customer_id", "amount"] }, result: { mode: "digest", clear: ["content"] } });
    expect(v.capture).toEqual({ mode: "digest", withheld: [["request", "args", REST], ["execution", "result", REST]] });
    expect(v.request.args).toEqual({ customer_id: "cust_123", amount: 2500, [REST]: expect.objectContaining({ $custody: "withheld" }) });
    // the names `reason` and `note` are nowhere: not in the view, not in the note
    expect(JSON.stringify(v)).not.toMatch(/7946 0000|"card"|"salt"|"reason"|"note"/);
    expect((v.execution as { result: { content: unknown; isError: boolean } }).result).toMatchObject({ content: p.execution.status === "executed" ? (p.execution as { result: { content: unknown } }).result.content : null, isError: false });
    expect(Object.keys(salts).sort()).toEqual(v.capture!.withheld.map(pathKey).sort());
    // the digests are over the full values, salted from the field salts: whoever can restore the values can recompute them
    expect(v.request.argsDigest).toBe(digestOf(p.request.args, saltFor(v.capture, salts, ["request", "args"])));
    expect(v.request.argsDigest).not.toBe(digestOf(p.request.args));
    const ex = v.execution as { resultDigest: string };
    expect(ex.resultDigest).toBe(digestOf((p.execution as { result: unknown }).result, saltFor(v.capture, salts, ["execution", "result"])));
    // nothing comes back without a disclosure or a key
    expect(restorePaths(v, v.capture).missing).toHaveLength(2);
    // a disclosure of the rest of each side folds back into the object the digest was made over
    const back = restorePaths(v, v.capture, disclose(v, salts, { request: { args: p.request.args }, execution: { result: (p.execution as { result: unknown }).result } }));
    expect(back.problems).toEqual([]);
    expect(back.missing).toEqual([]);
    expect(back.predicate.request.args).toEqual(p.request.args);
    expect(Object.hasOwn(back.predicate.request.args, REST)).toBe(false);
    expect(digestOf(back.predicate.request.args, saltFor(v.capture, salts, ["request", "args"]))).toBe(v.request.argsDigest);
    expect(digestOf((back.predicate.execution as { result: unknown }).result, saltFor(v.capture, salts, ["execution", "result"]))).toBe(ex.resultDigest);
    const lie = restorePaths(v, v.capture, disclose(v, salts, { request: { args: { ...p.request.args, reason: "something else" } } }));
    expect(lie.problems[0]!.error).toMatch(/disclosed request.args.\$rest does not match/);
    // a value alone, without its salt, cannot be checked and is said so
    const bare = restorePaths(v, v.capture, { request: { args: { [REST]: { reason: p.request.args.reason } } } });
    expect(bare.problems[0]!.error).toMatch(/must be \{ "\$custody": "disclosed", "salt", "value" \}/);
    // a salt alone, as reveal --include-salts writes for the holder to complete, is an unfinished disclosure and fails rather than passing as committed
    expect(restorePaths(v, v.capture, { request: { args: { [REST]: { $custody: "disclosed", salt: salts[pathKey(["request", "args", REST])] } } } }).problems[0]!.error).toMatch(/carries a salt but no value/);
    const enc = privateView(p, { args: { mode: "encrypted", clear: ["amount"] } }, key).predicate;
    const dec = restorePaths(enc, enc.capture, undefined, key);
    expect(dec.missing).toEqual([]);
    expect(dec.predicate.request.args).toEqual(p.request.args);
    expect([...dec.restored.values()].every((h) => h === "decrypted")).toBe(true);
    // a key that is not this value's is said so, not passed as committed with a hint to give the key
    const wrongKey = restorePaths(enc, enc.capture, undefined, captureKeyFrom(randomBytes(32).toString("hex")));
    expect(wrongKey.missing).toEqual([]);
    expect(wrongKey.problems[0]!.error).toMatch(/is encrypted under key [0-9a-f]{12}…, not the one given/);
    // a field literally named $rest is never kept in clear: it goes with the rest and comes back with it
    const named = privateView(predicate({ request: { args: { amount: 1, [REST]: "mine" }, argsDigest: "x", provenance: "claimed" } }), { args: { mode: "digest", clear: ["amount", REST] } });
    expect(Object.keys(named.predicate.request.args)).toEqual(["amount", REST]);
    expect(isCommitment(named.predicate.request.args[REST])).toBe(true);
    expect(restorePaths(named.predicate, named.predicate.capture, disclose(named.predicate, named.salts, { request: { args: { amount: 1, [REST]: "mine" } } })).predicate.request.args).toEqual({ amount: 1, [REST]: "mine" });
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
    expect(withheldPaths(v)).toEqual(["request.args.$rest", "policy.errors", "execution.reason"]);
    expect(Object.keys(v.request.args)).toEqual([REST]);
    expect(isCommitment(v.policy!.errors)).toBe(true);
    expect(JSON.stringify(v)).not.toContain("cust_123");
    // a side set to clear is in clear (its content, not the metadata an upstream wrote), and an empty error list is structural
    const clear = privateView(predicate(), { args: { mode: "digest" }, result: { mode: "clear" } }).predicate;
    expect(withheldPaths(clear)).toEqual(["request.args.$rest", "execution.result._meta"]);
    expect((clear.execution as { result: { content: unknown } }).result.content).toEqual([{ type: "text", text: "refund re_1 for cust_123" }]);
    expect(isCommitment((clear.execution as { result: { _meta: unknown } }).result._meta)).toBe(true);
    expect(clear.policy!.errors).toEqual([]);
    // the result's error flag is its status and stays; its metadata never does, listed in clear or not
    const meta = privateView(predicate(), { result: { mode: "digest", clear: ["content", "_meta", "isError"] } }).predicate;
    expect(withheldPaths(meta)).toEqual(["request.args.$rest", "execution.result.$rest"]);
    expect((meta.execution as { result: { isError: boolean; _meta?: unknown } }).result.isError).toBe(false);
    expect((meta.execution as { result: { _meta?: unknown } }).result._meta).toBeUndefined();
    // only the boolean flag is the status: an SDK tool may return anything under that name, and that is a value
    for (const mode of ["digest", "encrypted"] as const) {
      const odd = privateView(predicate({ execution: { status: "executed", result: { isError: { customer_id: "PRIVATE_555" }, message: "PRIVATE_555" }, resultDigest: "y", provenance: "claimed" } }), { result: { mode } }, key).predicate;
      expect(Object.keys((odd.execution as { result: Record<string, unknown> }).result)).toEqual([REST]);
      expect(JSON.stringify(odd)).not.toContain("PRIVATE_555");
      const str = privateView(predicate({ execution: { status: "failed", result: { isError: "PRIVATE_555", content: [] }, resultDigest: "y", provenance: "claimed" } }), { result: { mode } }, key).predicate;
      expect(JSON.stringify(str)).not.toContain("PRIVATE_555");
    }
    // a thrown message, and a part of the statement added later, start withheld
    const err = privateView({ ...predicate({ execution: { status: "error", error: "card declined for cust_123", provenance: "claimed" } }), later: { secret: "cust_123" } } as ReceiptPredicate, { args: { mode: "digest", clear: ["customer_id", "amount", "reason", "note"] } }).predicate;
    expect(withheldPaths(err)).toEqual(["execution.error", "later"]);
    expect(JSON.stringify(err)).not.toMatch(/declined|secret/);
    // one mode for what is outside the sides: encrypted as soon as any side is, so the key brings everything back
    const mixed = privateView(p, { args: { mode: "digest" }, result: { mode: "encrypted" } }, key).predicate;
    expect((mixed.request.args[REST] as { $custody: string }).$custody).toBe("withheld");
    expect((mixed.policy!.errors as { $custody: string }).$custody).toBe("encrypted");
    expect(restorePaths(mixed, mixed.capture, undefined, key).predicate.policy!.errors).toEqual(["no such customer cust_123"]);
  });

  it("keeps a field named __proto__ through capture and restoration, and a field literally named * is just a field", () => {
    const args = JSON.parse('{"__proto__":{"secret":"review"},"amount":2500,"*":"star"}') as Record<string, unknown>;
    const p = predicate({ request: { args, argsDigest: "x", provenance: "claimed" } });
    const { predicate: v, salts } = privateView(p, { args: { mode: "encrypted", clear: ["amount"] } }, key);
    expect(v.capture!.withheld).toEqual([["request", "args", REST], ["execution", "result", REST]]);
    const persisted = JSON.parse(JSON.stringify(v)) as ReceiptPredicate;
    expect(JSON.stringify(persisted)).not.toMatch(/__proto__|secret|star/);
    const back = restorePaths(persisted, persisted.capture, undefined, key);
    expect(back.missing).toEqual([]);
    expect(JSON.parse(JSON.stringify(back.predicate.request.args))).toEqual(args);
    expect(Object.hasOwn(back.predicate.request.args, "__proto__")).toBe(true);
    expect(digestOf(back.predicate.request.args, saltFor(v.capture, salts, ["request", "args"]))).toBe(v.request.argsDigest);
    expect(restorePaths(persisted, persisted.capture, disclose(v, salts, { request: { args } })).problems).toEqual([]);
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
    const { predicate: v, salts } = privateView(p, { args: { mode: "digest", clear: ["amount"] } });
    // the note came from this view, not from the predicate; a null is a value and goes with the rest; the fact named constructor is handled by own property; the result side was not set, so it is withheld too
    expect(withheldPaths(v).sort()).toEqual(["request.args.$rest", "facts.constructor.value.$rest", "facts.constructor.args.customer_id", "facts.constructor.resultDigest", "execution.result.$rest"].sort());
    expect(v.request.args.amount).toBe(2500);
    expect(Object.keys(v.request.args)).toEqual(["amount", REST]);
    expect(isCommitment(getAt(v, ["facts", "constructor", "resultDigest"]))).toBe(true);
    expect(Object.keys(salts)).toHaveLength(5);
    // with the full lookup result given, the digest is a commitment to that result, disclosed and checked like any value
    const full = { content: [{ type: "text", text: '{"id":"cust_123"}' }], _meta: { trace: "cust_123" } };
    const gv = privateView(p, { args: { mode: "digest", clear: ["amount"] } }, undefined, { factResults: { constructor: full } });
    const c = getAt(gv.predicate, ["facts", "constructor", "resultDigest"]);
    expect(isCommitment(c)).toBe(true);
    expect(JSON.stringify(gv.predicate)).not.toContain("trace");
    const back = restorePaths(gv.predicate, gv.predicate.capture, { facts: { constructor: { resultDigest: { $custody: "disclosed", salt: gv.salts[pathKey(["facts", "constructor", "resultDigest"])], value: full } } } });
    expect(back.restored.get(pathKey(["facts", "constructor", "resultDigest"]))).toBe("disclosed");
    expect(restorePaths(gv.predicate, gv.predicate.capture, { facts: { constructor: { resultDigest: { $custody: "disclosed", salt: gv.salts[pathKey(["facts", "constructor", "resultDigest"])], value: { ...full, _meta: { trace: "other" } } } } } }).problems).toHaveLength(1);
    // and even when every selected field is public: the rest of the result is not
    const publicFact = privateView({ ...p, facts: { customer: { tool: "customer.lookup", args: {}, value: { verified: true }, resultDigest: digestOf(full), provenance: "observed" as const } } }, { args: { mode: "digest", clear: ["amount"] }, facts: { mode: "digest", clear: ["verified"] } }, undefined, { factResults: { customer: full } }).predicate;
    expect(withheldPaths(publicFact)).toContain("facts.customer.resultDigest");
    expect(getAt(publicFact, ["facts", "customer", "resultDigest"])).not.toBe(digestOf(full));
    // the same when only the lookup's arguments are private and its value is in clear: the full result may repeat them
    for (const mode of ["digest", "encrypted"] as const) {
      const argsOnly = privateView(p, { args: { mode, clear: ["amount"] }, facts: { mode: "clear" } }, key).predicate;
      expect(withheldPaths(argsOnly)).toContain("facts.constructor.args.customer_id");
      expect(withheldPaths(argsOnly)).not.toContain("facts.constructor.value.$rest");
      expect(isCommitment(getAt(argsOnly, ["facts", "constructor", "resultDigest"]))).toBe(true);
    }
    // the receipt's view built on the authorization's carries the same commitments and salts for the shared parts
    const auth = privateView({ ...p, execution: undefined } as unknown as ReceiptPredicate, { args: { mode: "digest", clear: ["amount"] } });
    const after = privateView(p, { args: { mode: "digest", clear: ["amount"] } }, undefined, {}, auth);
    expect(after.predicate.request).toEqual(auth.predicate.request);
    expect(after.predicate.facts).toEqual(auth.predicate.facts);
    expect(after.predicate.request.argsDigest).toBe(auth.predicate.request.argsDigest);
    expect(withheldPaths(after.predicate)).toEqual([...withheldPaths(auth.predicate), "execution.result.$rest"]);
    for (const w of auth.predicate.capture!.withheld) expect(after.salts[pathKey(w)]).toBe(auth.salts[pathKey(w)]);
  });

  it("upstream-authored strings outside the three sides are withheld under any private rule: consumed fact ids, a provider's signature and bind, and the metadata, body, and envelope beside a result left in clear", () => {
    const p = predicate({
      request: { args: { amount: 2500, reason: "cust_123 asked" }, argsDigest: "x", provenance: "claimed" },
      consumed: { factIds: ["fact:cust_123"], provenance: "observed" },
      execution: { status: "executed", result: { content: [{ type: "text", text: "ok" }], _meta: { "x/trace": "cust_123" } }, resultDigest: "y", provenance: "claimed", upstream: { provider: "stripe-webhook", rawBody: '{"customer":"cust_123"}', signature: "t=1,v1=00", bind: "data.object.id" } },
    });
    // args private, result explicitly clear: the content stays, everything an upstream wrote beside it does not; the provider's signature is a MAC over the withheld body and its bind is a string the upstream chose
    const v = privateView(p, { args: { mode: "digest", clear: ["amount"] }, result: { mode: "clear" } }).predicate;
    expect(withheldPaths(v).sort()).toEqual(["request.args.$rest", "consumed.factIds", "execution.result._meta", "execution.upstream.rawBody", "execution.upstream.signature", "execution.upstream.bind"].sort());
    expect((v.execution as { result: { content: unknown } }).result.content).toEqual([{ type: "text", text: "ok" }]);
    expect((v.execution as { upstream: { provider: string } }).upstream.provider).toBe("stripe-webhook");
    expect(JSON.stringify(v)).not.toMatch(/cust_123|v1=00|data\.object|"reason"/);
    // an empty consumed list is structural
    const odd = privateView(predicate({ consumed: { factIds: [], provenance: "observed" }, execution: { status: "executed", result: { content: [] }, resultDigest: "y", provenance: "claimed", upstream: { provider: "github-delivery", rawBody: "{}", signature: "sha256=00", bind: "note cust_123" } } }), { args: { mode: "digest" } }).predicate;
    expect(withheldPaths(odd)).toContain("execution.upstream.bind");
    expect(withheldPaths(odd)).not.toContain("consumed.factIds");
    expect(JSON.stringify(odd)).not.toContain("cust_123");
  });

  it("a ciphertext moved to another receipt or path is a problem, not a disclosure; the host's ids are withheld; consumed is shared with the authorization once", () => {
    const a = privateView(predicate({ receiptId: "receipt-A", request: { args: { reason: "SENSITIVE phone +44 20 7946 0000", amount: 1 }, argsDigest: "x", provenance: "claimed" } }), { args: { mode: "encrypted", clear: ["amount"] } }, key).predicate;
    const moved = a.request.args[REST];
    // the same ciphertext under another receipt id, and under another path of the same receipt
    const b = { ...predicate({ receiptId: "receipt-B" }), execution: { status: "executed", result: { note: moved }, resultDigest: "y", provenance: "claimed" }, capture: { mode: "encrypted", withheld: [["execution", "result", "note"]] } } as ReceiptPredicate;
    const rb = restorePaths(b, b.capture, undefined, key);
    expect(rb.problems).toHaveLength(1);
    expect(rb.restored.size).toBe(0);
    const samePath = { ...a, execution: { status: "executed", result: { reason: moved }, resultDigest: "y", provenance: "claimed" }, capture: { mode: "encrypted", withheld: [["execution", "result", "reason"]] } } as ReceiptPredicate;
    expect(restorePaths(samePath, samePath.capture, undefined, key).problems).toHaveLength(1);
    expect(restorePaths(a, a.capture, undefined, key).predicate.request.args.reason).toBe("SENSITIVE phone +44 20 7946 0000");
    // the model and session ids are what the agent's call or process supplied: values under a private rule; none stays none
    const ids = privateView(predicate({ model: { id: "gpt-with-cust_123-in-it", provenance: "claimed" }, session: { id: "sess_cust_123", toolUseId: null, provenance: "claimed" } }), { args: { mode: "digest" } }).predicate;
    expect(withheldPaths(ids)).toEqual(expect.arrayContaining(["model.id", "session.id"]));
    expect(withheldPaths(ids)).not.toContain("session.toolUseId");
    expect(JSON.stringify(ids)).not.toContain("cust_123");
    expect(privateView(predicate(), { args: { mode: "digest" } }).predicate.model).toEqual({ id: null, provenance: "claimed" });
    // consumed is a shared part: the receipt built on the authorization carries its commitment once, with its salt
    const withIds = predicate({ consumed: { factIds: ["fact:1"], provenance: "observed" } });
    const auth = privateView({ ...withIds, execution: undefined } as unknown as ReceiptPredicate, { args: { mode: "digest" } });
    const after = privateView(withIds, { args: { mode: "digest" } }, undefined, {}, auth);
    expect(withheldPaths(after.predicate).filter((w) => w === "consumed.factIds")).toHaveLength(1);
    expect(after.predicate.consumed).toEqual(auth.predicate.consumed);
    expect(after.salts[pathKey(["consumed", "factIds"])]).toBe(auth.salts[pathKey(["consumed", "factIds"])]);
  });

  it("the rule for a call is one function: for a name no upstream offers, its rule and the wildcard together, the more private mode and only the fields both keep in clear", () => {
    const capture = { "legacy.export": { args: { mode: "digest" as const, clear: ["customer_id"] } }, "retired.clear": { args: { mode: "clear" as const } }, "*": { args: { mode: "digest" as const } } };
    expect(effectiveRule(capture, "legacy.export")).toBe(capture["legacy.export"]);
    // unknown: the wildcard keeps no field in clear, so neither does the call, whichever name the agent chose
    const sides = (r: unknown) => r as { args: { mode: string; clear?: string[] }; result: { mode: string; clear?: string[] }; facts: { mode: string; clear?: string[] } };
    expect(sides(effectiveRule(capture, "legacy.export", true)).args).toEqual({ mode: "digest", clear: [] });
    expect(sides(effectiveRule(capture, "retired.clear", true)).args).toEqual({ mode: "digest", clear: [] });
    // a more private mode on the retired name does not carry its wider clear list: the mode does not order which fields are public
    const enc = { "legacy.export": { args: { mode: "encrypted" as const, clear: ["customer_id"] } }, "*": { args: { mode: "digest" as const } } };
    expect(sides(effectiveRule(enc, "legacy.export", true)).args).toEqual({ mode: "encrypted", clear: [] });
    // the fields both keep stay, a side the wildcard leaves in clear takes the name's list, and an unset side follows each rule's mode
    const both = { "legacy.export": { args: { mode: "digest" as const, clear: ["customer_id", "amount"] } }, "*": { args: { mode: "encrypted" as const, clear: ["amount", "currency"] }, result: { mode: "clear" as const } } };
    const b = sides(effectiveRule(both, "legacy.export", true));
    expect(b.args).toEqual({ mode: "encrypted", clear: ["amount"] });
    expect(b.result).toEqual({ mode: "digest", clear: [] });
    expect(sides(effectiveRule({ ...capture, "*": { args: { mode: "clear" as const } } }, "legacy.export", true)).args).toEqual({ mode: "digest", clear: ["customer_id"] });
    expect(effectiveRule({ a: { args: { mode: "digest" as const } } }, "other", true)).toBeUndefined();
    expect(effectiveRule(capture, "constructor", true)).toBe(capture["*"]);
  });

  it("beside a result the rule leaves in clear, an upstream envelope that is the plain attestation stays so the signature can be checked; one carrying any other claim is withheld", () => {
    const upstream = generateKeyPair();
    const result = { content: [{ type: "text" as const, text: "ok" }], _meta: {} as Record<string, unknown> };
    const plain = signResult(result, upstream, "r-1", "stripe.refund")._meta[UPSTREAM_SIG_META_KEY];
    const chatty = dsseSign(UPSTREAM_TYPE, { receiptId: "r-1", tool: "stripe.refund", contentDigest: "00".repeat(32), customer_id: "cust_123" }, upstream);
    const base = (envelope: unknown): ReceiptPredicate => predicate({ execution: { status: "executed", result, resultDigest: "y", provenance: "claimed", upstream: { envelope } as never } });
    const kept = privateView(base(plain), { args: { mode: "digest" }, result: { mode: "clear" } }).predicate;
    expect(withheldPaths(kept)).not.toContain("execution.upstream.envelope");
    expect((kept.execution as { upstream: { envelope: unknown } }).upstream.envelope).toEqual(plain);
    const hidden = privateView(base(chatty), { args: { mode: "digest" }, result: { mode: "clear" } }).predicate;
    expect(withheldPaths(hidden)).toContain("execution.upstream.envelope");
    expect(JSON.stringify(hidden)).not.toContain(chatty.payload);
    // every other field of a plain attestation is upstream-authored too: an extra envelope field, an extra field in the
    // signature entry, a second entry, bytes riding along in the base64, a payload bound to another call, a key id that is
    // not one: each withholds the whole envelope, and the secret it carries is nowhere in the view
    const p = plain as { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[] };
    const other = (claims: Record<string, unknown>) => dsseSign(UPSTREAM_TYPE, { receiptId: "r-1", tool: "stripe.refund", contentDigest: contentDigest(result), ...claims }, upstream);
    const variants: [string, unknown][] = [
      ["envelope field", { ...p, customer_note: "SECRET_NOTE" }],
      ["signature field", { ...p, signatures: [{ ...p.signatures[0], customer_note: "SECRET_NOTE" }] }],
      ["second signature", { ...p, signatures: [...p.signatures, { keyid: "SECRET_NOTE", sig: p.signatures[0]!.sig }] }],
      ["key id", { ...p, signatures: [{ ...p.signatures[0], keyid: "SECRET_NOTE" }] }],
      ["payload type", { ...p, payloadType: "SECRET_NOTE" }],
      ["base64 tail", { ...p, payload: `${p.payload}SECRET_NOTE` }],
      ["signature length", { ...p, signatures: [{ ...p.signatures[0], sig: Buffer.from(`SECRET_NOTE${"x".repeat(54)}`).toString("base64") }] }],
      ["key standing for two", Object.assign(Object.create({ payloadType: p.payloadType, signatures: p.signatures }) as object, { payload: p.payload, "payloadType,signatures": "SECRET_NOTE" })],
      ["signature key standing for two", { ...p, signatures: [Object.assign(Object.create({ sig: p.signatures[0]!.sig }) as object, { keyid: p.signatures[0]!.keyid, "keyid,sig": "SECRET_NOTE" })] }],
      ["signature tail", { ...p, signatures: [{ ...p.signatures[0], sig: `${p.signatures[0]!.sig}SECRET_NOTE` }] }],
      ["payload not canonical", { ...p, payload: Buffer.from(JSON.stringify({ tool: "stripe.refund", receiptId: "r-1", contentDigest: contentDigest(result) }) + " ".repeat(3) + "\n").toString("base64") }],
      ["another receipt", other({ receiptId: "SECRET_NOTE" })],
      ["another tool", other({ tool: "SECRET_NOTE" })],
      ["another content", other({ contentDigest: sha256Hex("SECRET_NOTE") })],
    ];
    for (const [what, envelope] of variants) {
      const v = privateView(base(envelope), { args: { mode: "digest" }, result: { mode: "clear" } }).predicate;
      expect(withheldPaths(v), what).toContain("execution.upstream.envelope");
      expect(JSON.stringify(v), what).not.toContain("SECRET_NOTE");
      expect(JSON.stringify(v), what).not.toContain(sha256Hex("SECRET_NOTE"));
    }
    // the payload is compared as bytes: an invalid byte where the tool name has U+FFFD decodes to the same text, and is refused
    const odd = "stripe.refund\uFFFD";
    const oddEnv = signResult(result, upstream, "r-1", odd)._meta[UPSTREAM_SIG_META_KEY] as { payload: string };
    const oddBase = (envelope: unknown): ReceiptPredicate => ({ ...base(envelope), tool: { name: odd, provenance: "observed" } });
    const rule = { args: { mode: "digest" as const }, result: { mode: "clear" as const } };
    expect(withheldPaths(privateView(oddBase(oddEnv), rule).predicate)).not.toContain("execution.upstream.envelope");
    const raw = Buffer.from(oddEnv.payload, "base64");
    const at = raw.indexOf(Buffer.from("\uFFFD", "utf8"));
    const swapped = Buffer.concat([raw.subarray(0, at), Buffer.from([0xff]), raw.subarray(at + 3)]);
    expect(withheldPaths(privateView(oddBase({ ...oddEnv, payload: swapped.toString("base64") }), rule).predicate)).toContain("execution.upstream.envelope");
    // an unknown tool name is masked in the receipt, so an envelope naming it is never kept
    expect(withheldPaths(privateView(base(plain), { args: { mode: "digest" }, result: { mode: "clear" } }, undefined, { unknownTool: true }).predicate)).toContain("execution.upstream.envelope");
    // with the result private, the envelope goes with it either way: its content digest is an unsalted hash of the withheld content
    expect(withheldPaths(privateView(base(plain), { result: { mode: "digest" } }).predicate)).toContain("execution.upstream.envelope");
  });

  it("a reviewer who can guess a withheld value cannot confirm the guess from the receipt, in either mode (issue #126)", () => {
    const args = { amount: 2500, reason: "fraud" };
    const guesses = ["fraud", "duplicate", "goodwill", "requested by customer"];
    for (const mode of ["digest", "encrypted"] as const) {
      const { predicate: v, salts } = privateView(predicate({ request: { args, argsDigest: "x", provenance: "claimed" } }), { args: { mode, clear: ["amount"] } }, key);
      const c = v.request.args[REST] as { sha256: string };
      // nothing in the receipt is a salt, and no public computation over a guess reaches the commitment or the digest
      expect(JSON.stringify(v)).not.toMatch(/"salt"/);
      for (const guess of guesses) {
        expect(sha256Hex(JSON.stringify({ reason: guess }))).not.toBe(c.sha256);
        expect(digestOf({ reason: guess })).not.toBe(c.sha256);
        expect(digestOf({ amount: 2500, reason: guess })).not.toBe(v.request.argsDigest);
        expect(digestOf({ amount: 2500, reason: guess }, sha256Hex(""))).not.toBe(v.request.argsDigest);
      }
      // with the salt, and only with it, the true value checks and the others do not: the test can fail
      const salt = salts[pathKey(["request", "args", REST])]!;
      expect(guesses.filter((g) => checkCommitment(c as never, { reason: g }, salt))).toEqual(["fraud"]);
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
    // a salts directory that already exists with a wider mode is tightened by the issuer
    mkdirSync(join(fx.receiptsDir, SALTS_DIR), { recursive: true });
    chmodSync(join(fx.receiptsDir, SALTS_DIR), 0o755);
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
    expect(file).not.toMatch(/7946 0000|ending 4242|called from|"reason"/);
    // and without a rule the same call would show them, so the check can fail
    const clearCall = await gwClear.handleCall({ name: "stripe.refund", arguments: args });
    expect(leakText(clearBundleOf(clearCall))).toMatch(/7946 0000/);
    const p = decode(bundle).predicate;
    expect(p.request.args).toEqual({ customer_id: "cust_123", amount: 2500, [REST]: expect.objectContaining({ $custody: "encrypted" }) });
    expect(p.capture!.mode).toBe("encrypted");
    const paths = withheldPaths(p);
    expect(paths).toContain("request.args.$rest");
    // the digest is salted from the field salts the issuer kept beside the receipt, never in it, for the owner alone
    expect(file).not.toMatch(/"salt"/);
    const kept = saltsOf(fx.receiptsDir, p.receiptId);
    expect(statSync(join(fx.receiptsDir, SALTS_DIR, `${p.receiptId}.json`)).mode & 0o777).toBe(0o600);
    expect(statSync(join(fx.receiptsDir, SALTS_DIR)).mode & 0o777).toBe(0o700);
    // the file holds the salts of the digest-only commitments and none of the encrypted ones, whose salts the key alone recovers
    const kinds = Object.fromEntries(p.capture!.withheld.map((w) => [pathKey(w), (getAt(p, w) as { $custody: string }).$custody]));
    expect(Object.keys(kept).sort()).toEqual(Object.keys(kinds).filter((k) => kinds[k] === "withheld").sort());
    expect(kinds[pathKey(["request", "args", REST])]).toBe("encrypted");
    const salts = allSalts(fx.receiptsDir, p, key);
    expect(p.request.argsDigest).toBe(digestOf(args, saltFor(p.capture, salts, ["request", "args"])));
    expect(p.request.argsDigest).not.toBe(digestOf(args));
    expect(p.execution.status).toBe("executed");
    const ex = p.execution as { result: Record<string, unknown> };
    // the result shows its status flag and one commitment over everything else, the provider's delivery in the metadata included
    expect(Object.keys(ex.result).every((k) => k === REST || k === "isError")).toBe(true);
    expect(isCommitment(ex.result[REST])).toBe(true);
    expect(paths).toContain("execution.result.$rest");
    expect(paths).toEqual(expect.arrayContaining(["execution.upstream.rawBody", "execution.upstream.signature", "execution.upstream.bind"]));
    const up = (p.execution as { upstream: { rawBody: unknown; signature: unknown; bind: unknown; provider: string } }).upstream;
    expect(isCommitment(up.rawBody)).toBe(true);
    expect(isCommitment(up.signature)).toBe(true);
    expect(isCommitment(up.bind)).toBe(true);
    expect(up.provider).toBe("stripe-webhook");
    // the fact the policy decided on is one encrypted commitment: the policy saw it, the file shows neither its values nor its field names
    expect(Object.keys(p.facts.customer!.value as object)).toEqual([REST]);
    expect(file).not.toMatch(/"plan"|"email"|"verified"/);
    expect(p.policy!.decision).toBe("allow");
    // the lookup's arguments are copied from the call: the customer id is in clear there as in the request, and nothing else leaks through them
    expect(p.facts.customer!.args).toEqual({ customer_id: "cust_123" });
    expect(paths.filter((w) => w.startsWith("facts.customer.args"))).toEqual([]);
    // the lookup's full result is committed to, never digested in clear: the receipt shows the selected value only
    expect(isCommitment(p.facts.customer!.resultDigest)).toBe(true);
    expect(paths).toContain("facts.customer.resultDigest");
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
      expect(Object.keys(p.request.args)).toEqual([REST]);
      expect(isCommitment(p.facts.customer!.args.customer_id)).toBe(true);
      expect(withheldPaths(p)).toContain("facts.customer.args.customer_id");
      expect(leakText(bundleOf2(fx2, r))).not.toContain("cust_123");
      const o = { issuerKeys: [loadPublicKey(fx2.gatewayPub)], principalKeys: [loadPublicKey(fx2.principalPub)], logFile: fx2.logFile };
      const v = verifyBundle(bundleOf2(fx2, r), o);
      expect(v.ok, formatReport(v)).toBe(true);
      expect(check("fact customer args", v).detail).toMatch(/committed, not recomputed/);
      const disclosed = verifyBundle(bundleOf2(fx2, r), { ...o, disclosed: disclose(p, saltsOf(fx2.receiptsDir, p.receiptId), { facts: { customer: { args: { customer_id: "cust_123" } } } }) });
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
    const attestation = originalMeta["agent-custody/upstream-signature"] as { rawBody: string; signature: string; bind: string };
    const disclosed = disclose(p, salts, { request: { args }, execution: { result, upstream: { rawBody: attestation.rawBody, signature: attestation.signature, bind: attestation.bind } } });
    const withDisclosure = verifyBundle(bundle, { ...opts, disclosed });
    expect(withDisclosure.ok, formatReport(withDisclosure)).toBe(true);
    expect(check("request args digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("execution result digest", withDisclosure).detail).toBe("recomputed from disclosed values");
    expect(check("withheld execution.upstream.rawBody", withDisclosure).detail).toBe("holds against the disclosed value");
    expect(check("upstream signature (provider secret)", withDisclosure).ok).toBe(true);
    // key and disclosure together: each part comes back the way it can
    const both = verifyBundle(bundle, { ...opts, captureKey: key, disclosed: disclose(p, salts, { execution: { result } }) });
    expect(both.ok, formatReport(both)).toBe(true);
    expect(check("execution result digest", both).detail).toBe("recomputed from disclosed values");

    const lie = verifyBundle(bundle, { ...opts, disclosed: disclose(p, salts, { request: { args: { ...args, reason: "a different reason" } } }) });
    expect(lie.ok).toBe(false);
    expect(check("request args digest", lie).detail).toMatch(/disclosed request.args.\$rest does not match/);
    // a disclosure that lies about the fact the policy decided on fails too, key or no key
    const factLie = verifyBundle(bundle, { ...opts, captureKey: key, disclosed: disclose(p, salts, { facts: { customer: { value: { id: "cust_999", email: "x", verified: true, plan: "pro" } } } }) });
    expect(factLie.ok).toBe(false);
    expect(check("fact customer value", factLie).detail).toMatch(/does not match/);
    // a disclosure for another receipt is refused as such
    const other = verifyBundle(bundle, { ...opts, disclosed: { receiptId: "someone-else", ...disclose(p, salts, { request: { args } }) } });
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
      expect(Object.keys(p.request.args).sort()).toEqual(["customer_id", "amount", REST].sort());
      // the lookup's customer_id came from account_ref, which is withheld: so it is withheld too, under its own name (a config name)
      expect(isCommitment(p.facts.customer!.args.customer_id)).toBe(true);
      expect(p.facts.customer!.args.mode).toBe("full");
      expect(withheldPaths(p).filter((w) => w.startsWith("facts.customer.args"))).toEqual(["facts.customer.args.customer_id"]);
    } finally {
      await gw3.close();
    }
  });

  it("a fact argument literally named $rest is an argument, kept through capture and restoration, in either mode", async () => {
    for (const mode of ["digest", "encrypted"] as const) {
      const fxr = buildFixture(mkdtempSync(join(tmpdir(), `capture-restarg-${mode}-`)));
      const cfg = JSON.parse(readFileSync(fxr.configFile, "utf8"));
      cfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id", [REST]: "$args.reason" }, forTools: ["stripe.refund"] }];
      cfg.capture = { "*": { args: { mode, clear: ["customer_id", "amount"] } } };
      cfg.captureKeyEnv = "TEST_CAPTURE_KEY";
      writeFileSync(fxr.configFile, JSON.stringify(cfg));
      const gwr = await createGateway(loadConfig(fxr.configFile));
      try {
        const r = await gwr.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "dup" } });
        expect(r.isError).toBeFalsy();
        const bundle = bundleOf2(fxr, r);
        const p = decode(bundle).predicate;
        expect(isCommitment(p.facts.customer!.args[REST])).toBe(true);
        expect(withheldPaths(p)).toContain("facts.customer.args.$rest");
        const o = { issuerKeys: [loadPublicKey(fxr.gatewayPub)], principalKeys: [loadPublicKey(fxr.principalPub)], logFile: fxr.logFile };
        const salts = allSalts(fxr.receiptsDir, p, key);
        const disclosed = { facts: { customer: { args: { [REST]: { $custody: "disclosed", salt: salts[pathKey(["facts", "customer", "args", REST])], value: "dup" } } } } };
        const v = verifyBundle(bundle, { ...o, disclosed });
        expect(v.ok, formatReport(v)).toBe(true);
        expect(check("fact customer args", v).detail).toMatch(/hold against the disclosed value/);
        // the argument survives restoration as an argument, not as a slot to fold away
        const back = restorePaths(p, p.capture, disclosed, mode === "encrypted" ? key : undefined);
        expect(back.predicate.facts.customer!.args).toEqual({ customer_id: "cust_123", [REST]: "dup" });
      } finally {
        await gwr.close();
      }
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
      expect(Object.keys(p.request.args).sort()).toEqual(["amount", REST].sort());
      // the facts side was not set, so the customer record is withheld too
      expect(Object.keys(p.facts.customer!.value as object)).toEqual([REST]);
      expect(leakText(bundle)).not.toContain("declined");
      expect(leakText(bundle)).not.toContain("cust_123");
      const o = { issuerKeys: [loadPublicKey(fx6.gatewayPub)], principalKeys: [loadPublicKey(fx6.principalPub)], logFile: fx6.logFile };
      const v = verifyBundle(bundle, o);
      expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")).toBe(true);
      expect(check("withheld execution.error", v).detail).toMatch(/committed, not recomputed/);
      const message = text(r).replace(/^Upstream error: /, "").replace(/ \(receipt [^)]+\)$/, "");
      const salts = saltsOf(fx6.receiptsDir, p.receiptId);
      const disclosed = verifyBundle(bundle, { ...o, disclosed: disclose(p, salts, { execution: { error: message } }) });
      expect(check("withheld execution.error", disclosed).detail).toBe("holds against the disclosed value");
      expect(check("withheld execution.error", verifyBundle(bundle, { ...o, disclosed: disclose(p, salts, { execution: { error: "another message" } }) })).ok).toBe(false);
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
        expect(isCommitment(rest(p, ["request", "args"]))).toBe(true);
        expect(isCommitment(p.facts.customer!.args.customer_id)).toBe(true);
        expect(withheldPaths(p)).toContain("facts.customer.args.customer_id");
      } finally {
        await gw7.close();
      }
    }
  });

  it("a secret that the lookup's full result carries only in its metadata, beside a public selected fact, is not confirmable from the fact's digest, in either mode", async () => {
    for (const mode of ["digest", "encrypted"] as const) {
      const fxm = buildFixture(mkdtempSync(join(tmpdir(), `capture-factmeta-${mode}-`)));
      const cfg = JSON.parse(readFileSync(fxm.configFile, "utf8"));
      // the stand-in repeats the id it looked up in the record and in the result's metadata; the policy reads only `verified`
      cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
      cfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] }];
      cfg.capture = { "*": { args: { mode, clear: ["customer_id", "amount"] }, facts: { mode, clear: ["verified"] } } };
      cfg.captureKeyEnv = "TEST_CAPTURE_KEY";
      writeFileSync(fxm.configFile, JSON.stringify(cfg));
      const gwm = await createGateway(loadConfig(fxm.configFile));
      try {
        const secret = `SECRET_${mode}_${randomBytes(4).toString("hex")}`;
        const r = await gwm.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_1", account_ref: secret, amount: 2500 } });
        expect(r.isError).toBeFalsy();
        const bundle = bundleOf2(fxm, r);
        const p = decode(bundle).predicate;
        expect((p.facts.customer!.value as { verified: unknown }).verified).toBe(true);
        expect(isCommitment(p.facts.customer!.resultDigest)).toBe(true);
        expect(leakText(bundle)).not.toContain(secret);
        const o = { issuerKeys: [loadPublicKey(fxm.gatewayPub)], principalKeys: [loadPublicKey(fxm.principalPub)], logFile: fxm.logFile };
        const v = verifyBundle(bundle, o);
        expect(v.ok, formatReport(v)).toBe(true);
        expect(check("withheld facts.customer.resultDigest", v).detail).toMatch(/committed, not recomputed/);
        if (mode === "encrypted") {
          const withKey = verifyBundle(bundle, { ...o, captureKey: key });
          expect(withKey.ok, formatReport(withKey)).toBe(true);
          expect(check("withheld facts.customer.resultDigest", withKey).detail).toBe("holds against the decrypted value");
        }
      } finally {
        await gwm.close();
      }
    }
  });

  it("a call to a tool no upstream offers takes the rule its real name selects together with the wildcard, and the receipt shows the name as (unknown tool), in either mode", async () => {
    for (const mode of ["digest", "encrypted"] as const) {
      const fxu = buildFixture(mkdtempSync(join(tmpdir(), `capture-unknown-${mode}-`)));
      const cfg = JSON.parse(readFileSync(fxu.configFile, "utf8"));
      // an explicit rule for the name and no wildcard: the rule must be found by the real name, not the masked one
      cfg.capture = { "not.offered": { args: { mode } }, "legacy.export": { args: { mode: "clear" } }, "*": { args: { mode: "digest" } } };
      cfg.captureKeyEnv = "TEST_CAPTURE_KEY";
      writeFileSync(fxu.configFile, JSON.stringify(cfg));
      const gwu = await createGateway(loadConfig(fxu.configFile));
      try {
        const r = await gwu.handleCall({ name: "not.offered", arguments: { secret: `PRIVATE_UNKNOWN_${mode}` } });
        expect(r.isError).toBe(true);
        const bundle = bundleOf2(fxu, r);
        const p = decode(bundle).predicate;
        expect(p.execution.status).toBe("denied");
        expect(p.tool.name).toBe("(unknown tool)");
        expect(Object.keys(p.request.args)).toEqual([REST]);
        expect(leakText(bundle)).not.toMatch(/PRIVATE_UNKNOWN|not\.offered|"secret"/);
        const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fxu.gatewayPub)], principalKeys: [loadPublicKey(fxu.principalPub)], logFile: fxu.logFile });
        expect(v.ok, formatReport(v)).toBe(true);
        // a clear rule left for a name no upstream offers does not let the agent pick it: the wildcard, being more private, applies
        const legacy = await gwu.handleCall({ name: "legacy.export", arguments: { secret: `PRIVATE_LEGACY_${mode}` } });
        const lp = decode(bundleOf2(fxu, legacy)).predicate;
        expect(lp.tool.name).toBe("(unknown tool)");
        expect(leakText(bundleOf2(fxu, legacy))).not.toContain("PRIVATE_LEGACY");
        // and the fact arguments copied from the call follow the rule the issuer applies, not the name's wider clear list
        // whichever rule is the more private, the retired name's wider clear list does not survive: neither in the request nor in the fact arguments
        for (const rules of [
          { "legacy.export": { args: { mode: "digest", clear: ["customer_id"] } }, "*": { args: { mode: "encrypted" } } },
          { "legacy.export": { args: { mode: "encrypted", clear: ["customer_id"] } }, "*": { args: { mode: "digest" } } },
        ]) {
          const fxw = buildFixture(mkdtempSync(join(tmpdir(), `capture-unknown-wide-${mode}-`)));
          const wcfg = JSON.parse(readFileSync(fxw.configFile, "utf8"));
          wcfg.capture = rules;
          wcfg.captureKeyEnv = "TEST_CAPTURE_KEY";
          wcfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.refund", "legacy.export"] }];
          writeFileSync(fxw.configFile, JSON.stringify(wcfg));
          const gww = await createGateway(loadConfig(fxw.configFile));
          try {
            const wide = await gww.handleCall({ name: "legacy.export", arguments: { customer_id: "cust_123", amount: 1 } });
            const wb = bundleOf2(fxw, wide);
            const wp = decode(wb).predicate;
            expect(Object.keys(wp.request.args)).toEqual([REST]);
            expect(leakText(wb)).not.toContain("cust_123");
            const v = verifyBundle(wb, { issuerKeys: [loadPublicKey(fxw.gatewayPub)], principalKeys: [loadPublicKey(fxw.principalPub)], logFile: fxw.logFile });
            expect(v.ok, formatReport(v)).toBe(true);
          } finally {
            await gww.close();
          }
        }
        // an offered tool keeps its name under the same kind of rule
        const known = await gwu.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
        expect(decode(bundleOf2(fxu, known)).predicate.tool.name).toBe("stripe.refund");
      } finally {
        await gwu.close();
      }
    }
  });

  it("a pre-committed call's authorization and receipt carry the same commitments and salts, so the receipt still names the authorization; pruned, nothing is left", async () => {
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
      expect(ap.request.args).toEqual(p.request.args);
      expect(ap.facts.customer!.value).toEqual(p.facts.customer!.value);
      expect(ap.facts.customer!.resultDigest).toEqual(p.facts.customer!.resultDigest);
      expect(ap.capture!.withheld.map((w: Path) => w.join("."))).toEqual(withheldPaths(p).filter((w) => w.startsWith("request.") || w.startsWith("facts.") || w.startsWith("policy.") || w.startsWith("consumed.")));
      expect(withheldPaths(p)).toContain("execution.result.$rest");
      expect(leakText(bundle)).not.toContain("cust_123");
      // one salts file, covering the shared parts and the receipt's own
      const salts = saltsOf(fx8.receiptsDir, p.receiptId);
      expect(Object.keys(salts).sort()).toEqual(p.capture!.withheld.map(pathKey).sort());
      expect(p.request.argsDigest).toBe(digestOf({ customer_id: "cust_123", amount: 2500, reason: "dup" }, saltFor(p.capture, salts, ["request", "args"])));
      const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx8.gatewayPub)], principalKeys: [loadPublicKey(fx8.principalPub)], logFile: fx8.logFile });
      expect(v.ok, formatReport(v)).toBe(true);
      expect(check("authorization names this call", v).ok).toBe(true);
      // pruned, the call leaves nothing behind: not the bundle, not the salts, not the authorization that was committed before it
      const authorizationFile = join(fx8.receiptsDir, `${p.receiptId}.authorization.json`);
      expect(existsSync(authorizationFile)).toBe(true);
      pruneLog(fx8.logFile, new Date(Date.now() + 60_000).toISOString(), fx8.receiptsDir);
      expect(existsSync(join(fx8.receiptsDir, `${p.receiptId}.json`))).toBe(false);
      expect(existsSync(join(fx8.receiptsDir, SALTS_DIR, `${p.receiptId}.json`))).toBe(false);
      expect(existsSync(authorizationFile)).toBe(false);
    } finally {
      await gw8.close();
    }
  });

  it("reveal writes the salts of values it cannot reveal only when asked, a file carrying a salt without its value does not verify, and a bundle not the issuer's reveals nothing", async () => {
    const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2700, reason: "fraud" } });
    const bundle = bundleOf(r);
    const p = decode(bundle).predicate;
    const file = join(fx.receiptsDir, `${p.receiptId}.json`);
    const cli = join(import.meta.dirname, "..", "src", "cli.ts");
    const run = (...extra: string[]) => spawnSync(process.execPath, [cli, "reveal", file, "--capture-key-env", "TEST_CAPTURE_KEY", "--issuer-key", fx.gatewayPub, ...extra], { encoding: "utf8", env: { ...process.env, TEST_CAPTURE_KEY: KEY_HEX } });
    // by default: the encrypted values with their salts, nothing for the digest-only ones but their names
    const plain = run();
    expect(plain.status, plain.stderr).toBe(0);
    const disclosure = JSON.parse(plain.stdout) as Record<string, unknown>;
    expect(getAt(disclosure, ["request", "args", REST])).toMatchObject({ $custody: "disclosed", value: { reason: "fraud" } });
    expect(getAt(disclosure, ["execution", "result", REST])).toBeUndefined();
    expect(plain.stderr).toMatch(/Not revealed.*execution.result.\$rest.*--include-salts/s);
    const ok = verifyBundle(bundle, { ...opts, disclosed: disclosure });
    expect(ok.ok, formatReport(ok)).toBe(true);
    expect(check("request args digest", ok).detail).toBe("recomputed from disclosed values");
    // asked for: the salts go in, and the file fails until the holder fills in the values
    const withSalts = run("--include-salts");
    expect(withSalts.status, withSalts.stderr).toBe(0);
    const unfinished = JSON.parse(withSalts.stdout) as Record<string, unknown>;
    expect(getAt(unfinished, ["execution", "result", REST])).toEqual({ $custody: "disclosed", salt: expect.stringMatching(/^[0-9a-f]{32}$/) });
    expect(withSalts.stderr).toMatch(/do not hand it over unfinished/);
    const refused = verifyBundle(bundle, { ...opts, disclosed: unfinished });
    expect(refused.ok).toBe(false);
    expect(check("execution result digest", refused).detail).toMatch(/carries a salt but no value/);
    // the wrong key reveals nothing and says which key the values are under, with a failure, not a success that reads like one
    const wrong = spawnSync(process.execPath, [cli, "reveal", file, "--capture-key-env", "OTHER_KEY", "--issuer-key", fx.gatewayPub], { encoding: "utf8", env: { ...process.env, OTHER_KEY: randomBytes(32).toString("hex") } });
    expect(wrong.status).not.toBe(0);
    expect(wrong.stderr).toMatch(/encrypted under key [0-9a-f]{12}…, not the one given/);
    // --out writes decrypted values and salts: owner-only, whatever the umask, and whatever mode a file already there had
    const out = join(fx.dir, "disclosure-out.json");
    writeFileSync(out, "{}");
    chmodSync(out, 0o644);
    const before = process.umask(0o022);
    try {
      const written = run("--out", out);
      expect(written.status, written.stderr).toBe(0);
    } finally {
      process.umask(before);
    }
    expect(statSync(out).mode & 0o777).toBe(0o600);
    expect(getAt(JSON.parse(readFileSync(out, "utf8")), ["request", "args", REST])).toMatchObject({ value: { reason: "fraud" } });
    // a bundle assembled by someone else (another receipt's ciphertext at a path of their choosing, any signature) is refused before anything is decrypted
    const st = decode(bundle);
    const forged = { ...bundle, envelope: { ...bundle.envelope, payload: Buffer.from(JSON.stringify({ ...st, predicate: { ...st.predicate, receiptId: "../../etc/passwd" } })).toString("base64"), signatures: [{ keyid: "not-the-issuer", sig: "AAAA" }] } };
    const forgedFile = join(fx.dir, "forged.json");
    writeFileSync(forgedFile, JSON.stringify(forged));
    const bad = spawnSync(process.execPath, [cli, "reveal", forgedFile, "--capture-key-env", "TEST_CAPTURE_KEY", "--issuer-key", fx.gatewayPub, "--include-salts"], { encoding: "utf8", env: { ...process.env, TEST_CAPTURE_KEY: KEY_HEX } });
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toMatch(/not signed by the issuer key/);
    expect(bad.stdout).toBe("");
    // and without the issuer key the command does not run at all
    expect(spawnSync(process.execPath, [cli, "reveal", file, "--capture-key-env", "TEST_CAPTURE_KEY"], { encoding: "utf8", env: { ...process.env, TEST_CAPTURE_KEY: KEY_HEX } }).status).not.toBe(0);
    // --out never writes through a symlink left at that name
    const victim = join(fx.dir, "victim.txt");
    writeFileSync(victim, "untouched");
    const link = join(fx.dir, "disclosure-link.json");
    symlinkSync(victim, link);
    const viaLink = run("--out", link);
    expect(viaLink.status).not.toBe(0);
    expect(readFileSync(victim, "utf8")).toBe("untouched");
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
    // sentinels that cannot occur by chance in base64 or hex, in values and in field names
    const bundle = await sdk.record({ tool: "stripe.refund", args: { amount: 900, customer_id: "cust_SDK_nine" } }, { status: "executed", result: { refund_id: "re_9", card_last4: "ending 4242" } });
    expect(leakText(bundle)).not.toMatch(/cust_SDK_nine|ending 4242|customer_id|card_last4|refund_id/);
    const o = { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile };
    const bare = verifyBundle(bundle, o);
    expect(bare.ok, formatReport(bare)).toBe(true);
    expect(check("execution result digest", bare).detail).toMatch(/1 value\(s\) withheld \(1 encrypted\)/);
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
    expect(isCommitment(rest(p, ["request", "args"]))).toBe(true);
    expect(leakText(bundle)).not.toMatch(/cust_SDK_SECRET|customer_id/);
    expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile }).ok).toBe(true);
    // a tool without a rule records the message, as before
    const clear = await sdk.record({ tool: "stripe.payout", args: { customer_id: "cust_SDK_SECRET" } }, { status: "error", error: "payout declined for cust_SDK_SECRET" });
    expect((decode(clear).predicate.execution as { error: string }).error).toBe("payout declined for cust_SDK_SECRET");
  });
});

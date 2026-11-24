// The WordPress plugin's door is PHP (deploy/door/wordpress). Its receipts must be door receipts that `verifyBundle`
// accepts, its presets must decide as Cedar decides their policy text, and it must refuse a log answer that does not
// check. The PHP runs through deploy/door/wordpress/harness.php with canned HTTP answers, so nothing here uses the
// network or WordPress. A machine without `php` and its sodium extension skips the suite, visibly.
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize, digestOf, dsseSign, generateKeyPair, publicKeyFromPem, sha256Hex, type Envelope } from "../src/crypto.ts";
import { fileLog } from "../src/log-sink.ts";
import { evaluate } from "../src/policy.ts";
import { TREEHEAD_TYPE, type ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";

const harness = resolve(import.meta.dirname, "..", "..", "..", "deploy", "door", "wordpress", "harness.php");
// the door signs with sodium, which WordPress supplies where PHP has none
const hasPhp = spawnSync("php", ["-r", "exit(function_exists('sodium_crypto_sign_keypair') ? 0 : 1);"]).status === 0;

interface Call { fn: string; args: unknown[]; http?: { status: number; body: string } | { error: string } }
interface Answer { result?: unknown; error?: string; requests: { method: string; url: string; headers: Record<string, string>; body: string }[] }
function php(calls: Call[]): Answer[] {
  const run = spawnSync("php", [harness], { input: JSON.stringify(calls), encoding: "utf8" });
  if (run.status !== 0) throw new Error(`php exited with ${run.status}: ${run.stderr}${run.stdout}`);
  return JSON.parse(run.stdout) as Answer[];
}
const one = <T>(fn: string, args: unknown[], http?: Call["http"]): T => {
  const [a] = php([{ fn, args, ...(http ? { http } : {}) }]);
  if (a!.error !== undefined) throw new Error(a!.error);
  return a!.result as T;
};

const headers = { "user-agent": "Mozilla/5.0 (test) é", "content-type": "application/x-www-form-urlencoded", host: "shop.example", cookie: "not recorded" };
const passed = { provider: "turnstile", outcome: "passed" };
const arrivalOf = (challenge: unknown, extra: Record<string, string> = {}) => one<Record<string, unknown>>("arrival", [{ ...headers, ...extra }, "203.0.113.7", "POST", "/wp-comments-post.php", "comment", challenge]);

describe.skipIf(!hasPhp)("the WordPress door (PHP)", () => {
  const logKey = generateKeyPair();
  const log = fileLog(join(mkdtempSync(join(tmpdir(), "door-wordpress-")), "log.jsonl"), logKey);
  const logKeys = { [logKey.keyid]: logKey.publicKey.export({ type: "spki", format: "der" }).subarray(12).toString("base64") };
  const logCfg = { url: "https://log.example/", token: "t0ken", keys: logKeys };
  const key = one<string>("new_key", []);
  const doorKey = publicKeyFromPem(one<string>("public_pem", [key]));
  const appendVia = async (envelope: Envelope) => {
    const answer = await log.append(canonicalize(envelope));
    const [a] = php([{ fn: "append", args: [envelope, logCfg], http: { status: 200, body: JSON.stringify(answer) } }]);
    return { answer, php: a! };
  };

  it("writes canonical JSON and digests as crypto.ts does", () => {
    const values = [{ b: [], a: {}, c: "é/ \u0001\"\\", d: null, e: [1, { z: true, y: "x" }], "Ünï": 1 }, "plain", 42, [], {}];
    const answers = php(values.flatMap((v) => [{ fn: "canonicalize", args: [v] }, { fn: "digest_of", args: [v] }]));
    values.forEach((v, i) => {
      expect(answers[2 * i]!.result).toBe(canonicalize(v));
      expect(answers[2 * i + 1]!.result).toBe(digestOf(v));
    });
  });

  it("names its key as the verifier does", () => {
    expect(one<string>("keyid", [key])).toBe(doorKey.keyid);
  });

  it("decides each preset as Cedar decides the preset's policy text", () => {
    const presets = one<Record<string, { policy: string; enforced: boolean }>>("presets", []);
    expect(Object.keys(presets).sort()).toEqual(["humans", "strict", "watch"]);
    const arrivals = [null, { provider: "turnstile", outcome: "absent" }, { provider: "turnstile", outcome: "failed", error: "x" }, { provider: "hcaptcha", outcome: "unavailable" }, passed].map((c) => arrivalOf(c));
    const cases = Object.keys(presets).flatMap((preset) => arrivals.flatMap((arrival) => [true, false].map((loggedIn) => ({ preset, arrival, loggedIn }))));
    const answers = php(cases.map((c) => ({ fn: "evaluate", args: [c.preset, c.arrival, c.loggedIn] })));
    cases.forEach((c, i) => {
      const got = answers[i]!.result as { decision: string; reasons: string[]; errors: string[]; policyDigest: string; enforced?: boolean };
      const want = evaluate(presets[c.preset]!.policy, { agentId: "unknown", tool: "comment", context: { args: {}, facts: { arrival: c.arrival, wordpress: { loggedIn: c.loggedIn } } } });
      expect({ ...got, reasons: [...got.reasons].sort() }, `${c.preset} ${JSON.stringify(c.arrival.challenge)} loggedIn=${c.loggedIn}`).toEqual({ ...want, reasons: [...want.reasons].sort(), ...(presets[c.preset]!.enforced ? {} : { enforced: false }) });
    });
    expect(one<{ decision: string }>("evaluate", ["no-such-preset", arrivals[4], true]).decision).toBe("deny");
  });

  it("commits an allowed comment before WordPress handles it, and its receipt verifies", async () => {
    const d = one<{ head: Record<string, unknown>; forward: boolean; denied: unknown }>("decide", [key, "humans", arrivalOf(passed), headers, false]);
    expect(d.forward).toBe(true);
    expect(d.denied).toBeNull();
    const authorization = one<Envelope>("authorization", [d.head, key]);
    const committed = await appendVia(authorization);
    expect(committed.php.error).toBeUndefined();
    // the log gets the leaf hash and the token, never the receipt
    expect(committed.php.requests).toEqual([{ method: "POST", url: "https://log.example/append", headers: { "content-type": "application/json", authorization: "Bearer t0ken" }, body: JSON.stringify({ leafHash: one<string>("leaf_hash", [authorization]) }) }]);
    const execution = one<Record<string, unknown>>("answered", [302]);
    const envelope = one<Envelope>("receipt", [d.head, execution, { envelope: authorization, ...(committed.php.result as object) }, key]);
    const logged = await appendVia(envelope);
    const result = verifyBundle({ envelope, ...(logged.php.result as { treeHead: Envelope; inclusion: never }) }, { issuerKeys: [doorKey], principalKeys: [], logKeys: [logKey] });
    expect(result.checks.filter((c) => !c.ok)).toEqual([]);
    const p = (result.statement as ReceiptStatement).predicate;
    expect(p.issuer).toMatchObject({ kind: "door", framework: "wordpress", keyid: doorKey.keyid });
    expect(p.execution).toMatchObject({ status: "executed", result: { status: 302 }, provenance: "observed" });
    expect(p.authorization).toBeDefined();
    expect(p.policy).toMatchObject({ decision: "allow", reasons: ["policy1"] });
    expect(p.request.args).toEqual({ method: "POST", path: "/wp-comments-post.php", headers: { "user-agent": headers["user-agent"], "content-type": headers["content-type"], host: "shop.example" } });
    expect(p.facts.arrival!.value).toMatchObject({ class: "unknown", remote: "203.0.113.7", route: "comment", challenge: passed });
    expect(p.facts.wordpress!.value).toEqual({ loggedIn: false });
  });

  it("refuses an arrival without the challenge, and the receipt of the refusal verifies", async () => {
    const d = one<{ head: Record<string, unknown>; forward: boolean; denied: Record<string, unknown> }>("decide", [key, "humans", arrivalOf({ provider: "turnstile", outcome: "absent" }, { "x-agent-custody-agent": "some-bot", "x-agent-custody-grant": "abc", "signature-input": "sig1=()", "x-agent-custody-passport": "abc" }), { cookie: "not recorded" }, false]);
    expect(d.forward).toBe(false);
    const envelope = one<Envelope>("receipt", [d.head, d.denied, null, key]);
    const logged = await appendVia(envelope);
    const result = verifyBundle({ envelope, ...(logged.php.result as { treeHead: Envelope; inclusion: never }) }, { issuerKeys: [doorKey], principalKeys: [], logKeys: [logKey] });
    expect(result.checks.filter((c) => !c.ok)).toEqual([]);
    const p = (result.statement as ReceiptStatement).predicate;
    expect(p.execution).toEqual({ status: "denied", reason: "no permit policy matched", provenance: "observed" });
    // what the arrival presented is a claim: this door checks no grant, signature, or passport
    expect(p.facts.arrival!.value).toMatchObject({ class: "claimed", subject: "some-bot", declared: "some-bot", grant: "invalid", signature: "unchecked", passport: { outcome: "unchecked" } });
    expect(p.agent).toEqual({ id: "some-bot", provenance: "claimed" });
    expect(p.request.args).toEqual({ method: "POST", path: "/wp-comments-post.php", headers: {} });
  });

  it("watch records a deny and lets the request go on", () => {
    const d = one<{ head: { policy: Record<string, unknown> }; forward: boolean }>("decide", [key, "watch", arrivalOf(null), headers, false]);
    expect(d.forward).toBe(true);
    expect(d.head.policy).toMatchObject({ decision: "deny", enforced: false });
    expect(one<{ forward: boolean }>("decide", [key, "strict", arrivalOf(null), headers, true]).forward).toBe(false);
  });

  it("refuses a log answer that does not check", async () => {
    const envelope = one<Envelope>("authorization", [one<{ head: unknown }>("decide", [key, "humans", arrivalOf(passed), headers, false]).head, key]);
    const good = await log.append(canonicalize(envelope));
    const head = JSON.parse(Buffer.from(good.treeHead.payload, "base64").toString()) as Record<string, unknown>;
    const stranger = generateKeyPair();
    const tenant = { ...logCfg, url: "https://log.example/t/acme/" };
    const answers = php([
      { fn: "append", args: [envelope, logCfg], http: { status: 200, body: JSON.stringify(good) } },
      { fn: "append", args: [envelope, logCfg], http: { status: 200, body: JSON.stringify({ ...good, treeHead: dsseSign(TREEHEAD_TYPE, head, stranger) }) } },
      { fn: "append", args: [envelope, logCfg], http: { status: 200, body: JSON.stringify({ ...good, inclusion: { ...good.inclusion, hashes: [...good.inclusion.hashes.slice(0, -1), sha256Hex("x")] } }) } },
      { fn: "append", args: [envelope, logCfg], http: { status: 200, body: JSON.stringify({ ...good, treeHead: dsseSign(TREEHEAD_TYPE, { ...head, treeSize: (head.treeSize as number) + 1 }, logKey) }) } },
      { fn: "append", args: [envelope, logCfg], http: { status: 200, body: JSON.stringify({ ...good, treeHead: dsseSign("text/plain", head, logKey) }) } },
      { fn: "append", args: [envelope, logCfg], http: { status: 200, body: "{}" } },
      { fn: "append", args: [envelope, logCfg], http: { status: 429, body: "monthly quota reached" } },
      { fn: "append", args: [envelope, logCfg], http: { error: "timed out" } },
      // a hosted log names its tenant in each tree head
      { fn: "append", args: [envelope, tenant], http: { status: 200, body: JSON.stringify(good) } },
      { fn: "append", args: [envelope, tenant], http: { status: 200, body: JSON.stringify({ ...good, treeHead: dsseSign(TREEHEAD_TYPE, { ...head, log: "other" }, logKey) }) } },
      { fn: "append", args: [envelope, tenant], http: { status: 200, body: JSON.stringify({ ...good, treeHead: dsseSign(TREEHEAD_TYPE, { ...head, log: "acme" }, logKey) }) } },
    ]);
    expect(good.inclusion.hashes.length).toBeGreaterThan(0);
    expect(answers[0]!.error).toBeUndefined();
    expect(answers.slice(1, 10).map((a) => a.error)).toEqual([
      expect.stringContaining("does not verify against its pinned keys"),
      expect.stringContaining("does not place this leaf"),
      expect.stringContaining("different tree sizes"),
      expect.stringContaining("does not verify against its pinned keys"),
      expect.stringContaining("malformed"),
      expect.stringContaining("429 monthly quota reached"),
      "timed out",
      expect.stringContaining("another log"),
      expect.stringContaining("another log"),
    ]);
    expect(answers[10]!.error).toBeUndefined();
    expect(answers[10]!.requests[0]!.url).toBe("https://log.example/t/acme/append");
  });

  it("reads the log's key document, and refuses a key under another keyid", () => {
    const pem = logKey.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(one("parse_log_keys", [JSON.stringify({ keys: [{ keyid: logKey.keyid, publicKeyPem: pem }] })])).toEqual(logKeys);
    const bad = php([
      { fn: "parse_log_keys", args: [JSON.stringify({ keys: [{ keyid: generateKeyPair().keyid, publicKeyPem: pem }] })] },
      { fn: "parse_log_keys", args: [JSON.stringify({ keys: [] })] },
      { fn: "parse_log_keys", args: ["<html>"] },
    ]);
    expect(bad.map((b) => b.error)).toEqual([expect.stringContaining("not the keyid"), expect.stringContaining("no keys"), expect.stringContaining("no keys")]);
  });

  it("checks a challenge token with the provider", () => {
    const turnstile = { provider: "turnstile", siteKey: "site", secret: "s3cret", hostnames: ["shop.example"] };
    const ok = (body: unknown) => ({ status: 200, body: JSON.stringify(body) });
    const answers = php([
      { fn: "check_challenge", args: [turnstile, "t0k3n"], http: ok({ success: true, hostname: "Shop.Example" }) },
      { fn: "check_challenge", args: [turnstile, "  "], http: ok({ success: true, hostname: "shop.example" }) },
      { fn: "check_challenge", args: [turnstile, "x".repeat(4097)], http: ok({ success: true, hostname: "shop.example" }) },
      { fn: "check_challenge", args: [turnstile, "t0k3n"], http: ok({ success: true, hostname: "other.example" }) },
      { fn: "check_challenge", args: [turnstile, "t0k3n"], http: ok({ success: false, "error-codes": ["timeout-or-duplicate"] }) },
      { fn: "check_challenge", args: [turnstile, "t0k3n"], http: ok({ success: false, "error-codes": ["invalid-input-secret"] }) },
      { fn: "check_challenge", args: [turnstile, "t0k3n"], http: { status: 302, body: "" } },
      { fn: "check_challenge", args: [turnstile, "t0k3n"], http: { error: "timed out" } },
      { fn: "check_challenge", args: [{ ...turnstile, provider: "hcaptcha" }, "t0k3n"], http: ok({ success: true, hostname: "shop.example" }) },
    ]);
    expect(answers.map((a) => (a.result as { outcome: string }).outcome)).toEqual(["passed", "absent", "failed", "failed", "failed", "unavailable", "unavailable", "unavailable", "passed"]);
    expect(answers[0]!.requests).toEqual([{ method: "POST", url: "https://challenges.cloudflare.com/turnstile/v0/siteverify", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "secret=s3cret&response=t0k3n" }]);
    // no token, or one that no provider would issue, costs no call
    expect(answers[1]!.requests).toEqual([]);
    expect(answers[2]!.requests).toEqual([]);
    expect(answers[8]!.requests[0]).toMatchObject({ url: "https://api.hcaptcha.com/siteverify", body: "secret=s3cret&response=t0k3n&sitekey=site" });
    // neither the secret nor the token is in what the receipt records
    expect(JSON.stringify(answers.map((a) => a.result))).not.toMatch(/s3cret|t0k3n/);
  });

  it("matches the protected forms and the extra paths", () => {
    const all = ["comment", "login", "register", "lostpassword"];
    const route = (pagenow: string, action: string, path: string, protect = all, paths: string[] = []) => ({ fn: "route", args: [pagenow, action, path, protect, paths] });
    const answers = php([
      route("wp-comments-post.php", "", "/wp-comments-post.php"),
      route("wp-login.php", "", "/wp-login.php"),
      route("wp-login.php", "register", "/wp-login.php"),
      route("wp-login.php", "lostpassword", "/wp-login.php"),
      route("wp-login.php", "retrievepassword", "/wp-login.php"),
      route("wp-login.php", "logout", "/wp-login.php"),
      route("wp-login.php", "form", "/wp-login.php"),
      route("wp-comments-post.php", "", "/wp-comments-post.php", ["login"]),
      route("index.php", "", "/contact/"),
      route("index.php", "", "/contact/", all, ["/contact/"]),
      route("index.php", "", "/wp-json/contact-form-7/v1/x", all, ["/wp-json/contact-form-7/*"]),
      route("index.php", "", "//wp-json/%63ontact-form-7/v1/x", all, ["/wp-json/contact-form-7/*"]),
      route("index.php", "", "/wp-json/other", all, ["/wp-json/contact-form-7/*"]),
    ]);
    expect(answers.map((a) => a.result)).toEqual(["comment", "login", "register", "lostpassword", "lostpassword", null, null, null, null, "form", "form", "form", null]);
  });
});

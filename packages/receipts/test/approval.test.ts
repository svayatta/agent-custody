import { spawn, spawnSync } from "node:child_process";
import { fsyncSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { APPROVAL_TYPE, ApprovalSchema, consumeApproval, createApproval, verifyApproval, verifyApprovalStatement, type Approval, type ApprovalBinding } from "../src/approval.ts";
import { digestOf, dsseCountersign, dsseSign, generateKeyPair, type Envelope } from "../src/crypto.ts";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return { ...actual, fsyncSync: vi.fn(actual.fsyncSync) };
});

const first = generateKeyPair();
const second = generateKeyPair();
const untrusted = generateKeyPair();
const approvalId = "4438a9b3-aae6-4977-ab0f-3ec1bc4338ae";
const issuedAt = "2026-10-18T10:00:00.000Z";
const at = "2026-10-18T10:01:00.000Z";
const expiresAt = "2026-10-18T10:05:00.000Z";
const binding: ApprovalBinding = {
  principal: "owner", agent: "payments-agent", tool: "transfer",
  args: { amount: 1250, currency: "USD", beneficiary: "vendor-123", memo: "invoice 123" },
};
const signed = (input: ApprovalBinding = binding) => createApproval(first, { ...input, approvalId, issuedAt, expiresAt });
const payloadOf = (env: Envelope): Approval => JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")) as Approval;
const verify = (env: unknown, input: ApprovalBinding = binding) => verifyApproval(env, [first, second], input, { at });

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const directory = () => { const dir = mkdtempSync(join(tmpdir(), "custody-approval-")); dirs.push(dir); return dir; };

describe("payload-bound approvals", () => {
  it("signs both the complete arguments digest and the human-readable action", () => {
    const env = signed();
    expect(env.payloadType).toBe(APPROVAL_TYPE);
    const result = verify(env);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.approval).toEqual({
      version: "0.1", approvalId, principal: "owner", agent: "payments-agent", tool: "transfer",
      argsDigest: digestOf(binding.args), amount: 1250, currency: "USD", beneficiary: "vendor-123", issuedAt, expiresAt,
    });
    expect(result.approverKeyids).toEqual([first.keyid]);
  });

  it("generates a UUID and issuance time when omitted", () => {
    const env = createApproval(first, { ...binding, expiresAt: "2099-01-01T00:00:00Z" });
    expect(ApprovalSchema.safeParse(payloadOf(env)).success).toBe(true);
    expect(verifyApproval(env, [first], binding).ok).toBe(true);
  });

  it.each(["principal", "agent", "tool"] as const)("cannot be reused for a different %s", (field) => {
    const result = verify(signed(), { ...binding, [field]: "another" });
    expect(result).toEqual({ ok: false, error: `approval ${field} does not match this call` });
  });

  it("binds all arguments, including fields outside the explicit action summary", () => {
    expect(verify(signed(), { ...binding, args: { ...binding.args, memo: "another invoice" } })).toEqual({
      ok: false, error: "approval argsDigest does not match this call",
    });
    const args = JSON.parse('{"amount":1250,"currency":"USD","beneficiary":"vendor-123","memo":"invoice 123","__proto__":{"amount":1}}') as Record<string, unknown>;
    expect(verify(signed(), { ...binding, args }).ok).toBe(false);
    expect(verify(signed({ ...binding, args }), { ...binding, args }).ok).toBe(true);
  });

  it.each(["amount", "currency", "beneficiary"] as const)("rejects a signed %s that contradicts the complete args digest", (field) => {
    const payload = { ...payloadOf(signed()), [field]: field === "amount" ? 1 : "another" };
    const result = verify(dsseSign(APPROVAL_TYPE, payload, first));
    expect(result).toEqual({ ok: false, error: `approval ${field} does not match this call` });
  });

  it("requires explicit fields in both directions, even when the signed digest matches", () => {
    const payload = payloadOf(signed());
    delete payload.amount;
    expect(verify(dsseSign(APPROVAL_TYPE, payload, first))).toEqual({ ok: false, error: "approval amount does not match this call" });
    const input = { ...binding, args: { memo: "nothing monetary" } };
    expect(verify(dsseSign(APPROVAL_TYPE, { ...payloadOf(signed(input)), amount: 1 }, first), input).ok).toBe(false);
  });

  it("supports configured argument names and ignores inherited argument names", () => {
    const input = {
      ...binding, args: { cents: 0, unit: "EUR", recipient: "acct-7" },
      fields: { amount: "cents", currency: "unit", beneficiary: "recipient" },
    };
    expect(verify(signed(input), input).ok).toBe(true);
    expect(payloadOf(signed(input))).toMatchObject({ amount: 0, currency: "EUR", beneficiary: "acct-7" });
    const noFields = { ...binding, args: {}, fields: { beneficiary: "constructor" } };
    expect(payloadOf(signed(noFields))).not.toHaveProperty("beneficiary");
    expect(verify(signed(noFields), noFields).ok).toBe(true);
  });

  it.each([0.1, Number.MAX_SAFE_INTEGER + 1, "1250", null, undefined, NaN, Infinity])("refuses a non-integer-minor-unit amount %s", (amount) => {
    expect(() => signed({ ...binding, args: { ...binding.args, amount } })).toThrow(/amount|JSON data/);
  });

  it.each(["", 7, null])("refuses a non-string or empty currency and beneficiary %s", (value) => {
    for (const field of ["currency", "beneficiary"]) expect(() => signed({ ...binding, args: { ...binding.args, [field]: value } })).toThrow(field);
  });

  it("rejects non-JSON values whose canonical digest would lose information", () => {
    for (const value of [undefined, () => 1, BigInt(1), new Date(), NaN, Infinity]) {
      expect(() => signed({ ...binding, args: { value } })).toThrow(/JSON data/);
    }
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => signed({ ...binding, args: circular })).toThrow(/JSON data/);
  });
});

describe("trusted approvers and strict envelope validation", () => {
  it("requires two different trusted keys for four eyes approval", () => {
    const one = signed();
    expect(verifyApproval(one, [first, second], binding, { at, minApprovers: 2 }).ok).toBe(false);
    const two = dsseCountersign(one, second);
    const result = verifyApproval(two, [first, second], binding, { at, minApprovers: 2 });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.approverKeyids).toEqual([first.keyid, second.keyid]);
    expect(verifyApproval(dsseCountersign(one, untrusted), [first, second], binding, { at, minApprovers: 2 }).ok).toBe(false);
  });

  it("never counts duplicate signatures or configured keys as separate approvers", () => {
    const env = signed();
    env.signatures.push({ ...env.signatures[0]! });
    expect(verifyApproval(env, [first, first], binding, { at, minApprovers: 2 }).ok).toBe(false);
    const result = verify(env);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.approverKeyids).toEqual([first.keyid]);
  });

  it("rejects untrusted keys and tampered signatures or payloads", () => {
    const env = signed();
    expect(verifyApproval(env, [untrusted], binding, { at }).ok).toBe(false);
    expect(verify({ ...env, payload: Buffer.from(JSON.stringify({ ...payloadOf(env), amount: 1 })).toString("base64") }).ok).toBe(false);
    expect(verify({ ...env, signatures: [{ ...env.signatures[0], sig: Buffer.alloc(64).toString("base64") }] }).ok).toBe(false);
    // A bad signature under a trusted key does not hide another valid trusted signature.
    const two = dsseCountersign(env, second);
    two.signatures[0]!.sig = Buffer.alloc(64).toString("base64");
    expect(verify(two).ok).toBe(true);
    expect(verifyApproval(two, [first, second], binding, { at, minApprovers: 2 }).ok).toBe(false);
  });

  it("returns a failure, without throwing, for malicious envelope structures", () => {
    const env = signed();
    const throwing = { get payloadType() { throw new Error("untrusted getter"); } };
    for (const malformed of [
      null, false, [], {}, throwing,
      { ...env, payloadType: null }, { ...env, payloadType: "another/type" },
      { ...env, payload: "%%%=" }, { ...env, payload: "" }, { ...env, payload: env.payload + "\n" },
      { ...env, signatures: null }, { ...env, signatures: [null] }, { ...env, signatures: ["signature"] },
      { ...env, signatures: [{ keyid: first.keyid, sig: {} }] },
      { ...env, signatures: [{ ...env.signatures[0], arbitrary: true }] }, { ...env, arbitrary: true },
    ]) expect(verify(malformed).ok).toBe(false);
  });

  it("rejects malformed signed JSON and unknown signed schema fields", () => {
    const payload = payloadOf(signed());
    for (const malformed of [null, [], { ...payload, approvalId: "../escape" }, { ...payload, unexpected: true }, { ...payload, amount: 0.5 }]) {
      expect(verify(dsseSign(APPROVAL_TYPE, malformed, first)).ok).toBe(false);
    }
    const nonJson = dsseSign(APPROVAL_TYPE, "not a JSON object", first);
    expect(verify(nonJson).ok).toBe(false);
  });

  it("allows standalone signature/schema verification while leaving action/time checks explicit", () => {
    expect(verifyApprovalStatement(signed(), [first]).ok).toBe(true);
    expect(verifyApprovalStatement(signed(), [first, second], 2).ok).toBe(false);
  });
});

describe("approval validity", () => {
  it("accepts issuance itself, and refuses before issuance and at expiry", () => {
    const env = signed();
    expect(verifyApproval(env, [first], binding, { at: issuedAt }).ok).toBe(true);
    expect(verifyApproval(env, [first], binding, { at: "2026-10-18T09:59:59.999Z" })).toEqual({ ok: false, error: "approval is not yet valid" });
    expect(verifyApproval(env, [first], binding, { at: expiresAt })).toEqual({ ok: false, error: "approval has expired" });
    expect(verifyApproval(env, [first], binding, { at: "not a date" }).ok).toBe(false);
  });

  it("rejects an empty or reversed signed validity window", () => {
    for (const expiry of [issuedAt, "2026-10-18T09:59:00Z"]) {
      expect(() => createApproval(first, { ...binding, issuedAt, expiresAt: expiry })).toThrow(/expiry/);
      expect(verify(dsseSign(APPROVAL_TYPE, { ...payloadOf(signed()), expiresAt: expiry }, first)).ok).toBe(false);
    }
  });
});

describe("persistent atomic consumption", () => {
  const modulePath = resolve(import.meta.dirname, "../src/approval.ts");
  const childScript = (dir: string) => `import { consumeApproval } from ${JSON.stringify(modulePath)}; try { consumeApproval(${JSON.stringify(dir)}, ${JSON.stringify(approvalId)}, "child-receipt", ${JSON.stringify(at)}); } catch (error) { if (!String(error).includes("already been used")) throw error; process.exitCode = 9; }`;

  it("persists a private marker and refuses replay after a fresh process starts", () => {
    const root = directory();
    const dir = join(root, "used");
    consumeApproval(dir, approvalId, "receipt-one", at);
    const files = readdirSync(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^[0-9a-f]{64}\.json$/);
    expect(JSON.parse(readFileSync(join(dir, files[0]!), "utf8"))).toEqual({ approvalId, receiptId: "receipt-one", consumedAt: at });
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, files[0]!)).mode & 0o777).toBe(0o600);
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", childScript(dir)], { encoding: "utf8", timeout: 30_000 });
    expect(child.status, child.stderr).toBe(9);
    expect(() => consumeApproval(dir, approvalId, "receipt-two", at)).toThrow(/already been used/);
  });

  it("allows exactly one process to consume an approval in a race", async () => {
    const dir = join(directory(), "used");
    const run = () => new Promise<number | null>((resolveStatus, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", childScript(dir)], { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
      child.on("error", reject);
      child.on("exit", (status) => {
        if (status !== 0 && status !== 9) reject(new Error(stderr));
        else resolveStatus(status);
      });
    });
    expect((await Promise.all([run(), run()])).sort()).toEqual([0, 9]);
    expect(readdirSync(dir)).toHaveLength(1);
  });

  it("treats uppercase and lowercase spellings as the same single-use UUID", () => {
    const dir = directory();
    consumeApproval(dir, approvalId.toUpperCase(), "receipt-one", at);
    expect(() => consumeApproval(dir, approvalId.toLowerCase(), "receipt-two", at)).toThrow(/already been used/);
    expect(readdirSync(dir)).toHaveLength(1);
  });

  it.each(["file", "directory"])("fails closed and retains its claim if the %s sync fails", (stage) => {
    const dir = join(directory(), "new", "parents", "used");
    const sync = vi.mocked(fsyncSync);
    const realSync = sync.getMockImplementation()!;
    if (stage === "directory") sync.mockImplementationOnce(realSync);
    sync.mockImplementationOnce(() => { throw new Error("simulated storage sync failure"); });
    expect(() => consumeApproval(dir, approvalId, "receipt-one", at)).toThrow(/storage sync failure/);
    expect(readdirSync(dir)).toHaveLength(1);
    expect(() => consumeApproval(dir, approvalId, "receipt-two", at)).toThrow(/already been used/);
  });

  it("refuses invalid ids and timestamps before creating a marker", () => {
    const dir = join(directory(), "used");
    expect(() => consumeApproval(dir, "../../other", "receipt", at)).toThrow();
    expect(() => consumeApproval(dir, approvalId, "receipt", "not-a-date")).toThrow();
  });
});

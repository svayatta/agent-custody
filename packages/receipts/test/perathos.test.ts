// A Perathos session log is another project's record of an agent's tool calls. The reader must accept a log that
// follows their spec and refuse each kind of tampering the spec says a valid log rules out: an edited, removed,
// inserted or reordered receipt, a forged or missing seal, an untrusted signer, and a cut the head witness reveals.
// The logs here are written from the spec by a small writer in this file, not by Perathos itself.
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { canonicalize, sha256Hex } from "../src/crypto.ts";
import { formatPerathosReport, perathosReceiptHash, verifyPerathosLog } from "../src/perathos.ts";

type Receipt = Record<string, unknown>;
const signerOf = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, hex: (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32).toString("hex") };
};
const owner = signerOf();

/** a log as the spec writes it: seq from 1, prev_hash chained, receipt_hash over every field but itself and signature */
function write(steps: Receipt[], key: { privateKey: KeyObject; hex: string } | null = owner, session = "s-1"): Receipt[] {
  const out: Receipt[] = [];
  steps.forEach((step, i) => {
    const r: Receipt = { v: "perathos.receipt/v1", session_id: session, agent: "claude-code", seq: i + 1, ts: `2026-11-04T08:19:0${i}.000000Z`, prev_hash: i ? out[i - 1]!.receipt_hash : "0".repeat(64), ...step };
    if (r.kind === "checkpoint" && key && !("signer_error" in r)) r.signer = key.hex;
    r.receipt_hash = perathosReceiptHash(r);
    if (r.kind === "checkpoint" && key && !("signer_error" in r)) r.signature = { algorithm: "ed25519", verify_key: key.hex, signature: sign(null, Buffer.from(r.receipt_hash as string, "hex"), key.privateKey).toString("hex") };
    out.push(r);
  });
  return out;
}
const jsonl = (rs: Receipt[]) => rs.map((r) => JSON.stringify(r)).join("\n") + "\n";
const h = (v: unknown) => sha256Hex(typeof v === "string" ? v : canonicalize(v));
const pre = (tool: string, args: unknown, extra: Receipt = {}): Receipt => ({ kind: "pre", tool, tool_use_id: `t-${tool}`, args_hash: h(args), ...extra });
const post = (tool: string, result: unknown): Receipt => ({ kind: "post", tool, tool_use_id: `t-${tool}`, args_hash: h({}), result_hash: h(result), status: "ok" });
const checkpoint = (extra: Receipt = {}): Receipt => ({ kind: "checkpoint", event: "Stop", model: null, ...extra });
const session = () => write([pre("Bash", { command: "ls" }), post("Bash", "a\nb"), pre("Bash", { command: "railway volume delete pg-data" }, { guard: { decision: "deny", rule: "paas.railway", precondition: null } }), checkpoint(), pre("Read", { path: "x" }), post("Read", "x"), checkpoint()]);
const failed = (r: ReturnType<typeof verifyPerathosLog>) => r.checks.filter((c) => !c.ok).map((c) => c.name);

describe("verifyPerathosLog", () => {
  it("accepts a log written to the spec, and reports what it holds and what kind of evidence it is", () => {
    const r = verifyPerathosLog(jsonl(session()), { trustedKeys: [owner.hex] });
    expect(failed(r)).toEqual([]);
    expect(r).toMatchObject({ ok: true, session: "s-1", agent: "claude-code", receipts: 7, toolCalls: 3, checkpoints: 2, signers: [owner.hex], sealedThrough: 7, unsealedTail: 0, denied: 1 });
    // a Perathos log is recorded inside the agent's host, with the key held there: the report must not read as gateway attestation
    expect(r.provenance).toContain("inside the agent's host");
    expect(r.provenance).toContain("not that an enforcement point outside the agent saw each call");
    const text = formatPerathosReport(r);
    expect(text).toContain("RESULT: VALID");
    expect(text).toContain("denied          1 call(s) stopped by the guard");
  });

  it("refuses an edited receipt, even one whose hash was recomputed, because the next prev_hash no longer matches", () => {
    const edited = session();
    edited[0]!.tool = "Read";
    expect(failed(verifyPerathosLog(jsonl(edited)))).toEqual(["receipt_hash recomputes"]);
    edited[0]!.receipt_hash = perathosReceiptHash(edited[0]!);
    expect(failed(verifyPerathosLog(jsonl(edited)))).toEqual(["prev_hash chains each receipt to the one before"]);
  });

  it("refuses a removed, an inserted, or a reordered receipt", () => {
    const removed = session();
    removed.splice(2, 1);
    expect(failed(verifyPerathosLog(jsonl(removed)))).toEqual(expect.arrayContaining(["seq is 1, 2, 3, ... in file order", "prev_hash chains each receipt to the one before"]));
    const inserted = session();
    inserted.splice(1, 0, { ...inserted[0]! });
    expect(failed(verifyPerathosLog(jsonl(inserted)))).toEqual(expect.arrayContaining(["seq is 1, 2, 3, ... in file order"]));
    const swapped = session();
    [swapped[0], swapped[1]] = [swapped[1]!, swapped[0]!];
    expect(failed(verifyPerathosLog(jsonl(swapped)))).toEqual(expect.arrayContaining(["seq is 1, 2, 3, ... in file order", "prev_hash chains each receipt to the one before"]));
  });

  it("refuses a seal signed by another key under the owner's name, and a signer outside the trusted keys", () => {
    const forged = session();
    const stranger = signerOf();
    const last = forged.at(-1)!;
    (last.signature as Receipt).signature = sign(null, Buffer.from(last.receipt_hash as string, "hex"), stranger.privateKey).toString("hex");
    expect(failed(verifyPerathosLog(jsonl(forged)))).toEqual(["checkpoint signatures verify"]);
    const theirs = write([pre("Bash", {}), checkpoint()], stranger);
    expect(failed(verifyPerathosLog(jsonl(theirs), { trustedKeys: [owner.hex] }))).toEqual(["every signer is a trusted key"]);
    expect(verifyPerathosLog(jsonl(theirs)).ok).toBe(true); // no key pinned: valid, and the report names the signer
  });

  it("refuses a log no checkpoint seals, and an unsigned checkpoint, naming a signer failure; allows both as warnings on request", () => {
    expect(failed(verifyPerathosLog(jsonl(write([pre("Bash", {}), post("Bash", "")]))))).toEqual(["every checkpoint is signed"]);
    const failedSigner = write([pre("Bash", {}), checkpoint({ signer_error: "SignerError" }), pre("Bash", {}), checkpoint()]);
    const r = verifyPerathosLog(jsonl(failedSigner));
    expect(failed(r)).toEqual(["every checkpoint is signed"]);
    expect(r.checks.find((c) => !c.ok)?.detail).toContain("the recorder's signer failed when it was sealed (SignerError)");
    expect(r.signerFailures).toBe(1);
    const allowed = verifyPerathosLog(jsonl(failedSigner), { allowUnsigned: true });
    expect(allowed.ok).toBe(true);
    expect(allowed.warnings[0]).toContain("SignerError");
  });

  it("reports receipts after the last checkpoint as an unsealed tail, not an error, and catches a cut with the head witness", () => {
    const tail = write([pre("Bash", {}), checkpoint(), pre("Bash", { n: 1 }), post("Bash", "1")]);
    expect(verifyPerathosLog(jsonl(tail))).toMatchObject({ ok: true, sealedThrough: 2, unsealedTail: 2 });
    const full = session();
    const head = { seq: 7, receipt_hash: full[6]!.receipt_hash as string };
    expect(verifyPerathosLog(jsonl(full), { head }).ok).toBe(true);
    // cut back to the first checkpoint: still a valid chain on its own, which is why the head witness matters
    const cut = full.slice(0, 4);
    expect(verifyPerathosLog(jsonl(cut)).ok).toBe(true);
    expect(failed(verifyPerathosLog(jsonl(cut), { head }))).toEqual(["the head witness's checkpoint is in the log"]);
  });

  it("hashes every field it finds, known or not, and refuses a mixed session, time going back, a wrong format, and a line that is not JSON", () => {
    expect(verifyPerathosLog(jsonl(write([pre("Bash", {}, { result_from: "payload" }), checkpoint()]))).ok).toBe(true);
    const added = session();
    added[1]!.result_from = "payload";
    expect(failed(verifyPerathosLog(jsonl(added)))).toEqual(["receipt_hash recomputes"]);
    const mixed = [...write([pre("Bash", {})]), ...write([pre("Bash", {}), checkpoint()], owner, "s-2")];
    mixed[1]!.seq = 2;
    expect(failed(verifyPerathosLog(jsonl(mixed)))).toEqual(expect.arrayContaining(["one session, and time never goes back"]));
    const back = write([pre("Bash", {}), checkpoint()]);
    back[1]!.ts = "2026-11-04T08:00:00.000000Z";
    back[1]!.receipt_hash = perathosReceiptHash(back[1]!);
    expect(failed(verifyPerathosLog(jsonl(back)))).toEqual(expect.arrayContaining(["one session, and time never goes back"]));
    const v2 = write([{ ...pre("Bash", {}), v: "perathos.receipt/v2" }, checkpoint()]);
    expect(failed(verifyPerathosLog(jsonl(v2)))).toEqual(["format is perathos.receipt/v1 with a known kind"]);
    expect(failed(verifyPerathosLog(jsonl(session()) + "not json\n"))).toEqual(["every line is a JSON object"]);
    expect(failed(verifyPerathosLog(""))).toEqual(["every line is a JSON object", "every checkpoint is signed"]);
  });

  it("refuses a signer that is not an Ed25519 key instead of throwing", () => {
    const bad = session();
    const last = bad.at(-1)!;
    last.signer = "ff".repeat(32);
    (last.signature as Receipt).verify_key = "ff".repeat(32);
    last.receipt_hash = perathosReceiptHash(last);
    expect(failed(verifyPerathosLog(jsonl(bad)))).toEqual(["checkpoint signatures verify"]);
  });
});

describe("agent-custody verify-perathos", () => {
  const cli = resolve(import.meta.dirname, "..", "src", "cli.ts");
  const run = (args: string[]) => spawnSync(process.execPath, [cli, "verify-perathos", ...args], { encoding: "utf8" });
  it("exits 0 on a valid log and 1 on a tampered one, with --key, --head and --json", () => {
    const dir = mkdtempSync(join(tmpdir(), "perathos-"));
    const log = session();
    writeFileSync(join(dir, "s-1.jsonl"), jsonl(log));
    writeFileSync(join(dir, "s-1.head.json"), JSON.stringify({ seq: 7, receipt_hash: log[6]!.receipt_hash }));
    const ok = run([join(dir, "s-1.jsonl"), "--key", owner.hex, "--head", join(dir, "s-1.head.json")]);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain("RESULT: VALID");
    expect(ok.stdout).toContain("PROVENANCE: perathos.receipt/v1, recorded by hooks inside the agent's host (claude-code)");
    writeFileSync(join(dir, "cut.jsonl"), jsonl(log.slice(0, 4)));
    const cut = run([join(dir, "cut.jsonl"), "--head", join(dir, "s-1.head.json"), "--json"]);
    expect(cut.status).toBe(1);
    expect(JSON.parse(cut.stdout)).toMatchObject({ ok: false, sealedThrough: 4 });
    expect(run([join(dir, "s-1.jsonl"), "--key", "not-hex"]).stderr).toContain("--key takes an Ed25519 public key as 64 hex characters");
  });
});

// Aspect: reading another project's agent records, a Perathos session log (perathos.receipt/v1). Source: src/perathos.ts
// Run:    node examples/45-perathos-log.ts
//
// Perathos records Claude Code, Cursor and MCP tool calls from hooks inside the agent's host, hash-chains them, and
// seals turns with Ed25519 checkpoints. agent-custody reads that format from its published spec, so an auditor checks
// either project's records with one tool. The reader says what kind of evidence each is: a Perathos log shows that the
// holder of the host's key sealed this sequence; an agent-custody receipt shows an enforcement point outside the agent
// saw the call. This example writes a small log to the spec, verifies it, then cuts and edits it.
import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, sha256Hex } from "../src/crypto.ts";
import { formatPerathosReport, perathosReceiptHash, verifyPerathosLog } from "../src/perathos.ts";
import { out, step } from "./_out.ts";

const dir = out("45-perathos-log");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32).toString("hex");
const h = (v: unknown) => sha256Hex(typeof v === "string" ? v : canonicalize(v));

step(1, "A session as a Perathos recorder writes it: two calls, one denied by its guard, sealed by two checkpoints");
const steps: Record<string, unknown>[] = [
  { kind: "pre", tool: "Bash", tool_use_id: "t1", args_hash: h({ command: "railway volume list" }) },
  { kind: "post", tool: "Bash", tool_use_id: "t1", args_hash: h({ command: "railway volume list" }), result_hash: h("pg-data 10 GB"), status: "ok" },
  { kind: "pre", tool: "Bash", tool_use_id: "t2", args_hash: h({ command: "railway volume delete pg-data --yes" }), guard: { decision: "deny", rule: "paas.railway", precondition: null } },
  { kind: "checkpoint", event: "Stop", model: null },
  { kind: "pre", tool: "Read", tool_use_id: "t3", args_hash: h({ path: "README.md" }) },
  { kind: "post", tool: "Read", tool_use_id: "t3", args_hash: h({ path: "README.md" }), result_hash: h("# app"), status: "ok" },
  { kind: "checkpoint", event: "SessionEnd", model: null },
];
const log: Record<string, unknown>[] = [];
steps.forEach((s, i) => {
  const r: Record<string, unknown> = { v: "perathos.receipt/v1", session_id: "replay", agent: "claude-code", seq: i + 1, ts: `2026-11-04T08:19:0${i}.000000Z`, prev_hash: i ? log[i - 1]!.receipt_hash : "0".repeat(64), ...s };
  if (r.kind === "checkpoint") r.signer = signer;
  r.receipt_hash = perathosReceiptHash(r);
  if (r.kind === "checkpoint") r.signature = { algorithm: "ed25519", verify_key: signer, signature: sign(null, Buffer.from(r.receipt_hash as string, "hex"), privateKey).toString("hex") };
  log.push(r);
});
const file = join(dir, "replay.jsonl");
writeFileSync(file, log.map((r) => JSON.stringify(r)).join("\n") + "\n");
const head = { seq: 7, receipt_hash: log[6]!.receipt_hash as string };
console.log(`   ${file}, ${log.length} receipts; head witness at seq ${head.seq}`);

step(2, "Verify it with the recorder's key pinned and the head witness: node src/cli.ts verify-perathos replay.jsonl --key <hex> --head replay.head.json");
const ok = verifyPerathosLog(log.map((r) => JSON.stringify(r)).join("\n"), { trustedKeys: [signer], head });
console.log(formatPerathosReport(ok).split("\n").map((l) => `   ${l}`).join("\n"));
if (!ok.ok || ok.denied !== 1) throw new Error("the log written to the spec should verify");

step(3, "Cut the log back to the first checkpoint: the chain alone still holds, the head witness does not");
const cut = log.slice(0, 4).map((r) => JSON.stringify(r)).join("\n");
console.log(`   without the head witness: ${verifyPerathosLog(cut).ok ? "VALID" : "INVALID"}`);
const cutWithHead = verifyPerathosLog(cut, { head });
console.log(`   with it:                  ${cutWithHead.ok ? "VALID" : "INVALID"}, ${cutWithHead.checks.find((c) => !c.ok)?.detail}`);
if (cutWithHead.ok) throw new Error("a cut log should fail against its head witness");

step(4, "Turn the denied delete into an allow and recompute its hash: the next receipt's prev_hash gives it away");
const edited = log.map((r) => ({ ...r }));
edited[2]!.guard = { decision: "allow", rule: "paas.railway", precondition: null };
edited[2]!.receipt_hash = perathosReceiptHash(edited[2]!);
const e = verifyPerathosLog(edited.map((r) => JSON.stringify(r)).join("\n"));
for (const c of e.checks.filter((c) => !c.ok)) console.log(`   FAIL  ${c.name}  (${c.detail})`);
if (e.ok) throw new Error("an edited receipt should fail");

console.log("\n   RFC 3161 anchors and Perathos evidence packs are not read yet; the report says so.");
console.log("\nOK");

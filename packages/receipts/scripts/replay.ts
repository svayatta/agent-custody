// Builds a small replay to share: a denied call and an incomplete-evidence case, as receipts anyone can verify
// offline with the published packages. It runs receipts example 27 (a grant revoked mid-session) and state example
// 07 (blast radius over a private receipt), keeps only what an outside verifier would hold (receipts, public keys,
// the log, the ledger, the transcript; never a private key or a salt), writes a README with the commands, checks
// the folder with those commands run locally, and zips it. Everything in it is synthetic.
// Run: node scripts/replay.ts   (from packages/receipts, after `bun run build` at the repository root)
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const receiptsPkg = resolve(import.meta.dirname, "..");
// the README names the published packages of this version, so the commands in it run what built the folder
const version = (JSON.parse(readFileSync(join(receiptsPkg, "package.json"), "utf8")) as { version: string }).version;
const statePkg = resolve(receiptsPkg, "..", "state");
const base = join(receiptsPkg, "examples-out", "replay");
const name = "agent-custody-replay";
const out = join(base, name);
rmSync(base, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

/** runs an example, failing unless it ends with OK; its standard output is the transcript */
function run(cwd: string, file: string): string {
  const r = spawnSync(process.execPath, [file], { cwd, encoding: "utf8" });
  if (r.status !== 0 || !r.stdout.trimEnd().endsWith("OK")) throw new Error(`${file} failed:\n${r.stdout}\n${r.stderr}`);
  return r.stdout;
}
/** copies the public part of an example's output: never a private key, never the salts a withheld value is checked with */
function copyPublic(from: string, to: string, files: string[]) {
  mkdirSync(join(to, "keys"), { recursive: true });
  mkdirSync(join(to, "receipts"), { recursive: true });
  for (const f of readdirSync(join(from, "keys"))) if (f.endsWith(".pub") && !f.startsWith("upstream")) cpSync(join(from, "keys", f), join(to, "keys", f));
  for (const f of readdirSync(join(from, "receipts"))) if (f.endsWith(".json")) cpSync(join(from, "receipts", f), join(to, "receipts", f));
  for (const f of files) cpSync(join(from, f), join(to, f));
}
const receiptIds = (dir: string) => readdirSync(join(dir, "receipts")).filter((f) => /^[0-9a-f-]{36}\.json$/.test(f)).map((f) => f.slice(0, -5));
const toolOf = (dir: string, id: string) => {
  const b = JSON.parse(readFileSync(join(dir, "receipts", `${id}.json`), "utf8")) as { envelope: { payload: string } };
  const p = JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()).predicate as { tool: { name: string }; execution: { status: string }; timestamp: string };
  return { id, tool: p.tool.name, status: p.execution.status, at: p.timestamp };
};

// ---- the denied call ----
const denied = join(out, "denied-call");
const deniedRun = run(receiptsPkg, "examples/27-revocation.ts");
copyPublic(join(receiptsPkg, "examples-out", "27-revocation"), denied, ["log.jsonl", "grant.json", "revoked.json"]);
writeFileSync(join(denied, "transcript.txt"), deniedRun);
const deniedCalls = receiptIds(denied).map((id) => toolOf(denied, id)).sort((a, b) => a.at.localeCompare(b.at));

// ---- the incomplete evidence ----
const incomplete = join(out, "incomplete-evidence");
const incompleteRun = run(statePkg, "examples/07-incomplete-evidence.ts");
copyPublic(join(statePkg, "examples-out", "07-incomplete-evidence"), incomplete, ["log.jsonl", "grant.json", "ledger.jsonl", "demo-capture-key.hex"]);
writeFileSync(join(incomplete, "transcript.txt"), incompleteRun);
const factId = /fact ([0-9a-f-]{36}):/.exec(incompleteRun)?.[1];
if (!factId) throw new Error("no fact id in the transcript of example 07");
const refund = receiptIds(incomplete).map((id) => toolOf(incomplete, id)).find((c) => c.tool === "stripe.refund");
if (!refund) throw new Error("no refund receipt in example 07");

// ---- the README, with the commands for this replay's ids ----
const R = `npx -y -p @agent-custody/receipts@${version} agent-custody`;
const S = `npx -y -p @agent-custody/state@${version} agent-custody-memory`;
const verifyArgs = (dir: string, id: string) => `${dir}/receipts/${id}.json --issuer-key ${dir}/keys/gateway.pub --principal-key ${dir}/keys/principal.pub --log ${dir}/log.jsonl`;
const blastArgs = `--ledger incomplete-evidence/ledger.jsonl --receipts incomplete-evidence/receipts --fact ${factId}`;
// prints whether the bundle verified and the execution status with the reason the signed statement records
const WHY = `'const r = JSON.parse(require("fs").readFileSync(0, "utf8")); const e = r.statement.predicate.execution; console.log(r.ok, e.status + ": " + e.reason)'`;
const table = deniedCalls.map((c) => `| \`${c.id}\` | ${c.tool} | ${c.status} |`).join("\n");
const firstDenied = deniedCalls.find((c) => c.status === "denied")!;
writeFileSync(join(out, "README.md"), `# agent-custody replay: a denied call and incomplete evidence

Two runs of [agent-custody](https://github.com/svayatta/agent-custody) ${version}, kept as the evidence an outside reviewer
would hold: signed receipts, public keys, the transparency log, and a transcript of each run. Everything is
synthetic: keys generated for the run, a stand-in payments API, a made-up customer. No private key is included.

Every command runs from this folder with Node 22 or later and fetches the published packages from npm. Nothing
calls back to us.

## 1. A denied call: a grant revoked mid-session (\`denied-call/\`)

A customer (\`user_456\`) grants \`support-agent\` lookups and refunds, and \`support-agent\` delegates lookups to
\`lookup-agent\`. Both act. The operator then runs \`agent-custody revoke\` from another process, with no key rotation
and no restart. The next call of each session is refused, the delegated one included, and the refusal is itself a
signed receipt. \`transcript.txt\` is the run.

| receipt | tool | status |
| --- | --- | --- |
${table}

Verify any of them, a refusal for example:

\`\`\`bash
${R} verify ${verifyArgs("denied-call", firstDenied.id)}
\`\`\`

Every check passes: a denial is a true record. The report shows the grant, the scope check, and \`denied\`. The
signed statement records why; \`--json\` includes it:

\`\`\`bash
${R} verify ${verifyArgs("denied-call", firstDenied.id)} --json | node -e ${WHY}
\`\`\`

That prints \`true\` (verified) and \`denied: delegation grant has been revoked\`. \`revoked.json\` is the list the gateway
re-read: the sha256 of the grant's signed payload.

## 2. Incomplete evidence: a private receipt in a blast radius (\`incomplete-evidence/\`)

The agent records a belief (\`cust_123\` is on the enterprise plan), reads it, and refunds 500.00 on the strength of
it. A capture rule makes the refund's receipt private: the customer id and the amount stay in clear, and the rest
of the arguments, the result, and which beliefs the agent had been shown are withheld as commitments, encrypted
under the customer's key. The belief is then retracted. \`transcript.txt\` is the run.

The refund's receipt still verifies without the key. The withheld parts are reported as committed, not recomputed:

\`\`\`bash
${R} verify ${verifyArgs("incomplete-evidence", refund.id)}
\`\`\`

Ask what relied on the retracted belief, without the key. The answer does not say that nothing did. It lists the
refund as INCOMPLETE: a call that may have depended on the belief, with evidence the reader cannot open.

\`\`\`bash
${S} blast ${blastArgs}
\`\`\`

The same query with the customer's key finds the refund:

\`\`\`bash
DEMO_CAPTURE_KEY=$(cat incomplete-evidence/demo-capture-key.hex) ${S} blast ${blastArgs} --capture-key-env DEMO_CAPTURE_KEY
\`\`\`

\`demo-capture-key.hex\` is a demo key generated for this run, included so the second query can be replayed. In a
real deployment the customer holds it, and the operator and the reviewer do not. With it, \`verify\` also recomputes
every digest from the decrypted values:

\`\`\`bash
DEMO_CAPTURE_KEY=$(cat incomplete-evidence/demo-capture-key.hex) ${R} verify ${verifyArgs("incomplete-evidence", refund.id)} --capture-key-env DEMO_CAPTURE_KEY
\`\`\`

## In a browser

[agent-custody.dev/verify](https://agent-custody.dev/verify) runs the same checks in the page, offline once loaded.
Drop in a receipt and \`keys/gateway.pub\`.

## Source

\`denied-call\` is \`packages/receipts/examples/27-revocation.ts\` and \`incomplete-evidence\` is
\`packages/state/examples/07-incomplete-evidence.ts\` in the repository; \`packages/receipts/scripts/replay.ts\` built
this folder.
`);

// ---- check the folder: nothing private, nothing from this machine, and the commands do what the README says ----
const files = (dir: string): string[] => readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : [join(dir, f)]));
for (const f of files(out)) {
  const rel = relative(out, f);
  if (/\.key$|(^|\/)salts\//.test(rel)) throw new Error(`${rel} must not be in the replay`);
  const text = readFileSync(f, "utf8");
  if (/PRIVATE KEY|\/Users\/|\/home\/|\/private\/tmp/.test(text)) throw new Error(`${rel} carries a private key or a local path`);
}
const local = (cwd: string, args: string[], env: Record<string, string> = {}) => {
  const r = spawnSync(process.execPath, args, { cwd, encoding: "utf8", env: { ...process.env, ...env } });
  return { status: r.status, text: r.stdout + r.stderr };
};
const cli = join(receiptsPkg, "src", "cli.ts");
const stateCli = join(statePkg, "src", "cli.ts");
for (const c of deniedCalls) {
  const v = local(out, [cli, "verify", ...verifyArgs("denied-call", c.id).split(" ")]);
  if (v.status !== 0) throw new Error(`verify ${c.id} failed:\n${v.text}`);
}
const json = local(out, [cli, "verify", ...verifyArgs("denied-call", firstDenied.id).split(" "), "--json"]);
const why = spawnSync(process.execPath, ["-e", WHY.slice(1, -1)], { input: json.text, encoding: "utf8" }).stdout.trim();
if (why !== "true denied: delegation grant has been revoked") throw new Error(`the README's reason command prints ${why}`);
if (local(out, [cli, "verify", ...verifyArgs("incomplete-evidence", refund.id).split(" ")]).status !== 0) throw new Error("the private refund does not verify without the key");
const key = { DEMO_CAPTURE_KEY: readFileSync(join(incomplete, "demo-capture-key.hex"), "utf8").trim() };
if (local(out, [cli, "verify", ...verifyArgs("incomplete-evidence", refund.id).split(" "), "--capture-key-env", "DEMO_CAPTURE_KEY"], key).status !== 0) throw new Error("the private refund does not verify with the key");
const blind = local(out, [stateCli, "blast", ...blastArgs.split(" ")]);
const seeing = local(out, [stateCli, "blast", ...blastArgs.split(" "), "--capture-key-env", "DEMO_CAPTURE_KEY"], key);
if (!blind.text.includes("INCOMPLETE") || !blind.text.includes(refund.id.slice(0, 8))) throw new Error(`blast without the key does not list the refund as incomplete:\n${blind.text}`);
if (seeing.text.includes("INCOMPLETE") || !seeing.text.includes(refund.id.slice(0, 8))) throw new Error(`blast with the key does not find the refund:\n${seeing.text}`);

if (existsSync(`${out}.zip`)) rmSync(`${out}.zip`);
execFileSync("zip", ["-qr", `${name}.zip`, name], { cwd: base });
console.log(`${relative(process.cwd(), out)}/ and ${relative(process.cwd(), out)}.zip: ${files(out).length} files, ${deniedCalls.length} receipts in denied-call, refund ${refund.id.slice(0, 8)} in incomplete-evidence`);
console.log("OK");

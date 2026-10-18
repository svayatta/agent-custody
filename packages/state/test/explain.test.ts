// "Prove this action" is what a security owner asks first. From one receipt id they must get the ten answers, and
// the same answers as one signed artefact that fails as a whole when a receipt inside it is touched.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createDelegation, createGateway, generateKeyPair, loadPrivateKey, loadPublicKey, RECEIPT_META_KEY, verifyBundle, writeKeyPair, loadConfig } from "@agent-custody/receipts";
import { Ledger } from "../src/ledger.ts";
import { buildActionPack, formatExplain, signActionPack, verifyActionPack } from "../src/explain.ts";
import { listReceipts } from "../src/review.ts";

const value = (r: any) => JSON.parse(r.content[0].text);
const cli = join(import.meta.dirname, "..", "src", "cli.ts");

describe("explain a receipt", () => {
  it("answers the ten questions from one receipt, packs them signed, verifies, and fails when a receipt inside is touched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "explain-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const packKey = writeKeyPair(generateKeyPair(), join(dir, "keys"), "pack");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.retract"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
    const ledgerFile = join(dir, "ledger.jsonl");
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { command: process.execPath, args: [cli, "serve", "--ledger", ledgerFile] }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", precommit: ["memory.write"], receiptsDir: "receipts", logFile: "log.jsonl" }));
    const gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    const w = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "enterprise", space: "org" } });
    const writeId = String(w._meta?.[RECEIPT_META_KEY]);
    const factId = value(w).fact.factId;
    await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } });
    const derived = await gw.handleCall({ name: "memory.write", arguments: { subject: "acct:42", predicate: "discount", value: 20, space: "org" } });
    const derivedId = value(derived).fact.factId;
    await gw.close();

    const keys = { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))] };
    const ledger = new Ledger(ledgerFile);
    const pack = await buildActionPack(join(dir, "receipts"), writeId, ledger);
    expect(pack.written.map((f) => f.factId)).toEqual([factId]);
    expect(pack.status[factId]).toBe("believed");
    expect(pack.downstream.receipts.map((r) => r.tool)).toEqual(["memory.write"]);
    expect(pack.downstream.derivedFacts.map((f) => f.factId)).toEqual([derivedId]);
    expect(pack.downstream.stillBelieved).toHaveLength(1);
    expect(pack.missingReceipts).toEqual([]);

    const text = formatExplain(pack, verifyBundle(pack.receipt, keys), true);
    expect(text).toMatch(/^WHO\s+support-agent \(attested, named in a signed grant\)/m);
    expect(text).toMatch(/WHO AUTHORIZED IT\s+user_456, grant signed by key/);
    expect(text).toMatch(/WHAT WAS ALLOWED\s+tools memory.write, memory.read, memory.retract/);
    expect(text).toMatch(/WHAT IT DID\s+memory.write .*-> executed/);
    expect(text).toMatch(/authorization committed as leaf \d+, before the call was forwarded/);
    expect(text).toMatch(/CAN I VERIFY IT\s+VERIFIED, \d+ checks/);
    expect(text).toMatch(/DID ANYTHING DEPEND ON THIS\s+1 belief\(s\) written in this call, 1 later call\(s\) made after seeing them, 1 belief\(s\) derived/);
    expect(text).toMatch(/WHAT NEEDS REVERSAL\s+2 belief\(s\) still believed, and 1 later call\(s\) to review/);

    // without a ledger the belief questions are unknown, not empty
    const bare = formatExplain(await buildActionPack(join(dir, "receipts"), writeId), null, false);
    expect(bare).toMatch(/DID ANYTHING DEPEND ON THIS\s+unknown without a ledger/);
    expect(bare).toMatch(/CAN I VERIFY IT\s+not checked here/);

    // the signed pack
    const env = signActionPack(pack, loadPrivateKey(packKey.keyFile));
    const ok = verifyActionPack(env, [loadPublicKey(packKey.pubFile)], keys);
    expect(ok.checks.filter((c) => !c.ok)).toEqual([]);
    expect(ok.receipt?.ok).toBe(true);
    expect(verifyActionPack(env, [loadPublicKey(packKey.pubFile)]).ok).toBe(false);
    const touched = structuredClone(pack);
    const someId = Object.keys(touched.receipts)[0]!;
    touched.receipts[someId]!.envelope.payload = touched.receipts[someId]!.envelope.payload.replace(/^(.)/, (c) => (c === "A" ? "B" : "A"));
    const bad = verifyActionPack(signActionPack(touched, loadPrivateKey(packKey.keyFile)), [loadPublicKey(packKey.pubFile)], keys);
    expect(bad.ok).toBe(false);
    expect(bad.checks.find((c) => c.name === `downstream receipt ${someId.slice(0, 8)} verifies`)?.ok).toBe(false);

    // after the retraction the reversal question changes its answer
    await ledger.retract({ factId: derivedId, actor: "user:admin", reason: "wrong" });
    const after = await buildActionPack(join(dir, "receipts"), writeId, ledger);
    expect(after.downstream.stillBelieved).toHaveLength(0);
    expect(formatExplain(after, null, true)).toMatch(/WHAT NEEDS REVERSAL\s+1 belief\(s\) still believed/);

    // the CLI: explain, then pack and verify
    const shown = spawnSync(process.execPath, [cli, "explain", "--ledger", ledgerFile, "--receipts", join(dir, "receipts"), "--receipt", writeId, "--issuer-key", join(dir, "keys", "gateway.pub"), "--principal-key", join(dir, "keys", "principal.pub")], { encoding: "utf8", timeout: 60_000 });
    expect(shown.status, shown.stderr).toBe(0);
    expect(shown.stdout).toMatch(/CAN I VERIFY IT\s+VERIFIED/);
    const made = spawnSync(process.execPath, [cli, "explain", "--ledger", ledgerFile, "--receipts", join(dir, "receipts"), "--receipt", writeId, "--out", join(dir, "action.json"), "--sign", packKey.keyFile], { encoding: "utf8", timeout: 60_000 });
    expect(made.status, made.stderr).toBe(0);
    const checked = spawnSync(process.execPath, [cli, "explain", "--verify", join(dir, "action.json"), "--key", packKey.pubFile, "--issuer-key", join(dir, "keys", "gateway.pub"), "--principal-key", join(dir, "keys", "principal.pub")], { encoding: "utf8", timeout: 60_000 });
    expect(checked.status, checked.stdout + checked.stderr).toBe(0);
    expect(checked.stdout).toMatch(/RESULT: VERIFIED/);
    expect(checked.stdout).toMatch(/WHO\s+support-agent/);
    const receiptsOnly = spawnSync(process.execPath, [cli, "explain", "--receipts", join(dir, "receipts"), "--receipt", writeId], { encoding: "utf8", timeout: 60_000 });
    expect(receiptsOnly.status, receiptsOnly.stderr).toBe(0);
    expect(receiptsOnly.stdout).toMatch(/unknown without a ledger/);
    await ledger.close();
  });

  it("does not present a reconciliation receipt as a policy-allowed execution of the tool", async () => {
    const dir = mkdtempSync(join(tmpdir(), "explain-reconcile-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.read"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { command: process.execPath, args: [cli, "serve", "--ledger", join(dir, "ledger.jsonl")] }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" }));
    const gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    const read = await gw.handleCall({ name: "memory.read", arguments: { subject: "acct:42" } });
    await gw.close();
    const id = String(read._meta?.[RECEIPT_META_KEY]);
    // Give the receipt the fields of a reconciliation. Its signature no longer holds, and the explanation does not check it here.
    const file = join(dir, "receipts", `${id}.json`);
    const bundle = JSON.parse(readFileSync(file, "utf8"));
    const statement = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString());
    statement.predicate.reconciliation = { original: bundle, lookup: { tool: "refund.lookup", args: {}, statusPath: "status", identityPath: "idempotencyKey", confirmed: ["succeeded"], failed: ["failed"] } };
    statement.predicate.operation = { status: "failed" };
    statement.predicate.policy.reasons = ["reconciliation: the gateway read the provider record and evaluated no policy"];
    bundle.envelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    writeFileSync(file, JSON.stringify(bundle));
    const text = formatExplain(await buildActionPack(join(dir, "receipts"), id), null, false);
    expect(text).toMatch(/WHAT IT DID\s+reconciliation: the gateway read refund.lookup for memory.read; the operation is failed/);
    expect(text).toMatch(/WHY\s+no policy was evaluated/);
    expect(text).not.toMatch(/decided allow|the policy permitted it|-> executed/);
    expect(listReceipts({ receiptsDir: join(dir, "receipts"), ledger: new Ledger(join(dir, "ledger.jsonl")) })[0]!.status).toBe("reconciled");
  });
});

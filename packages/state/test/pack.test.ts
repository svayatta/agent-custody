// The pack is the artefact counsel gets. It must verify as a whole, and fail as a whole when any receipt in it is
// touched or any cited receipt is absent.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createDelegation, createGateway, digestOf, dsseSign, generateKeyPair, loadPublicKey, RECEIPT_META_KEY, writeKeyPair, loadConfig } from "@agent-custody/receipts";
import { Ledger } from "../src/ledger.ts";
import { buildPack, signPack, verifyPack } from "../src/pack.ts";

const value = (r: any) => JSON.parse(r.content[0].text);

describe("custody pack", () => {
  it("packs a fact's whole life behind the gateway, verifies, and fails when a receipt inside is touched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pack-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const packKey = writeKeyPair(generateKeyPair(), join(dir, "keys"), "pack");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.hold", "memory.release", "memory.forget"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
    const ledgerFile = join(dir, "ledger.jsonl");
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile] }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" }));
    const gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    const w = await gw.handleCall({ name: "memory.write", arguments: { subject: "person:1", predicate: "email", value: "dana@example.com", space: "team:support" } });
    const factId = value(w).fact.factId;
    await gw.handleCall({ name: "memory.read", arguments: { subject: "person:1" } });
    await gw.handleCall({ name: "memory.write", arguments: { subject: "person:1", predicate: "tier", value: "gold", space: "team:support" } });
    await gw.handleCall({ name: "memory.hold", arguments: { factId, reason: "matter 12" } });
    await gw.handleCall({ name: "memory.release", arguments: { factId, reason: "matter closed" } });
    const f = await gw.handleCall({ name: "memory.forget", arguments: { factId, reason: "deletion request 4471" } });
    await gw.close();

    const pack = await buildPack(new Ledger(ledgerFile), join(dir, "receipts"), factId);
    expect(pack.history.map((e) => e.kind)).toEqual(["assert", "hold", "release", "forget"]);
    expect(pack.missingReceipts).toEqual([]);
    expect(pack.forget?.receiptId).toBe(String(f._meta?.[RECEIPT_META_KEY]));
    expect(pack.forget?.verification).toEqual({});
    expect(pack.blast.derivedFacts.map((x) => x.predicate)).toEqual(["tier"]);
    expect(Object.keys(pack.receipts).length).toBeGreaterThanOrEqual(5);
    // the fact itself is erased in the pack; the receipts inside still carry what was said at the time, as documented
    expect(pack.fact?.value).toBeNull();
    expect(pack.fact?.forgotten?.digestKind).toBe("sha256");

    const keys = { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))] };
    const env = signPack(pack, generateKeyPairFrom(packKey.keyFile));
    const ok = verifyPack(env, [loadPublicKey(packKey.pubFile)], keys);
    expect(ok.checks.filter((c) => !c.ok)).toEqual([]);
    expect(ok.ok).toBe(true);

    // without issuer keys the pack signature passes but the receipts are reported unchecked
    expect(verifyPack(env, [loadPublicKey(packKey.pubFile)]).ok).toBe(false);
    // a touched receipt inside the pack fails the whole pack, even though the pack's own signature is re-made
    const touched = structuredClone(pack);
    const someId = Object.keys(touched.receipts)[0]!;
    touched.receipts[someId]!.envelope.payload = touched.receipts[someId]!.envelope.payload.replace(/^(.)/, (c) => (c === "A" ? "B" : "A"));
    const bad = verifyPack(signPack(touched, generateKeyPairFrom(packKey.keyFile)), [loadPublicKey(packKey.pubFile)], keys);
    expect(bad.ok).toBe(false);
    expect(bad.checks.find((c) => c.name === `receipt ${someId.slice(0, 8)} verifies`)?.ok).toBe(false);
    // a wrong pack key fails at the first check
    expect(verifyPack(env, [loadPublicKey(join(dir, "keys", "gateway.pub"))], keys).checks[0]?.ok).toBe(false);

    // the CLI round trip
    const made = spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "pack", "--ledger", ledgerFile, "--receipts", join(dir, "receipts"), "--fact", factId, "--out", join(dir, "pack.json"), "--sign", packKey.keyFile], { encoding: "utf8", timeout: 60_000 });
    expect(made.status, made.stderr).toBe(0);
    expect(made.stdout).toMatch(/forgotten at/);
    const checked = spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "pack", "--verify", join(dir, "pack.json"), "--key", packKey.pubFile, "--issuer-key", join(dir, "keys", "gateway.pub"), "--principal-key", join(dir, "keys", "principal.pub")], { encoding: "utf8", timeout: 60_000 });
    expect(checked.status, checked.stdout + checked.stderr).toBe(0);
    expect(checked.stdout).toMatch(/RESULT: VERIFIED/);
  });
});

import { loadPrivateKey } from "@agent-custody/receipts";
function generateKeyPairFrom(keyFile: string) {
  return loadPrivateKey(keyFile);
}

describe("custody pack negative verification cases", () => {
  async function makePack() {
    const dir = mkdtempSync(join(tmpdir(), "pack-negative-"));
    writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
    const principalKp = generateKeyPair();
    writeKeyPair(principalKp, join(dir, "keys"), "principal");
    const packKey = writeKeyPair(generateKeyPair(), join(dir, "keys"), "pack");
    const now = Date.now();
    writeFileSync(join(dir, "grant.json"), JSON.stringify(createDelegation(principalKp, { version: "0.1", principal: "user_456", agent: "support-agent", scopes: ["memory.write", "memory.read", "memory.hold", "memory.release", "memory.forget"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() })));
    writeFileSync(join(dir, "policy.cedar"), `permit(principal, action, resource);\n`);
    const ledgerFile = join(dir, "ledger.jsonl");
    writeFileSync(join(dir, "gateway.json"), JSON.stringify({ identity: { keyFile: "keys/gateway.key" }, upstream: { command: process.execPath, args: [join(import.meta.dirname, "..", "src", "cli.ts"), "serve", "--ledger", ledgerFile] }, grantFile: "grant.json", trustedPrincipalKeys: ["keys/principal.pub"], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" }));
    const gw = await createGateway(loadConfig(join(dir, "gateway.json")));
    const w = await gw.handleCall({ name: "memory.write", arguments: { subject: "person:1", predicate: "email", value: "dana@example.com", space: "team:support" } });
    const factId = value(w).fact.factId;
    await gw.handleCall({ name: "memory.read", arguments: { subject: "person:1" } });
    await gw.handleCall({ name: "memory.write", arguments: { subject: "person:1", predicate: "tier", value: "gold", space: "team:support" } });
    await gw.handleCall({ name: "memory.hold", arguments: { factId, reason: "matter 12" } });
    await gw.handleCall({ name: "memory.release", arguments: { factId, reason: "matter closed" } });
    await gw.handleCall({ name: "memory.forget", arguments: { factId, reason: "deletion request 4471" } });
    await gw.close();
    const pack = await buildPack(new Ledger(ledgerFile), join(dir, "receipts"), factId);
    const keys = { issuerKeys: [loadPublicKey(join(dir, "keys", "gateway.pub"))], principalKeys: [loadPublicKey(join(dir, "keys", "principal.pub"))] };
    return { dir, ledgerFile, factId, packKey, keys, pack };
  }

  it("skips non-JSON files and damaged bundles in the receipts dir", async () => {
    const { dir, ledgerFile, factId, pack } = await makePack();
    const before = Object.keys(pack.receipts).sort();
    expect(pack.missingReceipts).toEqual([]);
    writeFileSync(join(dir, "receipts", "notes.txt"), "not a bundle\n");
    writeFileSync(join(dir, "receipts", "broken.json"), "{not json\n");
    const again = await buildPack(new Ledger(ledgerFile), join(dir, "receipts"), factId);
    expect(Object.keys(again.receipts).sort()).toEqual(before);
    expect(again.missingReceipts).toEqual([]);
  });

  it("reports a cited receipt whose bundle file is gone as missing", async () => {
    const { dir, ledgerFile, factId, packKey, keys, pack } = await makePack();
    const someId = Object.keys(pack.receipts)[0]!;
    unlinkSync(join(dir, "receipts", `${someId}.json`));
    const again = await buildPack(new Ledger(ledgerFile), join(dir, "receipts"), factId);
    expect(again.missingReceipts).toContain(someId);
    const env = signPack(again, generateKeyPairFrom(packKey.keyFile));
    const res = verifyPack(env, [loadPublicKey(packKey.pubFile)], keys);
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.name === "no receipts missing")?.ok).toBe(false);
  });

  it("fails the pack-type check for a wrongly typed pack", async () => {
    const { factId, packKey, pack } = await makePack();
    const wrong = { _type: "https://in-toto.io/Statement/v1", subject: [{ name: `custody-pack:${factId}`, digest: { sha256: digestOf(pack) } }], predicateType: "https://example.invalid/not-a-pack", predicate: pack };
    const env = dsseSign("application/vnd.in-toto+json", wrong, generateKeyPairFrom(packKey.keyFile));
    const res = verifyPack(env, [loadPublicKey(packKey.pubFile)]);
    expect(res.ok).toBe(false);
    expect(res.pack).toBeNull();
    expect(res.checks.find((c) => c.name === "pack type")?.ok).toBe(false);
  });

  it("fails when a receipt inside is filed under another receipt's id", async () => {
    const { packKey, keys, pack } = await makePack();
    const touched = structuredClone(pack);
    const ids = Object.keys(touched.receipts);
    const first = ids[0]!;
    touched.receipts[first] = touched.receipts[ids[1]!]!;
    const bad = verifyPack(signPack(touched, generateKeyPairFrom(packKey.keyFile)), [loadPublicKey(packKey.pubFile)], keys);
    expect(bad.ok).toBe(false);
    expect(bad.checks.find((c) => c.name === `receipt ${first.slice(0, 8)} is the receipt it claims to be`)?.ok).toBe(false);
  });

  it("reports a damaged forget receipt bundle as missing, with no forget verification", async () => {
    const { dir, ledgerFile, factId, packKey, keys, pack } = await makePack();
    const forgetId = pack.forget?.receiptId;
    expect(forgetId).toBeTruthy();
    writeFileSync(join(dir, "receipts", `${forgetId}.json`), "{damaged\n");
    const again = await buildPack(new Ledger(ledgerFile), join(dir, "receipts"), factId);
    expect(again.missingReceipts).toContain(forgetId);
    expect(again.forget?.verification).toBeNull();
    const env = signPack(again, generateKeyPairFrom(packKey.keyFile));
    const res = verifyPack(env, [loadPublicKey(packKey.pubFile)], keys);
    expect(res.ok).toBe(false);
    expect(res.checks.find((c) => c.name === "no receipts missing")?.ok).toBe(false);
  });
});

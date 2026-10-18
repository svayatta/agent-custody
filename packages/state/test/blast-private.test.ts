// A receipt under a capture rule withholds what the agent had been shown. The blast query must say so rather than
// report an empty, apparently complete, dependency set; with the capture key it sees through.
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { captureKeyFrom, createIssuer, generateKeyPair, type ReceiptPredicate } from "@agent-custody/receipts";
import { blastRadius, formatBlastRadius, loadReceipts } from "../src/blast.ts";
import { buildActionPack, formatExplain } from "../src/explain.ts";
import { Ledger } from "../src/ledger.ts";

const KEY_HEX = randomBytes(32).toString("hex");

/** a gateway-shaped receipt for a call that consumed `consumed`, issued under `rules` */
async function issueCall(dir: string, consumed: string[], rules: Record<string, unknown> | undefined, mode: "digest" | "encrypted"): Promise<string> {
  const key = generateKeyPair();
  const issuer = createIssuer(key, join(dir, "receipts"), join(dir, "log.jsonl"), { capture: { rules: rules as never, key: captureKeyFrom(KEY_HEX) } });
  const receiptId = randomUUID();
  const p: ReceiptPredicate = {
    receiptId,
    timestamp: new Date().toISOString(),
    issuer: { kind: "gateway", keyid: key.keyid, version: "0" },
    principal: { id: "user_456", provenance: "claimed" },
    agent: { id: "support-agent", provenance: "claimed" },
    session: { id: null, toolUseId: null, provenance: "claimed" },
    model: { id: null, provenance: "claimed" },
    tool: { name: "memory.write", provenance: "observed" },
    request: { args: { subject: "acct:42", predicate: "tier", value: "gold" }, argsDigest: "x", provenance: "claimed" },
    facts: {},
    consumed: { factIds: consumed, provenance: "observed" },
    policy: { decision: "allow", reasons: ["policy0"], errors: [], policyDigest: "d", provenance: "observed" },
    execution: { status: "executed", result: { content: [{ type: "text", text: "ok" }] }, resultDigest: "y", provenance: "observed" },
  };
  void mode;
  await issuer.issue(p);
  return receiptId;
}

describe("blast radius under a capture rule", () => {
  for (const mode of ["digest", "encrypted"] as const) {
    it(`a receipt whose consumed ids are withheld is reported as such, not as having consumed nothing; the key sees through (${mode})`, async () => {
      const make = async (rules: Record<string, unknown> | undefined, validFrom?: string) => {
        const dir = mkdtempSync(join(tmpdir(), `blast-private-${mode}-`));
        mkdirSync(join(dir, "receipts"), { recursive: true });
        const ledger = new Ledger(join(dir, "ledger.jsonl"));
        const shown = await ledger.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "team", actor: "crm", ...(validFrom ? { validFrom } : {}) });
        const receiptId = await issueCall(dir, [shown.fact.factId], rules, mode);
        // a belief written in that call, derived from what the agent had been shown
        await ledger.assert({ subject: "acct:42", predicate: "tier", value: "gold", space: "team", actor: "support-agent", source: { receiptId } });
        return { dir, ledger, factId: shown.fact.factId, receiptId };
      };
      // the control: in clear, the call and the derived belief are found
      const clear = await make(undefined);
      const bc = await blastRadius(clear.ledger, loadReceipts(join(clear.dir, "receipts")), clear.factId);
      expect(bc.receipts.map((r) => r.receiptId)).toEqual([clear.receiptId]);
      expect(bc.derivedFacts).toHaveLength(1);
      expect(bc.withheld).toEqual([]);
      // under a private rule: nothing is found, and the query says it cannot see
      const priv = await make({ "*": { args: { mode } } });
      const summaries = loadReceipts(join(priv.dir, "receipts"));
      expect(summaries[0]!.consumedWithheld).toBe(true);
      expect(summaries[0]!.consumed).toEqual([]);
      const bp = await blastRadius(priv.ledger, summaries, priv.factId);
      expect(bp.receipts).toEqual([]);
      expect(bp.derivedFacts).toEqual([]);
      expect(bp.withheld.map((r) => r.receiptId)).toEqual([priv.receiptId]);
      expect(formatBlastRadius(bp, priv.factId)).toMatch(/INCOMPLETE: 1 call\(s\).*withhold what the agent had been shown/);
      // the authorization committed before a pre-committed call carries the same call: it is not a second receipt
      const bundleFile = join(priv.dir, "receipts", `${priv.receiptId}.json`);
      writeFileSync(join(priv.dir, "receipts", `${priv.receiptId}.authorization.json`), readFileSync(bundleFile, "utf8"));
      expect(loadReceipts(join(priv.dir, "receipts")).map((r) => r.receiptId)).toEqual([priv.receiptId]);
      expect((await blastRadius(priv.ledger, loadReceipts(join(priv.dir, "receipts")), priv.factId)).withheld).toHaveLength(1);
      // explain says the beliefs shown are withheld, and with the key it sees them
      const pack = await buildActionPack(join(priv.dir, "receipts"), priv.receiptId, priv.ledger);
      expect(pack.consumedWithheld).toBe(true);
      expect(pack.consumed.facts).toEqual([]);
      expect(formatExplain(pack, null, true)).toMatch(/withheld under the capture rule/);
      const packWithKey = await buildActionPack(join(priv.dir, "receipts"), priv.receiptId, priv.ledger, { captureKey: captureKeyFrom(KEY_HEX) });
      if (mode === "encrypted") {
        expect(packWithKey.consumedWithheld).toBe(false);
        expect(packWithKey.consumed.facts.map((f) => f.factId)).toEqual([priv.factId]);
        // the explanation prints what the key opened, not the receipt's commitment read as "nothing shown"
        const opened = formatExplain(packWithKey, null, true);
        expect(opened).toMatch(/1 belief\(s\) shown before this call:/);
        expect(opened).toContain("plan");
        expect(opened).not.toMatch(/no beliefs shown/);
      } else expect(packWithKey.consumedWithheld).toBe(true);
      // a fact valid from tomorrow is readable today and may be consumed today: the bound is when the ledger learned it, not when it is true
      const tomorrow = new Date(Date.now() + 86_400_000).toISOString();
      const future = await make({ "*": { args: { mode } } }, tomorrow);
      expect((await future.ledger.asOf({ validAt: tomorrow })).map((f) => f.factId)).toContain(future.factId);
      const bf = await blastRadius(future.ledger, loadReceipts(join(future.dir, "receipts")), future.factId);
      expect(bf.withheld.map((r) => r.receiptId)).toEqual([future.receiptId]);
      expect(formatBlastRadius(bf, future.factId)).toMatch(/INCOMPLETE/);
      // with the key, an encrypted receipt opens and the dependency is found; a digest-only one stays marked
      const withKey = loadReceipts(join(priv.dir, "receipts"), { captureKey: captureKeyFrom(KEY_HEX) });
      const bk = await blastRadius(priv.ledger, withKey, priv.factId);
      if (mode === "encrypted") {
        expect(withKey[0]!.consumedWithheld).toBe(false);
        expect(bk.receipts.map((r) => r.receiptId)).toEqual([priv.receiptId]);
        expect(bk.derivedFacts).toHaveLength(1);
        expect(bk.withheld).toEqual([]);
      } else {
        expect(withKey[0]!.consumedWithheld).toBe(true);
        expect(bk.withheld).toHaveLength(1);
      }
    });
  }
});

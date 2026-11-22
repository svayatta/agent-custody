// A sub-agent acts under a grant its parent agent signed, and the chain leads back to the principal. The verifier
// accepts only a chain where every link is signed by the key its parent names, every scope is one the parent holds,
// every window sits inside the parent's, and the principal never changes; a gateway opens a session for a chained
// grant exactly as for a direct one, and the receipt names the sub-agent, the principal, and carries the chain.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, publicKeyToPem } from "../src/crypto.ts";
import { createDelegation, delegateFrom, describeChain, verifyDelegation } from "../src/delegation.ts";
import { didKeyOf } from "../src/did-key.ts";
import { createGatewayHost, RECEIPT_META_KEY } from "../src/gateway.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";

const hour = 3600_000;
const iso = (t: number) => new Date(t).toISOString();

describe("delegation chains", () => {
  const principal = generateKeyPair();
  const agentA = generateKeyPair();
  const agentB = generateKeyPair();
  const now = Date.now();
  const root = createDelegation(principal, { version: "0.1", principal: "user_456", agent: "planner", scopes: ["stripe.refund", "customer.lookup", "stripe.payout"], issuedAt: iso(now - hour), expiresAt: iso(now + 4 * hour), agentKey: publicKeyToPem(agentA.publicKey) });

  it("a two-link chain verifies to the principal's key, reports the chain, and a three-link one still does", () => {
    const sub = delegateFrom(root, agentA, { agent: "refunder", scopes: ["stripe.refund", "customer.lookup"], expiresAt: iso(now + 2 * hour), agentKey: publicKeyToPem(agentB.publicKey) });
    const v = verifyDelegation(sub, [{ publicKey: principal.publicKey, keyid: principal.keyid }]);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    expect(v.keyid).toBe(principal.keyid);
    expect(v.delegation.agent).toBe("refunder");
    expect(v.chain.map((d) => d.agent)).toEqual(["planner", "refunder"]);
    expect(describeChain(v.chain)).toBe("user_456 → planner → refunder");
    const subsub = delegateFrom(sub, agentB, { agent: "lookup-only", scopes: ["customer.lookup"] });
    const v3 = verifyDelegation(subsub, [{ publicKey: principal.publicKey, keyid: principal.keyid }]);
    expect(v3.ok && v3.chain.map((d) => d.agent)).toEqual(["planner", "refunder", "lookup-only"]);
    expect(v3.ok && v3.delegation.expiresAt).toBe(iso(now + 2 * hour)); // inherits the parent's end when none is given
  });

  it("refuses at signing time, and at verification, a link that escalates scope, widens the window, or is signed by the wrong key; refuses a delegator without an agent key; and stops at the depth limit", () => {
    expect(() => delegateFrom(root, agentA, { agent: "x", scopes: ["stripe.refund", "admin.reset"] })).toThrow(/scopes its delegator lacks: admin.reset/);
    expect(() => delegateFrom(root, agentA, { agent: "x", scopes: ["stripe.refund"], expiresAt: iso(now + 9 * hour) })).toThrow(/window must lie inside/);
    expect(() => delegateFrom(root, agentB, { agent: "x", scopes: ["stripe.refund"] })).toThrow(/not the one the parent grant names/);
    const trusted = [{ publicKey: principal.publicKey, keyid: principal.keyid }];
    // signed by the right key but with escalated scope, built by hand to bypass the early check
    const escalated = createDelegation(agentA, { version: "0.1", principal: "user_456", agent: "x", scopes: ["admin.reset"], issuedAt: iso(now), expiresAt: iso(now + hour), parent: root });
    expect(verifyDelegation(escalated, trusted)).toMatchObject({ ok: false, error: expect.stringMatching(/link 1: x was given scopes planner does not hold: admin.reset/) });
    const widened = createDelegation(agentA, { version: "0.1", principal: "user_456", agent: "x", scopes: ["stripe.refund"], issuedAt: iso(now), expiresAt: iso(now + 9 * hour), parent: root });
    expect(verifyDelegation(widened, trusted)).toMatchObject({ ok: false, error: expect.stringMatching(/window is not inside/) });
    const wrongSigner = createDelegation(agentB, { version: "0.1", principal: "user_456", agent: "x", scopes: ["stripe.refund"], issuedAt: iso(now), expiresAt: iso(now + hour), parent: root });
    expect(verifyDelegation(wrongSigner, trusted)).toMatchObject({ ok: false, error: expect.stringMatching(/not signed by planner's key/) });
    const otherPrincipal = createDelegation(agentA, { version: "0.1", principal: "someone_else", agent: "x", scopes: ["stripe.refund"], issuedAt: iso(now), expiresAt: iso(now + hour), parent: root });
    expect(verifyDelegation(otherPrincipal, trusted)).toMatchObject({ ok: false, error: expect.stringMatching(/principal changed/) });
    const keyless = createDelegation(principal, { version: "0.1", principal: "user_456", agent: "planner", scopes: ["stripe.refund"], issuedAt: iso(now - hour), expiresAt: iso(now + hour) });
    expect(() => delegateFrom(keyless, agentA, { agent: "x", scopes: ["stripe.refund"] })).toThrow(/names no agent key/);
    // depth: root + three delegations is the most; a fourth is refused
    let env = root;
    let key = agentA;
    for (let i = 0; i < 3; i++) {
      const next = generateKeyPair();
      env = delegateFrom(env, key, { agent: `level-${i + 1}`, scopes: ["stripe.refund"], agentKey: publicKeyToPem(next.publicKey) });
      key = next;
    }
    expect(verifyDelegation(env, trusted).ok).toBe(true);
    const tooDeep = delegateFrom(env, key, { agent: "level-4", scopes: ["stripe.refund"] });
    expect(verifyDelegation(tooDeep, trusted)).toMatchObject({ ok: false, error: expect.stringMatching(/deeper than 4/) });
  });

  it("a gateway opens a session for a chained grant, the receipt names the sub-agent and the principal, and it verifies with the chain line in the report", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "chain-")));
    const principalKey = loadPrivateKey(join(fx.dir, "keys", "principal.key"));
    const planner = generateKeyPair();
    const parent = createDelegation(principalKey, { version: "0.1", principal: "user_456", agent: "planner", scopes: ["stripe.refund", "customer.lookup"], issuedAt: iso(now - hour), expiresAt: iso(now + 2 * hour), agentKey: publicKeyToPem(planner.publicKey) });
    const child = delegateFrom(parent, planner, { agent: "refunder", scopes: ["stripe.refund"] });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      const session = host.open(child);
      expect(session.agentId).toBe("refunder");
      expect((await session.listTools()).map((t) => t.name)).toEqual(["stripe.refund"]);
      const ok = await session.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      expect(ok.isError).toBeFalsy();
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(ok._meta?.[RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
      const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
      expect(p.agent).toEqual({ id: "refunder", provenance: "attested" });
      expect(p.principal).toMatchObject({ id: "user_456", provenance: "attested" });
      const report = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)] });
      expect(report.ok).toBe(true);
      const chainCheck = report.checks.find((c) => c.name === "delegation chain to the principal");
      expect(chainCheck).toMatchObject({ ok: true, detail: "user_456 → planner → refunder (1 delegation(s))" });
      expect(formatReport(report)).toContain("delegation chain to the principal");
      // a stranger's chain gets no session
      expect(() => host.open(createDelegation(generateKeyPair(), { version: "0.1", principal: "user_456", agent: "z", scopes: ["stripe.refund"], issuedAt: iso(now), expiresAt: iso(now + hour), parent }))).toThrow(/not signed by planner's key/);
    } finally {
      await host.close();
    }
  });

  it("a gateway opens no session for a grant whose did:key agent does not decode, or is not the key in agentKey, on any link", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "chain-did-")));
    const principalKey = loadPrivateKey(join(fx.dir, "keys", "principal.key"));
    const agent = generateKeyPair();
    const other = generateKeyPair();
    const did = didKeyOf(agent.publicKey);
    const grant = (agentId: string, agentKey?: string) => createDelegation(principalKey, { version: "0.1", principal: "user_456", agent: agentId, scopes: ["stripe.refund"], issuedAt: iso(now - hour), expiresAt: iso(now + hour), ...(agentKey ? { agentKey } : {}) });
    const host = await createGatewayHost(loadConfig(fx.configFile));
    try {
      expect(host.open(grant(did)).agentId).toBe(did);
      expect(host.open(grant(did, publicKeyToPem(agent.publicKey))).agentId).toBe(did);
      expect(() => host.open(grant("did:key:z6Mk0bad"))).toThrow(/^delegation grant rejected: the grant's did:key agent does not decode: /);
      expect(() => host.open(grant(did, publicKeyToPem(other.publicKey)))).toThrow("delegation grant rejected: the grant's agentKey is not the key its did:key agent names");
      // the parent's agentKey signs the sub-grant, so the chain verifies; the parent's did:key names another key
      const sub = delegateFrom(grant(did, publicKeyToPem(other.publicKey)), other, { agent: "refunder", scopes: ["stripe.refund"] });
      expect(() => host.open(sub)).toThrow(`delegation grant rejected: link 0 (${did}): the grant's agentKey is not the key its did:key agent names`);
    } finally {
      await host.close();
    }
  });
});

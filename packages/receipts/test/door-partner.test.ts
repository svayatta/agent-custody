// The partner engine slot. A detection verdict is only worth recording if nobody between the engine and the receipt
// could have made it up or moved it: so a verdict the engine signed for this arrival reaches the policy and lands in a
// receipt that verifies as attested under the engine's key; a verdict signed by any other key never reaches the policy,
// so a rule that requires the partner's verdict denies; a signed verdict for another arrival is refused at the door and
// fails the verifier when it is pasted into another receipt; and an engine that does not answer in time never turns
// into an allow: refused by default, or absent for the policy to decide. Every server here is local.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isCommitment } from "../src/capture.ts";
import { checkDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair, type KeyPair } from "../src/crypto.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import { PARTNER_FACT, checkPartnerAnswer, signVerdict, type PartnerVerdict } from "../src/door-partner.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";
import { startPartner, type PartnerStub } from "../scripts/fake-partner.ts";

/** The catalogue is public; the API is for arrivals the partner engine judged human, by a verdict it signed. */
const POLICY = `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"api", resource) when { context.facts has partner && context.facts.partner.verdict == "human" };
`;
const HUMAN = { "user-agent": "Mozilla/5.0 (Macintosh)" };

let origin: Origin;
const running: { close(): Promise<void> }[] = [];
beforeAll(async () => {
  origin = await startOrigin();
});
afterAll(async () => {
  for (const r of running.reverse()) await r.close();
  await origin.close();
});

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

interface Door {
  fx: DoorFixture;
  engineKey: KeyPair;
  enginePub: string;
  url: string;
  call(path: string, headers?: Record<string, string>): Promise<{ status: number; bundle: ReceiptBundle; st: ReceiptStatement; arrival: Arrival }>;
  verify(bundle: ReceiptBundle, upstream?: string[]): ReturnType<typeof verifyBundle>;
}

/** A door whose partner engine is the stub, signing with `signer` (the engine's own key unless given another). */
async function doorWith(partner: (engineUrl: string) => Record<string, unknown>, opts: { signer?: KeyPair; slowMs?: number; extra?: Record<string, unknown> } = {}): Promise<Door & { stub: PartnerStub }> {
  const dir = mkdtempSync(join(tmpdir(), "agent-custody-door-partner-"));
  const engineKey = generateKeyPair();
  const stub = await startPartner(opts.signer ?? engineKey, { slowMs: opts.slowMs ?? 5_000 });
  running.push(stub);
  const fx = buildDoorFixture(dir, origin.url, { ...opts.extra });
  const enginePub = writeKeyPair(engineKey, join(fx.dir, "keys"), "engine").pubFile;
  writeFileSync(join(fx.dir, "policy.cedar"), POLICY);
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
  cfg.partner = { engine: "stub-engine", keyFile: "keys/engine.pub", routes: ["api"], ...partner(stub.url) };
  writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
  const host: DoorHost = await createDoorHost(loadDoorConfig(fx.configFile));
  const door: RunningDoor = await serveDoor(host, { port: 0, log: () => {} });
  running.push({ close: async () => { await door.close(); await host.close(); } });
  return {
    fx, engineKey, enginePub, stub, url: door.url,
    async call(path, headers = HUMAN) {
      const res = await fetch(`${door.url}${path}`, { headers });
      await res.arrayBuffer();
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      const st = decode(bundle);
      return { status: res.status, bundle, st, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival };
    },
    verify: (bundle, upstream = [enginePub]) => verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], upstreamKeys: upstream.map(loadPublicKey), logFile: fx.logFile }),
  };
}

const failing = (r: ReturnType<typeof verifyBundle>) => r.checks.filter((c) => !c.ok).map((c) => c.name);

describe("a partner engine's signed verdict", () => {
  it("reaches the policy and lands in a receipt that verifies as attested under the engine's key, bound to this arrival", async () => {
    const d = await doorWith((url) => ({ url }));
    const human = await d.call("/api/orders");
    expect(human.status).toBe(200);
    expect(human.arrival.partner).toEqual({ engine: "stub-engine", outcome: "verified" });
    const fact = human.st.predicate.facts[PARTNER_FACT]!;
    expect(fact).toMatchObject({ tool: "door.partner", provenance: "attested", value: { engine: "stub-engine", verdict: "human", score: 3 } });
    // the engine was asked about this receipt, and signed for it
    expect(d.stub.seen.at(-1)).toMatchObject({ receiptId: human.st.predicate.receiptId, route: "api", method: "GET", path: "/api/orders", headers: { "user-agent": HUMAN["user-agent"] } });
    const r = d.verify(human.bundle);
    expect(failing(r)).toEqual([]);
    expect(r.checks.find((c) => c.name === "fact partner signature (upstream key)")).toMatchObject({ ok: true });

    // a reader who does not hold the engine's key cannot confirm the attested verdict, and the verifier says so
    expect(failing(d.verify(human.bundle, []))).toEqual(["fact partner signature (upstream key)"]);
    // nor can one who holds another key
    expect(failing(d.verify(human.bundle, [d.fx.principalPub]))).toEqual(["fact partner signature (upstream key)"]);

    // the engine's verdict is what the policy reads: a bot verdict, signed just as well, is refused
    const bot = await d.call("/api/orders", { "user-agent": "examplebot/1.0" });
    expect(bot.status).toBe(403);
    expect(bot.st.predicate.facts[PARTNER_FACT]!.value).toMatchObject({ verdict: "bot" });
    expect(failing(d.verify(bot.bundle))).toEqual([]);

    // a route the engine is not configured for is never asked about
    const asked = d.stub.seen.length;
    const read = await d.call("/catalogue/shoes");
    expect(read.status).toBe(200);
    expect(read.arrival.partner).toBeUndefined();
    expect(d.stub.seen.length).toBe(asked);
  });

  it("under the door's default capture rule the plain attestation stays in clear beside the verdict, so the verifier checks it", async () => {
    const d = await doorWith((url) => ({ url }), { extra: { capture: undefined } });
    const human = await d.call("/api/orders");
    expect(human.status).toBe(200);
    const fact = human.st.predicate.facts[PARTNER_FACT]!;
    expect(isCommitment(fact.attestation)).toBe(false);
    expect(isCommitment(human.st.predicate.request.args)).toBe(false);
    const r = d.verify(human.bundle);
    expect(failing(r)).toEqual([]);
    expect(r.checks.find((c) => c.name === "fact partner signature (upstream key)")).toMatchObject({ ok: true });
  });

  it("signed by another key, is not attested, never reaches the policy, and cannot satisfy a rule that requires the partner's verdict", async () => {
    const forger = generateKeyPair();
    const absent = await doorWith((url) => ({ url, onFailure: "absent" }), { signer: forger });
    const r = await absent.call("/api/orders");
    expect(r.arrival.partner).toMatchObject({ engine: "stub-engine", outcome: "rejected" });
    expect(r.arrival.partner!.error).toMatch(/signature does not hold/);
    expect(r.st.predicate.facts[PARTNER_FACT]).toBeUndefined();
    // the policy decided without the fact, and its rule needs it
    expect(r.status).toBe(403);
    expect(r.st.predicate.execution.status).toBe("denied");
    expect(failing(absent.verify(r.bundle))).toEqual([]);

    // by default the door refuses outright, even where the policy would allow without the verdict (the catalogue)
    const deny = await doorWith((url) => ({ url, routes: ["*"] }), { signer: forger });
    const seenBefore = origin.seen.length;
    const refused = await deny.call("/catalogue/shoes");
    expect(refused.status).toBe(503);
    expect(refused.st.predicate.execution).toMatchObject({ status: "withheld" });
    expect(origin.seen.length).toBe(seenBefore);
  });

  it("signed for a different arrival, is refused at the door, and fails the verifier when it is moved into another receipt", async () => {
    const d = await doorWith((url) => ({ url, routes: ["*"] }));
    const first = await d.call("/api/orders");
    expect(first.status).toBe(200);
    // the engine (or anyone who saw its answer) replays that signed verdict for the next arrival, a catalogue read the
    // policy would allow on its own: refused all the same, since a verdict that is not this arrival's is no verdict
    d.stub.mode = "replay";
    const seenBefore = origin.seen.length;
    const replayed = await d.call("/catalogue/shoes");
    expect(replayed.arrival.partner).toEqual({ engine: "stub-engine", outcome: "rejected", error: "the verdict's signature does not hold: signed for a different receipt" });
    expect(replayed.st.predicate.facts[PARTNER_FACT]).toBeUndefined();
    expect(replayed.status).toBe(503);
    expect(origin.seen.length).toBe(seenBefore);

    // an issuer that pastes the first receipt's signed verdict into the second, and re-signs, does not get past a reader
    const doorKey = loadPrivateKey(join(d.fx.dir, "keys", "door.key"));
    const st = decode(replayed.bundle);
    st.predicate.facts[PARTNER_FACT] = first.st.predicate.facts[PARTNER_FACT]!;
    const pasted = { ...replayed.bundle, envelope: dsseSign(RECEIPT_TYPE, st, doorKey) };
    const r = d.verify(pasted);
    expect(r.checks.find((c) => c.name === "fact partner signature (upstream key)")).toMatchObject({ ok: false, detail: "signed for a different receipt" });

    // and an edited verdict under the original signature fails too
    const edited = decode(first.bundle);
    (edited.predicate.facts[PARTNER_FACT]!.value as PartnerVerdict).verdict = "verified-human";
    const r2 = d.verify({ ...first.bundle, envelope: dsseSign(RECEIPT_TYPE, edited, doorKey) });
    expect(r2.checks.find((c) => c.name === "fact partner signature (upstream key)")).toMatchObject({ ok: false, detail: "signed content differs from the result in the receipt" });
  });

  it("that does not arrive in time follows partner.onFailure: deny (the default) refuses with 503, absent leaves the policy to decide; never an allow", async () => {
    const slow = await doorWith((url) => ({ url, timeoutMs: 200, routes: ["*"] }), { slowMs: 3_000 });
    slow.stub.mode = "slow";
    const seenBefore = origin.seen.length;
    // the catalogue's rule needs no verdict, so only the onFailure rule can refuse it
    const refused = await slow.call("/catalogue/shoes");
    expect(refused.status).toBe(503);
    expect(refused.arrival.partner).toMatchObject({ engine: "stub-engine", outcome: "unavailable" });
    expect(refused.st.predicate.execution).toMatchObject({ status: "withheld" });
    expect(String((refused.st.predicate.execution as { reason: string }).reason)).toMatch(/partner engine stub-engine gave no verified verdict \(unavailable/);
    expect(origin.seen.length).toBe(seenBefore);
    expect(failing(slow.verify(refused.bundle))).toEqual([]);

    // the engine down altogether is the same
    await slow.stub.close();
    const down = await slow.call("/catalogue/shoes");
    expect(down.status).toBe(503);
    expect(down.arrival.partner?.outcome).toBe("unavailable");

    // absent: asked on every route, the catalogue's rule does not need the verdict and the API's does
    const absent = await doorWith((url) => ({ url, timeoutMs: 200, onFailure: "absent", routes: ["*"] }), { slowMs: 3_000 });
    absent.stub.mode = "slow";
    const read = await absent.call("/catalogue/shoes");
    expect(read.status).toBe(200);
    expect(read.arrival.partner?.outcome).toBe("unavailable");
    expect(read.st.predicate.facts[PARTNER_FACT]).toBeUndefined();
    const api = await absent.call("/api/orders");
    expect(api.status).toBe(403);
    expect(api.st.predicate.execution.status).toBe("denied");
  });
});

describe("checkPartnerAnswer", () => {
  const key = generateKeyPair();
  const dir = mkdtempSync(join(tmpdir(), "agent-custody-partner-check-"));
  const pub = loadPublicKey(writeKeyPair(key, dir, "engine").pubFile);
  const expected = { engine: "e", receiptId: "00000000-0000-4000-8000-000000000001", route: "api" };
  const verdict: PartnerVerdict = { engine: "e", verdict: "human", score: 1 };

  it("accepts exactly a verdict of the configured engine signed for this receipt and route", () => {
    expect(checkPartnerAnswer({ verdict, signature: signVerdict(verdict, key, expected.receiptId, "api") }, pub, expected).check.outcome).toBe("verified");
    const otherRoute = checkPartnerAnswer({ verdict, signature: signVerdict(verdict, key, expected.receiptId, "refund") }, pub, expected);
    expect(otherRoute.check).toMatchObject({ outcome: "rejected", error: "the verdict's signature does not hold: signed for tool refund" });
    const otherEngine = { ...verdict, engine: "f" };
    expect(checkPartnerAnswer({ verdict: otherEngine, signature: signVerdict(otherEngine, key, expected.receiptId, "api") }, pub, expected).check.outcome).toBe("rejected");
  });

  it("refuses a verdict Cedar could not read or that carries fields of the engine's choosing", () => {
    for (const bad of [{ ...verdict, score: 0.5 }, { ...verdict, score: null }, { ...verdict, extra: "x" }, { ...verdict, verdict: "" }, { engine: "e" }]) {
      const r = checkPartnerAnswer({ verdict: bad, signature: signVerdict(bad as PartnerVerdict, key, expected.receiptId, "api") }, pub, expected);
      expect(r.check.outcome).toBe("rejected");
    }
  });

  it("refuses an envelope with more than the plain attestation, though its signature holds", () => {
    const signature = signVerdict(verdict, key, expected.receiptId, "api");
    const padded = { ...signature, signatures: [...signature.signatures, { keyid: "0".repeat(64), sig: signature.signatures[0]!.sig }] };
    expect(checkPartnerAnswer({ verdict, signature: padded }, pub, expected).check).toMatchObject({ outcome: "rejected", error: "the signature envelope carries more than the attestation of this verdict" });
  });
});

describe("partner config", () => {
  it("refuses a partner route the door does not have, so a typo does not silently skip the engine", () => {
    const fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-partner-cfg-")), "http://127.0.0.1:1", { partner: { engine: "e", url: "http://127.0.0.1:2/v", keyFile: "keys/principal.pub", routes: ["apis"] } });
    expect(() => loadDoorConfig(fx.configFile)).toThrow(/partner.routes names a route the door does not have/);
    const ok = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-partner-cfg-")), "http://127.0.0.1:1", { partner: { engine: "e", url: "http://127.0.0.1:2/v", keyFile: "keys/principal.pub", routes: ["api"] } });
    expect(loadDoorConfig(ok.configFile).partner).toMatchObject({ onFailure: "deny", timeoutMs: 1500, keyFile: join(ok.dir, "keys", "principal.pub") });
    expect(checkDoorConfig(ok.configFile).filter((f) => f.check === "partner")).toEqual([{ level: "ok", check: "partner", message: expect.stringContaining("the arrival is refused with 503") }]);
    // a key file the door cannot load is a startup error, reported before the door is run
    const missing = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-partner-cfg-")), "http://127.0.0.1:1", { partner: { engine: "e", url: "http://127.0.0.1:2/v", keyFile: "keys/nope.pub", routes: ["api"] } });
    expect(checkDoorConfig(missing.configFile).filter((f) => f.check === "partner").map((f) => f.level)).toEqual(["error"]);
  });
});

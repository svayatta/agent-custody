// did:key identity on grants. The codec reproduces the did:key spec's own Ed25519 identifiers, and its decoding is
// checked independently: the spec's example lists the X25519 key derived from its Ed25519 key, and converting the
// decoded key reproduces that X25519 identifier. At the door, a grant naming its agent by did:key is verified when a
// trusted principal signed it; claimed when the did:key does not decode, when the grant's agentKey is another key, or
// when the principal is not trusted; and an arrival with nothing is unknown. Each is a distinct receipt that verifies.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, publicKeyToPem, writeKeyPair, type Envelope, type KeyPair } from "../src/crypto.ts";
import { createDelegation, decodeDelegation } from "../src/delegation.ts";
import { base58btcDecode, base58btcEncode, didKeyOf, publicKeyFromDidKey } from "../src/did-key.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

// from https://w3c-ccg.github.io/did-key-spec/ ("Test Vectors" and "Ed25519 with X25519")
const SPEC_ED25519 = ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"];
const SPEC_X25519_OF_FIRST = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";

/** The X25519 public key of an Ed25519 public key: u = (1 + y) / (1 - y) mod 2^255 - 19. */
function x25519Of(ed: Uint8Array): Uint8Array {
  const p = 2n ** 255n - 19n;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) + BigInt(i === 31 ? ed[i]! & 0x7f : ed[i]!);
  const pow = (b: bigint, e: bigint) => {
    let r = 1n;
    for (b %= p; e > 0n; e >>= 1n, b = (b * b) % p) if (e & 1n) r = (r * b) % p;
    return r;
  };
  let u = ((1n + y) * pow((1n - y + p) % p, p - 2n)) % p;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++, u >>= 8n) out[i] = Number(u & 0xffn);
  return out;
}

describe("did:key for Ed25519", () => {
  it("reproduces the spec's identifiers, and the decoded key gives the spec's own X25519 key", () => {
    for (const did of SPEC_ED25519) expect(didKeyOf(publicKeyFromDidKey(did).publicKey)).toBe(did);
    const raw = base58btcDecode(SPEC_ED25519[0]!.slice("did:key:z".length)).subarray(2);
    expect("z" + base58btcEncode(Uint8Array.from([0xec, 0x01, ...x25519Of(raw)]))).toBe(SPEC_X25519_OF_FIRST);
  });

  it("a generated key's did:key starts z6Mk and names that key", () => {
    const kp = generateKeyPair();
    const did = didKeyOf(kp.publicKey);
    expect(did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
    expect(publicKeyFromDidKey(did).keyid).toBe(kp.keyid);
  });

  it("refuses what does not name an Ed25519 key, saying why", () => {
    expect(() => publicKeyFromDidKey("did:web:shop.example")).toThrow("is not a base58btc did:key");
    expect(() => publicKeyFromDidKey("did:key:z6Mk0OIl")).toThrow('"0" is not a base58btc character');
    expect(() => publicKeyFromDidKey(`did:key:${SPEC_X25519_OF_FIRST}`)).toThrow("does not name an Ed25519 key");
    const short = `did:key:z${base58btcEncode(Uint8Array.from([0xed, 0x01, ...new Uint8Array(31).fill(7)]))}`;
    expect(() => publicKeyFromDidKey(short)).toThrow("the did:key's Ed25519 key is 31 bytes, not 32");
  });
});

describe("a did:key grant at the door", () => {
  let origin: Origin;
  let fx: DoorFixture;
  let host: DoorHost;
  let door: RunningDoor;
  const agent = generateKeyPair();
  const did = didKeyOf(agent.publicKey);
  const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
  const grantFrom = (signer: KeyPair, agentId: string, extra: { agentKey?: string } = {}) => createDelegation(signer, { version: "0.1", principal: "shop-owner", agent: agentId, scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString(), ...extra });
  const refund = async (grant?: Envelope) => {
    const res = await fetch(`${door.url}/refunds`, { method: "POST", headers: { "content-type": "application/json", ...(grant ? { authorization: `Bearer ${grantHeader(grant)}` } : {}) }, body: JSON.stringify({ order: "o_d", amount: 100 }) });
    await res.text();
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
    const st = decode(bundle);
    return { res, st, id: st.predicate.receiptId, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, ok: verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile }).ok };
  };

  beforeAll(async () => {
    origin = await startOrigin();
    fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-did-key-")), origin.url);
    host = await createDoorHost(loadDoorConfig(fx.configFile));
    door = await serveDoor(host, { port: 0, log: () => {} });
  }, 60_000);
  afterAll(async () => {
    await door?.close();
    await host?.close();
    await origin?.close();
  });

  it("verified, claimed, and unknown, each a distinct receipt that verifies", async () => {
    const verified = await refund(grantFrom(fx.principalKey, did, { agentKey: publicKeyToPem(agent.publicKey) }));
    expect(verified.res.status).toBe(200);
    expect(verified.arrival).toMatchObject({ class: "verified", grant: "verified", subject: did });
    expect(verified.st.predicate.agent).toEqual({ id: did, provenance: "attested" });
    expect(verified.ok).toBe(true);
    // agentKey is optional: the did:key names the key by itself
    expect((await refund(grantFrom(fx.principalKey, did))).arrival.class).toBe("verified");

    const garbled = await refund(grantFrom(fx.principalKey, "did:key:z6Mk0bad"));
    expect(garbled.res.status).toBe(403);
    expect(garbled.arrival).toMatchObject({ class: "claimed", grant: "invalid", subject: "did:key:z6Mk0bad" });
    expect(garbled.arrival.grantError).toMatch(/^the grant's did:key agent does not decode: /);
    expect(garbled.st.predicate.agent).toEqual({ id: "did:key:z6Mk0bad", provenance: "claimed" });
    expect(garbled.st.predicate.principal).toEqual({ id: null, provenance: "claimed" });
    expect(garbled.ok).toBe(true);

    const twoKeys = await refund(grantFrom(fx.principalKey, did, { agentKey: publicKeyToPem(generateKeyPair().publicKey) }));
    expect(twoKeys.res.status).toBe(403);
    expect(twoKeys.arrival).toMatchObject({ class: "claimed", grant: "invalid", grantError: "the grant's agentKey is not the key its did:key agent names" });
    expect(twoKeys.ok).toBe(true);

    const stranger = await refund(grantFrom(generateKeyPair(), did));
    expect(stranger.res.status).toBe(403);
    expect(stranger.arrival).toMatchObject({ class: "claimed", grant: "invalid", subject: did });
    expect(stranger.ok).toBe(true);

    const nothing = await refund();
    expect(nothing.res.status).toBe(403);
    expect(nothing.arrival).toMatchObject({ class: "unknown", grant: "absent", subject: "unknown" });
    expect(nothing.ok).toBe(true);

    expect(new Set([verified.id, garbled.id, twoKeys.id, stranger.id, nothing.id]).size).toBe(5);
  });

  it("`agent-custody grant --did-key` names the agent by its key's did:key, and needs --agent-key without --agent", () => {
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-did-key-cli-"));
    const principal = writeKeyPair(generateKeyPair(), dir, "principal");
    const pub = writeKeyPair(agent, dir, "agent").pubFile;
    const cli = (...args: string[]) => spawnSync(process.execPath, [join(import.meta.dirname, "..", "src", "cli.ts"), "grant", "--key", principal.keyFile, "--principal", "shop-owner", "--scopes", "refund", "--out", join(dir, "grant.json"), ...args], { encoding: "utf8" });
    const ok = cli("--agent-key", pub, "--did-key");
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout).toContain(did);
    const grant = decodeDelegation(JSON.parse(readFileSync(join(dir, "grant.json"), "utf8")) as Envelope)!;
    expect(grant.agent).toBe(did);
    expect(grant.agentKey).toBe(publicKeyToPem(agent.publicKey));
    for (const bad of [cli("--did-key"), cli("--agent-key", pub, "--did-key", "--agent", "someone")]) {
      expect(bad.status).not.toBe(0);
      expect(bad.stderr).toContain("--did-key names the agent by the did:key of --agent-key");
    }
  });
});

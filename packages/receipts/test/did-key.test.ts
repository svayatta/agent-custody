// did:key identity on grants. The codec reproduces the did:key spec's own Ed25519 identifiers, and its decoding is
// checked independently: the spec's example lists the X25519 key derived from its Ed25519 key, and converting the
// decoded key reproduces that X25519 identifier. At the door, a grant naming its agent by did:key is verified when a
// trusted principal signed it; claimed when the did:key does not decode, when the grant's agentKey is another key, or
// when the principal is not trusted; and an arrival with nothing is unknown. Each is a distinct receipt that verifies.
// A request signature whose keyid is the grant's did:key binds the grant to its sender; one by another key is wrong-sender.
import { spawnSync } from "node:child_process";
import { sign as edSign } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, publicKeyToPem, writeKeyPair, type Envelope, type KeyPair } from "../src/crypto.ts";
import { createDelegation, decodeDelegation, delegateFrom, grantDigest } from "../src/delegation.ts";
import { base58btcDecode, base58btcEncode, didKeyOf, publicKeyFromDidKey } from "../src/did-key.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, classifyArrival, createDoorHost, serveDoor, type Arrival, type DoorHost, type DoorRequest, type RunningDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { createWebBotAuthVerifier, parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
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

  it("keeps leading zero bytes: each is a '1'", () => {
    expect(base58btcEncode(Uint8Array.from([0, 0, 1]))).toBe("112");
    expect([...base58btcDecode("112")]).toEqual([0, 0, 1]);
  });

  it("refuses what does not name an Ed25519 key, saying why", () => {
    expect(() => publicKeyFromDidKey(`did:key:z${"6".repeat(200)}`)).toThrow("the did:key is 209 characters; an Ed25519 did:key is 56");
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
    // bearer-grade: verified with no request signature, so a did:key says which key, not that the sender holds it
    expect(verified.arrival.signature).toBe("absent");
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

  /** The door's classification of a refund arriving with this grant, and optionally a request signature it verified. */
  const classify = (g: Envelope, signature?: Parameters<typeof classifyArrival>[5], revoked?: Parameters<typeof classifyArrival>[6]) => {
    const req = { method: "POST", url: "/refunds", headers: { host: "shop.example", authorization: `Bearer ${grantHeader(g)}` }, socket: { remoteAddress: "203.0.113.9" } } as unknown as DoorRequest;
    return classifyArrival(req, [loadPublicKey(fx.principalPub)], "refund", false, new Date().toISOString(), signature, revoked).arrival;
  };

  it("under a Web Bot Auth signature from an https origin a did:key grant is wrong-sender", () => {
    const a = classify(grantFrom(fx.principalKey, did), { outcome: "verified", agent: "https://crawler.example", keyid: "k1", label: "sig1" });
    expect(a).toMatchObject({ class: "claimed", grant: "wrong-sender", subject: did, signature: "verified" });
  });

  describe("under a request signature whose keyid is a did:key", () => {
    const AUTHORITY = "shop.example";
    let sfx: DoorFixture;
    let shost: DoorHost;
    let sdoor: RunningDoor;
    let n = 0;
    /** RFC 9421 headers signed by `key`, with `keyid` as the did:key (that key's own, unless given), over @authority. */
    const signedBy = (key: KeyPair, o: { keyid?: string; created?: number; nonce?: string; authority?: string } = {}) => {
      const created = o.created ?? Math.floor(Date.now() / 1000);
      const input = `sig1=("@authority");created=${created};expires=${created + 60};keyid="${o.keyid ?? didKeyOf(key.publicKey)}";alg="ed25519";nonce="${o.nonce ?? `did-${process.pid}-${++n}`}";tag="web-bot-auth"`;
      const base = signatureBase({ method: "POST", target: "/refunds", authority: o.authority ?? AUTHORITY, header: () => undefined }, parseDictionary(input).get("sig1") as SfInnerList);
      return { "signature-input": input, signature: `sig1=:${edSign(null, Buffer.from(base), key.privateKey).toString("base64")}:` };
    };
    // node:http, because fetch does not send a Host other than the URL's
    const send = (headers: Record<string, string>, grant?: Envelope) => new Promise<{ status: number; st: ReceiptStatement; arrival: Arrival; ok: boolean }>((resolve, reject) => {
      const u = new URL(sdoor.url);
      const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path: "/refunds", headers: { host: AUTHORITY, "content-type": "application/json", ...headers, ...(grant ? { authorization: `Bearer ${grantHeader(grant)}` } : {}) } }, (res) => {
        res.resume();
        res.on("end", () => {
          const bundle = JSON.parse(readFileSync(join(sfx.receiptsDir, `${res.headers[RECEIPT_HEADER]}.json`), "utf8")) as ReceiptBundle;
          const st = decode(bundle);
          resolve({ status: res.statusCode!, st, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, ok: verifyBundle(bundle, { issuerKeys: [loadPublicKey(sfx.doorPub)], principalKeys: [loadPublicKey(sfx.principalPub)], logFile: sfx.logFile }).ok });
        });
      });
      req.on("error", reject);
      req.end(JSON.stringify({ order: "o_s", amount: 100 }));
    });
    const sfxGrant = (agentId: string) => createDelegation(sfx.principalKey, { version: "0.1", principal: "shop-owner", agent: agentId, scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });

    beforeAll(async () => {
      sfx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-did-key-sig-")), origin.url, { webBotAuth: { agents: ["https://crawler.example"], authorities: [AUTHORITY] } });
      // the did:key carries its key, so the door fetches nothing: a directory fetch fails the test
      shost = await createDoorHost(loadDoorConfig(sfx.configFile), { fetch: ((input: string | URL | Request, init?: RequestInit) => (String(input instanceof Request ? input.url : input).startsWith("https://") ? Promise.reject(new Error("the door fetched a directory")) : fetch(input, init))) as typeof fetch });
      sdoor = await serveDoor(shost, { port: 0, log: () => {} });
    }, 60_000);
    afterAll(async () => {
      await sdoor?.close();
      await shost?.close();
    });

    it("by its own key, the grant is verified and bound to its sender, and the receipt verifies", async () => {
      const r = await send(signedBy(agent), sfxGrant(did));
      expect(r.status).toBe(200);
      expect(r.arrival).toMatchObject({ class: "verified", subject: did, grant: "verified", signature: "verified", signatureAgent: did, signatureKeyid: did, rate: { by: "agent" } });
      expect(r.arrival.signatureError).toBeUndefined();
      expect(r.st.predicate.agent).toEqual({ id: did, provenance: "attested" });
      expect(r.st.predicate.delegation).toBeDefined();
      expect(r.ok).toBe(true);
    });

    it("by another key, the grant is wrong-sender, the signature counts for nothing, and the receipt verifies", async () => {
      const thief = generateKeyPair();
      const thiefDid = didKeyOf(thief.publicKey);
      const r = await send(signedBy(thief), sfxGrant(did));
      expect(r.status).toBe(403);
      expect(r.arrival).toMatchObject({ class: "claimed", subject: did, grant: "wrong-sender", signature: "invalid", signatureAgent: thiefDid, grantError: `the grant names agent "${did}", and the request is signed by ${thiefDid}` });
      expect(r.arrival.signatureError).toContain("no verified grant in the request names that did:key");
      expect(r.st.predicate.agent).toEqual({ id: did, provenance: "claimed" });
      expect(r.st.predicate.delegation).toBeUndefined();
      expect(r.ok).toBe(true);
      // a grant for a named agent is not bound by a did:key signature either
      expect((await send(signedBy(thief), sfxGrant("shopping-agent"))).arrival).toMatchObject({ class: "claimed", grant: "wrong-sender", signature: "invalid" });
    });

    it("a signature that names the grant's did:key and is made with another key does not verify, and the grant stays bearer-grade", async () => {
      const r = await send(signedBy(generateKeyPair(), { keyid: did }), sfxGrant(did));
      expect(r.arrival).toMatchObject({ class: "verified", grant: "verified", signature: "invalid", signatureError: `sig1 does not verify with the key that ${did} names` });
      expect(r.ok).toBe(true);
      const moved = await send(signedBy(agent, { authority: "other.example" }), sfxGrant(did));
      expect(moved.arrival).toMatchObject({ signature: "invalid", signatureError: `sig1 does not verify with the key that ${did} names` });
      const garbled = await send(signedBy(agent, { keyid: "did:key:z6Mk0bad" }), sfxGrant(did));
      expect(garbled.arrival.signature).toBe("invalid");
      expect(garbled.arrival.signatureError).toMatch(/^the keyid of sig1 does not decode: /);
    });

    it("an expired signature and a replayed nonce are invalid", async () => {
      const old = await send(signedBy(agent, { created: Math.floor(Date.now() / 1000) - 3600 }), sfxGrant(did));
      expect(old.arrival).toMatchObject({ grant: "verified", signature: "invalid", signatureError: expect.stringMatching(/^sig1 expired at /) });
      const headers = signedBy(agent);
      expect((await send(headers, sfxGrant(did))).arrival.signature).toBe("verified");
      const again = await send(headers, sfxGrant(did));
      expect(again.arrival).toMatchObject({ signature: "invalid", signatureError: "sig1 repeats a nonce already used" });
      expect(again.ok).toBe(true);
    });

    it("a did:key signature keeps its nonce only for the agent of a trusted grant, so a stranger's keys cannot fill the nonce store", async () => {
      const v = createWebBotAuthVerifier({ agents: [], authorities: [AUTHORITY], requireNonce: true, maxAgeSeconds: 300, clockSkewSeconds: 60, timeoutMs: 1000, maxDirectoryBytes: 1024, cacheSeconds: 300, maxNonces: 1 }, fetch);
      const req = (h: Record<string, string>) => ({ method: "POST", target: "/refunds", authority: AUTHORITY, header: (name: string) => (Object.hasOwn(h, name) ? [h[name]!] : undefined) });
      const stranger = generateKeyPair();
      expect((await v.verify(req(signedBy(stranger)))).outcome).toBe("verified");
      expect((await v.verify(req(signedBy(stranger)), did)).outcome).toBe("verified");
      expect(v.nonces()).toBe(0);
      const headers = signedBy(agent);
      expect(await v.verify(req(headers), did)).toMatchObject({ outcome: "verified", agent: did, keyid: did });
      expect(v.nonces()).toBe(1);
      expect(await v.verify(req(headers), did)).toMatchObject({ outcome: "invalid", error: "sig1 repeats a nonce already used" });
    });

    it("with no verified grant for it, a did:key signature never makes the arrival verified: anyone can make a key", async () => {
      const alone = await send(signedBy(agent));
      expect(alone.status).toBe(403);
      expect(alone.arrival).toMatchObject({ class: "claimed", subject: "unknown", grant: "absent", signature: "invalid", rate: { by: "remote" } });
      expect(alone.st.predicate.agent).toEqual({ id: "unknown", provenance: "claimed" });
      expect(alone.ok).toBe(true);
      const stranger = await send(signedBy(agent), grantFrom(generateKeyPair(), did));
      expect(stranger.arrival).toMatchObject({ class: "claimed", grant: "invalid", signature: "invalid" });
      const expired = createDelegation(sfx.principalKey, { version: "0.1", principal: "shop-owner", agent: did, scopes: ["refund"], issuedAt: new Date(Date.now() - 7200_000).toISOString(), expiresAt: new Date(Date.now() - 3600_000).toISOString() });
      expect((await send(signedBy(agent), expired)).arrival).toMatchObject({ class: "claimed", grant: "invalid", signature: "invalid" });
    });
  });

  it("a revoked did:key grant is revoked", () => {
    const g = grantFrom(fx.principalKey, did);
    expect(classify(g, undefined, (digests) => (digests.includes(grantDigest(g)) ? "the grant has been revoked" : null))).toMatchObject({ class: "claimed", grant: "revoked" });
  });

  it("every link of a chain is checked: a parent whose did:key and agentKey disagree makes the sub-agent claimed", () => {
    const lead = generateKeyPair();
    const leadDid = didKeyOf(lead.publicKey);
    const good = grantFrom(fx.principalKey, leadDid, { agentKey: publicKeyToPem(lead.publicKey) });
    expect(classify(delegateFrom(good, lead, { agent: "helper", scopes: ["refund"] }))).toMatchObject({ class: "verified", subject: "helper" });

    // the parent names the agent did:key:A and agentKey B; B signs the sub-grant, so the chain verifies, and the door refuses it
    const other = generateKeyPair();
    const split = grantFrom(fx.principalKey, leadDid, { agentKey: publicKeyToPem(other.publicKey) });
    const a = classify(delegateFrom(split, other, { agent: "helper", scopes: ["refund"] }));
    expect(a).toMatchObject({ class: "claimed", grant: "invalid", subject: "helper", grantError: `link 0 (${leadDid}): the grant's agentKey is not the key its did:key agent names` });
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

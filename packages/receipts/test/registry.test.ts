// The agent registry. An organisation registers an agent on the portal with the agent's own did:key, and the portal
// signs it a passport. A door that holds only the registry's key, read from the registry's key document, admits that
// agent as verified when the request carries the passport and is signed by the passport's key: no grant, no setup per
// agent, nothing asked of the registry at request time. A passport is public, so it is worth nothing on its own: under
// another key's signature, or with no signature, the arrival is claimed. Revoking an agent stops its passports.
// Postgres runs in-process through PGlite; the portal and the door run on loopback.
import { sign as edSign } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, publicKeyFromPem, type Envelope, type KeyPair } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { didKeyOf } from "../src/did-key.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, classifyArrival, createDoorHost, serveDoor, type Arrival, type DoorHost, type DoorRequest, type RunningDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { PortalStore, servePortal, signSession, type RunningPortal } from "../src/portal.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { issuePassport, passportHeader, PASSPORT_HEADER, PASSPORT_TYPE, REGISTRY_DOCUMENT_PATH, RegistryStore, verifyPassport, type AgentEntry } from "../src/registry.ts";
import { localSigner } from "../src/signer.ts";
import { verifyBundle } from "../src/verify.ts";
import { parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

const SECRET = "portal-secret-for-registry-tests-32-chars";
const PORTAL_URL = "https://app.example.test/";
const AUTHORITY = "shop.example";
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

const registryKey = generateKeyPair();
const signer = localSigner(registryKey);

describe("a passport", () => {
  const agent = generateKeyPair();
  const entry = (o: Partial<AgentEntry> = {}): AgentEntry => ({ id: "agt_0123456789abcdef", owner: "acme", name: "Acme shopper", contact: "agents@acme.example", capabilities: ["refunds"], agent: didKeyOf(agent.publicKey), createdAt: new Date().toISOString(), expiresAt: inDays(30), revokedAt: null, ...o });

  it("verifies under the registry's key while it lives, and names the agent's key, owner, contact, and capabilities", async () => {
    const env = await issuePassport(signer, PORTAL_URL, entry(), 3600);
    const r = verifyPassport(env, [registryKey], new Date().toISOString());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.passport).toMatchObject({ registry: PORTAL_URL, agentId: "agt_0123456789abcdef", agent: didKeyOf(agent.publicKey), owner: "acme", contact: "agents@acme.example", capabilities: ["refunds"] });
    expect(Date.parse(r.passport.expiresAt) - Date.parse(r.passport.issuedAt)).toBe(3600_000);
    expect(r.keyid).toBe(registryKey.keyid);
  });

  it("never outlives the registration it was issued under", async () => {
    const soon = new Date(Date.now() + 60_000).toISOString();
    const env = await issuePassport(signer, PORTAL_URL, entry({ expiresAt: soon }), 86_400);
    const r = verifyPassport(env, [registryKey], new Date().toISOString());
    expect(r.ok && r.passport.expiresAt).toBe(soon);
  });

  it("is refused for a revoked or expired agent", async () => {
    await expect(issuePassport(signer, PORTAL_URL, entry({ revokedAt: new Date().toISOString() }))).rejects.toThrow("is revoked");
    await expect(issuePassport(signer, PORTAL_URL, entry({ expiresAt: new Date(Date.now() - 1000).toISOString() }))).rejects.toThrow("is expired");
  });

  it("does not verify under another key, outside its window, edited, or as another type", async () => {
    const env = await issuePassport(signer, PORTAL_URL, entry(), 3600);
    const now = new Date().toISOString();
    expect(verifyPassport(env, [generateKeyPair()], now)).toMatchObject({ ok: false, error: expect.stringContaining("not signed by a trusted registry key") });
    expect(verifyPassport(env, [], now)).toMatchObject({ ok: false, error: "the door trusts no registry key" });
    expect(verifyPassport(env, [registryKey], inDays(1))).toMatchObject({ ok: false, error: expect.stringContaining("the passport is valid from") });
    const payload = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8"));
    const edited: Envelope = { ...env, payload: Buffer.from(JSON.stringify({ ...payload, capabilities: ["refunds", "payouts"] })).toString("base64") };
    expect(verifyPassport(edited, [registryKey], now).ok).toBe(false);
    expect(verifyPassport({ ...env, payloadType: "application/vnd.agent-custody.delegation+json" }, [registryKey], now)).toMatchObject({ ok: false, error: expect.stringContaining(`not ${PASSPORT_TYPE}`) });
    // signed by the registry, and still not a passport: the agent is not a did:key
    const notDid = await signer.sign(PASSPORT_TYPE, { ...payload, agent: "shopping-agent" });
    expect(verifyPassport(notDid, [registryKey], now)).toMatchObject({ ok: false, error: expect.stringContaining("not well formed") });
  });
});

describe("the agent registry on the portal", () => {
  let db: PGlite;
  let tenancy: PostgresTenancy;
  let portal: RunningPortal;
  let plain: RunningPortal;

  // each person calls from an address of their own, so the portal's per-address limit on registrations is not reached
  let addresses = 0;
  const browser = (base: () => string, initialCookie = "") => {
    let cookie = initialCookie;
    const from = `10.9.0.${++addresses}`;
    return async (method: string, path: string, body?: unknown) => {
      const res = await fetch(new URL(path, base()), { method, headers: { "x-forwarded-for": from, ...(cookie ? { cookie } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
      const set = res.headers.get("set-cookie");
      if (set) cookie = set.split(";")[0]!;
      return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
    };
  };
  const open = (path: string) => fetch(new URL(path, portal.url)).then(async (r) => ({ status: r.status, json: (await r.json()) as any }));
  const owner = async (tenant: string) => {
    const call = browser(() => portal.url);
    expect((await call("POST", "/api/register", { email: `${tenant}@example.com`, password: "a-long-enough-password", tenant, name: "Dana", company: tenant })).status).toBe(200);
    return call;
  };

  beforeAll(async () => {
    db = new PGlite();
    await db.query("SELECT 1");
    tenancy = new PostgresTenancy(db);
    portal = await servePortal({ tenancy, client: db, secret: SECRET, publicUrl: "https://log.example.test/", portalUrl: PORTAL_URL, registry: { signer, passportSeconds: 3600 }, trustProxy: true, log: () => {} }, { port: 0 });
    plain = await servePortal({ tenancy, client: db, secret: SECRET, publicUrl: "https://log.example.test/", portalUrl: PORTAL_URL, trustProxy: true, log: () => {}, prefix: "plain_" }, { port: 0 });
  }, 60_000);
  afterAll(async () => {
    await portal?.close();
    await plain?.close();
    await db?.close();
  });

  it("publishes its keys at a well-known path", async () => {
    const doc = await open(REGISTRY_DOCUMENT_PATH);
    expect(doc.status).toBe(200);
    expect(doc.json).toMatchObject({ registry: PORTAL_URL, passportType: PASSPORT_TYPE, passportHeader: PASSPORT_HEADER, passportSeconds: 3600, keys: [{ keyid: registryKey.keyid, alg: "ed25519" }] });
    expect(publicKeyFromPem(doc.json.keys[0].publicKeyPem).keyid).toBe(registryKey.keyid);
  });

  it("registers an agent with its key, owner, contact, capabilities, and expiry, and hands back a passport that verifies", async () => {
    const call = await owner("acme");
    const agent = generateKeyPair();
    const r = await call("POST", "/api/agents", { name: "Acme shopper", contact: "agents@acme.example", capabilities: ["refunds", "catalogue", "refunds"], agent: didKeyOf(agent.publicKey), expiresAt: inDays(90) });
    expect(r.status).toBe(200);
    expect(r.json.agent).toMatchObject({ id: expect.stringMatching(/^agt_[0-9a-f]{16}$/), name: "Acme shopper", owner: "acme", contact: "agents@acme.example", capabilities: ["catalogue", "refunds"], agent: didKeyOf(agent.publicKey), status: "active" });
    expect(r.json.agent.keys).toEqual([{ kty: "OKP", crv: "Ed25519", x: agent.publicKey.export({ format: "jwk" }).x, kid: didKeyOf(agent.publicKey), exp: Math.floor(Date.parse(r.json.agent.expiresAt) / 1000) }]);
    const v = verifyPassport(r.json.passport, [registryKey], new Date().toISOString());
    expect(v.ok && v.passport).toMatchObject({ agentId: r.json.agent.id, owner: "acme", capabilities: ["catalogue", "refunds"] });

    // anyone may read the entry and fetch a fresh passport: it is worth nothing without the agent's key
    expect((await open(`/registry/agents/${r.json.agent.id}`)).json).toEqual(r.json.agent);
    const fresh = await open(`/registry/agents/${r.json.agent.id}/passport`);
    expect(fresh.status).toBe(200);
    expect(verifyPassport(fresh.json, [registryKey], new Date().toISOString()).ok).toBe(true);
    expect((await open("/registry/agents/agt_ffffffffffffffff")).status).toBe(404);
    expect((await open("/registry/agents/../api/me")).status).toBe(404);

    expect((await call("GET", "/api/agents")).json.agents.map((a: { id: string }) => a.id)).toEqual([r.json.agent.id]);
    const audit = await tenancy.audit({ tenant: "acme" });
    expect(audit.find((e) => e.action === "agent.register")?.detail).toMatchObject({ agent: r.json.agent.id, key: didKeyOf(agent.publicKey) });
  });

  it("refuses a key that is not an Ed25519 did:key, an expiry in the past or over a year out, and a key another agent holds", async () => {
    const call = await owner("bravo");
    const key = didKeyOf(generateKeyPair().publicKey);
    const base = { name: "Bravo bot", contact: "ops@bravo.example", agent: key, expiresAt: inDays(30) };
    for (const [body, error] of [
      [{ ...base, agent: "did:key:z6Mk0bad" }, "agent:"],
      [{ ...base, agent: "https://bravo.example" }, "agent:"],
      [{ ...base, expiresAt: inDays(-1) }, "must expire in the future"],
      [{ ...base, expiresAt: inDays(400) }, "at most 366 days"],
      [{ ...base, capabilities: ["Refunds!"] }, "capabilities"],
      [{ ...base, name: "" }, "name"],
      [{ ...base, contact: "line\nbreak" }, "control characters"],
    ] as const) {
      const r = await call("POST", "/api/agents", body);
      expect(r.status, JSON.stringify(body)).toBe(400);
      expect(r.json.error).toContain(error);
    }
    expect((await call("POST", "/api/agents", base)).status).toBe(200);
    expect((await call("POST", "/api/agents", { ...base, name: "Copy" })).json.error).toContain("already registered to an agent");
  });

  it("rotates an agent's key: the new passport names the new key", async () => {
    const call = await owner("charlie");
    const first = generateKeyPair();
    const second = generateKeyPair();
    const r = await call("POST", "/api/agents", { name: "Charlie agent", contact: "c@charlie.example", agent: didKeyOf(first.publicKey), expiresAt: inDays(30) });
    const u = await call("POST", `/api/agents/${r.json.agent.id}`, { agent: didKeyOf(second.publicKey), capabilities: ["checkout"] });
    expect(u.status).toBe(200);
    expect(u.json.agent).toMatchObject({ agent: didKeyOf(second.publicKey), capabilities: ["checkout"], name: "Charlie agent" });
    const v = verifyPassport(u.json.passport, [registryKey], new Date().toISOString());
    expect(v.ok && v.passport.agent).toBe(didKeyOf(second.publicKey));
    expect((await call("POST", `/api/agents/${r.json.agent.id}`, {})).json.error).toContain("nothing to change");
    expect((await tenancy.audit({ tenant: "charlie" })).find((e) => e.action === "agent.update")?.detail).toMatchObject({ changed: ["agent", "capabilities"] });
  });

  it("revokes an agent: its entry says so and it gets no more passports; another tenant cannot touch it", async () => {
    const call = await owner("delta");
    const other = await owner("echo");
    const r = await call("POST", "/api/agents", { name: "Delta agent", contact: "d@delta.example", agent: didKeyOf(generateKeyPair().publicKey), expiresAt: inDays(30) });
    const id = r.json.agent.id;
    expect((await other("POST", `/api/agents/${id}/revoke`, {})).status).toBe(404);
    expect((await other("POST", `/api/agents/${id}`, { name: "Mine now" })).status).toBe(404);
    expect((await call("POST", `/api/agents/${id}/revoke`, {})).json).toEqual({ revoked: true });
    expect((await call("POST", `/api/agents/${id}/revoke`, {})).status).toBe(404);
    expect((await open(`/registry/agents/${id}`)).json.status).toBe("revoked");
    expect(await open(`/registry/agents/${id}/passport`)).toEqual({ status: 410, json: { error: "the agent is revoked; the registry issues it no passport", status: "revoked" } });
    expect((await call("POST", `/api/agents/${id}`, { name: "Back" })).status).toBe(404);
  });

  it("lets a read-only member list agents and not register one", async () => {
    await owner("foxtrot");
    const store = new PortalStore(db);
    const reader = await store.createUser("reader@foxtrot.example", "a-long-enough-password");
    await store.addMember(reader.id, "foxtrot", "readonly");
    const call = browser(() => portal.url, `custody_session=${signSession(SECRET, reader.id)}`);
    expect((await call("GET", "/api/agents")).status).toBe(200);
    const r = await call("POST", "/api/agents", { name: "Nope", contact: "n@foxtrot.example", agent: didKeyOf(generateKeyPair().publicKey), expiresAt: inDays(30) });
    expect(r.status).toBe(403);
  });

  it("serves nothing of a registry when the portal runs without one", async () => {
    expect((await fetch(new URL(REGISTRY_DOCUMENT_PATH, plain.url))).status).toBe(404);
    const call = browser(() => plain.url);
    expect((await call("POST", "/api/register", { email: "golf@example.com", password: "a-long-enough-password", tenant: "golf", name: "Gil", company: "Golf" })).status).toBe(200);
    expect(await call("GET", "/api/agents")).toEqual({ status: 404, json: { error: "this portal runs no agent registry" } });
  });

  it("caps the agents an owner registers", async () => {
    const store = new RegistryStore(db, "cap_");
    for (let i = 0; i < 100; i++) await store.register("hotel", { name: `bot ${i}`, contact: "h@hotel.example", agent: didKeyOf(generateKeyPair().publicKey), expiresAt: inDays(10) });
    await expect(store.register("hotel", { name: "one more", contact: "h@hotel.example", agent: didKeyOf(generateKeyPair().publicKey), expiresAt: inDays(10) })).rejects.toThrow("at most 100 agents");
  }, 60_000);

  describe("and a door that holds only the registry's key", () => {
    let origin: Origin;
    let fx: DoorFixture;
    let host: DoorHost;
    let door: RunningDoor;
    let agent: KeyPair;
    let agentId: string;
    let passport: Envelope;
    let n = 0;

    /** RFC 9421 headers over @authority, signed by `key` with its did:key as keyid, as a Web Bot Auth client sends them. */
    const signedBy = (key: KeyPair, o: { nonce?: string } = {}) => {
      const created = Math.floor(Date.now() / 1000);
      const input = `sig1=("@authority");created=${created};expires=${created + 60};keyid="${didKeyOf(key.publicKey)}";alg="ed25519";nonce="${o.nonce ?? `reg-${process.pid}-${++n}`}";tag="web-bot-auth"`;
      const base = signatureBase({ method: "POST", target: "/refunds", authority: AUTHORITY, header: () => undefined }, parseDictionary(input).get("sig1") as SfInnerList);
      return { "signature-input": input, signature: `sig1=:${edSign(null, Buffer.from(base), key.privateKey).toString("base64")}:` };
    };
    // node:http, because fetch does not send a Host other than the URL's
    const send = (headers: Record<string, string>, amount = 100) => new Promise<{ status: number; st: ReceiptStatement; arrival: Arrival; ok: boolean }>((resolve, reject) => {
      const u = new URL(door.url);
      const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path: "/refunds", headers: { host: AUTHORITY, "content-type": "application/json", ...headers } }, (res) => {
        res.resume();
        res.on("end", () => {
          const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers[RECEIPT_HEADER]}.json`), "utf8")) as ReceiptBundle;
          const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString("utf8")) as ReceiptStatement;
          resolve({ status: res.statusCode!, st, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, ok: verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok });
        });
      });
      req.on("error", reject);
      req.end(JSON.stringify({ order: "o_1", amount }));
    });

    beforeAll(async () => {
      origin = await startOrigin();
      // the agent's organisation registers it and takes the passport the portal hands back
      const call = await owner("india");
      agent = generateKeyPair();
      const r = await call("POST", "/api/agents", { name: "India shopper", contact: "agents@india.example", capabilities: ["refunds"], agent: didKeyOf(agent.publicKey), expiresAt: inDays(30) });
      agentId = r.json.agent.id;
      passport = r.json.passport;
      // the site's door: no principal key, no signature agent; the registry's key from its key document, and a policy
      // that reads the registry's capabilities
      fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-registry-")), origin.url, { trustedPrincipalKeys: [], trustedRegistryKeys: ["keys/registry.pub"], webBotAuth: { authorities: [AUTHORITY] } });
      const doc = (await open(REGISTRY_DOCUMENT_PATH)).json as { keys: { publicKeyPem: string }[] };
      writeFileSync(join(fx.dir, "keys", "registry.pub"), doc.keys[0]!.publicKeyPem);
      writeFileSync(join(fx.dir, "policy.cedar"), `permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.facts.arrival has passport &&
  context.facts.arrival.passport.capabilities.contains("refunds") &&
  context.args.body.amount <= 5000
};
`);
      // the did:key carries its key and the passport carries the registry's word: the door fetches nothing but the origin
      host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: ((input: string | URL | Request, init?: RequestInit) => (String(input instanceof Request ? input.url : input).startsWith(origin.url) ? fetch(input, init) : Promise.reject(new Error("the door fetched something other than the origin")))) as typeof fetch });
      door = await serveDoor(host, { port: 0, log: () => {} });
    }, 60_000);
    afterAll(async () => {
      await door?.close();
      await host?.close();
      await origin?.close();
    });

    it("admits the registered agent as verified, the policy reads its capabilities, and the receipt verifies", async () => {
      const r = await send({ ...signedBy(agent), [PASSPORT_HEADER]: passportHeader(passport) });
      expect(r.status).toBe(200);
      expect(r.arrival).toMatchObject({ class: "verified", subject: didKeyOf(agent.publicKey), grant: "absent", signature: "verified", signatureAgent: didKeyOf(agent.publicKey) });
      expect(r.arrival.signatureError).toBeUndefined();
      expect(r.arrival.passport).toMatchObject({ outcome: "verified", registry: PORTAL_URL, registryKeyid: registryKey.keyid, agentId, agent: didKeyOf(agent.publicKey), owner: "india", capabilities: ["refunds"], envelope: passport });
      expect(r.st.predicate.agent).toEqual({ id: didKeyOf(agent.publicKey), provenance: "observed" });
      expect(r.st.predicate.principal).toEqual({ id: null, provenance: "claimed" });
      expect(r.ok).toBe(true);
      // the passport is the door's credential, not the origin's
      expect(origin.seen.at(-1)!.headers[PASSPORT_HEADER]).toBeUndefined();
      // the recorded passport checks again under the registry's key
      expect(verifyPassport(r.arrival.passport!.envelope!, [registryKey], r.st.predicate.timestamp).ok).toBe(true);
    });

    it("refuses the amount the policy does not allow, as a verified agent", async () => {
      const r = await send({ ...signedBy(agent), [PASSPORT_HEADER]: passportHeader(passport) }, 9000);
      expect(r).toMatchObject({ status: 403, arrival: { class: "verified" }, ok: true });
    });

    it("treats the passport under another key's signature as handed on: claimed, and refused", async () => {
      const thief = generateKeyPair();
      const r = await send({ ...signedBy(thief), [PASSPORT_HEADER]: passportHeader(passport) });
      expect(r.status).toBe(403);
      expect(r.arrival).toMatchObject({ class: "claimed", subject: didKeyOf(agent.publicKey), signature: "invalid", passport: { outcome: "wrong-sender", agentId, error: `the passport names ${didKeyOf(agent.publicKey)}, and the request is signed by ${didKeyOf(thief.publicKey)}` } });
      expect(r.arrival.signatureError).toContain("nor a passport from a trusted registry");
      expect(r.arrival.passport!.envelope).toBeUndefined();
      expect(r.st.predicate.agent).toEqual({ id: didKeyOf(agent.publicKey), provenance: "claimed" });
      expect(r.ok).toBe(true);
    });

    it("treats a passport with no signature as a claim", async () => {
      const r = await send({ [PASSPORT_HEADER]: passportHeader(passport) });
      expect(r).toMatchObject({ status: 403, arrival: { class: "claimed", signature: "absent", passport: { outcome: "wrong-sender" } }, ok: true });
    });

    it("refuses a replayed signature, so a passport and one captured request do not admit anyone twice", async () => {
      const headers = { ...signedBy(agent), [PASSPORT_HEADER]: passportHeader(passport) };
      expect((await send(headers)).arrival.class).toBe("verified");
      const again = await send(headers);
      expect(again.arrival).toMatchObject({ class: "claimed", signature: "invalid", signatureError: "sig1 repeats a nonce already used", passport: { outcome: "wrong-sender" } });
    });

    it("does not admit on a passport from another registry, an edited one, or a header that is not a passport", async () => {
      const elsewhere = await issuePassport(localSigner(generateKeyPair()), "https://registry.example/", { id: agentId, owner: "india", name: "India shopper", contact: "x@india.example", capabilities: ["refunds"], agent: didKeyOf(agent.publicKey), createdAt: new Date().toISOString(), expiresAt: inDays(1), revokedAt: null });
      const foreign = await send({ ...signedBy(agent), [PASSPORT_HEADER]: passportHeader(elsewhere) });
      expect(foreign.arrival).toMatchObject({ class: "claimed", signature: "invalid", passport: { outcome: "invalid", error: expect.stringContaining("not signed by a trusted registry key") } });
      const junk = await send({ ...signedBy(agent), [PASSPORT_HEADER]: "not-a-passport" });
      expect(junk.arrival).toMatchObject({ class: "claimed", passport: { outcome: "invalid", error: expect.stringContaining("is not a base64url DSSE envelope") } });
      expect(junk.ok).toBe(true);
    });

    it("judges an arrival that presents a grant by its grant, and only records the passport", () => {
      const principal = generateKeyPair();
      const grant = createDelegation(principal, { version: "0.1", principal: "shop-owner", agent: didKeyOf(agent.publicKey), scopes: ["other"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: inDays(1) });
      const req = { method: "POST", url: "/refunds", headers: { host: AUTHORITY, authorization: `Bearer ${grantHeader(grant)}`, [PASSPORT_HEADER]: passportHeader(passport) }, socket: { remoteAddress: "203.0.113.9" } } as unknown as DoorRequest;
      const sig = { outcome: "verified" as const, agent: didKeyOf(agent.publicKey), keyid: didKeyOf(agent.publicKey), label: "sig1" };
      const a = classifyArrival(req, [principal], "refund", false, new Date().toISOString(), sig, undefined, [registryKey]).arrival;
      expect(a).toMatchObject({ class: "claimed", grant: "out-of-scope", passport: { outcome: "verified" } });
    });

    it("records a passport as unchecked at a door that trusts no registry", () => {
      const req = { method: "POST", url: "/refunds", headers: { host: AUTHORITY, [PASSPORT_HEADER]: passportHeader(passport) }, socket: { remoteAddress: "203.0.113.9" } } as unknown as DoorRequest;
      const sig = { outcome: "verified" as const, agent: didKeyOf(agent.publicKey), keyid: didKeyOf(agent.publicKey), label: "sig1" };
      expect(classifyArrival(req, [], "refund", false, new Date().toISOString(), sig).arrival).toMatchObject({ class: "claimed", signature: "invalid", passport: { outcome: "unchecked" } });
    });

    it("refuses to start with registry keys and no webBotAuth to check the agent's signature", async () => {
      const bare = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-registry-bare-")), origin.url, { trustedRegistryKeys: ["keys/principal.pub"] });
      await expect(createDoorHost(loadDoorConfig(bare.configFile))).rejects.toThrow("trustedRegistryKeys needs webBotAuth");
    });

    it("loses the agent at the door once its passport expires after a revocation", async () => {
      const call = await owner("juliet");
      const key = generateKeyPair();
      const r = await call("POST", "/api/agents", { name: "Juliet agent", contact: "j@juliet.example", capabilities: ["refunds"], agent: didKeyOf(key.publicKey), expiresAt: inDays(30) });
      expect((await call("POST", `/api/agents/${r.json.agent.id}/revoke`, {})).status).toBe(200);
      expect((await open(`/registry/agents/${r.json.agent.id}/passport`)).status).toBe(410);
      // the passport it already held lives out its hour; then the door sees it as expired
      const req = { method: "POST", url: "/refunds", headers: { host: AUTHORITY, [PASSPORT_HEADER]: passportHeader(r.json.passport) }, socket: { remoteAddress: "203.0.113.9" } } as unknown as DoorRequest;
      const sig = { outcome: "verified" as const, agent: didKeyOf(key.publicKey), keyid: didKeyOf(key.publicKey), label: "sig1" };
      expect(classifyArrival(req, [], "refund", false, new Date().toISOString(), sig, undefined, [registryKey]).arrival.class).toBe("verified");
      const later = new Date(Date.now() + 3601_000).toISOString();
      expect(classifyArrival(req, [], "refund", false, later, sig, undefined, [registryKey]).arrival).toMatchObject({ class: "claimed", passport: { outcome: "invalid", error: expect.stringContaining("the passport is valid from") } });
    });
  });
});


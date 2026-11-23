// Admission lists and registry search. A site names its own lists of agents, and its policy reads the names of the
// lists an arrival's agent is on: the door admits a registered agent by its registry entry, and the decision is a
// receipt that records the lists and the digest of the lists in force. Only what the door checked puts an agent on a
// list: a claimed arrival, or a passport the signer is not bound to, is on none. The registry answers a search by
// capability with its active agents. Postgres runs in-process through PGlite; everything listens on loopback.
import { createHash, sign as edSign } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { compileAdmissionLists, type ArrivalIdentity } from "../src/admission.ts";
import { checkDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, type Envelope, type KeyPair } from "../src/crypto.ts";
import { didKeyOf } from "../src/did-key.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival, type DoorHost, type RunningDoor } from "../src/door.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { servePortal, type RunningPortal } from "../src/portal.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { issuePassport, PASSPORT_HEADER, passportHeader, registrationProof, type AgentEntry } from "../src/registry.ts";
import { localSigner } from "../src/signer.ts";
import { verifyBundle } from "../src/verify.ts";
import { parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

const REGISTRY = "https://app.example.test/";
const AUTHORITY = "shop.example";
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
const ERC = "eip155:8453:0x0000000000000000000000000000000000008004";

describe("admission lists", () => {
  const lists = compileAdmissionLists(JSON.stringify({ lists: {
    partners: [{ registry: REGISTRY, agentId: "agt_00000000000000a1" }, { erc8004: { agentRegistry: ERC.toUpperCase().replace("EIP155", "eip155").replace("0X", "0x"), agentId: "7" } }],
    crawlers: [{ agent: "https://crawler.example" }],
    blocked: [{ agent: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" }],
  } }));
  const verified = (o: Partial<ArrivalIdentity> = {}): ArrivalIdentity => ({ class: "verified", subject: "did:key:z6Mkother", ...o });

  it("names the lists a verified arrival's agent is on, by its registry entry, its ERC-8004 identity, or its subject", () => {
    expect(lists.names).toEqual(["blocked", "crawlers", "partners"]);
    expect(lists.match(verified({ passport: { outcome: "verified", registry: REGISTRY, agentId: "agt_00000000000000a1" } }))).toEqual(["partners"]);
    expect(lists.match(verified({ passport: { outcome: "verified", registry: REGISTRY, agentId: "agt_00000000000000b2", erc8004: { agentRegistry: ERC, agentId: "7" } } }))).toEqual(["partners"]);
    expect(lists.match(verified({ subject: "https://crawler.example" }))).toEqual(["crawlers"]);
    expect(lists.match(verified({ subject: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", passport: { outcome: "verified", registry: REGISTRY, agentId: "agt_00000000000000a1" } }))).toEqual(["blocked", "partners"]);
    // the entry names its registry: the same id at another registry is another agent
    expect(lists.match(verified({ passport: { outcome: "verified", registry: "https://registry.example/", agentId: "agt_00000000000000a1" } }))).toEqual([]);
  });

  it("puts nothing the door did not check on a list", () => {
    expect(lists.match({ class: "claimed", subject: "https://crawler.example" })).toEqual([]);
    expect(lists.match({ class: "unknown", subject: "unknown" })).toEqual([]);
    // a passport under another key: the arrival may be verified as itself, but the registry entry is not its own
    expect(lists.match(verified({ passport: { outcome: "wrong-sender", registry: REGISTRY, agentId: "agt_00000000000000a1" } }))).toEqual([]);
    expect(lists.match(verified({ passport: { outcome: "unbound", registry: REGISTRY, agentId: "agt_00000000000000a1" } }))).toEqual([]);
  });

  it("refuses a file that is not a set of named lists of agents", () => {
    for (const [text, error] of [
      ["{", "not JSON"],
      [JSON.stringify({ lists: { Partners: [] } }), "a list name is lowercase"],
      [JSON.stringify({ lists: { partners: [{ agentId: "agt_00000000000000a1" }] } }), "lists.partners.0"],
      [JSON.stringify({ lists: { partners: [{ registry: REGISTRY, agentId: "agt_1" }] } }), "lists.partners.0"],
      [JSON.stringify({ lists: { partners: [{ agent: "x", role: "admin" }] } }), "lists.partners.0"],
      [JSON.stringify({ lists: {}, extra: true }), "Unrecognized key"],
      [JSON.stringify({ lists: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`l${i}`, []])) }), "at most 64 lists"],
    ] as const) expect(() => compileAdmissionLists(text), text).toThrow(error);
  });
});

describe("a door with admission lists, in front of registered agents", () => {
  const registryKey = generateKeyPair();
  const signer = localSigner(registryKey);
  let origin: Origin;
  let fx: DoorFixture;
  let host: DoorHost;
  let door: RunningDoor;
  let n = 0;
  const listsFile = () => join(fx.dir, "admission.json");
  const writeLists = (l: unknown) => writeFileSync(listsFile(), typeof l === "string" ? l : JSON.stringify(l));

  /** a registered agent: its key, its registry entry, and a passport from the registry */
  const registered = async (id: string, capabilities = ["refunds"]) => {
    const key = generateKeyPair();
    const entry: AgentEntry = { id, owner: "carted", name: `agent ${id}`, contact: "agents@carted.example", capabilities, agent: didKeyOf(key.publicKey), createdAt: new Date().toISOString(), expiresAt: inDays(30), revokedAt: null };
    return { key, id, did: entry.agent, passport: await issuePassport(signer, REGISTRY, entry, 3600) };
  };
  const BODY = JSON.stringify({ order: "o_1", amount: 100 });
  /** the request a registered agent sends: its passport, a digest of the body, and a signature that binds both */
  const signedBy = (key: KeyPair, passport: Envelope) => {
    const fields: Record<string, string> = { [PASSPORT_HEADER]: passportHeader(passport), "content-digest": `sha-256=:${createHash("sha256").update(BODY).digest("base64")}:` };
    const created = Math.floor(Date.now() / 1000);
    const input = `sig1=("@authority" "@method" "@path" "@query" "${PASSPORT_HEADER}" "content-digest");created=${created};expires=${created + 60};keyid="${didKeyOf(key.publicKey)}";alg="ed25519";nonce="adm-${process.pid}-${++n}";tag="web-bot-auth"`;
    const base = signatureBase({ method: "POST", target: "/refunds", authority: AUTHORITY, header: (name) => (fields[name] !== undefined ? [fields[name]!] : undefined) }, parseDictionary(input).get("sig1") as SfInnerList);
    return { ...fields, "signature-input": input, signature: `sig1=:${edSign(null, Buffer.from(base), key.privateKey).toString("base64")}:` };
  };
  const send = (headers: Record<string, string>) => new Promise<{ status: number; arrival: Arrival; ok: boolean; st: ReceiptStatement }>((resolve, reject) => {
    const u = new URL(door.url);
    const req = httpRequest({ host: u.hostname, port: u.port, method: "POST", path: "/refunds", headers: { host: AUTHORITY, "content-type": "application/json", ...headers } }, (res) => {
      res.resume();
      res.on("end", () => {
        const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers[RECEIPT_HEADER]}.json`), "utf8")) as ReceiptBundle;
        const st = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement;
        resolve({ status: res.statusCode!, st, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival, ok: verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok });
      });
    });
    req.on("error", reject);
    req.end(BODY);
  });

  let partner: Awaited<ReturnType<typeof registered>>;
  let stranger: Awaited<ReturnType<typeof registered>>;
  let banned: Awaited<ReturnType<typeof registered>>;

  beforeAll(async () => {
    origin = await startOrigin();
    partner = await registered("agt_00000000000000a1");
    stranger = await registered("agt_00000000000000b2");
    banned = await registered("agt_00000000000000c3");
    fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-admission-")), origin.url, { trustedPrincipalKeys: [], trustedRegistryKeys: ["keys/registry.pub"], webBotAuth: { authorities: [AUTHORITY] }, admissionLists: "admission.json" });
    writeFileSync(join(fx.dir, "keys", "registry.pub"), registryKey.publicKey.export({ type: "spki", format: "pem" }) as string);
    // the banned agent is a partner by its registry entry and blocked by its key: the forbid wins
    writeLists({ lists: { partners: [{ registry: REGISTRY, agentId: partner.id }, { registry: REGISTRY, agentId: banned.id }], blocked: [{ agent: banned.did }] } });
    writeFileSync(join(fx.dir, "policy.cedar"), `// a refund is for a verified partner, and never for a blocked agent
permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.class == "verified" && context.facts.arrival has admission && context.facts.arrival.admission.lists.contains("partners") };
forbid(principal, action == Action::"refund", resource)
when { context.facts.arrival has admission && context.facts.arrival.admission.lists.contains("blocked") };
`);
    host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: ((input: string | URL | Request, init?: RequestInit) => (String(input instanceof Request ? input.url : input).startsWith(origin.url) ? fetch(input, init) : Promise.reject(new Error("the door fetched something other than the origin")))) as typeof fetch });
    door = await serveDoor(host, { port: 0, log: () => {} });
  }, 60_000);
  afterAll(async () => {
    await door?.close();
    await host?.close();
    await origin?.close();
  });

  it("admits a partner by its registry entry, and the receipt records the lists and their digest", async () => {
    const r = await send(signedBy(partner.key, partner.passport));
    expect(r.status).toBe(200);
    expect(r.arrival).toMatchObject({ class: "verified", passport: { outcome: "verified", agentId: partner.id }, admission: { lists: ["partners"], digest: createHash("sha256").update(readFileSync(listsFile())).digest("hex") } });
    expect(r.st.predicate.policy?.decision).toBe("allow");
    expect(r.ok).toBe(true);
  });

  it("refuses a registered agent that is on no list, and a blocked one that is also a partner", async () => {
    const s = await send(signedBy(stranger.key, stranger.passport));
    expect(s).toMatchObject({ status: 403, arrival: { class: "verified", admission: { lists: [] } }, ok: true });
    const b = await send(signedBy(banned.key, banned.passport));
    expect(b).toMatchObject({ status: 403, arrival: { class: "verified", admission: { lists: ["blocked", "partners"] } }, ok: true });
    expect(b.st.predicate.policy?.decision).toBe("deny");
  });

  it("does not put a copied passport's agent on its lists", async () => {
    const r = await send(signedBy(generateKeyPair(), partner.passport));
    expect(r).toMatchObject({ status: 403, arrival: { class: "claimed", passport: { outcome: "wrong-sender" }, admission: { lists: [] } }, ok: true });
  });

  it("reads a changed lists file on the next arrival, and keeps the lists in force when the file breaks", async () => {
    writeLists({ lists: { partners: [{ registry: REGISTRY, agentId: partner.id }, { registry: REGISTRY, agentId: stranger.id }], blocked: [{ agent: banned.did }] } });
    const added = await send(signedBy(stranger.key, stranger.passport));
    expect(added).toMatchObject({ status: 200, arrival: { admission: { lists: ["partners"] } } });
    const digest = added.arrival.admission!.digest;
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    writeLists('{ "lists": { "partners": [ { "registry": 1 } ] } }');
    const kept = await send(signedBy(stranger.key, stranger.passport));
    expect(kept).toMatchObject({ status: 200, arrival: { admission: { lists: ["partners"], digest } } });
    expect(errors.mock.calls.some(([m]) => String(m).includes("ADMISSION LISTS NOT RELOADED"))).toBe(true);
    errors.mockRestore();
  });

  it("refuses to start on a lists file that is not valid, and check says why", async () => {
    const bad = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-admission-bad-")), origin.url, { admissionLists: "admission.json" });
    writeFileSync(join(bad.dir, "admission.json"), JSON.stringify({ lists: { "Not A Name": [] } }));
    await expect(createDoorHost(loadDoorConfig(bad.configFile))).rejects.toThrow("the admission lists are not valid");
    expect(checkDoorConfig(bad.configFile).find((f) => f.check === "admissionLists")).toMatchObject({ level: "error" });
    writeFileSync(join(bad.dir, "admission.json"), JSON.stringify({ lists: { partners: [] } }));
    expect(checkDoorConfig(bad.configFile).find((f) => f.check === "admissionLists")).toMatchObject({ level: "ok", message: expect.stringContaining("1 admission list(s)") });
  });
});

describe("the registry's search by capability", () => {
  let db: PGlite;
  let portal: RunningPortal;
  beforeAll(async () => {
    db = new PGlite();
    await db.query("SELECT 1");
    portal = await servePortal({ tenancy: new PostgresTenancy(db), client: db, secret: "portal-secret-for-admission-tests-32ch", publicUrl: "https://log.example.test/", portalUrl: REGISTRY, registry: { signer: localSigner(generateKeyPair()) }, log: () => {} }, { port: 0 });
  }, 60_000);
  afterAll(async () => {
    await portal?.close();
    await db?.close();
  });
  const get = async (path: string) => { const r = await fetch(new URL(path, portal.url)); return { status: r.status, json: (await r.json()) as any }; };

  it("lists the active agents that hold a capability, a page at a time, and never a revoked one", async () => {
    let cookie = "";
    const call = async (path: string, body: unknown) => {
      const res = await fetch(new URL(path, portal.url), { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
      const set = res.headers.get("set-cookie");
      if (set) cookie = set.split(";")[0]!;
      return (await res.json()) as any;
    };
    await call("/api/register", { email: "ops@carted.example", password: "a-long-enough-password", tenant: "carted", name: "Ana", company: "Carted" });
    const reg = async (name: string, capabilities: string[]) => (await call("/api/agents", { name, contact: "a@carted.example", capabilities, ...registrationProof(generateKeyPair(), REGISTRY, "carted"), expiresAt: inDays(30) })).agent.id as string;
    const a = await reg("refunder one", ["refunds"]);
    const b = await reg("refunder two", ["checkout", "refunds"]);
    await reg("browser", ["catalogue"]);
    const c = await reg("refunder revoked", ["refunds"]);
    await call(`/api/agents/${c}/revoke`, {});

    const all = await get("/registry/agents?capability=refunds");
    expect(all.status).toBe(200);
    expect(all.json.agents.map((e: { id: string }) => e.id)).toEqual([a, b].sort());
    expect(all.json.agents[0]).toMatchObject({ status: "active", capabilities: expect.arrayContaining(["refunds"]), keys: [{ kty: "OKP" }] });
    expect(all.json.next).toBeNull();
    const first = await get("/registry/agents?capability=refunds&limit=1");
    expect(first.json.agents).toHaveLength(1);
    const second = await get(`/registry/agents?capability=refunds&limit=1&after=${first.json.next}`);
    expect([first.json.agents[0].id, second.json.agents[0].id]).toEqual([a, b].sort());
    expect(second.json.next).toBeNull();
    expect((await get("/registry/agents?owner=carted")).json.agents).toHaveLength(3);
    expect((await get("/registry/agents?capability=payouts")).json.agents).toEqual([]);
  });

  it("refuses a capability, an owner, a cursor, or a limit that is not one", async () => {
    expect((await get("/registry/agents?capability=Refunds!")).json.error).toContain("capability");
    expect((await get("/registry/agents?owner=NO")).json.error).toContain("owner");
    expect((await get("/registry/agents?after=1;drop")).json.error).toContain("after");
    expect((await get("/registry/agents?limit=lots")).status).toBe(400);
  });
});

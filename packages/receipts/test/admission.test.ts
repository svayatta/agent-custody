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
import { compareVersions } from "../src/passport.ts";
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

  it("matches an entry however its registry URL or origin is spelled, so a block list cannot miss its agent", () => {
    // the door names a registry as its passports do (with a trailing slash) and a Web Bot Auth agent by URL.origin; an
    // entry spelled another way must still match, or a blocked agent gets in and nothing says so
    const spelled = (entry: object) => compileAdmissionLists(JSON.stringify({ lists: { blocked: [entry] } }));
    const byRegistry = verified({ passport: { outcome: "verified", registry: "https://app.example.test/", agentId: "agt_00000000000000a1" } });
    for (const registry of ["https://app.example.test/", "https://app.example.test", "https://APP.example.test/", "https://app.example.test:443/"]) {
      expect(spelled({ registry, agentId: "agt_00000000000000a1" }).match(byRegistry), registry).toEqual(["blocked"]);
    }
    for (const agent of ["https://crawler.example", "https://crawler.example/", "https://Crawler.Example"]) {
      expect(spelled({ agent }).match(verified({ subject: "https://crawler.example" })), agent).toEqual(["blocked"]);
    }
    // a grant's agent with a path is compared whole, and a did:key exactly
    expect(spelled({ agent: "https://Agents.example/bot" }).match(verified({ subject: "https://agents.example/bot" }))).toEqual(["blocked"]);
    expect(spelled({ agent: "https://agents.example/bot" }).match(verified({ subject: "https://agents.example/other" }))).toEqual([]);
    expect(spelled({ agent: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" }).match(verified({ subject: "did:key:z6mkpthr8vnsbxyaawhut2geadd9jswubv8xroanwwsdvkth" }))).toEqual([]);
  });

  it("names an agent at one version or a range of versions, and never an arrival whose passport carries none", () => {
    const ranged = compileAdmissionLists(JSON.stringify({ lists: {
      exact: [{ registry: REGISTRY, agentId: "agt_00000000000000a1", version: "1.4.0" }],
      ones: [{ registry: REGISTRY, agentId: "agt_00000000000000a1", versions: { from: "1.2.0", below: "2.0.0" } }],
      old: [{ registry: REGISTRY, agentId: "agt_00000000000000a1", versions: { below: "1.0.0" } }],
      any: [{ registry: REGISTRY, agentId: "agt_00000000000000a1" }],
    } }));
    const at = (agentVersion?: string) => ranged.match(verified({ passport: { outcome: "verified", registry: REGISTRY, agentId: "agt_00000000000000a1", ...(agentVersion ? { agentVersion } : {}) } }));
    expect(at("1.4.0")).toEqual(["any", "exact", "ones"]);
    expect(at("1.4.1")).toEqual(["any", "ones"]);
    expect(at("1.10.0")).toEqual(["any", "ones"]); // numbers, not strings: 1.10 is above 1.2
    expect(at("2.0.0")).toEqual(["any"]);
    expect(at("0.9.9")).toEqual(["any", "old"]);
    expect(at()).toEqual(["any"]);
    // not a version: in no range, never admitted by one (the door's passport check refuses these first; the export must not admit them either)
    for (const v of ["1.4", "garbage", "1.4.0.1"]) expect(at(v), v).toEqual(["any"]);
    expect(() => compareVersions("garbage", "1.0.0")).toThrow("not a version");
    for (const [bad, why] of [
      [{ version: "1.4" }, "MAJOR.MINOR.PATCH"],
      [{ versions: {} }, "versions needs from, below, or both"],
      [{ versions: { from: "2.0.0", below: "1.0.0" } }, "from must be below below"],
      [{ version: "1.0.0", versions: { from: "1.0.0" } }, "give version or versions, not both"],
    ] as const) expect(() => compileAdmissionLists(JSON.stringify({ lists: { x: [{ registry: REGISTRY, agentId: "agt_00000000000000a1", ...bad }] } })), why).toThrow(why);
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

  it("admits an agent at the version its list names, and at the next version records the version and that no list named it", async () => {
    // the site admits version 1.4.0; the agent's owner ships 1.5.0
    const key = generateKeyPair();
    const entry: AgentEntry = { id: "agt_00000000000000d4", owner: "carted", name: "versioned agent", contact: "agents@carted.example", capabilities: ["refunds"], agent: didKeyOf(key.publicKey), createdAt: new Date().toISOString(), expiresAt: inDays(30), revokedAt: null, endpoints: ["api.stripe.com", "https://mcp.carted.example/mcp"] };
    const before = readFileSync(listsFile(), "utf8");
    const lists = JSON.parse(before) as { lists: Record<string, unknown[]> };
    lists.lists.partners!.push({ registry: REGISTRY, agentId: entry.id, version: "1.4.0" });
    writeLists(lists);
    try {
      const at = (version: string) => issuePassport(signer, REGISTRY, { ...entry, version }, 3600);
      const known = await send(signedBy(key, await at("1.4.0")));
      expect(known).toMatchObject({ status: 200, ok: true, arrival: { class: "verified", passport: { outcome: "verified", agentVersion: "1.4.0", endpoints: ["api.stripe.com", "https://mcp.carted.example/mcp"] }, admission: { lists: ["partners"] } } });
      const next = await send(signedBy(key, await at("1.5.0")));
      expect(next).toMatchObject({ status: 403, ok: true, arrival: { class: "verified", passport: { outcome: "verified", agentVersion: "1.5.0" }, admission: { lists: [] } } });
      expect(next.st.predicate.policy?.decision).toBe("deny");
    } finally {
      writeLists(before);
    }
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
    // the registry names itself as its passports do, so a site copies it into a list entry rather than typing it
    expect(all.json.registry).toBe(REGISTRY);
    // a search is not a directory of contacts: the contact is on the agent's own entry, and in its passport
    expect(all.json.agents.every((e: object) => !("contact" in e))).toBe(true);
    // nor of histories, which are each agent's own and can be long
    expect(all.json.agents.every((e: object) => !("history" in e))).toBe(true);
    expect((await get(`/registry/agents/${a}`)).json.contact).toBe("a@carted.example");
    const first = await get("/registry/agents?capability=refunds&limit=1");
    expect(first.json.agents).toHaveLength(1);
    const second = await get(`/registry/agents?capability=refunds&limit=1&after=${first.json.next}`);
    expect([first.json.agents[0].id, second.json.agents[0].id]).toEqual([a, b].sort());
    expect(second.json.next).toBeNull();
    expect((await get("/registry/agents?owner=carted")).json.agents).toHaveLength(3);
    expect((await get("/registry/agents?capability=payouts")).json.agents).toEqual([]);
  });

  it("slows one address that walks the registry, and not another", async () => {
    const proxied = await servePortal({ tenancy: new PostgresTenancy(db), client: db, secret: "portal-secret-for-admission-tests-32ch", publicUrl: "https://log.example.test/", portalUrl: REGISTRY, registry: { signer: localSigner(generateKeyPair()) }, trustProxy: true, log: () => {}, prefix: "walk_" }, { port: 0 });
    try {
      const from = (addr: string, path: string) => fetch(new URL(path, proxied.url), { headers: { "x-forwarded-for": addr } });
      const statuses: number[] = [];
      for (let i = 0; i < 125; i++) statuses.push((await from("198.51.100.7", i % 2 ? "/registry/agents?capability=refunds" : "/registry/agents/agt_00000000000000a1")).status);
      expect(statuses.slice(0, 120).every((s) => s === 200 || s === 404)).toBe(true);
      const slowed = await from("198.51.100.7", "/registry/agents?capability=refunds");
      expect(slowed.status).toBe(429);
      expect(slowed.headers.get("retry-after")).toBe("2");
      expect((await from("198.51.100.8", "/registry/agents?capability=refunds")).status).toBe(200);
    } finally {
      await proxied.close();
    }
  });

  it("refuses a capability, an owner, a cursor, or a limit that is not one", async () => {
    expect((await get("/registry/agents?capability=Refunds!")).json.error).toContain("capability");
    expect((await get("/registry/agents?owner=NO")).json.error).toContain("owner");
    expect((await get("/registry/agents?after=1;drop")).json.error).toContain("after");
    for (const limit of ["lots", "0", "101", "500", "999", "1000", "-1", ""]) expect((await get(`/registry/agents?limit=${limit}`)).status, `limit=${limit}`).toBe(400);
    expect((await get("/registry/agents?limit=100")).status).toBe(200);
  });
});

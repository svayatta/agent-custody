// Linking a registered agent to its ERC-8004 identity. The registry stores a link only when the chain and the token's
// registration file agree with its own entry: the token exists and has an owner, the file is a registration-v1 file,
// active, listing that very token among its registrations and the agent's did:key as a DID service. Anything else is
// refused with the reason, and a stale link is checked again before a passport carries it. The chain is a stand-in
// JSON-RPC endpoint and the file hosts are stand-ins: nothing leaves the machine.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { generateKeyPair, type KeyPair } from "../src/crypto.ts";
import { didKeyOf } from "../src/did-key.ts";
import { classifyArrival, type DoorRequest } from "../src/door.ts";
import { createErc8004Resolver, decodeAbiString, ERC8004_REGISTRATION_TYPE, type Erc8004Resolver } from "../src/erc8004.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { portalHandler, servePortal, type RunningPortal } from "../src/portal.ts";
import { Erc8004LinkSchema } from "../src/erc8004-link.ts";
import { createDelegation } from "../src/delegation.ts";
import { grantHeader } from "../src/gateway-http.ts";
import { PASSPORT_HEADER, passportHeader, REGISTRY_DOCUMENT_PATH, registrationProof, RegistryStore, verifyPassport } from "../src/registry.ts";
import { localSigner } from "../src/signer.ts";

const CHAIN = "8453";
const REGISTRY_ADDRESS = "0x0000000000000000000000000000000000008004";
const AGENT_REGISTRY = `eip155:${CHAIN}:${REGISTRY_ADDRESS}`;
const RPC = "https://rpc.example.test/";
const OWNER = "0x00000000000000000000000000000000000000b0";

/** An ABI-encoded `string` return value. */
const abiString = (s: string) => {
  const hex = Buffer.from(s, "utf8").toString("hex");
  return `0x${(32).toString(16).padStart(64, "0")}${(hex.length / 2).toString(16).padStart(64, "0")}${hex.padEnd(Math.ceil(hex.length / 64) * 64, "0")}`;
};
const registration = (o: { did: string; agentId?: string; active?: boolean; type?: string; registry?: string }) => JSON.stringify({
  type: o.type ?? ERC8004_REGISTRATION_TYPE,
  name: "Carted shopper",
  description: "Buys and returns things for Carted's customers",
  image: "https://carted.example/agent.png",
  services: [{ name: "web", endpoint: "https://carted.example/" }, { name: "DID", endpoint: o.did, version: "v1" }],
  x402Support: false,
  active: o.active ?? true,
  registrations: [{ agentId: Number(o.agentId ?? "7"), agentRegistry: o.registry ?? AGENT_REGISTRY }],
  supportedTrust: ["reputation"],
});

/** The stand-in chain: token id → token URI; a token not in the map reverts, as ownerOf does for a token that does not exist. */
function standInChain() {
  const tokens = new Map<string, string>();
  const calls: string[] = [];
  let down = false;
  const fetchRpc: typeof fetch = async (url, init) => {
    if (String(url) !== RPC) return new Response("not stood in", { status: 500 });
    if (down) throw new Error("connect ECONNREFUSED");
    const { method, params } = JSON.parse(String(init?.body)) as { method: string; params: [{ to: string; data: string }, string] };
    calls.push(method);
    const answer = (result: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), { status: 200, headers: { "content-type": "application/json" } });
    if (method === "eth_blockNumber") return answer("0x1a2b3c");
    if (method !== "eth_call" || params[0].to !== REGISTRY_ADDRESS || params[1] !== "0x1a2b3c") return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32601, message: "unexpected call" } }));
    const id = BigInt(`0x${params[0].data.slice(10)}`).toString();
    const uri = tokens.get(id);
    if (uri === undefined) return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: 3, message: "execution reverted: ERC721NonexistentToken" } }));
    if (params[0].data.startsWith("0x6352211e")) return answer(`0x${OWNER.slice(2).padStart(64, "0")}`);
    if (params[0].data.startsWith("0xc87b56dd")) return answer(abiString(uri));
    return answer("0x");
  };
  return { tokens, calls, fetchRpc, setDown: (d: boolean) => { down = d; } };
}

describe("an ERC-8004 link", () => {
  const did = didKeyOf(generateKeyPair().publicKey);
  const chain = standInChain();
  const files = new Map<string, string>();
  const fetched: string[] = [];
  const resolver = createErc8004Resolver({
    rpc: { [CHAIN]: RPC },
    ipfsGateway: "https://ipfs.example.test",
    fetch: chain.fetchRpc,
    fetchFile: async (url, o) => {
      fetched.push(url);
      const f = files.get(url);
      if (f === undefined) throw new Error(`${url} answered 404`);
      if (f.length > o.maxBytes) throw new Error(`${url} is larger than ${o.maxBytes} bytes`);
      return Buffer.from(f);
    },
  });
  const check = (agentId: string, key = did) => resolver.check({ agentRegistry: AGENT_REGISTRY, agentId }, key);

  it("holds when the file lists the token and the agent's key, over https, inline, or through the IPFS gateway", async () => {
    chain.tokens.set("7", "https://carted.example/agent.json");
    files.set("https://carted.example/agent.json", registration({ did }));
    const r = await check("7");
    expect(r).toMatchObject({ ok: true, link: { agentRegistry: AGENT_REGISTRY, agentId: "7", owner: OWNER, block: 0x1a2b3c, fileDigest: expect.stringMatching(/^[0-9a-f]{64}$/) } });

    chain.tokens.set("8", `data:application/json;base64,${Buffer.from(registration({ did, agentId: "8" })).toString("base64")}`);
    expect((await check("8")).ok).toBe(true);

    chain.tokens.set("9", "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/agent.json");
    files.set("https://ipfs.example.test/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/agent.json", registration({ did, agentId: "9" }));
    expect((await check("9")).ok).toBe(true);
  });

  it("is refused, with the reason, when the chain or the file does not agree", async () => {
    const cases: [string, string, string][] = [
      ["404", "", "does not exist"],
      ["20", registration({ did, agentId: "20", active: false }), "not active"],
      ["21", registration({ did, agentId: "99" }), "does not list token 21"],
      ["22", registration({ did, agentId: "22", registry: `eip155:1:${REGISTRY_ADDRESS}` }), "does not list token 22"],
      ["23", registration({ did: didKeyOf(generateKeyPair().publicKey), agentId: "23" }), "no DID service with the agent's key"],
      ["24", registration({ did, agentId: "24", type: "https://example.test/other" }), "not an ERC-8004 registration-v1 file"],
      ["25", "{ not json", "not JSON"],
      ["26", "x".repeat(70 * 1024), "larger than"],
    ];
    for (const [id, file, error] of cases) {
      if (id !== "404") {
        chain.tokens.set(id, `https://carted.example/${id}.json`);
        files.set(`https://carted.example/${id}.json`, file);
      }
      const r = await check(id);
      expect(r.ok, id).toBe(false);
      expect(!r.ok && r.error, id).toContain(error);
    }
    chain.tokens.set("30", "ipfs://bafy/agent.json");
    expect(await createErc8004Resolver({ rpc: { [CHAIN]: RPC }, fetch: chain.fetchRpc }).check({ agentRegistry: AGENT_REGISTRY, agentId: "30" }, did)).toMatchObject({ ok: false, error: expect.stringContaining("no IPFS gateway") });
    chain.tokens.set("31", "http://carted.example/agent.json");
    expect(await check("31")).toMatchObject({ ok: false, error: expect.stringContaining("not https, ipfs, or an inline JSON data URI") });
    expect(await resolver.check({ agentRegistry: `eip155:1:${REGISTRY_ADDRESS}`, agentId: "7" }, did)).toMatchObject({ ok: false, error: expect.stringContaining("reads no ERC-8004 registry on chain 1") });
    chain.setDown(true);
    expect(await check("7")).toMatchObject({ ok: false, error: expect.stringContaining("could not be reached") });
    chain.setDown(false);
  });

  it("never lets an IPFS path climb out of the gateway's /ipfs/ path", async () => {
    for (const [id, uri] of [
      ["32", "ipfs://bafy/../../.well-known/x"],
      ["33", "ipfs://bafy/./agent.json"],
      ["34", "ipfs://bafy/a/../../../admin"],
      ["35", "ipfs://bafy/%2e%2e/%2e%2e/x"],
      ["36", "ipfs://../x"],
    ] as const) {
      chain.tokens.set(id, uri);
      const before = fetched.length;
      const r = await check(id);
      expect(r.ok, uri).toBe(false);
      expect(!r.ok && r.error, uri).toContain("the IPFS URI is not a CID and a path of plain segments");
      expect(fetched.length, uri).toBe(before);
    }
    // a gateway with a path of its own keeps the path under its own /ipfs/
    const prefixed = createErc8004Resolver({ rpc: { [CHAIN]: RPC }, fetch: chain.fetchRpc, ipfsGateway: "https://gw.example.test/base", fetchFile: async (url) => { fetched.push(url); return Buffer.from(registration({ did, agentId: "37" })); } });
    chain.tokens.set("37", "ipfs://bafyok/agent.json");
    expect((await prefixed.check({ agentRegistry: AGENT_REGISTRY, agentId: "37" }, did)).ok).toBe(true);
    expect(fetched.at(-1)).toBe("https://gw.example.test/base/ipfs/bafyok/agent.json");
  });

  it("never fetches a registration file from an internal address", async () => {
    const plain = createErc8004Resolver({ rpc: { [CHAIN]: RPC }, fetch: chain.fetchRpc, timeoutMs: 2000 });
    for (const [id, uri] of [["40", "https://127.0.0.1/agent.json"], ["41", "https://[::1]/agent.json"], ["42", "https://169.254.169.254/latest/meta-data"], ["43", "https://localhost/agent.json"]] as const) {
      chain.tokens.set(id, uri);
      const r = await plain.check({ agentRegistry: AGENT_REGISTRY, agentId: id }, did);
      expect(r.ok, uri).toBe(false);
      expect(!r.ok && r.error, uri).toMatch(/internal address/);
    }
  });

  it("ends a registration file fetch at its deadline, even when the host keeps the connection alive", async () => {
    // a host that sends a byte now and then never trips a socket idle timeout; the fetch must still end at the deadline
    let given: AbortSignal | undefined;
    const slow = createErc8004Resolver({ rpc: { [CHAIN]: RPC }, fetch: chain.fetchRpc, timeoutMs: 200, fetchFile: (_url, o) => { given = o.signal; return new Promise<Buffer>(() => {}); } });
    chain.tokens.set("44", "https://slow.example/agent.json");
    const started = Date.now();
    const r = await slow.check({ agentRegistry: AGENT_REGISTRY, agentId: "44" }, did);
    expect(r).toMatchObject({ ok: false, error: expect.stringContaining("did not finish within 200 ms") });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(given?.aborted).toBe(true);
  });

  it("takes a token id only when it is a uint256", () => {
    const max = (2n ** 256n - 1n).toString();
    expect(Erc8004LinkSchema.safeParse({ agentRegistry: AGENT_REGISTRY, agentId: max }).success).toBe(true);
    const over = Erc8004LinkSchema.safeParse({ agentRegistry: AGENT_REGISTRY, agentId: (2n ** 256n).toString() });
    expect(over.success).toBe(false);
    expect(over.error?.issues[0]?.message).toBe("agentId is not a uint256");
    expect(Erc8004LinkSchema.safeParse({ agentRegistry: AGENT_REGISTRY, agentId: "9".repeat(78) }).success).toBe(false);
  });

  it("reads an ABI string only when its encoding holds together", () => {
    expect(decodeAbiString(abiString("ipfs://x"), 100)).toBe("ipfs://x");
    expect(() => decodeAbiString(abiString("ipfs://x").slice(0, 140), 100)).toThrow("shorter than the string");
    expect(() => decodeAbiString(abiString("x".repeat(200)), 100)).toThrow("longer than 100 bytes");
    expect(() => decodeAbiString("0x1234", 100)).toThrow("not an ABI-encoded string");
  });
});

describe("the registry with ERC-8004 links", () => {
  let db: PGlite;
  let portal: RunningPortal;
  let bare: RunningPortal;
  const registryKey = generateKeyPair();
  const chain = standInChain();
  const files = new Map<string, string>();
  const resolver: Erc8004Resolver = createErc8004Resolver({ rpc: { [CHAIN]: RPC }, fetch: chain.fetchRpc, fetchFile: async (url) => { const f = files.get(url); if (f === undefined) throw new Error("404"); return Buffer.from(f); } });
  let n = 0;
  const owner = async (base: string, tenant: string) => {
    let cookie = "";
    const from = `10.8.0.${++n}`;
    const call = async (method: string, path: string, body?: unknown) => {
      const res = await fetch(new URL(path, base), { method, headers: { "x-forwarded-for": from, ...(cookie ? { cookie } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
      const set = res.headers.get("set-cookie");
      if (set) cookie = set.split(";")[0]!;
      return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
    };
    expect((await call("POST", "/api/register", { email: `${tenant}@example.com`, password: "a-long-enough-password", tenant, name: "Ana", company: tenant })).status).toBe(200);
    return call;
  };
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
  /** the key's did:key and its proof for registering it with `tenant` */
  const keyed = (tenant: string, key: KeyPair) => registrationProof(key, "https://app.example.test/", tenant);
  const publish = (id: string, did: string, o: { active?: boolean } = {}) => {
    chain.tokens.set(id, `https://agents.example/${id}.json`);
    files.set(`https://agents.example/${id}.json`, registration({ did, agentId: id, ...o }));
  };

  beforeAll(async () => {
    db = new PGlite();
    await db.query("SELECT 1");
    const tenancy = new PostgresTenancy(db);
    portal = await servePortal({ tenancy, client: db, secret: "portal-secret-for-erc8004-tests-32-chars", publicUrl: "https://log.example.test/", portalUrl: "https://app.example.test/", registry: { signer: localSigner(registryKey), erc8004: resolver, erc8004RecheckSeconds: 3600 }, trustProxy: true, log: () => {} }, { port: 0 });
    bare = await servePortal({ tenancy, client: db, secret: "portal-secret-for-erc8004-tests-32-chars", publicUrl: "https://log.example.test/", portalUrl: "https://app.example.test/", registry: { signer: localSigner(registryKey) }, trustProxy: true, log: () => {}, prefix: "bare_" }, { port: 0 });
  }, 60_000);
  afterAll(async () => {
    await portal?.close();
    await bare?.close();
    await db?.close();
  });

  it("links an agent whose registration file lists its key, and every passport carries the link to the door", async () => {
    const doc = await (await fetch(new URL(REGISTRY_DOCUMENT_PATH, portal.url))).json() as { erc8004Chains: string[] };
    expect(doc.erc8004Chains).toEqual([CHAIN]);
    const call = await owner(portal.url, "carted");
    const agent = generateKeyPair();
    const did = didKeyOf(agent.publicKey);
    publish("7", did);
    const r = await call("POST", "/api/agents", { name: "Carted shopper", contact: "agents@carted.example", capabilities: ["refunds"], ...keyed("carted", agent), expiresAt: inDays(30), erc8004: { agentRegistry: AGENT_REGISTRY.toUpperCase().replace("EIP155", "eip155").replace("0X", "0x"), agentId: "7" } });
    expect(r.status).toBe(200);
    expect(r.json.agent.erc8004).toMatchObject({ agentRegistry: AGENT_REGISTRY, agentId: "7", owner: OWNER, block: 0x1a2b3c });
    const v = verifyPassport(r.json.passport, [registryKey], new Date().toISOString());
    expect(v.ok && v.passport.erc8004).toEqual({ agentRegistry: AGENT_REGISTRY, agentId: "7", owner: OWNER, block: 0x1a2b3c });

    // the door reads the link from the passport, and asks the chain nothing
    const req = { method: "POST", url: "/refunds", headers: { host: "shop.example", [PASSPORT_HEADER]: passportHeader(r.json.passport) }, socket: { remoteAddress: "203.0.113.9" } } as unknown as DoorRequest;
    const a = classifyArrival(req, [], "refund", false, new Date().toISOString(), { outcome: "verified", agent: did, keyid: did, label: "sig1", covered: ["@authority", "@method", "@path", PASSPORT_HEADER, "content-digest"] }, undefined, [registryKey], true).arrival;
    expect(a).toMatchObject({ class: "verified", passport: { outcome: "verified", erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "7", owner: OWNER } } });

    // someone verified as themselves, by their own grant, attaching this agent's public passport: the link stays out
    const principal = generateKeyPair();
    const thief = generateKeyPair();
    const thiefDid = didKeyOf(thief.publicKey);
    const grant = createDelegation(principal, { version: "0.1", principal: "shop-owner", agent: thiefDid, scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: inDays(1) });
    const carried = { method: "POST", url: "/refunds", headers: { host: "shop.example", authorization: `Bearer ${grantHeader(grant)}`, [PASSPORT_HEADER]: passportHeader(r.json.passport) }, socket: { remoteAddress: "203.0.113.9" } } as unknown as DoorRequest;
    const t = classifyArrival(carried, [principal], "refund", false, new Date().toISOString(), { outcome: "verified", agent: thiefDid, keyid: thiefDid, label: "sig1", covered: ["@authority", "@method", "@path", PASSPORT_HEADER, "content-digest"] }, undefined, [registryKey], true).arrival;
    expect(t).toMatchObject({ class: "verified", subject: thiefDid, passport: { outcome: "wrong-sender" } });
    expect(t.passport!.erc8004).toBeUndefined();
  });

  it("will not start with a recheck interval that would keep every link out of every passport", () => {
    const start = (erc8004RecheckSeconds: number) => () => portalHandler({ tenancy: new PostgresTenancy(db), client: db, secret: "portal-secret-for-erc8004-tests-32-chars", publicUrl: "https://log.example.test/", portalUrl: "https://app.example.test/", registry: { signer: localSigner(registryKey), erc8004: resolver, erc8004RecheckSeconds }, log: () => {} });
    for (const bad of [Number.NaN, 0, -1, 59, 1.5, 86_401]) expect(start(bad), String(bad)).toThrow("rechecked every 60 to 86400 seconds");
    expect(start(60)).not.toThrow();
  });

  it("refuses a link the chain does not back, and a link on a registry that reads no chain", async () => {
    const call = await owner(portal.url, "bravo");
    const bravo = keyed("bravo", generateKeyPair());
    publish("50", didKeyOf(generateKeyPair().publicKey));
    const r = await call("POST", "/api/agents", { name: "Bravo bot", contact: "ops@bravo.example", ...bravo, expiresAt: inDays(30), erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "50" } });
    expect(r.status).toBe(400);
    expect(r.json.error).toContain("erc8004: the registration file lists no DID service with the agent's key");
    expect((await call("POST", "/api/agents", { name: "Bravo bot", contact: "ops@bravo.example", ...bravo, expiresAt: inDays(30), erc8004: { agentRegistry: "eip155:8453:not-an-address", agentId: "50" } })).json.error).toContain("agentRegistry");
    const other = await owner(bare.url, "charlie");
    const nolink = await other("POST", "/api/agents", { name: "Charlie", contact: "c@charlie.example", ...keyed("charlie", generateKeyPair()), expiresAt: inDays(30), erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "7" } });
    expect(nolink).toEqual({ status: 400, json: { error: "erc8004: this registry reads no ERC-8004 registry" } });
  });

  it("checks a standing link again when the key rotates, and unlinks on null", async () => {
    const call = await owner(portal.url, "delta");
    const firstKey = generateKeyPair();
    const secondKey = generateKeyPair();
    const first = didKeyOf(firstKey.publicKey);
    const second = didKeyOf(secondKey.publicKey);
    publish("60", first);
    const r = await call("POST", "/api/agents", { name: "Delta", contact: "d@delta.example", ...keyed("delta", firstKey), expiresAt: inDays(30), erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "60" } });
    const id = r.json.agent.id;
    // the file still names the old key: the rotation is refused, and nothing changes
    const refused = await call("POST", `/api/agents/${id}`, keyed("delta", secondKey));
    expect(refused.status).toBe(400);
    expect(refused.json.error).toContain("no DID service with the agent's key");
    publish("60", second);
    const rotated = await call("POST", `/api/agents/${id}`, keyed("delta", secondKey));
    expect(rotated.json.agent).toMatchObject({ agent: second, erc8004: { agentId: "60" } });
    const unlinked = await call("POST", `/api/agents/${id}`, { erc8004: null });
    expect(unlinked.json.agent.erc8004).toBeNull();
    const v = verifyPassport(unlinked.json.passport, [registryKey], new Date().toISOString());
    expect(v.ok && v.passport.erc8004).toBeUndefined();
  });

  it("stores a late recheck only while the row still names the key and the token that were checked", async () => {
    const store = new RegistryStore(db, "https://app.example.test/", "cas_");
    const checker = (link: { agentRegistry: string; agentId: string }, key: string) => resolver.check(link, key);
    const key = generateKeyPair();
    const did = didKeyOf(key.publicKey);
    publish("80", did);
    publish("81", did);
    const e = await store.register("foxtrot", { name: "Fox", contact: "f@fox.example", ...registrationProof(key, "https://app.example.test/", "foxtrot"), expiresAt: inDays(30), erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "80" } }, Date.now(), checker);
    // a recheck of token 80 starts; while it is in flight the owner moves the link to token 81
    const checked = { agent: did, link: { agentRegistry: AGENT_REGISTRY, agentId: "80" } };
    const late = await resolver.check(checked.link, did);
    expect(late.ok).toBe(true);
    await store.update("foxtrot", e.id, { erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "81" } }, Date.now(), checker);
    // the late success does not bring token 80 back, and a late failure does not mark token 81 broken
    expect((await store.recordErc8004(e.id, checked, late))!.erc8004).toMatchObject({ agentId: "81" });
    expect((await store.recordErc8004(e.id, checked, { ok: false, error: "the registration file says the agent is not active" }))!.erc8004!.error).toBeUndefined();
    // the same after a key rotation: a result checked for the old key is not stored
    const next = generateKeyPair();
    publish("81", didKeyOf(next.publicKey));
    await store.update("foxtrot", e.id, registrationProof(next, "https://app.example.test/", "foxtrot"), Date.now(), checker);
    const oldKey = { agent: did, link: { agentRegistry: AGENT_REGISTRY, agentId: "81" } };
    expect((await store.recordErc8004(e.id, oldKey, { ok: false, error: "no DID service" }))!.erc8004!.error).toBeUndefined();
    // a result for what the row names now is stored
    const now = { agent: didKeyOf(next.publicKey), link: { agentRegistry: AGENT_REGISTRY, agentId: "81" } };
    expect((await store.recordErc8004(e.id, now, { ok: false, error: "the registration file says the agent is not active" }))!.erc8004!.error).toContain("not active");
  });

  it("checks a stale link again before a passport carries it, drops it when the file stops agreeing, and does not ask the chain on every request", async () => {
    const call = await owner(portal.url, "echo");
    const echoKey = generateKeyPair();
    const did = didKeyOf(echoKey.publicKey);
    publish("70", did);
    const r = await call("POST", "/api/agents", { name: "Echo", contact: "e@echo.example", ...keyed("echo", echoKey), expiresAt: inDays(30), erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "70" } });
    const id = r.json.agent.id;
    // the last check is two hours old, and since then the owner marked the agent inactive
    await db.query(`UPDATE portal_agents SET erc8004 = jsonb_set(erc8004::jsonb, '{checkedAt}', to_jsonb($2::text))::text WHERE id = $1`, [id, new Date(Date.now() - 7200_000).toISOString()]);
    publish("70", did, { active: false });
    const before = chain.calls.length;
    const passport = await (await fetch(new URL(`/registry/agents/${id}/passport`, portal.url))).json();
    expect(chain.calls.length).toBeGreaterThan(before);
    const v = verifyPassport(passport, [registryKey], new Date().toISOString());
    expect(v.ok && v.passport.erc8004).toBeUndefined();
    const entry = await (await fetch(new URL(`/registry/agents/${id}`, portal.url))).json() as { erc8004: { error: string } };
    expect(entry.erc8004.error).toContain("not active");
    // a second request within the minute does not reach the chain
    const after = chain.calls.length;
    await fetch(new URL(`/registry/agents/${id}/passport`, portal.url));
    expect(chain.calls.length).toBe(after);
  });
});

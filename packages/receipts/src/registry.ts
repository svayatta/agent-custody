// The agent registry: an organisation registers its agents on the portal, each with its own Ed25519 key named as a
// did:key, and the registry signs a passport for each: a short-lived statement of who the agent is (its key, its
// owner, a contact, its capabilities). A door that trusts the registry's key admits an agent that presents a passport
// and signs its request with the key the passport names. The door needs nothing per agent and asks the registry nothing
// at request time: the registry's key document is all it holds.
//
// A passport is public. It proves nothing without a signature by the agent's own key on the same request, so it is
// served to anyone who asks, like a certificate. It lives for a day by default: revoking an agent stops new passports,
// and the last one issued stops working when it expires.
import { randomBytes, sign as edSign, verify as edVerify } from "node:crypto";
import { z } from "zod";
import type { Envelope, KeyPair } from "./crypto.ts";
import { DID_KEY_PREFIX, didKeyOf, publicKeyFromDidKey } from "./did-key.ts";
import { transaction, type PostgresLike } from "./log-store.ts";
import { AGENT_ID, AGENT_VERSION, CAPABILITY, DEFAULT_PASSPORT_SECONDS, DID_KEY, EndpointSchema, MAX_ENDPOINT_CHARS, MAX_PASSPORT_HEADER, PASSPORT_HEADER, PASSPORT_TYPE, passportHeader, PassportSchema, text, type Passport } from "./passport.ts";
import type { Signer } from "./signer.ts";
import { Erc8004LinkSchema, type Erc8004Check, type Erc8004Checked, type Erc8004Link } from "./erc8004-link.ts";

export * from "./passport.ts";

const didKeyOfKey = (k: KeyPair) => didKeyOf(k.publicKey);

/** the furthest ahead an agent's registration may expire */
export const MAX_REGISTRATION_DAYS = 366;
export const MAX_AGENTS_PER_OWNER = 100;

/**
 * What an agent's key signs to show that whoever registers it holds it: the registry, the owner, and the key. Without
 * it, a tenant could register a did:key it saw in a grant or a signature, and choose that agent's capabilities.
 */
export function registrationMessage(registryUrl: string, owner: string, didKey: string): Buffer {
  return Buffer.from(`agent-custody registry registration v1\n${registryUrl}\n${owner}\n${didKey}`, "utf8");
}

/** The proof a registration carries: the agent's key's Ed25519 signature over `registrationMessage`, base64url. */
export function registrationProof(agentKey: KeyPair, registryUrl: string, owner: string): { agent: string; proof: string } {
  const agent = didKeyOfKey(agentKey);
  return { agent, proof: edSign(null, registrationMessage(registryUrl, owner, agent), agentKey.privateKey).toString("base64url") };
}

/** One registered agent, as the registry keeps it. */
export interface AgentEntry {
  id: string;
  owner: string;
  name: string;
  contact: string;
  capabilities: string[];
  /** the agent's current key */
  agent: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  /** the version its owner registered, MAJOR.MINOR.PATCH; null or absent when none */
  version?: string | null;
  /** since when this version and key have been in force; the registration's time when absent */
  versionSince?: string;
  /** the tool endpoints its owner says it calls: a claim */
  endpoints?: string[];
  /** the versions and keys it had before, newest first, each with when it was in force */
  history?: AgentVersionRecord[];
  /** the linked ERC-8004 identity as last checked, with the error of the last check when it failed */
  erc8004?: (Erc8004Checked & { error?: string; errorAt?: string }) | null;
}

/** A version and key an agent had, and when they were in force. */
export interface AgentVersionRecord {
  version: string | null;
  agent: string;
  from: string;
  to: string;
}

/** how many past versions an entry keeps; the oldest go first */
export const MAX_AGENT_HISTORY = 100;

/** The ERC-8004 link a passport may carry: one whose last check succeeded within `recheckSeconds`. */
export function freshErc8004(e: AgentEntry, recheckSeconds: number, now = Date.now()): Erc8004Checked | null {
  const l = e.erc8004;
  return l && !l.error && now - Date.parse(l.checkedAt) <= recheckSeconds * 1000 ? l : null;
}

export type AgentStatus = "active" | "revoked" | "expired";
export const agentStatus = (e: AgentEntry, now = Date.now()): AgentStatus => (e.revokedAt ? "revoked" : Date.parse(e.expiresAt) <= now ? "expired" : "active");

/** What the registry publishes about an agent: the entry, its status, and its key as a JWK. */
export function publicEntry(e: AgentEntry, now = Date.now()) {
  const x = publicKeyFromDidKey(e.agent).publicKey.export({ format: "jwk" }).x as string;
  return {
    id: e.id,
    name: e.name,
    owner: e.owner,
    contact: e.contact,
    capabilities: e.capabilities,
    agent: e.agent,
    keys: [{ kty: "OKP", crv: "Ed25519", x, kid: e.agent, exp: Math.floor(Date.parse(e.expiresAt) / 1000) }],
    createdAt: e.createdAt,
    expiresAt: e.expiresAt,
    status: agentStatus(e, now),
    version: e.version ?? null,
    versionSince: e.versionSince ?? e.createdAt,
    /** the version this one replaced, when it replaced one */
    replaces: e.history?.[0]?.version ?? null,
    endpoints: e.endpoints ?? [],
    history: e.history ?? [],
    erc8004: e.erc8004 ?? null,
  };
}

/** A request to register or change an agent, checked; throws a message fit for the caller. */
export const AgentInputSchema = z.object({
  name: text(100),
  contact: text(200),
  capabilities: z.array(z.string().regex(CAPABILITY, { message: "a capability is lowercase letters, digits, and . _ : -, at most 64 characters" })).max(32).optional(),
  agent: z.string().regex(DID_KEY, { message: "the agent's key is an Ed25519 did:key (did:key:z6Mk...)" }),
  /** the agent key's signature over `registrationMessage`, base64url: needed to register a key, and to change to a new one */
  proof: z.string().regex(/^[A-Za-z0-9_-]{86}$/, { message: "proof is the agent key's Ed25519 signature over the registration message, base64url" }).optional(),
  expiresAt: z.iso.datetime({ offset: true }),
  /** the agent's version, MAJOR.MINOR.PATCH, or null for none; a change is recorded in the entry's history */
  version: z.string().regex(AGENT_VERSION, { message: "version is MAJOR.MINOR.PATCH, numbers only" }).nullable().optional(),
  /** the tool endpoints the agent says it calls: host names or https/wss URLs, shown to sites as a claim */
  endpoints: z.array(EndpointSchema).max(32).refine((l) => l.reduce((n, e) => n + e.length, 0) <= MAX_ENDPOINT_CHARS, { message: `the endpoints take at most ${MAX_ENDPOINT_CHARS} characters together, so that a door can read the passport` }).optional(),
  /** link an ERC-8004 identity (checked against the chain before it is stored), or null to unlink */
  erc8004: Erc8004LinkSchema.nullable().optional(),
});
export type AgentInput = z.infer<typeof AgentInputSchema>;

export class RegistryInputError extends Error {}

/** Checks an ERC-8004 link against the chain for a did:key; absent when the registry reads no chain. */
export type Erc8004Checker = (link: Erc8004Link, didKey: string) => Promise<Erc8004Check>;

async function checkedLink(checker: Erc8004Checker | undefined, link: Erc8004Link, didKey: string): Promise<Erc8004Checked> {
  if (!checker) throw new RegistryInputError("erc8004: this registry reads no ERC-8004 registry");
  const r = await checker(link, didKey);
  if (!r.ok) throw new RegistryInputError(`erc8004: ${r.error}`);
  return r.link;
}

function checkProof(registryUrl: string, owner: string, didKey: string, proof: string | undefined): void {
  if (!proof) throw new RegistryInputError("proof: a key is registered with its proof, the agent key's signature over the registration message (registrationProof, or agent-custody registry proof)");
  if (!edVerify(null, registrationMessage(registryUrl, owner, didKey), publicKeyFromDidKey(didKey).publicKey, Buffer.from(proof, "base64url"))) throw new RegistryInputError(`proof: the signature does not verify with ${didKey} over the registration message for this registry and owner`);
}

/** Postgres refused a row that breaks the one-live-agent-per-key index. */
const keyTaken = (e: unknown) => !!e && typeof e === "object" && (e as { code?: unknown }).code === "23505";
const TAKEN = "agent: this key is already registered to an agent; each agent has its own key";

function checkInput(raw: unknown, partial: boolean, now: number): Partial<AgentInput> {
  const schema = partial ? AgentInputSchema.partial() : AgentInputSchema;
  const r = schema.safeParse(raw);
  if (!r.success) throw new RegistryInputError(r.error.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; "));
  const v = r.data;
  if (v.agent) {
    try {
      publicKeyFromDidKey(v.agent);
    } catch (e) {
      throw new RegistryInputError(`agent: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (v.expiresAt) {
    const t = Date.parse(v.expiresAt);
    if (t <= now) throw new RegistryInputError("expiresAt: the registration must expire in the future");
    if (t > now + MAX_REGISTRATION_DAYS * 86_400_000) throw new RegistryInputError(`expiresAt: a registration lasts at most ${MAX_REGISTRATION_DAYS} days; renew it before then`);
  }
  if (v.capabilities) v.capabilities = [...new Set(v.capabilities)].sort();
  return v;
}

/** The registry's table, beside the portal's own. */
export class RegistryStore {
  private readonly client: PostgresLike;
  private readonly t: string;
  private ready: Promise<void> | null = null;
  private readonly registryUrl: string;
  /** `registryUrl` is what a registration's proof names */
  constructor(client: PostgresLike, registryUrl: string, prefix = "portal_") {
    if (!/^[a-z_][a-z0-9_]*$/.test(prefix)) throw new Error(`invalid table prefix ${prefix}`);
    this.client = client;
    this.registryUrl = registryUrl;
    this.t = `${prefix}agents`;
  }
  private init(): Promise<void> {
    this.ready ??= (async () => {
      await this.client.query(`CREATE TABLE IF NOT EXISTS ${this.t} (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, contact TEXT NOT NULL, capabilities TEXT[] NOT NULL, agent TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ)`);
      await this.client.query(`CREATE INDEX IF NOT EXISTS ${this.t}_owner ON ${this.t} (owner)`);
      // one live agent per key, held by the database so that two registrations at once cannot both pass
      await this.client.query(`CREATE UNIQUE INDEX IF NOT EXISTS ${this.t}_live_key ON ${this.t} (agent) WHERE revoked_at IS NULL`);
      await this.client.query(`ALTER TABLE ${this.t} ADD COLUMN IF NOT EXISTS erc8004 TEXT`);
      await this.client.query(`CREATE INDEX IF NOT EXISTS ${this.t}_capabilities ON ${this.t} USING GIN (capabilities)`);
      await this.client.query(`ALTER TABLE ${this.t} ADD COLUMN IF NOT EXISTS agent_version TEXT`);
      await this.client.query(`ALTER TABLE ${this.t} ADD COLUMN IF NOT EXISTS version_since TIMESTAMPTZ`);
      await this.client.query(`ALTER TABLE ${this.t} ADD COLUMN IF NOT EXISTS endpoints TEXT[] NOT NULL DEFAULT '{}'`);
      await this.client.query(`ALTER TABLE ${this.t} ADD COLUMN IF NOT EXISTS history TEXT`);
      // a row from before these columns starts its first stretch at its registration, to the millisecond, as the entry
      // reads it: the guard in update compares the stored value with the one it read, and NULL would never match
      await this.client.query(`UPDATE ${this.t} SET version_since = date_trunc('milliseconds', created_at) WHERE version_since IS NULL`);
    })();
    return this.ready;
  }
  private static row(r: Record<string, unknown>): AgentEntry {
    const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString());
    return { id: String(r.id), owner: String(r.owner), name: String(r.name), contact: String(r.contact), capabilities: (r.capabilities as string[]) ?? [], agent: String(r.agent), createdAt: iso(r.created_at), expiresAt: iso(r.expires_at), revokedAt: r.revoked_at ? iso(r.revoked_at) : null, version: r.agent_version ? String(r.agent_version) : null, versionSince: iso(r.version_since ?? r.created_at), endpoints: (r.endpoints as string[] | null) ?? [], history: r.history ? (JSON.parse(String(r.history)) as AgentVersionRecord[]) : [], erc8004: r.erc8004 ? (JSON.parse(String(r.erc8004)) as AgentEntry["erc8004"]) : null };
  }
  async register(owner: string, raw: unknown, now = Date.now(), erc8004?: Erc8004Checker): Promise<AgentEntry> {
    await this.init();
    const v = checkInput(raw, false, now) as AgentInput;
    checkProof(this.registryUrl, owner, v.agent, v.proof);
    const link = v.erc8004 ? await checkedLink(erc8004, v.erc8004, v.agent) : null;
    const capabilities = v.capabilities ?? [];
    const id = `agt_${randomBytes(8).toString("hex")}`;
    try {
      // the owner's lock makes the count and the insert one step, so registrations at once cannot pass the cap together
      return await transaction(this.client, async (q) => {
        await q("SELECT pg_advisory_xact_lock(hashtext($1))", [`${this.t}:${owner}`]);
        const { rows: count } = await q(`SELECT count(*)::int AS n FROM ${this.t} WHERE owner = $1 AND revoked_at IS NULL`, [owner]);
        if (Number((count[0] as { n: number }).n) >= MAX_AGENTS_PER_OWNER) throw new RegistryInputError(`an owner registers at most ${MAX_AGENTS_PER_OWNER} agents; revoke one first`);
        const { rows } = await q(`INSERT INTO ${this.t} (id, owner, name, contact, capabilities, agent, created_at, expires_at, erc8004, agent_version, version_since, endpoints, history) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $7, $11, '[]') RETURNING *`, [id, owner, v.name, v.contact, capabilities, v.agent, new Date(now).toISOString(), v.expiresAt, link ? JSON.stringify(link) : null, v.version ?? null, v.endpoints ?? []]);
        return RegistryStore.row(rows[0] as Record<string, unknown>);
      });
    } catch (e) {
      if (keyTaken(e)) throw new RegistryInputError(TAKEN);
      throw e;
    }
  }
  async get(id: string): Promise<AgentEntry | null> {
    if (!AGENT_ID.test(id)) return null;
    await this.init();
    const { rows } = await this.client.query(`SELECT * FROM ${this.t} WHERE id = $1`, [id]);
    return rows[0] ? RegistryStore.row(rows[0] as Record<string, unknown>) : null;
  }
  async list(owner: string): Promise<AgentEntry[]> {
    await this.init();
    const { rows } = await this.client.query(`SELECT * FROM ${this.t} WHERE owner = $1 ORDER BY created_at, id`, [owner]);
    return rows.map((r) => RegistryStore.row(r as Record<string, unknown>));
  }
  /** Changes an active agent of this owner: any of name, contact, capabilities, key, expiry, version, endpoints, ERC-8004 link. Null when the owner has no such active agent. */
  async update(owner: string, id: string, raw: unknown, now = Date.now(), erc8004?: Erc8004Checker): Promise<AgentEntry | null> {
    await this.init();
    const v = checkInput(raw, true, now);
    if (Object.keys(v).filter((k) => k !== "proof").length === 0) throw new RegistryInputError("nothing to change: give name, contact, capabilities, agent, expiresAt, version, endpoints, or erc8004");
    const current = await this.get(id);
    if (!current || current.owner !== owner || agentStatus(current, now) === "revoked") return null;
    if (v.agent && v.agent !== current.agent) checkProof(this.registryUrl, owner, v.agent, v.proof);
    const { proof: _proof, erc8004: wanted, ...fields } = v;
    const next = { ...current, ...fields };
    // a new version or a new key starts a new stretch of the entry's history; the one it replaces is kept, with its dates
    const moved = (v.version !== undefined && v.version !== current.version) || next.agent !== current.agent;
    const past = current.history ?? [];
    const history = moved ? [{ version: current.version ?? null, agent: current.agent, from: current.versionSince ?? current.createdAt, to: new Date(now).toISOString() }, ...past].slice(0, MAX_AGENT_HISTORY) : past;
    const since = moved ? new Date(now).toISOString() : (current.versionSince ?? current.createdAt);
    // a link stays only while the registration file lists the agent's key: a new key checks the standing link again
    const target = wanted === undefined ? (current.erc8004 && next.agent !== current.agent ? current.erc8004 : undefined) : wanted;
    const link = target === undefined ? current.erc8004 : target === null ? null : await checkedLink(erc8004, target, next.agent);
    try {
      // the version and key read above must still be the row's, so two changes at once cannot both write one stretch of history
      const { rows } = await this.client.query(`UPDATE ${this.t} SET name = $3, contact = $4, capabilities = $5, agent = $6, expires_at = $7, erc8004 = $8, agent_version = $9, version_since = $10, endpoints = $11, history = $12 WHERE id = $1 AND owner = $2 AND revoked_at IS NULL AND agent = $13 AND agent_version IS NOT DISTINCT FROM $14 AND version_since IS NOT DISTINCT FROM $15 RETURNING *`, [id, owner, next.name, next.contact, next.capabilities, next.agent, next.expiresAt, link ? JSON.stringify(link) : null, next.version ?? null, since, next.endpoints ?? [], JSON.stringify(history), current.agent, current.version ?? null, current.versionSince ?? null]);
      if (rows[0]) return RegistryStore.row(rows[0] as Record<string, unknown>);
      // the row was there when read: if it still is, another change moved its version or key in between, and this one, which read the old ones, is not written
      const after = await this.get(id);
      if (after && after.owner === owner && agentStatus(after, now) !== "revoked") throw new RegistryInputError("the agent's version or key changed while this change was made; read the entry again and retry");
      return null;
    } catch (e) {
      if (keyTaken(e)) throw new RegistryInputError(TAKEN);
      throw e;
    }
  }
  /**
   * Active agents, by id, that hold `capability` (and belong to `owner`) when given: at most `limit` of them, after the
   * id `after`. What the registry's public search serves; revoked and expired agents are not listed.
   */
  async search(o: { capability?: string; owner?: string; after?: string; limit?: number }, now = Date.now()): Promise<{ agents: AgentEntry[]; next: string | null }> {
    await this.init();
    if (o.capability !== undefined && !CAPABILITY.test(o.capability)) throw new RegistryInputError("capability: lowercase letters, digits, and . _ : -, at most 64 characters");
    if (o.owner !== undefined && !/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/.test(o.owner)) throw new RegistryInputError("owner: a tenant id");
    if (o.after !== undefined && !AGENT_ID.test(o.after)) throw new RegistryInputError("after: an agent id, the next value of the last page");
    const limit = Math.min(Math.max(Math.trunc(o.limit ?? 50), 1), 100);
    const where = ["revoked_at IS NULL", "expires_at > $1"];
    const values: unknown[] = [new Date(now).toISOString()];
    const param = (v: unknown) => { values.push(v); return `$${values.length}`; };
    if (o.capability !== undefined) where.push(`capabilities @> ${param([o.capability])}::text[]`);
    if (o.owner !== undefined) where.push(`owner = ${param(o.owner)}`);
    if (o.after !== undefined) where.push(`id > ${param(o.after)}`);
    const { rows } = await this.client.query(`SELECT * FROM ${this.t} WHERE ${where.join(" AND ")} ORDER BY id LIMIT ${param(limit + 1)}`, values);
    const agents = rows.slice(0, limit).map((r) => RegistryStore.row(r as Record<string, unknown>));
    return { agents, next: rows.length > limit ? agents.at(-1)!.id : null };
  }
  /**
   * Records a later check of an agent's standing link: the fresh result, or the error beside the last good one. `checked`
   * is the key and the link that were checked. The result is stored only while the row still names them: a check that
   * finishes after the owner changed the link or rotated the key would otherwise write over the new link. Returns the
   * row as it is.
   */
  async recordErc8004(id: string, checked: { agent: string; link: Erc8004Link }, r: Erc8004Check, now = Date.now()): Promise<AgentEntry | null> {
    await this.init();
    const current = await this.get(id);
    if (!current?.erc8004) return current;
    if (current.agent !== checked.agent || current.erc8004.agentRegistry !== checked.link.agentRegistry || current.erc8004.agentId !== checked.link.agentId) return current;
    const link = r.ok ? r.link : { ...current.erc8004, error: r.error.slice(0, 300), errorAt: new Date(now).toISOString() };
    // the same comparison in the write, so a change between the read and the write is not overwritten either
    const { rows } = await this.client.query(`UPDATE ${this.t} SET erc8004 = $2 WHERE id = $1 AND agent = $3 AND erc8004::jsonb->>'agentRegistry' = $4 AND erc8004::jsonb->>'agentId' = $5 AND revoked_at IS NULL RETURNING *`, [id, JSON.stringify(link), checked.agent, checked.link.agentRegistry, checked.link.agentId]);
    return rows[0] ? RegistryStore.row(rows[0] as Record<string, unknown>) : await this.get(id);
  }
  /** Revokes an agent of this owner for good: the registry issues it no more passports. False when there is none to revoke. */
  async revoke(owner: string, id: string, now = Date.now()): Promise<boolean> {
    await this.init();
    if (!AGENT_ID.test(id)) return false;
    const { rows } = await this.client.query(`UPDATE ${this.t} SET revoked_at = $3 WHERE id = $1 AND owner = $2 AND revoked_at IS NULL RETURNING id`, [id, owner, new Date(now).toISOString()]);
    return rows.length > 0;
  }
}

/**
 * Signs a passport for an active agent. It lives `passportSeconds`, never past the registration's expiry, and carries
 * `erc8004` when given (the link as last checked). Throws when the agent is revoked or expired.
 */
export async function issuePassport(signer: Signer, registryUrl: string, e: AgentEntry, passportSeconds = DEFAULT_PASSPORT_SECONDS, now = Date.now(), erc8004?: Erc8004Checked | null): Promise<Envelope> {
  const status = agentStatus(e, now);
  if (status !== "active") throw new RegistryInputError(`the agent ${e.id} is ${status}; the registry issues it no passport`);
  if (!e.agent.startsWith(DID_KEY_PREFIX)) throw new Error("the agent's key is not a did:key");
  const expires = Math.min(now + passportSeconds * 1000, Date.parse(e.expiresAt));
  const passport: Passport = PassportSchema.parse({
    version: "0.1",
    registry: registryUrl,
    agentId: e.id,
    agent: e.agent,
    name: e.name,
    owner: e.owner,
    contact: e.contact,
    capabilities: e.capabilities,
    ...(e.version ? { agentVersion: e.version } : {}),
    ...(e.endpoints?.length ? { endpoints: e.endpoints } : {}),
    ...(erc8004 ? { erc8004: { agentRegistry: erc8004.agentRegistry, agentId: erc8004.agentId, owner: erc8004.owner, block: erc8004.block } } : {}),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(expires).toISOString(),
  });
  const env = await signer.sign(PASSPORT_TYPE, passport);
  const size = passportHeader(env).length;
  if (size > MAX_PASSPORT_HEADER) throw new RegistryInputError(`the passport would be ${size} characters, more than the ${MAX_PASSPORT_HEADER} a door reads; declare fewer or shorter endpoints or capabilities`);
  return env;
}

/** The registry's key document, served at REGISTRY_DOCUMENT_PATH. */
export async function registryDocument(signer: Signer, registryUrl: string, passportSeconds: number, erc8004Chains: string[] = []) {
  return {
    registry: registryUrl,
    /** the chain ids whose ERC-8004 registries it checks links against */
    erc8004Chains,
    passportType: PASSPORT_TYPE,
    passportHeader: PASSPORT_HEADER,
    passportSeconds,
    agents: `${registryUrl}registry/agents/`,
    keys: (await signer.keys()).keys,
  };
}

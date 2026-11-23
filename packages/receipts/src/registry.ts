// The agent registry: an organisation registers its agents on the portal, each with its own Ed25519 key named as a
// did:key, and the registry signs a passport for each: a short-lived statement of who the agent is (its key, its
// owner, a contact, its capabilities). A door that trusts the registry's key admits an agent that presents a passport
// and signs its request with the key the passport names. The door needs nothing per agent and asks the registry nothing
// at request time: the registry's key document is all it holds.
//
// A passport is public. It proves nothing without a signature by the agent's own key on the same request, so it is
// served to anyone who asks, like a certificate. It lives for a day by default: revoking an agent stops new passports,
// and the last one issued stops working when it expires.
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { dsseVerify, sha256Hex, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { DID_KEY_PREFIX, publicKeyFromDidKey } from "./did-key.ts";
import type { PostgresLike } from "./log-store.ts";
import type { Signer } from "./signer.ts";

export const PASSPORT_TYPE = "application/vnd.agent-custody.passport+json";
/** the header an agent presents its passport in: the DSSE envelope as base64url JSON */
export const PASSPORT_HEADER = "x-agent-custody-passport";
/** where a registry publishes its keys and how it issues passports */
export const REGISTRY_DOCUMENT_PATH = "/.well-known/agent-custody-registry.json";
/** a passport header longer than this is not read */
export const MAX_PASSPORT_HEADER = 8192;
/** how long a passport lives unless the registry is configured otherwise */
export const DEFAULT_PASSPORT_SECONDS = 86_400;
export const MAX_PASSPORT_SECONDS = 7 * 86_400;
/** the furthest ahead an agent's registration may expire */
export const MAX_REGISTRATION_DAYS = 366;
export const MAX_AGENTS_PER_OWNER = 100;

export const AGENT_ID = /^agt_[0-9a-f]{16}$/;
export const CAPABILITY = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const DID_KEY = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/;
const text = (max: number) => z.string().trim().min(1).max(max).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), { message: "control characters are not allowed" });

export const PassportSchema = z.object({
  version: z.literal("0.1"),
  /** the registry that issued it: its public URL */
  registry: z.string().url().max(200),
  agentId: z.string().regex(AGENT_ID),
  /** the agent's key; a door admits the passport only on a request this key signed */
  agent: z.string().regex(DID_KEY),
  name: text(100),
  /** the portal tenant that registered the agent */
  owner: text(64),
  /** how a site reaches the agent's operator */
  contact: text(200),
  capabilities: z.array(z.string().regex(CAPABILITY)).max(32),
  issuedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true }),
});
export type Passport = z.infer<typeof PassportSchema>;

export type PassportVerifyResult = { ok: true; passport: Passport; keyid: string; digest: string } | { ok: false; error: string };

/** What a passport names by: sha256 over the payload its signature covers. */
export const passportDigest = (env: Envelope): string => sha256Hex(Buffer.from(env.payload, "base64"));

/** Checks a passport: signed by one of the registry keys, well formed, naming a did:key that decodes, and valid at `at`. */
export function verifyPassport(env: Envelope, registryKeys: PublicKeyRef[], at: string): PassportVerifyResult {
  if (env.payloadType !== PASSPORT_TYPE) return { ok: false, error: `the passport's payloadType is ${String(env.payloadType).slice(0, 80)}, not ${PASSPORT_TYPE}` };
  if (registryKeys.length === 0) return { ok: false, error: "the door trusts no registry key" };
  const r = dsseVerify(env, registryKeys);
  if (!r.ok) return { ok: false, error: `the passport is not signed by a trusted registry key: ${r.error}` };
  const parsed = PassportSchema.safeParse(r.payload);
  if (!parsed.success) return { ok: false, error: `the passport is not well formed: ${parsed.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ")}` };
  const p = parsed.data;
  try {
    publicKeyFromDidKey(p.agent);
  } catch (e) {
    return { ok: false, error: `the passport's agent key does not decode: ${e instanceof Error ? e.message : String(e)}` };
  }
  const t = Date.parse(at);
  if (t < Date.parse(p.issuedAt) || t > Date.parse(p.expiresAt)) return { ok: false, error: `the passport is valid from ${p.issuedAt} to ${p.expiresAt}` };
  return { ok: true, passport: p, keyid: r.keyid, digest: passportDigest(env) };
}

export function passportHeader(env: Envelope): string {
  return Buffer.from(JSON.stringify(env)).toString("base64url");
}

/** The passport an arrival presented, unverified; null when there is none or it is not an envelope. */
export function parsePassportHeader(headers: Record<string, string | string[] | undefined>): Envelope | null {
  const raw = headers[PASSPORT_HEADER];
  if (typeof raw !== "string" || !raw || raw.length > MAX_PASSPORT_HEADER) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Envelope;
    return parsed && typeof parsed === "object" && typeof parsed.payloadType === "string" && typeof parsed.payload === "string" && Array.isArray(parsed.signatures) ? parsed : null;
  } catch {
    return null;
  }
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
  };
}

/** A request to register or change an agent, checked; throws a message fit for the caller. */
export const AgentInputSchema = z.object({
  name: text(100),
  contact: text(200),
  capabilities: z.array(z.string().regex(CAPABILITY, { message: "a capability is lowercase letters, digits, and . _ : -, at most 64 characters" })).max(32).optional(),
  agent: z.string().regex(DID_KEY, { message: "the agent's key is an Ed25519 did:key (did:key:z6Mk...)" }),
  expiresAt: z.iso.datetime({ offset: true }),
});
export type AgentInput = z.infer<typeof AgentInputSchema>;

export class RegistryInputError extends Error {}

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
  constructor(client: PostgresLike, prefix = "portal_") {
    if (!/^[a-z_][a-z0-9_]*$/.test(prefix)) throw new Error(`invalid table prefix ${prefix}`);
    this.client = client;
    this.t = `${prefix}agents`;
  }
  private init(): Promise<void> {
    this.ready ??= (async () => {
      await this.client.query(`CREATE TABLE IF NOT EXISTS ${this.t} (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, contact TEXT NOT NULL, capabilities TEXT[] NOT NULL, agent TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ)`);
      await this.client.query(`CREATE INDEX IF NOT EXISTS ${this.t}_owner ON ${this.t} (owner)`);
    })();
    return this.ready;
  }
  private static row(r: Record<string, unknown>): AgentEntry {
    const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString());
    return { id: String(r.id), owner: String(r.owner), name: String(r.name), contact: String(r.contact), capabilities: (r.capabilities as string[]) ?? [], agent: String(r.agent), createdAt: iso(r.created_at), expiresAt: iso(r.expires_at), revokedAt: r.revoked_at ? iso(r.revoked_at) : null };
  }
  async register(owner: string, raw: unknown, now = Date.now()): Promise<AgentEntry> {
    await this.init();
    const v = checkInput(raw, false, now) as AgentInput;
    const capabilities = v.capabilities ?? [];
    const { rows: count } = await this.client.query(`SELECT count(*)::int AS n FROM ${this.t} WHERE owner = $1 AND revoked_at IS NULL`, [owner]);
    if (Number((count[0] as { n: number }).n) >= MAX_AGENTS_PER_OWNER) throw new RegistryInputError(`an owner registers at most ${MAX_AGENTS_PER_OWNER} agents; revoke one first`);
    const { rows: taken } = await this.client.query(`SELECT id FROM ${this.t} WHERE agent = $1 AND revoked_at IS NULL`, [v.agent]);
    if (taken.length) throw new RegistryInputError("agent: this key is already registered to an agent; each agent has its own key");
    const id = `agt_${randomBytes(8).toString("hex")}`;
    const { rows } = await this.client.query(`INSERT INTO ${this.t} (id, owner, name, contact, capabilities, agent, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`, [id, owner, v.name, v.contact, capabilities, v.agent, new Date(now).toISOString(), v.expiresAt]);
    return RegistryStore.row(rows[0] as Record<string, unknown>);
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
  /** Changes an active agent of this owner: any of name, contact, capabilities, key, expiry. Null when the owner has no such active agent. */
  async update(owner: string, id: string, raw: unknown, now = Date.now()): Promise<AgentEntry | null> {
    await this.init();
    const v = checkInput(raw, true, now);
    if (Object.keys(v).length === 0) throw new RegistryInputError("nothing to change: give name, contact, capabilities, agent, or expiresAt");
    const current = await this.get(id);
    if (!current || current.owner !== owner || agentStatus(current, now) === "revoked") return null;
    if (v.agent && v.agent !== current.agent) {
      const { rows: taken } = await this.client.query(`SELECT id FROM ${this.t} WHERE agent = $1 AND revoked_at IS NULL`, [v.agent]);
      if (taken.length) throw new RegistryInputError("agent: this key is already registered to an agent; each agent has its own key");
    }
    const next = { ...current, ...v };
    const { rows } = await this.client.query(`UPDATE ${this.t} SET name = $3, contact = $4, capabilities = $5, agent = $6, expires_at = $7 WHERE id = $1 AND owner = $2 AND revoked_at IS NULL RETURNING *`, [id, owner, next.name, next.contact, next.capabilities, next.agent, next.expiresAt]);
    return rows[0] ? RegistryStore.row(rows[0] as Record<string, unknown>) : null;
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
 * Signs a passport for an active agent. It lives `passportSeconds`, never past the registration's expiry. Throws when
 * the agent is revoked or expired.
 */
export async function issuePassport(signer: Signer, registryUrl: string, e: AgentEntry, passportSeconds = DEFAULT_PASSPORT_SECONDS, now = Date.now()): Promise<Envelope> {
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
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(expires).toISOString(),
  });
  return signer.sign(PASSPORT_TYPE, passport);
}

/** The registry's key document, served at REGISTRY_DOCUMENT_PATH. */
export async function registryDocument(signer: Signer, registryUrl: string, passportSeconds: number) {
  return {
    registry: registryUrl,
    passportType: PASSPORT_TYPE,
    passportHeader: PASSPORT_HEADER,
    passportSeconds,
    agents: `${registryUrl}registry/agents/`,
    keys: (await signer.keys()).keys,
  };
}

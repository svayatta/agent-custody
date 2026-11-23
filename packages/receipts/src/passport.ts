// The passport an agent registry signs, and its check: what a door needs of the registry, with nothing that keeps or
// stores agents, so that a door, the Worker's included, imports no database or file code.
import { z } from "zod";
import { dsseVerify, sha256Hex, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { publicKeyFromDidKey } from "./did-key.ts";
import { ERC8004_REGISTRY } from "./erc8004-link.ts";

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

export const AGENT_ID = /^agt_[0-9a-f]{16}$/;
export const CAPABILITY = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
export const DID_KEY = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/;
/** an agent's version: MAJOR.MINOR.PATCH, numbers only, compared as numbers */
export const AGENT_VERSION = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/;

/** Orders two versions that match AGENT_VERSION: negative, zero, or positive. */
export function compareVersions(a: string, b: string): number {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return 0;
}

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

/** A tool endpoint an agent says it calls: a host name, or an https or wss URL (an MCP server). A claim, never checked by the registry. */
export const EndpointSchema = z.string().max(200).refine((v) => {
  if (HOSTNAME.test(v)) return true;
  try {
    const u = new URL(v);
    return (u.protocol === "https:" || u.protocol === "wss:") && !u.username && !u.password && HOSTNAME.test(u.hostname);
  } catch {
    return false;
  }
}, { message: "an endpoint is a lowercase host name, or an https or wss URL without credentials" });

export const text = (max: number) => z.string().trim().min(1).max(max).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), { message: "control characters are not allowed" });

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
  /** the version of the agent its owner registered; absent when none was */
  agentVersion: z.string().regex(AGENT_VERSION).optional(),
  /** the tool endpoints the agent's owner says it calls: a claim, which the registry does not check */
  endpoints: z.array(EndpointSchema).max(32).optional(),
  /** the agent's ERC-8004 identity, as the registry last checked it against the chain; absent when it has none or the check is stale */
  erc8004: z.object({ agentRegistry: z.string().regex(ERC8004_REGISTRY), agentId: z.string().regex(/^[0-9]{1,78}$/), owner: z.string().regex(/^0x[0-9a-f]{40}$/), block: z.number().int().nonnegative() }).optional(),
  issuedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true }),
});
export type Passport = z.infer<typeof PassportSchema>;

export type PassportVerifyResult = { ok: true; passport: Passport; keyid: string; digest: string } | { ok: false; error: string };

/** What a passport names by: sha256 over the payload its signature covers. */
export const passportDigest = (env: Envelope): string => sha256Hex(Buffer.from(env.payload, "base64"));

/** Checks a passport: signed by one of the registry keys, well formed, naming a did:key that decodes, and valid at `at`. */
export function verifyPassport(env: Envelope, registryKeys: PublicKeyRef[], at: string): PassportVerifyResult {
  const r = passportSignedBy(env, registryKeys);
  if (!r.ok) return r;
  const t = Date.parse(at);
  if (t < Date.parse(r.passport.issuedAt) || t > Date.parse(r.passport.expiresAt)) return { ok: false, error: `the passport is valid from ${r.passport.issuedAt} to ${r.passport.expiresAt}` };
  return r;
}

/** A passport signed by one of the registry keys, well formed, naming a did:key that decodes, whatever its window. */
export function passportSignedBy(env: Envelope, registryKeys: PublicKeyRef[]): PassportVerifyResult {
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

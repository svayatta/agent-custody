// A delegation grant: a principal signs a statement that an agent may use certain tools for a window of time.
//
// A grant may carry the agent's own public key (`agentKey`); an agent so named may delegate to a sub-agent by signing
// a narrower grant that embeds the grant it came from (`parent`). A verifier walks the chain to the principal: every
// link is signed by the key its parent names, every scope is one its parent holds, every window lies inside its
// parent's, and the principal is the same throughout. The receipt then names the sub-agent as the agent and the
// principal as the principal, exactly as with a direct grant, and the whole chain travels inside the receipt.
import { z } from "zod";
import { dsseSign, dsseVerify, publicKeyFromPem, sha256Hex, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";

export const DELEGATION_TYPE = "application/vnd.agent-custody.delegation+json";
/** the longest chain a verifier walks: the principal's grant and up to three delegations below it */
export const MAX_DELEGATION_DEPTH = 4;

const EnvelopeSchema = z.object({ payloadType: z.string(), payload: z.string(), signatures: z.array(z.object({ keyid: z.string(), sig: z.string() })).min(1) });

export const DelegationSchema = z.object({
  version: z.literal("0.1"),
  principal: z.string().min(1),
  agent: z.string().min(1),
  scopes: z.array(z.string().min(1)).min(1),
  issuedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true }),
  /** the agent's own public key, SPKI PEM; with it the agent may delegate to a sub-agent */
  agentKey: z.string().min(1).optional(),
  /** the grant this one was delegated from; the chain ends at a grant signed by a trusted principal */
  parent: EnvelopeSchema.optional(),
});
export type Delegation = z.infer<typeof DelegationSchema>;

export function createDelegation(principalKey: KeyPair, d: Delegation): Envelope {
  return dsseSign(DELEGATION_TYPE, DelegationSchema.parse(d), principalKey);
}

export interface SubDelegation {
  agent: string;
  scopes: string[];
  issuedAt?: string;
  expiresAt?: string;
  /** the sub-agent's own public key, so it may delegate further */
  agentKey?: string;
}

/** True when the envelope's payload, verified or not, carries a parent: what decides whether the chain check is reported. */
export function delegationHasParent(env: Envelope): boolean {
  try {
    const raw = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")) as { parent?: unknown };
    return !!raw && typeof raw === "object" && raw.parent !== undefined;
  } catch {
    return false;
  }
}

/** The parent's payload as written, without verifying it; the verifier does that. */
export function decodeDelegation(env: Envelope): Delegation | null {
  try {
    const parsed = DelegationSchema.safeParse(JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/**
 * An agent delegates part of its grant to a sub-agent. `agentKey` is the delegating agent's key, the one its own grant
 * names. The result embeds the parent; it is refused here, before signing, when it asks for more than the parent has.
 */
export function delegateFrom(parent: Envelope, agentKey: KeyPair, sub: SubDelegation): Envelope {
  const p = decodeDelegation(parent);
  if (!p) throw new Error("the parent grant is not a delegation");
  if (!p.agentKey) throw new Error(`the parent grant names no agent key, so ${p.agent} cannot delegate`);
  if (publicKeyFromPem(p.agentKey).keyid !== agentKey.keyid) throw new Error(`this key is not the one the parent grant names for ${p.agent}`);
  const extra = sub.scopes.filter((s) => !p.scopes.includes(s));
  if (extra.length) throw new Error(`a sub-agent cannot be given scopes its delegator lacks: ${extra.join(", ")}`);
  const issuedAt = sub.issuedAt ?? new Date().toISOString();
  const expiresAt = sub.expiresAt ?? p.expiresAt;
  if (Date.parse(issuedAt) < Date.parse(p.issuedAt) || Date.parse(expiresAt) > Date.parse(p.expiresAt)) throw new Error("a sub-agent's window must lie inside its delegator's");
  return createDelegation(agentKey, { version: "0.1", principal: p.principal, agent: sub.agent, scopes: sub.scopes, issuedAt, expiresAt, ...(sub.agentKey ? { agentKey: sub.agentKey } : {}), parent });
}

export type DelegationVerifyResult =
  | {
      ok: true;
      /** the grant the receipt was issued under: the leaf of the chain */
      delegation: Delegation;
      /** the principal's key: the signer of the root grant */
      keyid: string;
      /** root first, leaf last; one entry for a direct grant */
      chain: Delegation[];
    }
  | { ok: false; error: string };

/** Verifies a grant, walking its chain to a grant signed by one of the trusted principal keys. */
export function verifyDelegation(env: Envelope, trustedPrincipals: PublicKeyRef[], depth = 1): DelegationVerifyResult {
  if (env.payloadType !== DELEGATION_TYPE) return { ok: false, error: `unexpected payloadType ${env.payloadType}` };
  if (depth > MAX_DELEGATION_DEPTH) return { ok: false, error: `delegation chain deeper than ${MAX_DELEGATION_DEPTH}` };
  const unverified = decodeDelegation(env);
  if (!unverified) return { ok: false, error: "invalid delegation" };
  if (!unverified.parent) {
    const r = dsseVerify(env, trustedPrincipals);
    if (!r.ok) return r;
    const parsed = DelegationSchema.safeParse(r.payload);
    if (!parsed.success) return { ok: false, error: `invalid delegation: ${parsed.error.message}` };
    return { ok: true, delegation: parsed.data, keyid: r.keyid, chain: [parsed.data] };
  }
  const up = verifyDelegation(unverified.parent, trustedPrincipals, depth + 1);
  if (!up.ok) return { ok: false, error: `link ${depth}: ${up.error}` };
  const parent = up.delegation;
  if (!parent.agentKey) return { ok: false, error: `link ${depth}: ${parent.agent} holds no agent key and cannot delegate` };
  let parentKey: PublicKeyRef;
  try {
    parentKey = publicKeyFromPem(parent.agentKey);
  } catch {
    return { ok: false, error: `link ${depth}: the agent key named for ${parent.agent} is not a public key` };
  }
  const r = dsseVerify(env, [parentKey]);
  if (!r.ok) return { ok: false, error: `link ${depth}: not signed by ${parent.agent}'s key: ${r.error}` };
  const parsed = DelegationSchema.safeParse(r.payload);
  if (!parsed.success) return { ok: false, error: `invalid delegation: ${parsed.error.message}` };
  const d = parsed.data;
  if (d.principal !== parent.principal) return { ok: false, error: `link ${depth}: principal changed from ${parent.principal} to ${d.principal}` };
  const extra = d.scopes.filter((s) => !parent.scopes.includes(s));
  if (extra.length) return { ok: false, error: `link ${depth}: ${d.agent} was given scopes ${parent.agent} does not hold: ${extra.join(", ")}` };
  if (Date.parse(d.issuedAt) < Date.parse(parent.issuedAt) || Date.parse(d.expiresAt) > Date.parse(parent.expiresAt)) return { ok: false, error: `link ${depth}: ${d.agent}'s window is not inside ${parent.agent}'s` };
  return { ok: true, delegation: d, keyid: up.keyid, chain: [...up.chain, d] };
}

/** True when `at` (ISO) lies inside the grant's validity window. */
/**
 * What names a grant for revocation: sha256 over the payload its signature covers. Extra signatures or envelope fields
 * leave it unchanged, so an agent cannot get a revoked grant past the list by repacking the envelope.
 */
export function grantDigest(env: Envelope): string {
  return sha256Hex(Buffer.from(env.payload, "base64"));
}

/** The digest of every link from this grant up to the principal's own, leaf first: revoking any link revokes the grants below it. */
export function grantChainDigests(env: Envelope): string[] {
  const out: string[] = [];
  for (let e: Envelope | undefined = env; e && out.length <= MAX_DELEGATION_DEPTH; e = decodeDelegation(e)?.parent) out.push(grantDigest(e));
  return out;
}

export function delegationValidAt(d: Delegation, at: string): boolean {
  const t = Date.parse(at);
  return t >= Date.parse(d.issuedAt) && t <= Date.parse(d.expiresAt);
}

/** "principal → agent → sub-agent", for reports. */
export function describeChain(chain: Delegation[]): string {
  return [chain[0]!.principal, ...chain.map((d) => d.agent)].join(" → ");
}

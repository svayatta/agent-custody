// An OPA server the operator runs, asked for every call through its Data API. The gateway holds no policy text then,
// so a receipt cannot pin the text's sha256 as it does for a local file. It pins what the server reports instead: the
// sha256 of the decision URL and the revision of each bundle loaded, with provenance=true on every query. Each new
// digest is recorded with what it stands for, so a receipt's policyDigest maps back to a bundle revision.
import { sha256Hex } from "./crypto.ts";
import type { PolicyDecision, PolicyRequest } from "./policy.ts";
import { REGO_PACKAGE, regoDecision, regoInput } from "./policy-rego.ts";

export interface OpaServerConfig {
  /** the OPA server, e.g. http://localhost:8181 */
  url: string;
  /** the package whose `allow` and `deny` rules decide, as a path under /v1/data; default agentcustody */
  decision?: string;
  /** environment variable holding a bearer token for the server */
  tokenEnv?: string;
  /** milliseconds one query may take; past that the call is denied. Default 2000 */
  timeoutMs?: number;
}

export interface OpaProvenance {
  /** the policy digest receipts carry while this provenance holds */
  digest: string;
  /** the decision URL, without its query */
  decision: string;
  /** bundle name to revision, as the server reports them */
  bundles: Record<string, string>;
}

export interface OpaServerPolicy {
  /** the decision for one call; any failure to get a well-formed answer is a deny */
  decide(req: PolicyRequest): Promise<PolicyDecision>;
  /** the digest of the provenance seen last */
  digest(): string;
  /** queries the server once without input, so a gateway that cannot reach it, or reaches one without the package, does not start */
  probe(): Promise<void>;
}

/** Bundle revisions out of OPA's `provenance` object: `bundles.<name>.revision`, or the older top-level `revision`. */
export function opaRevisions(provenance: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!provenance || typeof provenance !== "object") return out;
  const p = provenance as { revision?: unknown; bundles?: Record<string, { revision?: unknown }> };
  if (typeof p.revision === "string" && p.revision) out[""] = p.revision;
  for (const [name, b] of Object.entries(p.bundles ?? {})) if (b && typeof b.revision === "string") out[name] = b.revision;
  return out;
}

export function opaDigest(decision: string, bundles: Record<string, string>): string {
  return sha256Hex(JSON.stringify({ decision, bundles: Object.keys(bundles).sort().map((name) => [name, bundles[name]]) }));
}

export function createOpaServerPolicy(cfg: OpaServerConfig, onProvenance: (p: OpaProvenance) => void): OpaServerPolicy {
  const path = (cfg.decision ?? REGO_PACKAGE).replace(/^\/+|\/+$/g, "").replaceAll(".", "/");
  const decision = new URL(`v1/data/${path}`, cfg.url.endsWith("/") ? cfg.url : `${cfg.url}/`).toString();
  const rule = `data.${path.replaceAll("/", ".")}`;
  const where = `${rule} on ${new URL(cfg.url).origin}`;
  const token = cfg.tokenEnv ? process.env[cfg.tokenEnv] ?? (() => { throw new Error(`opa: environment variable ${cfg.tokenEnv} is not set`); })() : undefined;
  let current = opaDigest(decision, {});
  const seen = new Set<string>();

  const query = async (input?: unknown): Promise<{ result: unknown; digest: string }> => {
    const res = await fetch(`${decision}?provenance=true`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(input === undefined ? {} : { input }),
      signal: AbortSignal.timeout(cfg.timeoutMs ?? 2000),
    });
    if (!res.ok) throw new Error(`OPA server answered ${res.status} ${res.statusText}`.trim());
    const body = await res.json() as { result?: unknown; provenance?: unknown };
    const bundles = opaRevisions(body.provenance);
    const digest = opaDigest(decision, bundles);
    if (!seen.has(digest)) {
      seen.add(digest);
      onProvenance({ digest, decision, bundles });
    }
    current = digest;
    return { result: body.result, digest };
  };

  return {
    async decide(req) {
      try {
        const { result, digest } = await query(regoInput(req));
        return regoDecision(result, digest, rule, where);
      } catch (e) {
        return { decision: "deny", reasons: [], errors: [`opa: ${e instanceof Error ? e.message : String(e)}`], policyDigest: current };
      }
    },
    digest: () => current,
    async probe() {
      const { result } = await query();
      if (result === undefined) throw new Error(`opa: ${where} is undefined; load a policy with package ${path.replaceAll("/", ".")}`);
    },
  };
}

// Admission lists: a site's own named lists of agents ("partners", "blocked"), which its Cedar policy references. The
// door matches each arrival against them and records the names of the lists the arrival's agent is on, with a digest
// of the lists in force, in the arrival fact; the policy decides what each list means, and the receipt records the
// decision. A list names agents only by what the door checks: a registry entry or an ERC-8004 identity from a verified
// passport, or the subject of a verified arrival (a did:key, a Web Bot Auth origin, or the agent a trusted grant names).
// An arrival the door did not verify is on no list, so a claim cannot put an agent on one, nor take it off a block list
// the policy reads as "forbid unless listed".
import { z } from "zod";
import { sha256Hex } from "./crypto.ts";
import { ERC8004_REGISTRY } from "./erc8004-link.ts";
import { AGENT_ID, AGENT_VERSION, compareVersions } from "./passport.ts";

export const LIST_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const MAX_LISTS = 64;
export const MAX_LIST_ENTRIES = 10_000;

/**
 * One spelling for a URL, so that a list entry matches whatever case, default port, or trailing slash it was written
 * with: a bare origin becomes `URL.origin` (how the door names a Web Bot Auth agent), any other URL its `href`. A value
 * that is not an http(s) URL, such as a did:key, is left as it is.
 */
export function canonicalAgent(v: string): string {
  if (!/^https?:\/\//i.test(v)) return v;
  try {
    const u = new URL(v);
    return u.pathname === "/" && !u.search && !u.hash && !u.username && !u.password ? u.origin : u.href;
  } catch {
    return v;
  }
}

/** A registry's URL as its passports name it: `URL.href`, so `https://APP.example:443` is `https://app.example/`. */
export const canonicalRegistry = (v: string): string => {
  try {
    return new URL(v).href;
  } catch {
    return v;
  }
};

const EntrySchema = z.union([
  /**
   * a registry entry: the registry's URL, as its passports name it, and the agent's id there; it survives key rotation.
   * `version` names one version of the agent, and `versions` a range (`from` inclusive, `below` exclusive); an arrival
   * whose passport carries another version, or none, is not on the list by this entry
   */
  z.object({
    registry: z.string().url().max(200).transform(canonicalRegistry),
    agentId: z.string().regex(AGENT_ID),
    version: z.string().regex(AGENT_VERSION, { message: "version is MAJOR.MINOR.PATCH, numbers only" }).optional(),
    versions: z.object({ from: z.string().regex(AGENT_VERSION).optional(), below: z.string().regex(AGENT_VERSION).optional() }).strict()
      .refine((r) => r.from !== undefined || r.below !== undefined, { message: "versions needs from, below, or both" })
      .refine((r) => r.from === undefined || r.below === undefined || compareVersions(r.from, r.below) < 0, { message: "versions: from must be below below" })
      .optional(),
  }).strict().refine((e) => e.version === undefined || e.versions === undefined, { message: "give version or versions, not both" }),
  /**
   * an ERC-8004 identity, as a verified passport's registry checked it on chain. `registry` names the one registry
   * whose check counts; without it, every registry whose key the door trusts can put an agent on the list by this entry
   */
  z.object({
    erc8004: z.object({ agentRegistry: z.string().regex(ERC8004_REGISTRY).transform((r) => r.toLowerCase()), agentId: z.string().regex(/^(0|[1-9][0-9]{0,77})$/) }).strict(),
    registry: z.string().url().max(200).transform(canonicalRegistry).optional(),
  }).strict(),
  /** the subject of a verified arrival: a did:key, a Web Bot Auth signature agent's origin, or a grant's agent */
  z.object({ agent: z.string().min(1).max(200).transform(canonicalAgent) }).strict(),
]);
export type AdmissionEntry = z.infer<typeof EntrySchema>;

export const AdmissionListsSchema = z.object({
  lists: z.record(z.string(), z.array(EntrySchema).max(MAX_LIST_ENTRIES)).superRefine((lists, ctx) => {
    const names = Object.keys(lists);
    if (names.length > MAX_LISTS) ctx.addIssue({ code: "custom", message: `at most ${MAX_LISTS} lists` });
    for (const name of names) if (!LIST_NAME.test(name)) ctx.addIssue({ code: "custom", path: [name], message: `"${name.slice(0, 40)}": a list name is lowercase letters, digits, and . _ -, at most 64 characters` });
  }),
}).strict();

/** The lists in force, compiled for lookup, with the sha256 of the file they came from. */
export interface AdmissionLists {
  digest: string;
  names: string[];
  match(identity: ArrivalIdentity): string[];
}

/** What the door checked about an arrival, as far as a list can name it. */
export interface ArrivalIdentity {
  /** the arrival's class; only `verified` matches anything */
  class: string;
  subject: string;
  /** the passport, when its outcome is `verified` */
  passport?: { outcome: string; registry?: string; agentId?: string; agentVersion?: string; erc8004?: { agentRegistry: string; agentId: string } };
}

const erc8004Key = (link: { agentRegistry: string; agentId: string }, registry?: string): string => `erc8004 ${link.agentRegistry} ${link.agentId}${registry === undefined ? "" : ` from ${registry}`}`;
const keyOf = (e: AdmissionEntry): string => ("erc8004" in e ? erc8004Key(e.erc8004, e.registry) : "registry" in e ? `registry ${e.registry} ${e.agentId}` : `agent ${e.agent}`);

/** The versions an entry admits (`from` and `upTo` inclusive, `below` exclusive), or undefined for every version. */
type VersionRange = { from?: string; upTo?: string; below?: string } | undefined;
const rangeOf = (e: AdmissionEntry): VersionRange => ("agentId" in e ? (e.version !== undefined ? { from: e.version, upTo: e.version } : e.versions) : undefined);
function inRange(r: VersionRange, version: string | undefined): boolean {
  if (!r) return true;
  // a version that is not one is in no range: compareVersions would refuse it, and a list must not admit it
  if (version === undefined || !AGENT_VERSION.test(version)) return false;
  if (r.from !== undefined && compareVersions(version, r.from) < 0) return false;
  if (r.upTo !== undefined && compareVersions(version, r.upTo) > 0) return false;
  return r.below === undefined || compareVersions(version, r.below) < 0;
}

/** Parses and compiles a lists file; throws, naming what is wrong, when it is not one. */
export function compileAdmissionLists(text: string): AdmissionLists {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error("the admission lists are not JSON");
  }
  const parsed = AdmissionListsSchema.safeParse(raw);
  if (!parsed.success) throw new Error(`the admission lists are not valid: ${parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "file"} ${i.message}`).join("; ")}`);
  // each key holds the lists that name it, with the versions each entry admits
  const index = new Map<string, { name: string; range: VersionRange }[]>();
  for (const [name, entries] of Object.entries(parsed.data.lists)) {
    for (const e of entries) {
      const k = keyOf(e);
      index.set(k, [...(index.get(k) ?? []), { name, range: rangeOf(e) }]);
    }
  }
  const names = Object.keys(parsed.data.lists).sort();
  return {
    digest: sha256Hex(text),
    names,
    match(a) {
      if (a.class !== "verified") return [];
      const keys = [`agent ${canonicalAgent(a.subject)}`];
      const p = a.passport;
      if (p?.outcome === "verified" && p.registry && p.agentId) {
        keys.push(`registry ${canonicalRegistry(p.registry)} ${p.agentId}`);
        if (p.erc8004) {
          const link = { agentRegistry: p.erc8004.agentRegistry.toLowerCase(), agentId: p.erc8004.agentId };
          keys.push(erc8004Key(link), erc8004Key(link, canonicalRegistry(p.registry)));
        }
      }
      const on = new Set<string>();
      const version = p?.outcome === "verified" ? p.agentVersion : undefined;
      for (const k of keys) for (const { name, range } of index.get(k) ?? []) if (inRange(range, version)) on.add(name);
      return [...on].sort();
    },
  };
}

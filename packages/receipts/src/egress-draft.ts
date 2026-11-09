// A first egress policy, drafted from what the agents did while the witness observed them. It is a record of the
// window, not a judgment: a destination an agent should never have reached is permitted like any other.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { internalAddress, isAddressLiteral } from "./addresses.ts";
import { DESTINATION_FACT, type Destination } from "./egress.ts";
import type { ReceiptBundle, ReceiptPredicate } from "./receipt.ts";
import { verifyBundle, type VerifyOptions } from "./verify.ts";

export interface DraftDestination {
  /** `host:port`, the Cedar action */
  name: string;
  count: number;
  first: string;
  last: string;
  /** an IP literal in an internal range: the witness dials a literal a rule names, so only the platform refuses it */
  internal: boolean;
}

export interface DraftAgent {
  id: string;
  count: number;
  first: string;
  last: string;
  destinations: DraftDestination[];
}

export interface DraftSkip {
  file: string;
  kind: "unverified" | "not-egress" | "no-agent" | "not-relayed" | "unsafe-name";
  reason: string;
}

const SKIP_LABEL: Record<DraftSkip["kind"], string> = {
  unverified: "did not verify",
  "not-egress": "not an egress receipt",
  "no-agent": "no verified agent",
  "not-relayed": "not relayed (denied, error, or withheld)",
  "unsafe-name": "a name a Cedar string cannot carry",
};

export interface EgressPolicyDraft {
  /** the Cedar text, which starts with the review warning */
  policy: string;
  agents: DraftAgent[];
  /** receipt files read */
  read: number;
  /** relayed connections from a verified agent, the ones the draft permits */
  used: number;
  skipped: DraftSkip[];
}

export const DRAFT_WARNING = [
  "// DRAFT. Review every line before you enforce it.",
  "// This policy permits every destination the agents below reached while the witness observed them,",
  "// including any they should not have reached. A permit here records what happened, not that it was right.",
  "// Delete each destination you do not recognise. A provider that needs a credential (api.stripe.com,",
  "// api.openai.com, ...) belongs in the gateway, which holds the key, not in a permit here.",
];

const AUTHORIZATION = ".authorization.json";
// A name goes into a Cedar string and a line comment: a quote, a backslash, or a control character could end either.
const UNSAFE = /["\\\u0000-\u001f\u007f]/;

/** Why a verified receipt does not count towards the draft, or null when it does. */
function notUsed(p: ReceiptPredicate): Omit<DraftSkip, "file"> | null {
  if (p.issuer.kind !== "egress") return { kind: "not-egress", reason: `issuer kind ${p.issuer.kind}` };
  if (p.agent.provenance !== "observed") return { kind: "no-agent", reason: "the proxy credential was absent or did not verify" };
  if (p.execution.status !== "executed") return { kind: "not-relayed", reason: p.execution.status };
  if (UNSAFE.test(p.agent.id) || UNSAFE.test(p.tool.name)) return { kind: "unsafe-name", reason: "the agent id or destination holds a quote, a backslash, or a control character" };
  return null;
}

/**
 * Reads every receipt bundle in `receiptsDir`, verifies each with `keys`, and drafts one `permit` per verified agent
 * over the `host:port` destinations of the connections the witness relayed for it. A receipt that does not verify,
 * names no verified agent, or was not relayed is skipped and listed with its reason. Agents and destinations are sorted.
 */
export function draftEgressPolicy(receiptsDir: string, keys: Pick<VerifyOptions, "issuerKeys" | "logKeys" | "logFile">): EgressPolicyDraft {
  const files = readdirSync(receiptsDir, { withFileTypes: true })
    .filter((e) => (e.isFile() || e.isSymbolicLink()) && e.name.endsWith(".json") && !e.name.endsWith(AUTHORIZATION))
    .map((e) => e.name)
    .sort();
  const skipped: DraftSkip[] = [];
  const byAgent = new Map<string, Map<string, DraftDestination>>();
  let used = 0;
  for (const file of files) {
    let p: ReceiptPredicate;
    try {
      const result = verifyBundle(JSON.parse(readFileSync(join(receiptsDir, file), "utf8")) as ReceiptBundle, { ...keys, principalKeys: [] });
      if (!result.ok || !result.statement) {
        skipped.push({ file, kind: "unverified", reason: `failed ${result.checks.filter((c) => !c.ok).map((c) => c.name).join("; ")}` });
        continue;
      }
      p = result.statement.predicate;
    } catch (e) {
      skipped.push({ file, kind: "unverified", reason: `${e instanceof Error ? e.message : String(e)}` });
      continue;
    }
    const why = notUsed(p);
    if (why) {
      skipped.push({ file, ...why });
      continue;
    }
    used++;
    const host = (p.facts[DESTINATION_FACT]?.value as Destination | undefined)?.host ?? "";
    const dests = byAgent.get(p.agent.id) ?? new Map<string, DraftDestination>();
    byAgent.set(p.agent.id, dests);
    const d = dests.get(p.tool.name);
    if (d) {
      d.count++;
      if (p.timestamp < d.first) d.first = p.timestamp;
      if (p.timestamp > d.last) d.last = p.timestamp;
    } else {
      dests.set(p.tool.name, { name: p.tool.name, count: 1, first: p.timestamp, last: p.timestamp, internal: isAddressLiteral(host) && internalAddress(host) });
    }
  }
  const order = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0);
  const agents: DraftAgent[] = [...byAgent].map(([id, dests]) => {
    const destinations = [...dests.values()].sort((a, b) => order(a.name, b.name));
    return {
      id,
      count: destinations.reduce((n, d) => n + d.count, 0),
      first: destinations.map((d) => d.first).sort()[0]!,
      last: destinations.map((d) => d.last).sort().at(-1)!,
      destinations,
    };
  }).sort((a, b) => order(a.id, b.id));
  return { policy: formatDraft(agents, files.length, used, skipped), agents, read: files.length, used, skipped };
}

const times = (n: number, first: string, last: string) => `${n} connection${n === 1 ? "" : "s"}, first ${first}, last ${last}`;

function formatDraft(agents: DraftAgent[], read: number, used: number, skipped: DraftSkip[]): string {
  const lines = [...DRAFT_WARNING, "//", `// Drafted by agent-custody egress draft-policy from ${read} receipt${read === 1 ? "" : "s"}: ${used} relayed connection${used === 1 ? "" : "s"} from verified agents used, ${skipped.length} skipped.`];
  for (const kind of Object.keys(SKIP_LABEL) as DraftSkip["kind"][]) {
    const n = skipped.filter((s) => s.kind === kind).length;
    if (n) lines.push(`//   skipped, ${SKIP_LABEL[kind]}: ${n}`);
  }
  for (const a of agents) {
    lines.push("", `// ${a.id}: ${times(a.count, a.first, a.last)}`);
    lines.push(`permit(principal == Agent::"${a.id}", action in [`);
    a.destinations.forEach((d, i) => {
      const note = d.internal ? "; INTERNAL ADDRESS: the witness dials an IP literal a rule names, and only the platform's deny list refuses it" : "";
      lines.push(`  Action::"${d.name}"${i < a.destinations.length - 1 ? "," : ""} // ${times(d.count, d.first, d.last)}${note}`);
    });
    lines.push("], resource);");
  }
  if (!agents.length) lines.push("", "// No relayed connection from a verified agent: nothing to permit.");
  return lines.join("\n") + "\n";
}

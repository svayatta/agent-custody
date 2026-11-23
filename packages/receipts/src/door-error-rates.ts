// Error rates for the door's signals, from labelled door receipts. What must hold: a rate is reported for one kind of
// arrival and one label source at a time, never pooled. A pooled rate depends on the mix of kinds in the sample, so it
// would say nothing about the next site. And only receipts that verify under the door's key are scored.
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { PublicKeyRef } from "./crypto.ts";
import { ARRIVAL_FACT, type Arrival } from "./door-core.ts";
import { LABELS, LABEL_USES, type LabelQuestion } from "./door-measure.ts";
import type { ReceiptBundle, ReceiptStatement } from "./receipt.ts";
import { verifyBundle } from "./verify.ts";

/**
 * Where a label came from. `test-set`: the arrival was built to be that kind, so the label is true by construction.
 * `operator`: a person who knows the traffic said so. `challenge`: derived from a passed Turnstile or hCaptcha check,
 * so it carries the provider's own error rate. `door`: the door's own check said so (a verified agent, from
 * `door labels`). Such a label is good for the flags and never for a question about `class`, which would score the
 * door against itself; its `validFor` says so.
 */
export const LABEL_SOURCES = ["test-set", "operator", "challenge", "door"] as const;
export type LabelSource = (typeof LABEL_SOURCES)[number];

/**
 * One line of a labels file: what one receipt's arrival really was. A line that `door labels --receipt-ids` exports is
 * also a record of `door measure`, so the fields of that format are accepted here and not read.
 */
export const DoorLabelSchema = z.object({
  receiptId: z.string().min(1),
  /** the kind of arrival, such as `browser` or `forged-signature`; rates are reported per kind */
  kind: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/, { message: "a kind is lower-case letters, digits, and hyphens, at most 64" }),
  /** a program, not a person at a browser */
  automated: z.boolean(),
  /** the agent it names, under a permission this door accepts for this route; null when it named no agent, or when the label does not say */
  genuine: z.boolean().nullable(),
  source: z.enum(LABEL_SOURCES),
  /** the questions and flags this label is good for; absent when it is good for all. A question that is not in the list does not score the label */
  validFor: z.array(z.enum(LABEL_USES)).optional(),
  set: z.string().optional(),
  session: z.string().optional(),
  label: z.enum(LABELS).optional(),
  labelSource: z.string().optional(),
  flags: z.record(z.string(), z.boolean()).optional(),
}).strict().refine((l) => l.label === undefined || (l.label === "automated") === l.automated, { message: "label and automated disagree", path: ["label"] });
export type DoorLabel = z.infer<typeof DoorLabelSchema>;

export interface DoorQuestion {
  id: LabelQuestion;
  asks: string;
  /** what an error is for this question */
  wrong: string;
  applies: (label: DoorLabel) => boolean;
  isWrong: (arrival: Arrival, label: DoorLabel) => boolean;
}

/** The questions the door's signals answer today. Each is scored only on the labels it applies to. */
export const DOOR_QUESTIONS: DoorQuestion[] = [
  {
    id: "agent",
    asks: "Does `class` tell a program from a person?",
    wrong: "a program whose class is `unknown`, or a person whose class is not",
    applies: () => true,
    isWrong: (a, l) => (l.automated ? a.class === "unknown" : a.class !== "unknown"),
  },
  {
    id: "verified",
    asks: "Is `verified` given to the genuine agent, and only to it?",
    wrong: "a genuine agent that is not `verified`, or an arrival that is not genuine and is",
    applies: (l) => l.genuine !== null,
    isWrong: (a, l) => (l.genuine ? a.class !== "verified" : a.class === "verified"),
  },
];

export interface ErrorRateRow {
  question: DoorQuestion["id"];
  kind: string;
  source: LabelSource;
  arrivals: number;
  wrong: number;
  rate: number;
  /** the Wilson score interval at 95% */
  low: number;
  high: number;
}

/** The Wilson score interval for `errors` in `n` at 95%. With no errors it still gives an upper bound, which is the honest figure for a small sample. */
export function wilson(errors: number, n: number): { low: number; high: number } {
  if (n === 0) return { low: 0, high: 1 };
  const z = 1.959963984540054;
  const p = errors / n;
  const d = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const margin = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  // at 0 or n errors the bound is exactly 0 or 1; floating point would leave a residue
  return { low: errors === 0 ? 0 : (centre - margin) / d, high: errors === n ? 1 : (centre + margin) / d };
}

export interface DoorArrivals {
  arrivals: Map<string, Arrival>;
  skipped: { file: string; reason: string }[];
}

/** The arrival fact of every door receipt in `dir` that verifies under `issuerKeys`, the principal keys that sign its grants, and the log, when given. Anything else is skipped with its reason. */
export function readDoorArrivals(dir: string, opts: { issuerKeys: PublicKeyRef[]; principalKeys?: PublicKeyRef[]; logKeys?: PublicKeyRef[]; logFile?: string }): DoorArrivals {
  const arrivals = new Map<string, Arrival>();
  const skipped: DoorArrivals["skipped"] = [];
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    const path = join(dir, file);
    if (!lstatSync(path).isFile()) {
      skipped.push({ file, reason: "not a regular file" });
      continue;
    }
    try {
      const bundle = JSON.parse(readFileSync(path, "utf8")) as ReceiptBundle;
      const result = verifyBundle(bundle, { issuerKeys: opts.issuerKeys, principalKeys: opts.principalKeys ?? [], ...(opts.logKeys ? { logKeys: opts.logKeys } : {}), ...(opts.logFile ? { logFile: opts.logFile } : {}) });
      if (!result.ok) {
        skipped.push({ file, reason: `does not verify: ${result.checks.filter((c) => !c.ok).map((c) => c.name).join("; ")}` });
        continue;
      }
      const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString("utf8")) as ReceiptStatement).predicate;
      if (p.issuer.kind !== "door") {
        skipped.push({ file, reason: `issued by a ${p.issuer.kind}, not a door` });
        continue;
      }
      const arrival = p.facts[ARRIVAL_FACT]?.value as Arrival | undefined;
      if (!arrival || typeof arrival !== "object" || typeof arrival.class !== "string") {
        skipped.push({ file, reason: "the arrival fact is withheld or missing; its capture rule must keep facts in clear" });
        continue;
      }
      arrivals.set(p.receiptId, arrival);
    } catch (e) {
      skipped.push({ file, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  return { arrivals, skipped };
}

/** A labels file: one JSON object per line, as `DoorLabelSchema`. A line that does not parse throws with its number; a receipt labelled twice throws. */
export function parseLabels(text: string): DoorLabel[] {
  const labels: DoorLabel[] = [];
  const seen = new Set<string>();
  text.split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      throw new Error(`labels line ${i + 1}: not JSON`);
    }
    const r = DoorLabelSchema.safeParse(raw);
    if (!r.success) throw new Error(`labels line ${i + 1}: ${r.error.issues.map((x) => `${x.path.join(".") || "line"}: ${x.message}`).join("; ")}`);
    if (seen.has(r.data.receiptId)) throw new Error(`labels line ${i + 1}: receipt ${r.data.receiptId} is labelled twice`);
    seen.add(r.data.receiptId);
    labels.push(r.data);
  });
  return labels;
}

/** Labels from passed challenges, for receipts that have no label: the provider judged a person present. They carry the provider's error rate. */
export function challengeLabels(arrivals: Map<string, Arrival>, labelled: Iterable<string>): DoorLabel[] {
  const taken = new Set(labelled);
  const out: DoorLabel[] = [];
  for (const [receiptId, a] of arrivals) {
    if (!taken.has(receiptId) && a.challenge?.outcome === "passed") out.push({ receiptId, kind: "challenge-passed", automated: false, genuine: null, source: "challenge" });
  }
  return out;
}

/** One row per question, label source, and kind. `unmatched` lists labels whose receipt was not read or did not verify. */
export function doorErrorRates(arrivals: Map<string, Arrival>, labels: DoorLabel[]): { rows: ErrorRateRow[]; unmatched: string[] } {
  const unmatched: string[] = [];
  const groups = new Map<string, { question: DoorQuestion["id"]; kind: string; source: LabelSource; arrivals: number; wrong: number }>();
  for (const label of labels) {
    const arrival = arrivals.get(label.receiptId);
    if (!arrival) {
      unmatched.push(label.receiptId);
      continue;
    }
    for (const q of DOOR_QUESTIONS) {
      if (!q.applies(label) || (label.validFor && !label.validFor.includes(q.id))) continue;
      const key = `${q.id}\0${label.source}\0${label.kind}`;
      const g = groups.get(key) ?? { question: q.id, kind: label.kind, source: label.source, arrivals: 0, wrong: 0 };
      g.arrivals++;
      if (q.isWrong(arrival, label)) g.wrong++;
      groups.set(key, g);
    }
  }
  const order = (id: DoorQuestion["id"]) => DOOR_QUESTIONS.findIndex((q) => q.id === id);
  const rows = [...groups.values()]
    .sort((a, b) => order(a.question) - order(b.question))
    .map((g) => ({ ...g, rate: g.wrong / g.arrivals, ...wilson(g.wrong, g.arrivals) }));
  return { rows, unmatched };
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

/** The rows as Markdown: a table per question, each row one kind from one label source. */
export function formatErrorRates(rows: ErrorRateRow[]): string {
  const out: string[] = [];
  for (const q of DOOR_QUESTIONS) {
    const mine = rows.filter((r) => r.question === q.id);
    if (!mine.length) continue;
    out.push(`**${q.asks}** An error is ${q.wrong}.`, "", "| kind | labels | arrivals | wrong | error rate (lower is better) | 95% interval |", "| --- | --- | ---: | ---: | ---: | --- |");
    for (const r of mine) out.push(`| \`${r.kind}\` | ${r.source} | ${r.arrivals} | ${r.wrong} | ${pct(r.rate)} | ${pct(r.low)} to ${pct(r.high)} |`);
    out.push("");
  }
  return out.join("\n");
}

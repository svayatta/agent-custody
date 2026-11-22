// Writes the published error rates of the door's signals (docs/door-error-rates.md). Run it with node from
// packages/receipts:
//
//   node scripts/door-error-rates.ts results --date <YYYY-MM-DD> <labelled.jsonl>...   measures the sets and writes labelled/results.json
//   node scripts/door-error-rates.ts page                                              writes the tables of the page from labelled/results.json
//
// The page holds no number that a person typed: test/door-measure.test.ts makes the tables again and compares.
import { createReadStream, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { createMeasure, intervalText, parseLabelledRecord, ratePercent, type Label, type MeasureResult, type Rate } from "../src/door-measure.ts";
import { FLAG_SIGNALS, type FlagSignal } from "../src/door-signals.ts";

const here = join(import.meta.dirname, "..");
export const RESULTS_FILE = join(here, "labelled", "results.json");
export const MANIFEST_FILE = join(here, "labelled", "manifest.json");
export const PAGE_FILE = join(here, "docs", "door-error-rates.md");
export const REGION = ["<!-- #region results -->", "<!-- #endregion results -->"] as const;

export interface Results extends MeasureResult {
  /** the day of the measure, UTC */
  date: string;
}
export interface Manifest {
  sets: { set: string; labels: Partial<Record<Label, string>> }[];
  /** why a flag has no measure on a side */
  notMeasured: Partial<Record<FlagSignal, Partial<Record<Label, string>>>>;
}

const SIDES: { label: Label; name: string; direction: string }[] = [
  { label: "human", name: "false-positive rate", direction: "lower is better" },
  { label: "automated", name: "detection rate", direction: "higher is better" },
];
const UNITS = [{ key: "sessions", title: "per session" }, { key: "arrivals", title: "per arrival" }] as const;

/** The tables of the page: for each unit and each side, one row for each flag and set with a measure, and one "not measured" row for each flag without. */
export function tablesOf(results: Results, manifest: Manifest): string {
  const out: string[] = [];
  for (const unit of UNITS) {
    for (const side of SIDES) {
      out.push(`### ${side.name[0]!.toUpperCase()}${side.name.slice(1)} ${unit.title} (${side.direction})`, "");
      out.push(`| flag | set | ${unit.key} | flagged | ${side.name} (${side.direction}) | ${results.confidencePercent}% interval | what \`${side.label}\` means in this set |`, "| --- | --- | --- | --- | --- | --- | --- |");
      for (const flag of FLAG_SIGNALS) {
        let rows = 0;
        for (const set of results.sets) {
          const r: Rate = set.flags.find((f) => f.flag === flag)![side.label][unit.key];
          if (r.rate === null) continue;
          rows++;
          const meaning = manifest.sets.find((s) => s.set === set.set)?.labels[side.label];
          if (!meaning) throw new Error(`the manifest does not say what ${side.label} means in ${set.set}`);
          out.push(`| \`${flag}\` | ${set.set} | ${r.n} | ${r.flagged} | ${ratePercent(r)} | ${intervalText(r)} | ${meaning} |`);
        }
        if (!rows) {
          const why = manifest.notMeasured[flag]?.[side.label];
          if (!why) throw new Error(`the manifest does not say why ${flag} has no measure for ${side.label}`);
          out.push(`| \`${flag}\` | not measured | | | | | ${why} |`);
        }
      }
      out.push("");
    }
  }
  return out.join("\n").trimEnd();
}

/** The page with its tables made again from the results. */
export function pageWith(page: string, tables: string): string {
  const [start, end] = [page.indexOf(REGION[0]), page.indexOf(REGION[1])];
  if (start < 0 || end < start) throw new Error("the page has no results region");
  return `${page.slice(0, start + REGION[0].length)}\n${tables}\n${page.slice(end)}`;
}

if (process.argv[1] === import.meta.filename) {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "results") {
    if (rest[0] !== "--date" || !/^\d{4}-\d{2}-\d{2}$/.test(rest[1] ?? "") || rest.length < 3) throw new Error("results needs --date <YYYY-MM-DD> and at least one labelled set");
    const m = createMeasure();
    for (const file of rest.slice(2)) for await (const line of createInterface({ input: createReadStream(file), crlfDelay: Infinity })) if (line.trim()) m.add(parseLabelledRecord(line));
    const results: Results = { date: rest[1]!, ...m.result() };
    writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2) + "\n");
    console.log(`wrote ${RESULTS_FILE}: ${results.sets.map((s) => s.set).join(", ")}`);
  } else if (mode === "page") {
    const tables = tablesOf(JSON.parse(readFileSync(RESULTS_FILE, "utf8")) as Results, JSON.parse(readFileSync(MANIFEST_FILE, "utf8")) as Manifest);
    writeFileSync(PAGE_FILE, pageWith(readFileSync(PAGE_FILE, "utf8"), tables));
    console.log(`wrote the tables of ${PAGE_FILE}`);
  } else throw new Error("door-error-rates needs results or page");
}

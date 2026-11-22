// Makes a labelled set from the KeyRecs keystroke dataset (Zenodo record 7886743, CC-BY-4.0), for
// `agent-custody door measure` (docs/door-error-rates.md). Run it with node from packages/receipts:
//
//   node scripts/door-labels-keyrecs.ts <fixed-text.csv> [--stats <file>] > keyrecs.jsonl
//
// Each row of fixed-text.csv is one repetition: a recruited participant types the same 10 characters. The row becomes
// one form report with 10 key presses. The fill time is the sum of the nine DD columns: the time from the first key
// press to the last key press. The form report counts the time to the submit, which is later, so this fill time is
// never too long. A sum below zero is a recording error and becomes 0. The label is good for `behaviour.form.fast`
// only: the dataset has no pointer press and no submit, so it says nothing about `behaviour.form.noInput`.
// `--stats` writes the counts of the set and of its fast repetitions to a file (labelled/keyrecs-stats.json).
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import type { LabelledRecord } from "../src/door-measure.ts";
import { FORM_FAST_MS_PER_KEY } from "../src/door-signals.ts";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { stats: { type: "string" } } });
const file = positionals[0];
if (!file) throw new Error("door-labels-keyrecs needs the path of fixed-text.csv");
const [head, ...rows] = readFileSync(file, "utf8").trim().split(/\r?\n/).map((line) => line.split(","));
const dd = head!.flatMap((name, i) => (name.startsWith("DD.") ? [i] : []));
if (dd.length !== 9 || head![0] !== "participant" || head![1] !== "session" || head![2] !== "repetition") throw new Error("not the KeyRecs fixed-text.csv: the columns differ");
const KEYS = dd.length + 1;

rows.sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : Number(a[1]) - Number(b[1]) || Number(a[2]) - Number(b[2])));
const out: string[] = [];
// the repetitions whose time for each key is below the threshold of `behaviour.form.fast`, by session
const fast = new Map<string, { repetitions: number; belowZero: number; fillMs: number[] }>();
for (const row of rows) {
  const seconds = dd.reduce((sum, i) => sum + Number(row[i]), 0);
  if (!Number.isFinite(seconds)) throw new Error(`a row of ${row[0]} has a time that is not a number`);
  const ms = Math.max(0, Math.round(seconds * 1000));
  if (ms < KEYS * FORM_FAST_MS_PER_KEY) {
    const f = fast.get(`${row[0]}-${row[1]}`) ?? { repetitions: 0, belowZero: 0, fillMs: [] };
    fast.set(`${row[0]}-${row[1]}`, f);
    f.repetitions++;
    if (seconds < 0) f.belowZero++;
    else f.fillMs.push(ms);
  }
  const record: LabelledRecord = {
    set: "keyrecs-fixed-text",
    session: `${row[0]}-${row[1]}`,
    label: "human",
    labelSource: "recruited-participant",
    validFor: ["behaviour.form.fast"],
    // the dataset has no clock time: the repetition number keeps the order
    observation: { at: Number(row[2]), method: "POST", path: "/", referer: "absent", secFetch: {}, form: `v=1;ms=${ms};k=${KEYS};p=0;paste=0;trusted=1` },
  };
  out.push(JSON.stringify(record));
}
process.stdout.write(out.join("\n") + "\n");
if (values.stats) {
  const stats = {
    participants: new Set(rows.map((r) => r[0])).size,
    sessions: new Set(rows.map((r) => `${r[0]}-${r[1]}`)).size,
    sessionsForEachParticipant: [...new Set(rows.map((r) => r[1]))].length,
    repetitions: rows.length,
    keysInARepetition: KEYS,
    fastBelowMs: KEYS * FORM_FAST_MS_PER_KEY,
    fastRepetitions: [...fast.values()].reduce((n, f) => n + f.repetitions, 0),
    fastSessions: [...fast].map(([session, f]) => ({ session, repetitions: f.repetitions, withATimeBelowZero: f.belowZero, ...(f.fillMs.length ? { shortestFillMs: Math.min(...f.fillMs), longestFillMs: Math.max(...f.fillMs) } : {}) })),
  };
  writeFileSync(values.stats, JSON.stringify(stats, null, 2) + "\n");
}

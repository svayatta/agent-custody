// Aspect: the false-positive rate of each door flag, measured on a labelled set. Source: src/door-measure.ts
// Run:    node examples/61-door-measure.ts
//
// A labelled set is JSON Lines: one recorded arrival per line, with a label. The measure replays each session through
// the door's own signal functions and counts, for each flag, the humans it marks and the automated clients it marks.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { formatMeasure, measure, parseLabelledRecord } from "../src/door-measure.ts";
import { step } from "./_out.ts";

step(1, "read the labelled set that this repository records from real clients");
const lines = readFileSync(join(import.meta.dirname, "..", "labelled", "capture.jsonl"), "utf8").trim().split("\n");
const records = lines.map(parseLabelledRecord);
console.log(`   ${records.length} labelled arrivals`);

step(2, "replay them, and print each flag's rates with the 95% interval");
const result = measure(records);
console.log(formatMeasure(result));

step(3, "a small set gives a wide interval: no real browser is flagged, and the interval still reaches far above zero");
const browsers = result.sets.find((s) => s.set === "capture-real-browsers")!;
const mismatch = browsers.flags.find((f) => f.flag === "fingerprint.headers.mismatch")!.human.sessions;
console.log(`   fingerprint.headers.mismatch on real browsers: ${mismatch.flagged} of ${mismatch.n} sessions, interval up to ${mismatch.high! / 100}%`);
if (mismatch.flagged !== 0 || mismatch.n === 0 || mismatch.high! < 1000) throw new Error("the capture set does not measure as recorded");

console.log("\nOK");

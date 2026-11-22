// Aspect: published error rates for the door's signals. Source: src/door-test-set.ts, src/door-error-rates.ts
// Run:    node examples/58-door-error-rates.ts
//
// The door is given arrivals of known kinds: a browser, scripts, genuine agents, and impostors with forged, replayed,
// untrusted, expired, or misdirected credentials. Each receipt is verified, each arrival scored against its label, and
// the rates are printed per kind with a 95% interval, never pooled. Then one receipt is labelled as an operator would,
// and one receipt that does not verify is shown to change nothing.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { doorErrorRates, formatErrorRates, parseLabels, readDoorArrivals } from "../src/door-error-rates.ts";
import { buildDoorTestSet } from "../src/door-test-set.ts";
import { out, step } from "./_out.ts";

const dir = out("58-door-error-rates");

step(1, "build the labelled test set: 25 arrivals of each of 12 kinds, decided by the door core, with no network");
const set = await buildDoorTestSet(dir, { perKind: 25 });
console.log(`   ${set.labels.length} labelled arrivals, receipts in ${set.receiptsDir}`);

step(2, "read the receipts that verify under the door's key, and score each kind against its label");
const read = readDoorArrivals(set.receiptsDir, { issuerKeys: [set.doorKey], principalKeys: [set.principalKey], logFile: set.logFile });
assert.equal(read.skipped.length, 0);
const { rows } = doorErrorRates(read.arrivals, parseLabels(readFileSync(set.labelsFile, "utf8")));
console.log(formatErrorRates(rows).replace(/^/gm, "   "));
assert.deepEqual(rows.filter((r) => r.question === "verified" && r.wrong > 0), []);
assert.deepEqual(rows.filter((r) => r.wrong > 0).map((r) => r.kind), ["script", "script-as-browser"]);

step(3, "an operator's label is its own row: a crawler the site runs, labelled from what the operator knows");
const signed = set.labels.find((l) => l.kind === "signed-agent")!;
const mine = doorErrorRates(read.arrivals, [{ receiptId: signed.receiptId, kind: "our-crawler", automated: true, genuine: true, source: "operator" }]).rows;
console.log(`   ${mine.map((r) => `${r.question}: ${r.kind} (${r.source}) ${r.wrong} wrong of ${r.arrivals}`).join("; ")}`);
assert.equal(mine.every((r) => r.source === "operator" && r.wrong === 0), true);

step(4, "a receipt edited to say verified no longer verifies, so it is skipped and cannot move a rate");
const file = readdirSync(set.receiptsDir).find((f) => f === `${set.labels.find((l) => l.kind === "forged-signature")!.receiptId}.json`)!;
const bundle = JSON.parse(readFileSync(join(set.receiptsDir, file), "utf8"));
const payload = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString());
payload.predicate.facts.arrival.value.class = "verified";
bundle.envelope.payload = Buffer.from(JSON.stringify(payload)).toString("base64");
writeFileSync(join(set.receiptsDir, file), JSON.stringify(bundle));
const again = readDoorArrivals(set.receiptsDir, { issuerKeys: [set.doorKey], principalKeys: [set.principalKey] });
console.log(`   skipped ${again.skipped[0]!.file}: ${again.skipped[0]!.reason}`);
assert.equal(again.skipped.length, 1);
assert.equal(doorErrorRates(again.arrivals, set.labels).unmatched.length, 1);

console.log("\nOK");

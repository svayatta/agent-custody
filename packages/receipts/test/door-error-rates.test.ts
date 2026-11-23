// Published error rates for the door. What a reader relies on: a rate is for one kind of arrival and one label source,
// never a blend whose value depends on the sample's mix; a receipt that does not verify cannot move a rate; and the
// published page says what the door does now, because a test builds the set again and compares.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair, writeKeyPair } from "../src/crypto.ts";
import type { Arrival } from "../src/door-core.ts";
import { challengeLabels, doorErrorRates, parseLabels, readDoorArrivals, wilson, type DoorLabel } from "../src/door-error-rates.ts";
import { buildDoorTestSet, DOOR_TEST_KINDS, type DoorTestSet } from "../src/door-test-set.ts";
import { block, measuredBlocks, PAGE } from "../scripts/door-error-rates-page.ts";

const arrival = (over: Partial<Arrival>): Arrival => ({ class: "unknown", subject: "unknown", grant: "absent", signature: "absent", remote: "198.51.100.1", method: "GET", path: "/", route: "api", ...over });
const label = (receiptId: string, over: Partial<DoorLabel>): DoorLabel => ({ receiptId, kind: "browser", automated: false, genuine: null, source: "operator", ...over });

let set: DoorTestSet;
let dir: string;
beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "door-error-rates-"));
  set = await buildDoorTestSet(dir, { perKind: 4 });
});

describe("door error rates", () => {
  it("gives an upper bound when no error was seen, so a small clean sample is not read as perfect", () => {
    expect(wilson(0, 200).low).toBe(0);
    expect(wilson(0, 200).high).toBeCloseTo(0.0188, 4);
    expect(wilson(10, 100).low).toBeCloseTo(0.0552, 4);
    expect(wilson(10, 100).high).toBeCloseTo(0.1744, 4);
    expect(wilson(0, 0)).toEqual({ low: 0, high: 1 });
  });

  it("reports each kind and each label source on its own row and never a pooled rate", () => {
    const arrivals = new Map([["a", arrival({})], ["b", arrival({})], ["c", arrival({ class: "verified" })], ["d", arrival({})]]);
    const { rows } = doorErrorRates(arrivals, [
      label("a", { kind: "browser" }),
      label("b", { kind: "script", automated: true }),
      label("c", { kind: "script", automated: true, genuine: false }),
      label("d", { kind: "browser", source: "challenge" }),
    ]);
    const agent = rows.filter((r) => r.question === "agent").map((r) => [r.kind, r.source, r.arrivals, r.wrong]);
    expect(agent).toEqual([["browser", "operator", 1, 0], ["script", "operator", 2, 1], ["browser", "challenge", 1, 0]]);
    // the verified question applies only where the label says whether the arrival is genuine
    expect(rows.filter((r) => r.question === "verified").map((r) => [r.kind, r.wrong])).toEqual([["script", 1]]);
  });

  it("reads only receipts that verify under the door's key, so an edited or foreign receipt cannot move a rate", () => {
    const other = generateKeyPair();
    const wrongKey = readDoorArrivals(set.receiptsDir, { issuerKeys: [other], principalKeys: [set.principalKey] });
    expect(wrongKey.arrivals.size).toBe(0);
    expect(wrongKey.skipped[0]!.reason).toContain("does not verify");
    const { rows, unmatched } = doorErrorRates(wrongKey.arrivals, set.labels);
    expect(rows).toEqual([]);
    expect(unmatched).toHaveLength(set.labels.length);

    // an impostor's receipt: its class is claimed, so the edit changes the signed bytes
    const file = `${set.labels.find((l) => l.kind === "forged-signature")!.receiptId}.json`;
    const edited = mkdtempSync(join(tmpdir(), "door-error-rates-edited-"));
    const bundle = JSON.parse(readFileSync(join(set.receiptsDir, file), "utf8"));
    const payload = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString());
    payload.predicate.facts.arrival.value.class = "verified";
    bundle.envelope.payload = Buffer.from(JSON.stringify(payload)).toString("base64");
    writeFileSync(join(edited, file), JSON.stringify(bundle));
    expect(readDoorArrivals(edited, { issuerKeys: [set.doorKey] }).arrivals.size).toBe(0);
  });

  it("refuses a labels file with a malformed line or a receipt labelled twice, naming the line", () => {
    expect(() => parseLabels('{"receiptId":"a","kind":"Browser","automated":false,"genuine":null,"source":"operator"}')).toThrow(/line 1: kind/);
    expect(() => parseLabels('{"receiptId":"a","kind":"b","automated":false,"genuine":null,"source":"guess"}')).toThrow(/line 1: source/);
    expect(() => parseLabels('{"receiptId":"a","kind":"b","automated":false,"genuine":null,"source":"operator","extra":1}')).toThrow(/line 1/);
    const line = '{"receiptId":"a","kind":"b","automated":false,"genuine":null,"source":"operator"}';
    expect(() => parseLabels(`${line}\n\n${line}`)).toThrow(/line 3: receipt a is labelled twice/);
    expect(() => parseLabels("not json")).toThrow(/line 1: not JSON/);
  });

  it("scores a label only on the questions in its validFor, and reads a line that door labels exports", () => {
    const own = '{"receiptId":"a","set":"own-door","session":"s1","label":"automated","labelSource":"verified-agent","kind":"verified-agent","automated":true,"genuine":null,"source":"door","validFor":["behaviour.timing.regular"],"flags":{"behaviour.timing.regular":false}}';
    const labels = parseLabels(`${own}\n{"receiptId":"b","kind":"verified-agent","automated":true,"genuine":null,"source":"operator"}`);
    const arrivals = new Map([["a", arrival({ class: "verified" })], ["b", arrival({ class: "verified" })]]);
    // the door's own word about a verified agent does not score the door's class; the operator's word does
    expect(doorErrorRates(arrivals, labels).rows.map((r) => [r.question, r.source, r.arrivals])).toEqual([["agent", "operator", 1]]);
    expect(() => parseLabels(own.replace('"label":"automated"', '"label":"human"'))).toThrow(/line 1: label/);
    expect(() => parseLabels(own.replace("behaviour.timing.regular\"]", 'no-such-use"]'))).toThrow(/line 1: validFor/);
  });

  it("derives challenge labels only for receipts that have no label of their own, and keeps them in their own source", () => {
    const arrivals = new Map([["a", arrival({ challenge: { provider: "turnstile", outcome: "passed" } })], ["b", arrival({ challenge: { provider: "turnstile", outcome: "passed" } })], ["c", arrival({ challenge: { provider: "turnstile", outcome: "failed" } })]]);
    expect(challengeLabels(arrivals, ["b"])).toEqual([{ receiptId: "a", kind: "challenge-passed", automated: false, genuine: null, source: "challenge" }]);
  });

  it("finds in the test set what the page says: verified only for genuine agents, and a program that presents nothing is unknown like a person", () => {
    const read = readDoorArrivals(set.receiptsDir, { issuerKeys: [set.doorKey], principalKeys: [set.principalKey] });
    expect(read.skipped).toEqual([]);
    const { rows, unmatched } = doorErrorRates(read.arrivals, set.labels);
    expect(unmatched).toEqual([]);
    expect(rows.filter((r) => r.question === "verified" && r.wrong > 0)).toEqual([]);
    expect(rows.filter((r) => r.question === "agent" && r.wrong > 0).map((r) => [r.kind, r.wrong, r.arrivals])).toEqual([["script", 4, 4], ["script-as-browser", 4, 4]]);
    // the reason it is structural: a browser and a program sending its headers leave the same arrival fact
    const strip = (a: Arrival) => ({ ...a, remote: undefined, rate: undefined });
    const browser = set.labels.find((l) => l.kind === "browser")!;
    const imitation = set.labels.find((l) => l.kind === "script-as-browser")!;
    expect(strip(read.arrivals.get(imitation.receiptId)!)).toEqual(strip(read.arrivals.get(browser.receiptId)!));
    expect(new Set(set.labels.map((l) => l.kind))).toEqual(new Set(DOOR_TEST_KINDS.map((k) => k.kind)));
  });

  it("the published page holds the numbers and kinds the door produces now (node scripts/door-error-rates-page.ts writes them)", async () => {
    const page = readFileSync(PAGE, "utf8");
    const now = await measuredBlocks();
    expect(block(page, "error-rates")).toBe(now["error-rates"]);
    expect(block(page, "error-rates-kinds")).toBe(now["error-rates-kinds"]);
  });

  it("the command scores a receipts directory against a labels file, and reports receipts it skipped", () => {
    const keys = join(dir, "keys");
    const door = writeKeyPair(set.doorKey, keys, "door").pubFile;
    const principal = writeKeyPair(set.principalKey, keys, "principal").pubFile;
    const cli = (...a: string[]) => spawnSync(process.execPath, ["--import", "tsx", join(import.meta.dirname, "../src/cli.ts"), "door", "error-rates", ...a], { encoding: "utf8", timeout: 60_000 });
    const ok = cli("--receipts", set.receiptsDir, "--labels", set.labelsFile, "--issuer-key", door, "--principal-key", principal, "--log", set.logFile);
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout).toContain("| `script` | test-set | 4 | 4 | 100.0% |");
    expect(ok.stderr).toBe("");
    const json = cli("--receipts", set.receiptsDir, "--labels", set.labelsFile, "--issuer-key", door, "--json");
    // without the principal's key the granted agents' receipts do not verify, and their labels are reported, not scored
    expect(JSON.parse(json.stdout).unmatched).toHaveLength(4);
    expect(json.stderr).toContain("label(s) name a receipt that was not read or did not verify");
    const missing = cli("--labels", set.labelsFile);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain("--test-set");
  });
});

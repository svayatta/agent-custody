// The measure behind the published error rates of the door's signals (docs/door-error-rates.md). A rate that the page
// states must be one that the tool measured: so the counts must follow the door's own functions, a flag must not count
// an arrival that it cannot apply to, the committed capture must give the committed results again, and the page must
// hold the tables that the results give and no other rate. Nothing here uses the network or the large public sets.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadDoorConfig } from "../src/config.ts";
import { createDelegation } from "../src/delegation.ts";
import { RECEIPT_HEADER, createDoorHost, serveDoor } from "../src/door.ts";
import { createMeasure, flagValues, formatMeasure, formatRate, intervalText, labelsFromReceipts, measure, parseLabelledRecord, percent, rateOf, ratePercent, thresholds, type LabelledRecord, type MeasureResult, type SetMeasure } from "../src/door-measure.ts";
import * as signals from "../src/door-signals.ts";
import { parseLabels } from "../src/door-error-rates.ts";
import { FLAG_SIGNALS, KNOWN_TOOL_JA4, TIMING_MIN_GAPS, type FlagSignal, type Observation } from "../src/door-signals.ts";
import { grantHeader } from "../src/grant-header.ts";
import type { ReceiptPredicate } from "../src/receipt.ts";
import { buildDoorFixture, startOrigin } from "../scripts/door-fixture.ts";
import { MANIFEST_FILE, PAGE_FILE, REGION, RESULTS_FILE, pageWith, tablesOf, type Manifest, type Results } from "../scripts/door-flag-rates-page.ts";

const labelled = join(import.meta.dirname, "..", "labelled");
const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const seen = (at: number, over: Partial<Observation> = {}): Observation => ({ at, method: "GET", path: "/", referer: "absent", secFetch: {}, ...over });
const record = (session: string, label: LabelledRecord["label"], observation: Observation, over: Partial<LabelledRecord> = {}): LabelledRecord => ({ set: "test", session, label, labelSource: "test", observation, ...over });
const flagOf = (result: MeasureResult, flag: FlagSignal, set = "test") => result.sets.find((s) => s.set === set)!.flags.find((f) => f.flag === flag)!;
const open: { close(): Promise<void> | void }[] = [];
afterAll(async () => {
  for (const o of open) await o.close();
});

describe("a rate and its interval", () => {
  it("is the Wilson score interval, in integers per 10,000, rounded outward", () => {
    expect(rateOf(5, 10)).toEqual({ n: 10, flagged: 5, rate: 5000, low: 2365, high: 7635 });
    expect(rateOf(0, 10)).toEqual({ n: 10, flagged: 0, rate: 0, low: 0, high: 2776 });
    expect(rateOf(10, 10)).toEqual({ n: 10, flagged: 10, rate: 10_000, low: 7224, high: 10_000 });
    expect(rateOf(1, 3)).toMatchObject({ rate: 3333 });
    // a wider set gives a narrower interval
    const [small, large] = [rateOf(2, 20), rateOf(200, 2000)];
    expect(large.high! - large.low!).toBeLessThan(small.high! - small.low!);
  });

  it("is not measured when the flag applies to nothing, and never reads as zero when something was flagged", () => {
    expect(rateOf(0, 0)).toEqual({ n: 0, flagged: 0, rate: null, low: null, high: null });
    expect(formatRate(rateOf(0, 0))).toBe("not measured");
    expect(formatRate(rateOf(9, 50_724))).toBe("9/50724 = <0.1% (0.0% to 0.1%)");
    expect(formatRate(rateOf(0, 3))).toBe("0/3 = 0.0% (0.0% to 56.2%)");
    expect([percent(0), percent(5), percent(10_000)]).toEqual(["0.0%", "0.1%", "100.0%"]);
  });

  it("prints each bound of the interval outward, so the printed interval is never narrower than the computed one", () => {
    // 27 and 361 per 10,000: the low bound goes down to 0.2% and the high bound goes up to 3.7%
    expect(rateOf(2, 198)).toMatchObject({ low: 27, high: 361 });
    expect(formatRate(rateOf(2, 198))).toBe("2/198 = 1.0% (0.2% to 3.7%)");
    expect(formatRate(rateOf(3, 200))).toBe("3/200 = 1.5% (0.5% to 4.4%)");
    expect(intervalText({ n: 1, flagged: 0, rate: 185, low: 181, high: 189 })).toBe("1.8% to 1.9%");
    expect([percent(27, "down"), percent(27, "up"), percent(30, "down"), percent(30, "up")]).toEqual(["0.2%", "0.3%", "0.3%", "0.3%"]);
    for (const [flagged, n] of [[0, 1], [1, 3], [2, 198], [9, 50_724], [72, 9720], [96, 19_772], [5, 5], [1, 5]] as const) {
      const r = rateOf(flagged, n);
      const [low, high] = intervalText(r).split(" to ").map((t) => Math.round(Number.parseFloat(t) * 100));
      expect(low!, `${flagged}/${n} low`).toBeLessThanOrEqual(r.low!);
      expect(high!, `${flagged}/${n} high`).toBeGreaterThanOrEqual(r.high!);
      expect(ratePercent(r) === "0.0%", `${flagged}/${n} reads as zero`).toBe(flagged === 0);
    }
  });
});

describe("the replay of recorded sessions", () => {
  it("gives each session its own history, in the recorded time, and counts per arrival and per session", () => {
    const steady = Array.from({ length: TIMING_MIN_GAPS + 3 }, (_, i) => record("robot", "automated", seen(i * 1000)));
    const uneven = [0, 300, 4000, 4100, 9000, 20_000, 20_500, 31_000].map((at) => record("person", "human", seen(at)));
    // the two sessions come interleaved, as two sources do at a door
    const result = measure(steady.flatMap((r, i) => [r, uneven[i]!]));
    const timing = flagOf(result, "behaviour.timing.regular");
    // the flag needs TIMING_MIN_GAPS gaps: the first TIMING_MIN_GAPS arrivals are not flagged, the 3 after them are
    expect(timing.automated.arrivals).toMatchObject({ n: 8, flagged: 3 });
    expect(timing.automated.sessions).toMatchObject({ n: 1, flagged: 1, rate: 10_000 });
    expect(timing.human.arrivals).toMatchObject({ n: 8, flagged: 0 });
    expect(timing.human.sessions).toMatchObject({ n: 1, flagged: 0, rate: 0 });
    expect(result.sets[0]).toMatchObject({ arrivals: { human: 8, automated: 8 }, sessions: { human: 1, automated: 1 }, labelSources: { human: { test: 8 }, automated: { test: 8 } } });
    expect(result.thresholds).toEqual(thresholds());
    expect(result).toMatchObject({ per: 10_000, confidencePercent: 95 });
  });

  it("records every exported constant of door-signals.ts that a flag reads", () => {
    // not read by a flag: the name of the header, the cap that the form script applies in the browser, and the list of the flags
    const notRead = ["FORM_REPORT_HEADER", "MAX_FORM_EVENTS", "FLAG_SIGNALS"];
    const constants = Object.keys(signals).filter((name) => /^[A-Z][A-Z0-9_]+$/.test(name) && !notRead.includes(name));
    expect(Object.keys(thresholds()).sort()).toEqual(constants.sort());
    expect(thresholds()).toMatchObject({ STATE_CHANGING: ["DELETE", "PATCH", "POST", "PUT"], MAX_FORM_FILL_MS: signals.MAX_FORM_FILL_MS });
    expect(JSON.parse(JSON.stringify(thresholds()))).toEqual(thresholds());
  });

  it("remembers a page load of the same session only: a write after it is not a direct write", () => {
    const result = measure([
      record("with-page", "human", seen(0, { accept: "text/html" })),
      record("with-page", "human", seen(1000, { method: "POST" })),
      record("no-page", "automated", seen(500, { method: "POST" })),
    ]);
    const direct = flagOf(result, "behaviour.navigation.directWrite");
    expect(direct.human.arrivals).toMatchObject({ n: 2, flagged: 0 });
    expect(direct.automated.sessions).toMatchObject({ n: 1, flagged: 1 });
  });

  it("does not count an arrival for a flag whose group is absent, or that the label is not good for", () => {
    const names = { names: ["host", "user-agent", "accept"], ordered: true };
    const result = measure([
      record("bare", "automated", seen(0)),
      record("headers", "automated", seen(0, { userAgent: CHROME, secure: true, headers: names })),
      record("tls", "automated", seen(0, { userAgent: CHROME, tls: { ja4: "t12d1516h2_000000000000_111111111111" } })),
      record("tls-other", "automated", seen(0, { tls: { negotiated: "TLSv1.3" } })),
      record("form", "automated", seen(0, { form: "v=1;ms=0;k=0;p=0;paste=0;trusted=1" })),
      record("form-bad", "automated", seen(0, { form: "not a report" })),
      record("limited", "automated", seen(0, { userAgent: CHROME, secure: true, headers: names, form: "v=1;ms=10;k=20;p=0;paste=0;trusted=1" }), { validFor: ["behaviour.form.fast"] }),
    ]);
    const counted = Object.fromEntries(FLAG_SIGNALS.map((f) => [f, [flagOf(result, f).automated.arrivals.n, flagOf(result, f).automated.arrivals.flagged]]));
    expect(counted).toEqual({
      "fingerprint.headers.mismatch": [1, 1],
      "fingerprint.tls.mismatch": [1, 1],
      "fingerprint.tls.knownTool": [1, 0],
      "behaviour.timing.regular": [6, 0],
      "behaviour.navigation.directWrite": [6, 0],
      "behaviour.form.fast": [2, 1],
      "behaviour.form.noInput": [1, 1],
    });
    expect(flagOf(result, "fingerprint.headers.mismatch").human.sessions).toEqual({ n: 0, flagged: 0, rate: null, low: null, high: null });
    expect(formatMeasure(result)).toContain("detection rate (automated flagged; higher is better)    per session: 1/1 = 100.0%");
  });

  it("counts the flags that a door computed, and takes an absent flag as one that does not apply", () => {
    const result = measure([
      { set: "own", session: "s1", label: "human", labelSource: "challenge-passed", flags: { "behaviour.timing.regular": false, "behaviour.navigation.directWrite": true } },
      { set: "own", session: "s1", label: "human", labelSource: "challenge-passed", flags: { "behaviour.timing.regular": false } },
    ]);
    expect(flagOf(result, "behaviour.navigation.directWrite", "own").human).toMatchObject({ arrivals: { n: 1, flagged: 1 }, sessions: { n: 1, flagged: 1 } });
    expect(flagOf(result, "behaviour.timing.regular", "own").human).toMatchObject({ arrivals: { n: 2, flagged: 0 }, sessions: { n: 1, flagged: 0 } });
    expect(flagOf(result, "fingerprint.headers.mismatch", "own").human.arrivals.rate).toBeNull();
  });

  it("refuses a session with two labels, a session that goes back in time, and a line that is not a record", () => {
    const m = createMeasure();
    m.add(record("a", "human", seen(1000)));
    expect(() => m.add(record("a", "automated", seen(2000)))).toThrow("two labels");
    expect(() => m.add(record("a", "human", seen(999)))).toThrow("goes back in time");
    const line = (over: object) => JSON.stringify({ ...record("a", "human", seen(0)), ...over });
    expect(parseLabelledRecord(line({}))).toMatchObject({ session: "a", label: "human" });
    for (const [over, why] of [[{ label: "person" }, "label is"], [{ session: "" }, "session is a name"], [{ flags: {} }, "not both"], [{ observation: undefined }, "not both"], [{ observation: { at: "0" } }, "observation needs"], [{ validFor: ["behaviour.other"] }, "validFor"], [{ observation: undefined, flags: { "behaviour.other": true } }, "is not a flag"], [{ observation: undefined, flags: { "behaviour.form.fast": 1 } }, "true or false"]] as const) {
      expect(() => parseLabelledRecord(line(over)), why).toThrow(why);
    }
    expect(() => parseLabelledRecord("[]")).toThrow("JSON object");
  });

  it("refuses an observation with a field of the wrong type, and a method that is not in upper case", () => {
    const line = (over: Partial<Record<keyof Observation, unknown>>) => JSON.stringify({ ...record("a", "human", seen(0)), observation: { ...seen(0), ...over } });
    // a method in lower case is not a write to the door's rule, so a set that holds one would measure no direct write
    expect(() => parseLabelledRecord(line({ method: "post" }))).toThrow("upper case");
    expect(() => parseLabelledRecord(line({ method: "" }))).toThrow("upper case");
    for (const [over, why] of [
      [{ userAgent: 5 }, "observation.userAgent is a string"], [{ accept: ["text/html"] }, "observation.accept is a string"], [{ form: { ms: 1 } }, "observation.form is a string"],
      [{ secure: "true" }, "observation.secure is a boolean"], [{ secFetch: { site: 1 } }, "observation.secFetch.site is a string"], [{ secFetch: null }, "observation.secFetch is an object"],
      [{ headers: { names: ["host", 7], ordered: true } }, "each name is a string"], [{ tls: "t13d" }, "observation.tls is an object"], [{ tls: { ja4: 13 } }, "observation.tls.ja4 is a string"],
      [{ tls: { helloLength: "517" } }, "observation.tls.helloLength is a number"], [{ referer: "https://shop.example/" }, "observation.referer is"], [{ at: null }, "observation needs"],
    ] as const) {
      expect(() => parseLabelledRecord(line(over)), why).toThrow(why);
    }
    const full = seen(1, { method: "POST", userAgent: CHROME, accept: "*/*", secure: true, form: "v=1;ms=1;k=1;p=1;paste=0;trusted=1", secFetch: { site: "same-origin" }, headers: { names: ["host"], ordered: false }, tls: { ja4: "t13d1516h2_000000000000_111111111111", helloLength: 517 } });
    expect(parseLabelledRecord(JSON.stringify(record("a", "human", full))).observation).toEqual(full);
  });
});

describe("the labels from a door's own receipts", () => {
  const signals = { fingerprint: { headers: { client: "browser", family: "chromium", count: 12, mismatch: false } }, behaviour: { timing: { gaps: 0, regular: false }, navigation: { pageLoaded: false, referer: "absent", directWrite: true } } };
  const predicate = (minute: number, arrival: Record<string, unknown>, kind = "door") =>
    ({ issuer: { kind }, timestamp: new Date(Date.UTC(2026, 0, 1, 0, minute)).toISOString(), facts: { arrival: { value: { remote: "203.0.113.9", subject: "unknown", class: "unknown", path: "/private/path", ...arrival } } } }) as unknown as ReceiptPredicate;

  it("labels a passed challenge human and a verified agent automated, leaves the rest out, and exports flags and labels only", () => {
    const out = labelsFromReceipts([
      predicate(0, { ...signals, challenge: { outcome: "passed" } }),
      predicate(1, { ...signals, class: "verified", subject: "shopping-agent" }),
      predicate(2, { ...signals }),
      predicate(3, { ...signals, challenge: { outcome: "failed" } }),
      predicate(4, { ...signals, class: "verified", subject: "shopping-agent", challenge: { outcome: "passed" } }),
      predicate(5, { challenge: { outcome: "passed" } }),
      predicate(6, { ...signals, challenge: { outcome: "passed" } }, "gateway"),
      // the same address after a silence longer than the history window is a new session
      predicate(40, { ...signals, challenge: { outcome: "passed" } }),
    ], "own-door");
    expect(out).toMatchObject({ read: 7, noSignals: 1, unlabelled: 3 });
    const flags = { "fingerprint.headers.mismatch": false, "behaviour.timing.regular": false, "behaviour.navigation.directWrite": true };
    expect(out.records).toEqual([
      { set: "own-door", session: "s1", label: "human", labelSource: "challenge-passed", kind: "challenge-passed", automated: false, genuine: null, source: "challenge", flags },
      { set: "own-door", session: "s2", label: "automated", labelSource: "verified-agent", kind: "verified-agent", automated: true, genuine: null, source: "door", validFor: [...FLAG_SIGNALS], flags },
      { set: "own-door", session: "s3", label: "human", labelSource: "challenge-passed", kind: "challenge-passed", automated: false, genuine: null, source: "challenge", flags },
    ]);
    const text = JSON.stringify(out.records);
    for (const secret of ["203.0.113.9", "shopping-agent", "/private/path", "2026"]) expect(text).not.toContain(secret);
    for (const r of out.records) expect(parseLabelledRecord(JSON.stringify(r))).toEqual(r);
    // with receiptIds a record names its receipt, and is then also a label of door error-rates
    const named = labelsFromReceipts([{ ...predicate(0, { ...signals, challenge: { outcome: "passed" } }), receiptId: "r-1" } as ReceiptPredicate], "own-door", { receiptIds: true }).records;
    expect(named.map((r) => r.receiptId)).toEqual(["r-1"]);
    expect(parseLabels(JSON.stringify(named[0]))).toMatchObject([{ receiptId: "r-1", kind: "challenge-passed", automated: false, genuine: null, source: "challenge" }]);
    // a set name that door measure refuses is refused here, and not after the export
    for (const set of ["own door", "", "a\nb", "x".repeat(129)]) expect(() => labelsFromReceipts([], set), JSON.stringify(set)).toThrow("the set name is");
  });

  it("applies a flag as the measure of a recording does: no header flag without the header set, no TLS flag without a JA4, no form flag for a malformed report", () => {
    const partial = { fingerprint: { headers: { client: "browser", family: "chromium", mismatch: false }, tls: { malformed: false, negotiated: "13", mismatch: false, knownTool: false } }, behaviour: { ...signals.behaviour, form: { report: "malformed", fast: false, noInput: false } } };
    expect(Object.keys(flagValues(partial as never, false))).toEqual(["behaviour.timing.regular", "behaviour.navigation.directWrite"]);
  });

  it("door labels reads the receipts of a real door, and door measure counts them", async () => {
    const origin = await startOrigin();
    open.push(origin);
    process.env.DOOR_MEASURE_TEST_TURNSTILE = "secret";
    const fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-measure-")), origin.url, { behaviour: {}, challenge: { provider: "turnstile", siteKey: "site", secretEnv: "DOOR_MEASURE_TEST_TURNSTILE", hostnames: ["shop.example"] } });
    writeFileSync(join(fx.dir, "policy.cedar"), "permit(principal, action, resource);\n");
    const provider: typeof fetch = async (input, init) => (String(input instanceof Request ? input.url : input).startsWith("https://challenges.cloudflare.com/") ? new Response(JSON.stringify({ success: true, hostname: "shop.example" }), { headers: { "content-type": "application/json" } }) : fetch(input, init));
    const host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: provider });
    const door = await serveDoor(host, { port: 0, log: () => {} });
    open.push(door, host);
    const grant = grantHeader(createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["api"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString() }));
    const ids: (string | null)[] = [];
    for (const [method, path, headers] of [["POST", "/refunds", { "x-agent-custody-challenge": "token", "content-type": "application/json" }], ["GET", "/api/orders", { "x-agent-custody-grant": grant }], ["GET", "/catalogue/a", {}]] as const) {
      const res = await fetch(`${door.url}${path}`, { method, headers, ...(method === "POST" ? { body: "{}" } : {}) });
      await res.arrayBuffer();
      ids.push(res.headers.get(RECEIPT_HEADER));
    }
    await expect.poll(() => readdirSync(fx.receiptsDir).filter((f) => ids.includes(f.replace(/\.json$/, ""))).length).toBe(3);
    const out = join(fx.dir, "own.jsonl");
    const labels = spawnSync(process.execPath, [cli, "door", "labels", "--receipts", fx.receiptsDir, "--issuer-key", fx.doorPub, "--principal-key", fx.principalPub, "--out", out], { encoding: "utf8" });
    expect(labels.status, labels.stderr).toBe(0);
    expect(labels.stderr).toContain("3 door receipt(s) read, 0 file(s) skipped");
    expect(labels.stderr).toContain("1 human (challenge passed), 1 automated (verified agent), 1 without a label");
    const records = readFileSync(out, "utf8").trim().split("\n").map((l) => JSON.parse(l) as LabelledRecord);
    expect(records.map((r) => [r.label, r.labelSource, Object.keys(r).sort().join()])).toEqual([["human", "challenge-passed", "automated,flags,genuine,kind,label,labelSource,session,set,source"], ["automated", "verified-agent", "automated,flags,genuine,kind,label,labelSource,session,set,source,validFor"]]);
    // a write with no page load before it, from a person and from an agent alike
    expect(records.map((r) => r.flags!["behaviour.navigation.directWrite"])).toEqual([true, false]);
    const measured = spawnSync(process.execPath, [cli, "door", "measure", out, "--json"], { encoding: "utf8" });
    expect(measured.status, measured.stderr).toBe(0);
    const result = JSON.parse(measured.stdout) as MeasureResult;
    expect(flagOf(result, "behaviour.navigation.directWrite", "own-door").human.sessions).toMatchObject({ n: 1, flagged: 1 });
    // without the principal's key the agent's receipt does not verify, and the tool says what it needs
    const noPrincipal = spawnSync(process.execPath, [cli, "door", "labels", "--receipts", fx.receiptsDir, "--issuer-key", fx.doorPub], { encoding: "utf8" });
    expect(noPrincipal.stderr).toContain("2 door receipt(s) read, 1 file(s) skipped (not a receipt that verifies with these keys; a verified agent's receipt needs --principal-key)");
    expect(noPrincipal.stdout.trim().split("\n").map((l) => (JSON.parse(l) as LabelledRecord).label)).toEqual(["human"]);
    // a door with another key signed nothing here
    const other = spawnSync(process.execPath, [cli, "door", "labels", "--receipts", fx.receiptsDir, "--issuer-key", fx.principalPub], { encoding: "utf8" });
    expect(other.status).toBe(1);
    expect(other.stdout).toBe("");
    expect(other.stderr).toContain("0 door receipt(s) read, 3 file(s) skipped");
  }, 300_000);
});

describe("the committed capture and the published page", () => {
  const results = JSON.parse(readFileSync(RESULTS_FILE, "utf8")) as Results;
  const manifest = JSON.parse(readFileSync(MANIFEST_FILE, "utf8")) as Manifest & { sets: { set: string; committed: boolean; counts: Record<string, { sessions: number; arrivals: number }>; files: { name: string; sha256?: string }[] }[] };
  const page = readFileSync(PAGE_FILE, "utf8");
  const capture = readFileSync(join(labelled, "capture.jsonl"), "utf8").trim().split("\n").map(parseLabelledRecord);

  it("the capture, measured again, gives the committed results, with the thresholds of this code", () => {
    const again = measure(capture);
    const committed = results.sets.filter((s) => s.set.startsWith("capture-"));
    expect(again.sets).toEqual(committed);
    expect(committed.map((s) => s.set)).toEqual(["capture-headless-chrome", "capture-headless-chrome-browser-ua", "capture-real-browsers", "capture-tools", "capture-tools-browser-ua"]);
    // a changed constant makes every published rate stale: measure again, and write results.json and the page again
    expect(results.thresholds).toEqual(JSON.parse(JSON.stringify(thresholds())));
    expect(results.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("door measure on plain Node gives the same result as text and as JSON", () => {
    const run = (...args: string[]) => spawnSync(process.execPath, [cli, "door", "measure", join(labelled, "capture.jsonl"), ...args], { encoding: "utf8" });
    const json = run("--json");
    expect(json.status, json.stderr).toBe(0);
    expect((JSON.parse(json.stdout) as MeasureResult).sets).toEqual(results.sets.filter((s) => s.set.startsWith("capture-")));
    const text = run();
    expect(text.stdout).toContain("capture-real-browsers: 28 human arrivals in 4 sessions, 0 automated arrivals in 0 sessions");
    expect(text.stdout).toContain("false-positive rate (humans flagged; lower is better)");
    expect(text.stdout).toContain("behaviour.timing.regular: not measured");
    const bad = join(mkdtempSync(join(tmpdir(), "agent-custody-door-measure-bad-")), "bad.jsonl");
    writeFileSync(bad, `${JSON.stringify(capture[0])}\n{"set":"x"}\n`);
    const refused = spawnSync(process.execPath, [cli, "door", "measure", bad], { encoding: "utf8" });
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain("bad.jsonl:2: session is a name");
  }, 300_000);

  it("the manifest counts each set as the results do, and names the capture file by its hash", async () => {
    const { createHash } = await import("node:crypto");
    const sha = createHash("sha256").update(readFileSync(join(labelled, "capture.jsonl"))).digest("hex");
    expect(manifest.sets.map((s) => s.set).sort()).toEqual(results.sets.map((s) => s.set));
    for (const m of manifest.sets) {
      const r: SetMeasure = results.sets.find((s) => s.set === m.set)!;
      expect({ human: { sessions: r.sessions.human, arrivals: r.arrivals.human }, automated: { sessions: r.sessions.automated, arrivals: r.arrivals.automated } }, m.set).toEqual(m.counts);
      if (m.committed) expect(m.files, m.set).toEqual([{ name: "capture.jsonl", sha256: sha }]);
    }
  });

  it("the known-tool table holds the fingerprints that the capture recorded from a tool, so no record of the capture counts for that flag", () => {
    const ja4s = (...sets: string[]) => new Set(capture.filter((r) => sets.includes(r.set)).map((r) => r.observation?.tls?.ja4).filter((v) => v !== undefined));
    expect([...KNOWN_TOOL_JA4.keys()].sort()).toEqual([...ja4s("capture-tools")].sort());
    for (const browser of ja4s("capture-real-browsers", "capture-headless-chrome", "capture-headless-chrome-browser-ua")) expect(KNOWN_TOOL_JA4.has(browser)).toBe(false);
    // the table was made from this capture: a tool is in it and a browser is not, by construction, so neither side is a measure
    for (const r of capture) expect(r.validFor, r.session).not.toContain("fingerprint.tls.knownTool");
    const known = (set: string) => results.sets.find((s) => s.set === set)!.flags.find((f) => f.flag === "fingerprint.tls.knownTool")!;
    for (const s of results.sets) for (const side of [known(s.set).human, known(s.set).automated]) expect(side.sessions.rate, s.set).toBeNull();
    expect(Object.keys(manifest.notMeasured["fingerprint.tls.knownTool"]!).sort()).toEqual(["automated", "human"]);
  });

  it("a mismatch flag counts no client that states no browser: for its User-Agent the flag is false by construction", () => {
    for (const r of capture) {
      const states = signals.statedClient(r.observation!.userAgent).kind === "browser";
      for (const flag of ["fingerprint.headers.mismatch", "fingerprint.tls.mismatch"] as const) if (r.validFor!.includes(flag)) expect(states, `${r.session} ${flag}`).toBe(true);
    }
    expect(new Set(capture.filter((r) => r.set === "capture-headless-chrome").map((r) => signals.statedClient(r.observation!.userAgent).family))).toEqual(new Set(["headless-chrome"]));
  });

  it("the page holds the tables that the results give, each with its direction, and a row for each flag on each side", () => {
    const tables = tablesOf(results, manifest);
    expect(pageWith(page, tables)).toBe(page);
    for (const title of ["False-positive rate per session (lower is better)", "Detection rate per session (higher is better)", "False-positive rate per arrival (lower is better)", "Detection rate per arrival (higher is better)"]) {
      const table = tables.slice(tables.indexOf(`### ${title}`)).split("\n### ")[0]!;
      expect(table.split("\n")[2]).toContain(title.includes("False") ? "false-positive rate (lower is better)" : "detection rate (higher is better)");
      for (const flag of FLAG_SIGNALS) expect(table, `${title}: ${flag}`).toContain(`| \`${flag}\` |`);
    }
    expect(tables).toContain("| `behaviour.form.noInput` | not measured |");
    expect(tables).toContain("| `fingerprint.tls.knownTool` | not measured |");
  });

  it("the page states no rate and no number that is not a number in the committed files", () => {
    const [start, end] = [page.indexOf(REGION[0]), page.indexOf(REGION[1])];
    // the tables between the markers are compared whole above; the rest is prose, without code and without link targets
    const flagsPart = page.indexOf("\n## Behaviour and fingerprint flags");
    expect(flagsPart).toBeGreaterThan(0);
    // the part about the credential signals has its own test (door-error-rates.test.ts)
    const prose = (page.slice(flagsPart, start) + page.slice(end)).replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "").replace(/\]\([^)\s]*\)/g, "]");
    const rates = new Set<string>();
    for (const s of results.sets) for (const f of s.flags) for (const side of [f.human, f.automated]) for (const r of [side.arrivals, side.sessions]) if (r.rate !== null) for (const text of [ratePercent(r), ...intervalText(r).split(" to ")]) rates.add(text);
    for (const name of ["TIMING_REGULAR_SPREAD_PERCENT"] as const) rates.add(`${results.thresholds[name]}%`);
    rates.add(`${results.confidencePercent}%`);
    for (const [rate] of prose.matchAll(/<?\d+(?:\.\d+)?%/g)) expect([...rates], rate).toContain(rate);

    // every number value of the committed JSON files, and no digits from inside a text value such as a hash
    const known = new Set<number>();
    const collect = (v: unknown): void => {
      if (typeof v === "number") known.add(v);
      else if (v && typeof v === "object") for (const x of Object.values(v)) collect(x);
    };
    for (const f of ["results.json", "manifest.json", "rule-check.json", "capture.meta.json", "keyrecs-stats.json", "lagopoulos-join.json"]) collect(JSON.parse(readFileSync(join(labelled, f), "utf8")));
    const dates = new Set([results.date, (JSON.parse(readFileSync(join(labelled, "capture.meta.json"), "utf8")) as { date: string }).date]);
    // names that hold a digit and state no measure
    const NAMES = ["JA4", "HTTP/2", "TLS 1.3", "CC-BY-4.0", "Apache-2.0", "BSD-3-Clause", "March 2018", "136M keystrokes"];
    let text = prose;
    for (const date of dates) text = text.replaceAll(date, "");
    for (const name of NAMES) text = text.replaceAll(name, "");
    const numbers = [...text.matchAll(/\d[\d,]*(?:\.\d+)?/g)].map((m) => m[0]);
    expect(numbers.length).toBeGreaterThan(20);
    expect(numbers.filter((number) => !known.has(Number(number.replaceAll(",", ""))))).toEqual([]);
  });
});

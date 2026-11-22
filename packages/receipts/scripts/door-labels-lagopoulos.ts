// Makes a labelled set from the "Web robot detection - Server logs" dataset of Lagopoulos and Tsoumakas (Zenodo record
// 3477932, CC-BY-4.0), for `agent-custody door measure` (docs/door-error-rates.md). Run it with node from
// packages/receipts:
//
//   node scripts/door-labels-lagopoulos.ts <public_v2.json> <simple_features.csv> --out <lagopoulos.jsonl> [--half tune|report] [--stats <file>]
//
// The raw log is read as a stream, twice, and is never held whole. The ids of simple_features.csv are not the ids of the
// raw records, so the script builds the sessions again as the dataset describes them: the same masked address and the
// same User-Agent, and a new session after 30 minutes of silence. A record without a method (a 408 with no request) is
// not an arrival and is left out. A rebuilt session gets the ROBOT label of the feature rows with the same number of
// requests, duration, bytes, status classes, and methods, when those rows agree on the label and are as many as the
// rebuilt sessions with these values. The other sessions get no label and are left out. The script prints the counts,
// and `--stats` writes them to a file (labelled/lagopoulos-join.json).
//
// ROBOT is 1 when the dataset's authors found the User-Agent in a list of robots. So `automated` is a robot that says
// so, and `human` is every other client, a robot that hides included. The label comes from the User-Agent, so a record
// holds no User-Agent and no header, and the label is good for the two flags that read neither: the timing flag and the
// direct-write flag. The log has no Accept header, so no page load is known: the direct-write flag is then true for
// every write without a same-origin Referer, which a door flags as often or less often.
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream, readFileSync, writeFileSync } from "node:fs";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import type { LabelledRecord } from "../src/door-measure.ts";
import type { RefererRelation } from "../src/door-signals.ts";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { out: { type: "string" }, half: { type: "string" }, stats: { type: "string" } } });
const [rawFile, featuresFile] = positionals;
if (!rawFile || !featuresFile || !values.out) throw new Error("door-labels-lagopoulos needs <public_v2.json> <simple_features.csv> --out <file>");
if (values.half !== undefined && values.half !== "tune" && values.half !== "report") throw new Error("--half is tune or report");

const SET = "lagopoulos-2018";
const SITE = "search.lib.auth.gr";
const SESSION_GAP_MS = 30 * 60_000;

interface Raw { ip: string; useragent: string; timestamp: string; method?: string; resource?: string; referrer?: string; response?: string; bytes?: string }
/** Each line of the file is `"<id>":{...},`. Gives every record that is a request. */
async function* requests(seen?: (id: string, isRequest: boolean) => void): AsyncGenerator<Raw & { method: string; at: number }> {
  const times = new Map<string, number>();
  let last = 0;
  for await (const line of createInterface({ input: createReadStream(rawFile!), crlfDelay: Infinity })) {
    if (line.length < 3) continue;
    const r = JSON.parse(line.slice(line.indexOf(":") + 1).replace(/,$/, "")) as Raw;
    seen?.(line.slice(1, line.indexOf('":')), typeof r.method === "string");
    if (typeof r.method !== "string") continue;
    let at = times.get(r.timestamp);
    if (at === undefined) {
      if (times.size > 100_000) times.clear();
      times.set(r.timestamp, (at = Date.parse(r.timestamp)));
    }
    if (!Number.isFinite(at) || at < last) throw new Error("the log is not in time order");
    last = at;
    yield Object.assign(r, { method: r.method, at });
  }
}

interface Rebuilt { useragent: string; first: number; last: number; n: number; bytes: number; status: number[]; get: number; post: number; head: number; label?: LabelledRecord["label"] }
const sessions: Rebuilt[] = [];
/** The index of the session that a request falls in. Both passes call it in the same order, so the indexes agree. */
function sessionIndex(open: Map<string, { i: number; last: number }>, r: { ip: string; useragent: string; at: number }, create: () => number): number {
  const key = `${r.ip}\n${r.useragent}`;
  let s = open.get(key);
  if (!s || r.at - s.last > SESSION_GAP_MS) open.set(key, (s = { i: create(), last: r.at }));
  s.last = r.at;
  return s.i;
}

// ---- pass 1: the sessions and their features
const [head, ...rows] = readFileSync(featuresFile, "utf8").trim().split(/\r?\n/).map((line) => line.split(","));
const featureIds = new Set(rows.map((row) => row[0]));
const raw = { records: 0, withoutARequest: 0, idsThatAreFeatureRowIds: 0 };
let total = 0;
const first = new Map<string, { i: number; last: number }>();
for await (const r of requests((id, isRequest) => {
  raw.records++;
  if (!isRequest) raw.withoutARequest++;
  if (featureIds.has(id)) raw.idsThatAreFeatureRowIds++;
})) {
  total++;
  const s = sessions[sessionIndex(first, r, () => sessions.push({ useragent: r.useragent, first: r.at, last: r.at, n: 0, bytes: 0, status: [0, 0, 0, 0], get: 0, post: 0, head: 0 }) - 1)]!;
  s.last = r.at;
  s.n++;
  s.bytes += Number(r.bytes) || 0;
  const status = Math.floor(Number(r.response) / 100) - 2;
  if (status >= 0 && status < 4) s.status[status]!++;
  if (r.method === "GET") s.get++;
  else if (r.method === "POST") s.post++;
  else if (r.method === "HEAD") s.head++;
}

// ---- the join with the feature rows
const col = (name: string) => {
  const i = head!.indexOf(name);
  if (i < 0) throw new Error(`simple_features.csv has no ${name} column`);
  return i;
};
const C = { n: col("NUMBER_OF_REQUESTS"), duration: col("TOTAL_DURATION"), data: col("DATA"), s2: col("HTTP_RESPONSE_2XX"), s3: col("HTTP_RESPONSE_3XX"), s4: col("HTTP_RESPONSE_4XX"), s5: col("HTTP_RESPONSE_5XX"), get: col("GET_METHOD"), post: col("POST_METHOD"), head: col("HEAD_METHOD"), robot: col("ROBOT") };
const featureRows = new Map<string, { count: number; robots: Set<string> }>();
for (const row of rows) {
  const n = Number(row[C.n]);
  const part = (i: number) => Math.round(Number(row[i]) * n);
  const key = [n, Math.round(Number(row[C.duration])), Math.round(Number(row[C.data])), part(C.s2), part(C.s3), part(C.s4), part(C.s5), part(C.get), part(C.post), part(C.head)].join(",");
  const g = featureRows.get(key) ?? { count: 0, robots: new Set<string>() };
  featureRows.set(key, g);
  g.count++;
  g.robots.add(row[C.robot]!);
}
const keyOf = (s: Rebuilt) => [s.n, (s.last - s.first) / 1000, s.bytes, ...s.status, s.get, s.post, s.head].join(",");
const rebuilt = new Map<string, number>();
for (const s of sessions) rebuilt.set(keyOf(s), (rebuilt.get(keyOf(s)) ?? 0) + 1);
const join = { rows: rows.length, rowsWithASession: 0, labelled: 0, noRow: 0, rowsDisagree: 0, countsDiffer: 0 };
for (const [key, g] of featureRows) join.rowsWithASession += Math.min(g.count, rebuilt.get(key) ?? 0);
for (const s of sessions) {
  const g = featureRows.get(keyOf(s));
  if (!g) join.noRow++;
  else if (g.robots.size !== 1) join.rowsDisagree++;
  else if (g.count !== rebuilt.get(keyOf(s))) join.countsDiffer++;
  else {
    s.label = g.robots.has("1") ? "automated" : "human";
    join.labelled++;
  }
}

// how far the label follows the User-Agent: the User-Agents of the labelled sessions, and those that have both labels
const labelsOfUserAgent = new Map<string, Set<string>>();
for (const s of sessions) if (s.label) (labelsOfUserAgent.get(s.useragent) ?? labelsOfUserAgent.set(s.useragent, new Set()).get(s.useragent)!).add(s.label);
const userAgents = { inLabelledSessions: labelsOfUserAgent.size, withBothLabels: [...labelsOfUserAgent.values()].filter((l) => l.size > 1).length };

// ---- pass 2: the labelled records. The split is by the hash of the session name: an even first byte tunes, an odd one reports.
const inHalf = (name: string) => values.half === undefined || (createHash("sha256").update(name).digest()[0]! % 2 === 0) === (values.half === "tune");
const out = createWriteStream(values.out);
const second = new Map<string, { i: number; last: number }>();
let next = 0;
const written = { human: { sessions: new Set<number>(), arrivals: 0 }, automated: { sessions: new Set<number>(), arrivals: 0 } };
for await (const r of requests()) {
  const i = sessionIndex(second, r, () => next++);
  const s = sessions[i]!;
  if (!s.label || !inHalf(`s${i}`)) continue;
  let referer: RefererRelation = "absent";
  if (r.referrer && r.referrer !== "-") {
    try {
      referer = new URL(r.referrer).hostname.toLowerCase() === SITE ? "same-origin" : "cross-origin";
    } catch {
      referer = "cross-origin";
    }
  }
  const record: LabelledRecord = {
    set: SET,
    session: `s${i}`,
    label: s.label,
    labelSource: "user-agent-lists",
    validFor: ["behaviour.timing.regular", "behaviour.navigation.directWrite"],
    observation: { at: r.at, method: r.method.toUpperCase().slice(0, 16), path: (r.resource ?? "").slice(0, 2048), referer, secFetch: {} },
  };
  written[s.label].sessions.add(i);
  written[s.label].arrivals++;
  if (!out.write(JSON.stringify(record) + "\n")) await once(out, "drain");
}
out.end();
await once(out, "finish");
const stats = JSON.stringify({
  raw,
  requests: total,
  rebuiltSessions: sessions.length,
  join,
  userAgents,
  half: values.half ?? "all",
  written: { human: { sessions: written.human.sessions.size, arrivals: written.human.arrivals }, automated: { sessions: written.automated.sessions.size, arrivals: written.automated.arrivals } },
}, null, 2);
console.error(stats);
if (values.stats) writeFileSync(values.stats, stats + "\n");

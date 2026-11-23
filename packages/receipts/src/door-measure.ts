// How often each flag of the door's signals is wrong, measured on labelled arrivals. A labelled record is one arrival
// with a label, `human` or `automated`. The measure replays each session in time order through the door's own functions,
// with the recorded times, and counts per flag and per set. Nothing here does I/O: the caller passes the records.
import type { Arrival } from "./door-core.ts";
import {
  BROWSER_HEADERS, FLAG_SIGNALS, FORM_FAST_MIN_KEYS, FORM_FAST_MS_PER_KEY, HISTORY_MAX_ARRIVALS, HISTORY_WINDOW_MS, KNOWN_TOOL_JA4, MAX_FORM_FILL_MS, MAX_FORM_REPORT,
  MAX_HEADER_NAMES, MAX_HEADER_NAME_LENGTH, MAX_TLS_VALUE, MAX_USER_AGENT, SEC_CH_UA_SINCE, SEC_FETCH_HEADERS, SEC_FETCH_SINCE, STATE_CHANGING,
  TIMING_MIN_GAPS, TIMING_REGULAR_MIN_MEDIAN_MS, TIMING_REGULAR_SPREAD_PERCENT, TLS13_SINCE, createHistoryTracker, flagOf, signalsOf,
  type FlagSignal, type HistoryTracker, type Observation, type Signals,
} from "./door-signals.ts";
import type { ReceiptPredicate } from "./receipt.ts";

export const LABELS = ["human", "automated"] as const;
export type Label = (typeof LABELS)[number];

/** The questions about `class` that `door error-rates` scores (src/door-error-rates.ts). */
export const LABEL_QUESTIONS = ["agent", "verified"] as const;
export type LabelQuestion = (typeof LABEL_QUESTIONS)[number];
/** What a label can be good for: a question about `class`, or a flag. `validFor` holds these names in both label formats. */
export const LABEL_USES = [...LABEL_QUESTIONS, ...FLAG_SIGNALS] as const;
export type LabelUse = (typeof LABEL_USES)[number];

/** The value of each flag that applies to one arrival. A flag that does not apply is absent. */
export type FlagValues = Partial<Record<FlagSignal, boolean>>;

/**
 * One line of a labelled set (JSON Lines). It has `observation`, which the measure replays, or `flags`, which a door
 * computed when the arrival came. The records of one session are in time order.
 */
export interface LabelledRecord {
  /** the name of the labelled set */
  set: string;
  /** the session inside the set: one client over one period */
  session: string;
  label: Label;
  /** how the label was assigned */
  labelSource: string;
  /** what this label is good for; absent when it is good for every flag and question. A flag that is not in the list does not count the record */
  validFor?: LabelUse[];
  /** what was recorded of the arrival; `at` is the recorded time in milliseconds */
  observation?: Observation;
  /** for a record exported from a door: the flags the door computed */
  flags?: FlagValues;
  /**
   * The fields of a `door error-rates` label (`DoorLabelSchema`), on a record that `door labels` exports. The measure
   * does not read them. `automated` says what `label` says.
   */
  receiptId?: string;
  kind?: string;
  automated?: boolean;
  genuine?: boolean | null;
  source?: string;
}

/** A count with its rate. `rate`, `low`, and `high` are integers per 10,000, and null when `n` is 0: not measured. */
export interface Rate {
  /** how many arrivals, or sessions, the flag applies to */
  n: number;
  flagged: number;
  rate: number | null;
  /** the 95% Wilson interval, rounded outward */
  low: number | null;
  high: number | null;
}

export interface SideMeasure {
  /** each arrival counts once */
  arrivals: Rate;
  /** each session counts once; a session is flagged when one of its arrivals is */
  sessions: Rate;
}

export interface FlagMeasure {
  flag: FlagSignal;
  /** the false-positive rate: humans that the flag marks */
  human: SideMeasure;
  /** the detection rate: automated clients that the flag marks */
  automated: SideMeasure;
}

export interface SetMeasure {
  set: string;
  arrivals: Record<Label, number>;
  sessions: Record<Label, number>;
  /** arrivals per label source */
  labelSources: Record<Label, Record<string, number>>;
  flags: FlagMeasure[];
}

export interface MeasureResult {
  format: "agent-custody/door-measure/v1";
  /** `rate`, `low`, and `high` are integers per this many */
  per: 10000;
  /** the confidence level of the Wilson interval, in percent */
  confidencePercent: 95;
  /** the constants of door-signals.ts that the flags read, as they were for this measure */
  thresholds: Record<string, unknown>;
  sets: SetMeasure[];
}

/**
 * Every exported constant of door-signals.ts that a flag reads. A result measured with other values does not describe
 * this door. The rules that read a User-Agent (`statedClient`, the embedded-Chromium forms) are code and not constants:
 * a change to them needs a new measure too, and this record does not show it.
 */
export function thresholds(): Record<string, unknown> {
  return {
    HISTORY_WINDOW_MS, HISTORY_MAX_ARRIVALS, TIMING_MIN_GAPS, TIMING_REGULAR_SPREAD_PERCENT, TIMING_REGULAR_MIN_MEDIAN_MS, FORM_FAST_MIN_KEYS, FORM_FAST_MS_PER_KEY,
    MAX_FORM_REPORT, MAX_FORM_FILL_MS, MAX_HEADER_NAMES, MAX_HEADER_NAME_LENGTH, MAX_USER_AGENT, MAX_TLS_VALUE, STATE_CHANGING: [...STATE_CHANGING].sort(),
    BROWSER_HEADERS, SEC_FETCH_HEADERS, SEC_FETCH_SINCE, SEC_CH_UA_SINCE, TLS13_SINCE, KNOWN_TOOL_JA4: Object.fromEntries([...KNOWN_TOOL_JA4].sort(([a], [b]) => (a < b ? -1 : 1))),
  };
}

const Z = 1.959963984540054;

/** The rate `flagged / n` and its 95% Wilson score interval, as integers per 10,000. The interval is rounded outward. */
export function rateOf(flagged: number, n: number): Rate {
  if (n === 0) return { n, flagged, rate: null, low: null, high: null };
  const p = flagged / n;
  const z2 = Z * Z;
  const centre = (p + z2 / (2 * n)) / (1 + z2 / n);
  const half = (Z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / (1 + z2 / n);
  const round = (x: number) => Math.round(x * 1e6) / 1e6;
  return {
    n,
    flagged,
    rate: Math.round((flagged * 10_000) / n),
    low: flagged === 0 ? 0 : Math.max(0, Math.floor(round((centre - half) * 10_000))),
    high: flagged === n ? 10_000 : Math.min(10_000, Math.ceil(round((centre + half) * 10_000))),
  };
}

/**
 * The flags that apply to an arrival, from its signals. The header flag applies only when the record has the header
 * names. The TLS flags apply only when a well-formed JA4 arrived. The form flags apply only to a well-formed form report.
 */
export function flagValues(signals: Pick<Signals, "fingerprint" | "behaviour">, hasHeaders: boolean): FlagValues {
  const out: FlagValues = {};
  for (const flag of FLAG_SIGNALS) {
    const value = flagOf(signals as Signals, flag);
    if (value === undefined) continue;
    if (flag === "fingerprint.headers.mismatch" && !hasHeaders) continue;
    if (flag.startsWith("fingerprint.tls.") && signals.fingerprint.tls?.ja4 === undefined) continue;
    if (flag.startsWith("behaviour.form.") && signals.behaviour.form?.report !== "claimed") continue;
    out[flag] = value;
  }
  return out;
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
/** True when the text can be the name of a set, a session, or a label source. */
export const isName = (v: unknown): v is string => typeof v === "string" && NAME.test(v);
const optional = (o: Record<string, unknown>, where: string, fields: string[], type: "string" | "boolean" | "number") => {
  for (const f of fields) if (o[f] !== undefined && (typeof o[f] !== type || (type === "number" && !Number.isFinite(o[f])))) throw new Error(`${where}${f} is a ${type}`);
};

/**
 * A labelled record from one line of a set. Throws with the reason when the line is not one. Every field of the
 * observation has its type checked here, so the replay never meets a number where the door's code reads text. The
 * method is in upper case, as the door records it.
 */
export function parseLabelledRecord(line: string): LabelledRecord {
  const r: unknown = JSON.parse(line);
  if (!isObject(r)) throw new Error("a record is a JSON object");
  for (const field of ["set", "session", "labelSource"] as const) if (!isName(r[field])) throw new Error(`${field} is a name of letters, digits, and . _ : / -`);
  if (r.label !== "human" && r.label !== "automated") throw new Error('label is "human" or "automated"');
  if (r.validFor !== undefined && !(Array.isArray(r.validFor) && r.validFor.every((f) => (LABEL_USES as readonly unknown[]).includes(f)))) throw new Error("validFor is a list of flags and questions");
  if (r.automated !== undefined && r.automated !== (r.label === "automated")) throw new Error("automated is true for the label automated and false for the label human");
  if ((r.observation === undefined) === (r.flags === undefined)) throw new Error("a record has observation or flags, and not both");
  if (r.observation !== undefined) {
    const o = r.observation;
    if (!isObject(o) || !Number.isFinite(o.at) || typeof o.method !== "string" || typeof o.path !== "string") throw new Error("observation needs at (a number), method, and path");
    if (!/^[A-Z]{1,16}$/.test(o.method)) throw new Error("observation.method is in upper case, as the door records it");
    if (o.referer !== "same-origin" && o.referer !== "cross-origin" && o.referer !== "absent") throw new Error('observation.referer is "same-origin", "cross-origin", or "absent"');
    optional(o, "observation.", ["userAgent", "accept", "form"], "string");
    optional(o, "observation.", ["secure"], "boolean");
    if (!isObject(o.secFetch)) throw new Error("observation.secFetch is an object");
    optional(o.secFetch, "observation.secFetch.", ["site", "mode", "dest"], "string");
    if (o.headers !== undefined && (!isObject(o.headers) || !Array.isArray(o.headers.names) || !o.headers.names.every((n) => typeof n === "string") || typeof o.headers.ordered !== "boolean")) throw new Error("observation.headers is { names, ordered }, and each name is a string");
    if (o.tls !== undefined) {
      if (!isObject(o.tls)) throw new Error("observation.tls is an object");
      optional(o.tls, "observation.tls.", ["ja4", "negotiated", "cipher", "extensionsSha1"], "string");
      optional(o.tls, "observation.tls.", ["helloLength"], "number");
    }
  } else {
    if (!isObject(r.flags)) throw new Error("flags is an object");
    for (const [flag, value] of Object.entries(r.flags)) {
      if (!(FLAG_SIGNALS as readonly string[]).includes(flag)) throw new Error(`${flag} is not a flag`);
      if (typeof value !== "boolean") throw new Error(`flags.${flag} is true or false`);
    }
  }
  return r as unknown as LabelledRecord;
}

export interface Measure {
  /** counts one record; throws when a session changes its label or goes back in time */
  add(record: LabelledRecord): void;
  result(): MeasureResult;
}

interface SessionState {
  label: Label;
  last: number;
  tracker?: HistoryTracker;
  applies: Set<FlagSignal>;
  flagged: Set<FlagSignal>;
}
interface SetState {
  sessions: Map<string, SessionState>;
  labelSources: Record<Label, Map<string, number>>;
  arrivals: Record<Label, Map<FlagSignal, { n: number; flagged: number }>>;
  count: Record<Label, number>;
}

/**
 * Counts labelled records as they come, so a large set is never held whole. Each session has its own history, as one
 * source has at the door, and its records must come in time order. The memory grows with the number of sessions.
 */
export function createMeasure(): Measure {
  const sets = new Map<string, SetState>();
  return {
    add(record) {
      let set = sets.get(record.set);
      if (!set) {
        set = { sessions: new Map(), labelSources: { human: new Map(), automated: new Map() }, arrivals: { human: new Map(), automated: new Map() }, count: { human: 0, automated: 0 } };
        sets.set(record.set, set);
      }
      let session = set.sessions.get(record.session);
      if (!session) {
        session = { label: record.label, last: -Infinity, applies: new Set(), flagged: new Set() };
        set.sessions.set(record.session, session);
      }
      if (session.label !== record.label) throw new Error(`session ${record.session} of ${record.set} has two labels`);
      let values: FlagValues;
      if (record.observation) {
        const o = record.observation;
        if (o.at < session.last) throw new Error(`session ${record.session} of ${record.set} goes back in time: sort its records by observation.at`);
        session.last = o.at;
        session.tracker ??= createHistoryTracker({ maxSources: 1 });
        values = flagValues(signalsOf(o, session.tracker.record("session", o)), !!o.headers);
      } else values = record.flags ?? {};
      set.count[record.label]++;
      const sources = set.labelSources[record.label];
      sources.set(record.labelSource, (sources.get(record.labelSource) ?? 0) + 1);
      for (const flag of FLAG_SIGNALS) {
        const value = values[flag];
        if (value === undefined || (record.validFor && !record.validFor.includes(flag))) continue;
        const cell = set.arrivals[record.label].get(flag) ?? { n: 0, flagged: 0 };
        set.arrivals[record.label].set(flag, cell);
        cell.n++;
        session.applies.add(flag);
        if (value) {
          cell.flagged++;
          session.flagged.add(flag);
        }
      }
    },
    result() {
      const names = [...sets.keys()].sort();
      return {
        format: "agent-custody/door-measure/v1",
        per: 10000,
        confidencePercent: 95,
        thresholds: thresholds(),
        sets: names.map((name) => {
          const set = sets.get(name)!;
          const side = (label: Label, flag: FlagSignal): SideMeasure => {
            const cell = set.arrivals[label].get(flag) ?? { n: 0, flagged: 0 };
            let n = 0;
            let flagged = 0;
            for (const s of set.sessions.values()) {
              if (s.label !== label || !s.applies.has(flag)) continue;
              n++;
              if (s.flagged.has(flag)) flagged++;
            }
            return { arrivals: rateOf(cell.flagged, cell.n), sessions: rateOf(flagged, n) };
          };
          const sessions = { human: 0, automated: 0 };
          for (const s of set.sessions.values()) sessions[s.label]++;
          const sources = (label: Label) => Object.fromEntries([...set.labelSources[label]].sort(([a], [b]) => (a < b ? -1 : 1)));
          return {
            set: name,
            arrivals: { ...set.count },
            sessions,
            labelSources: { human: sources("human"), automated: sources("automated") },
            flags: FLAG_SIGNALS.map((flag) => ({ flag, human: side("human", flag), automated: side("automated", flag) })),
          };
        }),
      };
    },
  };
}

/** The measure of a set that fits in memory. The records of each session are sorted by their recorded time first. */
export function measure(records: Iterable<LabelledRecord>): MeasureResult {
  const all = [...records];
  const order = new Map(all.map((r, i) => [r, i]));
  all.sort((a, b) => (a.observation?.at ?? 0) - (b.observation?.at ?? 0) || order.get(a)! - order.get(b)!);
  const m = createMeasure();
  for (const r of all) m.add(r);
  return m.result();
}

/**
 * An integer per 10,000 as a percentage with one decimal. `down` and `up` round to the printed digit in that direction:
 * a bound of an interval is printed outward, so the printed interval is never narrower than the computed one.
 */
export function percent(per10k: number, round: "nearest" | "down" | "up" = "nearest"): string {
  const tenths = round === "down" ? Math.floor(per10k / 10) : round === "up" ? Math.ceil(per10k / 10) : Math.round(per10k / 10);
  return `${(tenths / 10).toFixed(1)}%`;
}

/** The rate of a measured count as a percentage. A count above zero that rounds to 0.0% is `<0.1%`, so that it does not read as zero. */
export function ratePercent(r: Rate): string {
  return r.flagged > 0 && r.rate! < 5 ? "<0.1%" : percent(r.rate!);
}

/** The interval of a measured count as text, each bound printed outward: `0.2% to 3.7%`. */
export function intervalText(r: Rate): string {
  return `${percent(r.low!, "down")} to ${percent(r.high!, "up")}`;
}

/** One rate as text: `3/200 = 1.5% (0.5% to 4.4%)`, or `not measured` when the flag applies to nothing. */
export function formatRate(r: Rate): string {
  if (r.rate === null) return "not measured";
  return `${r.flagged}/${r.n} = ${ratePercent(r)} (${intervalText(r)})`;
}

/** The result as text: for each set, each flag, with both sides per session and per arrival. */
export function formatMeasure(result: MeasureResult): string {
  const lines: string[] = [];
  for (const set of result.sets) {
    lines.push(`${set.set}: ${set.arrivals.human} human arrivals in ${set.sessions.human} sessions, ${set.arrivals.automated} automated arrivals in ${set.sessions.automated} sessions`);
    for (const label of LABELS) for (const [source, n] of Object.entries(set.labelSources[label])) lines.push(`  ${label} by ${source}: ${n}`);
    for (const f of set.flags) {
      if (f.human.arrivals.n + f.automated.arrivals.n === 0) {
        lines.push(`  ${f.flag}: not measured`);
        continue;
      }
      lines.push(`  ${f.flag}`);
      lines.push(`    false-positive rate (humans flagged; lower is better)   per session: ${formatRate(f.human.sessions)}; per arrival: ${formatRate(f.human.arrivals)}`);
      lines.push(`    detection rate (automated flagged; higher is better)    per session: ${formatRate(f.automated.sessions)}; per arrival: ${formatRate(f.automated.arrivals)}`);
    }
  }
  if (!result.sets.length) lines.push("no labelled record");
  lines.push("Each interval is a 95% Wilson interval. The arrivals of one session are not independent, so the interval per session is the one to read.");
  return lines.join("\n");
}

export interface LabelExport {
  records: LabelledRecord[];
  /** door receipts read */
  read: number;
  /** receipts of a door that had no `behaviour` config: no flag to export */
  noSignals: number;
  /** arrivals with no label: no passed challenge and no verified agent */
  unlabelled: number;
}

/**
 * A labelled set from a door's own verified receipts. An arrival that passed the challenge is `human`
 * (`challenge-passed`); an arrival of a verified agent is `automated` (`verified-agent`); the rest have no label and
 * are left out, as is a verified agent that passed the challenge. A record holds the label and the flags only. The session is a number: the door's source (the agent, else
 * the address), cut where it is silent for `HISTORY_WINDOW_MS`. No path, address, agent name, header, or time leaves.
 *
 * Each record also holds the label in the fields of `door error-rates`: `kind`, `automated`, `genuine`, and `source`.
 * `genuine` is always null: a receipt does not say whether an agent is the agent that it names, except through the
 * door's own check, and that check is what `door error-rates` scores. The label of a verified agent is the door's own
 * word (`source: "door"`), so its `validFor` holds the flags only and no question about `class` counts it. With
 * `receiptIds` a record has its `receiptId`, which `door error-rates --labels` needs. The id names one receipt of the
 * operator, so it is off unless asked for.
 */
export function labelsFromReceipts(predicates: Iterable<ReceiptPredicate>, set: string, opts: { receiptIds?: boolean } = {}): LabelExport {
  if (!isName(set)) throw new Error("the set name is letters, digits, and . _ : / -, as door measure reads it");
  const out: LabelExport = { records: [], read: 0, noSignals: 0, unlabelled: 0 };
  const door = [...predicates].filter((p) => p.issuer.kind === "door").sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  const sessions = new Map<string, { id: number; last: number }>();
  let next = 1;
  for (const p of door) {
    out.read++;
    const arrival = p.facts.arrival?.value as Arrival | undefined;
    if (!arrival?.fingerprint || !arrival.behaviour) {
      out.noSignals++;
      continue;
    }
    const source = arrival.class === "verified" ? `agent:${arrival.subject}` : `remote:${arrival.remote}`;
    const at = Date.parse(p.timestamp);
    let session = sessions.get(source);
    if (!session || at - session.last > HISTORY_WINDOW_MS) sessions.set(source, (session = { id: next++, last: at }));
    session.last = at;
    const passed = arrival.challenge?.outcome === "passed";
    const verified = arrival.class === "verified";
    // a verified agent that passed the challenge has both labels, so it has none
    const label: Pick<LabelledRecord, "label" | "labelSource" | "kind" | "automated" | "genuine" | "source" | "validFor"> | null =
      passed === verified
        ? null
        : passed
          ? { label: "human", labelSource: "challenge-passed", kind: "challenge-passed", automated: false, genuine: null, source: "challenge" }
          : { label: "automated", labelSource: "verified-agent", kind: "verified-agent", automated: true, genuine: null, source: "door", validFor: [...FLAG_SIGNALS] };
    if (!label) {
      out.unlabelled++;
      continue;
    }
    // the door's fact does not say whether it received the header set; `count` is present only when it did
    const flags = flagValues({ fingerprint: arrival.fingerprint, behaviour: arrival.behaviour }, arrival.fingerprint.headers.count !== undefined);
    out.records.push({ ...(opts.receiptIds ? { receiptId: p.receiptId } : {}), set, session: `s${session.id}`, ...label, flags });
  }
  return out;
}

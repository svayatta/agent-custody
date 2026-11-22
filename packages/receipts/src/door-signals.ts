// The door's behavioural and fingerprint signals. Each signal is a pure function of an `Observation`, the record of what
// the door saw of one arrival, and of the source's `SourceHistory`. Nothing here does I/O, so a tool can replay recorded
// observations through the same functions and measure how often each flag is wrong. A signal is not a verdict: the door
// never refuses an arrival because of one. Only the operator's policy reads them, as `context.facts.arrival.fingerprint`
// and `context.facts.arrival.behaviour`. Every number is an integer, because Cedar has no floats.
import { sha256Hex } from "./crypto.ts";

/** the request header in which the form protector script sends its form report; a claim by the client */
export const FORM_REPORT_HEADER = "x-agent-custody-form";

/** how long a source's arrivals and its last page load are remembered */
export const HISTORY_WINDOW_MS = 30 * 60_000;
/** arrival times kept per source, so the timing signals read at most one gap fewer */
export const HISTORY_MAX_ARRIVALS = 17;
/** `timing.regular` needs at least this many gaps */
export const TIMING_MIN_GAPS = 5;
/** `timing.regular`: the longest gap minus the shortest gap is at most this percentage of the median gap */
export const TIMING_REGULAR_SPREAD_PERCENT = 10;
/** `timing.regular` needs a median gap of at least this; faster arrivals are a burst, which `rate` counts */
export const TIMING_REGULAR_MIN_MEDIAN_MS = 100;
/** `form.fast` needs at least this many key presses */
export const FORM_FAST_MIN_KEYS = 8;
/** `form.fast`: the fill took less than this many milliseconds for each key press */
export const FORM_FAST_MS_PER_KEY = 20;
/** a form report longer than this is malformed */
export const MAX_FORM_REPORT = 64;
/** the largest fill time a form report can state: one day */
export const MAX_FORM_FILL_MS = 86_400_000;
/** the largest event count a form report can state */
export const MAX_FORM_EVENTS = 99_999;
/** header names read from one arrival; the rest are not counted or hashed */
export const MAX_HEADER_NAMES = 128;
/** a header name longer than this is cut */
export const MAX_HEADER_NAME_LENGTH = 64;
/** the User-Agent is read up to this length */
export const MAX_USER_AGENT = 512;
/** a TLS fingerprint value longer than this is cut, and is then malformed */
export const MAX_TLS_VALUE = 64;

export type BrowserFamily = "chromium" | "firefox" | "safari";
/** the first major version of each browser family that sends `sec-fetch-site`, `sec-fetch-mode`, and `sec-fetch-dest` on every request to an https site */
export const SEC_FETCH_SINCE: Record<BrowserFamily, number> = { chromium: 80, firefox: 90, safari: 17 };
/** the Chromium major version from which `headers.mismatch` expects `sec-ch-ua` on every request to an https site */
export const SEC_CH_UA_SINCE = 100;
/** the major version of each browser family from which `tls.mismatch` expects TLS 1.3 and ALPN in the ClientHello */
export const TLS13_SINCE: Record<BrowserFamily, number> = { chromium: 70, firefox: 63, safari: 13 };
/** the header that every browser family sends on every request */
export const BROWSER_HEADERS = ["accept-language"];
export const SEC_FETCH_HEADERS = ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"];
/**
 * JA4 fingerprints of known tools, each with the tool's family. Every value was recorded by the labelled capture
 * (scripts/door-capture.ts, labelled/capture.meta.json), never taken from memory. A fingerprint belongs to one build of
 * the tool's TLS library, so another version of the tool can have another fingerprint, and the table misses it.
 */
export const KNOWN_TOOL_JA4: ReadonlyMap<string, string> = new Map([
  ["t13d4907h2_0d8feac7bc37_7395dae3b2f3", "curl"],
  ["t13d171100_ab0a1bf427ad_e44827223d20", "python"],
  ["t13d1912h2_9dc949149365_e5728521abd4", "go"],
  ["t13d5212h1_b262b3658495_8e6e362c5eac", "node"],
  // the same client when it resumes a session
  ["t13d5213h1_b262b3658495_66863fb0a24c", "node"],
  ["t13d1713h1_5b57614c22b0_6a3d802a7139", "bun"],
]);

/** What the host knows of the client's TLS ClientHello. The door never reads it from a header that a client can set. */
export interface TlsObservation {
  /** the JA4 string, as the operator's proxy or Cloudflare gives it */
  ja4?: string;
  /** the negotiated version, as Cloudflare names it (`TLSv1.3`) */
  negotiated?: string;
  /** the negotiated cipher, as Cloudflare names it */
  cipher?: string;
  /** Cloudflare's `tlsClientExtensionsSha1` */
  extensionsSha1?: string;
  /** the length of the ClientHello in bytes */
  helloLength?: number;
}

export type RefererRelation = "same-origin" | "cross-origin" | "absent";

/** What the door saw of one arrival: all that the signals read. It holds no cookie, no query, no body, and no address. */
export interface Observation {
  /** the time of the arrival in milliseconds on a monotonic clock; the caller supplies it, so a replay supplies the recorded time */
  at: number;
  method: string;
  path: string;
  /**
   * The header names that the door received, lowercase, without the door's own headers. `ordered` is false when the
   * host cannot see the order (a fetch `Request`, a Worker). Absent when the host does not receive the client's full
   * header set: in authz mode the proxy selects the headers of a check.
   */
  headers?: { names: string[]; ordered: boolean };
  /** true only when the host knows that the client used https */
  secure?: boolean;
  userAgent?: string;
  accept?: string;
  referer: RefererRelation;
  /** `sec-fetch-site`, `sec-fetch-mode`, and `sec-fetch-dest`, as sent */
  secFetch: { site?: string; mode?: string; dest?: string };
  tls?: TlsObservation;
  /** the form report header, as sent; a claim by the client */
  form?: string;
}

/** The part of a request that `observationOf` reads. A Node `IncomingMessage` and a `DoorRequest` are each one. */
export interface ObservedRequest {
  headers: Record<string, string | string[] | undefined>;
  /** names and values in turn, in the order received, as Node keeps them */
  rawHeaders?: string[] | undefined;
  /** set by the host from the connection, never from a client header */
  transport?: { secure?: boolean; tls?: TlsObservation } | undefined;
}

export interface ObserveOptions {
  /** the door's `trustProxy`: `x-forwarded-proto`, `x-forwarded-host`, and `tlsHeader` are then the proxy's */
  trustProxy?: boolean;
  /** the header in which the operator's proxy puts the JA4 string; read only with `trustProxy` */
  tlsHeader?: string;
  /** more header names that are the door's own, left out of the header fingerprint */
  own?: string[];
  /** true when the host receives only the headers that a proxy selected */
  partialHeaders?: boolean;
}

const one = (v: string | string[] | undefined, max: number): string | undefined => {
  const s = Array.isArray(v) ? v.join(", ") : v;
  return typeof s === "string" && s !== "" ? s.slice(0, max) : undefined;
};
const lastOf = (v: string | undefined): string | undefined => v?.split(",").pop()?.trim().toLowerCase() || undefined;

// a host without the default port of https or http, as `normalizeAuthority` of web-bot-auth.ts gives it
const authority = (host: string) => host.trim().toLowerCase().replace(/:(443|80)$/, "");

/**
 * The relation of a `Referer` to the host that the request names. The scheme is not compared, because the door does
 * not always know it, so a default port on one side and none on the other is the same host.
 */
export function refererRelation(referer: string | undefined, host: string | undefined): RefererRelation {
  if (!referer) return "absent";
  try {
    return host !== undefined && authority(new URL(referer).host) === authority(host) ? "same-origin" : "cross-origin";
  } catch {
    return "cross-origin";
  }
}

/**
 * The observation of one request. Every value is cut to a fixed length, so a hostile header cannot make it large. The
 * TLS fingerprint comes from `transport`, or from `tlsHeader` when `trustProxy` is set; without both, a header that
 * names a fingerprint is the client's word and is not read.
 */
export function observationOf(req: ObservedRequest, at: number, method: string, path: string, opts: ObserveOptions = {}): Observation {
  const h = req.headers;
  const tlsHeader = opts.trustProxy ? opts.tlsHeader?.toLowerCase() : undefined;
  const own = new Set([...(opts.own ?? []), ...(opts.tlsHeader ? [opts.tlsHeader] : [])].map((n) => n.toLowerCase()));
  let headers: Observation["headers"];
  if (!opts.partialHeaders) {
    const raw = req.rawHeaders;
    const names: string[] = [];
    const all = raw ? raw.filter((_, i) => i % 2 === 0) : Object.keys(h).filter((k) => h[k] !== undefined);
    for (const name of all) {
      if (names.length >= MAX_HEADER_NAMES) break;
      const n = String(name).toLowerCase().slice(0, MAX_HEADER_NAME_LENGTH);
      if (!n.startsWith("x-agent-custody-") && !own.has(n)) names.push(n);
    }
    headers = { names, ordered: !!raw };
  }
  const forwardedProto = opts.trustProxy ? lastOf(one(h["x-forwarded-proto"], 64)) : undefined;
  const secure = req.transport?.secure ?? (forwardedProto === "https" ? true : undefined);
  const host = (opts.trustProxy ? lastOf(one(h["x-forwarded-host"], 512)) : undefined) ?? one(h.host, 512);
  const headerJa4 = tlsHeader ? one(h[tlsHeader], MAX_TLS_VALUE + 1) : undefined;
  const tls = headerJa4 !== undefined ? { ja4: headerJa4 } : req.transport?.tls;
  const userAgent = one(h["user-agent"], MAX_USER_AGENT);
  const accept = one(h.accept, 256);
  const site = one(h["sec-fetch-site"], 32);
  const mode = one(h["sec-fetch-mode"], 32);
  const dest = one(h["sec-fetch-dest"], 32);
  const form = one(h[FORM_REPORT_HEADER], MAX_FORM_REPORT + 1);
  return {
    at,
    method: method.toUpperCase().slice(0, 16),
    path: path.slice(0, 2048),
    ...(headers ? { headers } : {}),
    ...(secure !== undefined ? { secure } : {}),
    ...(userAgent !== undefined ? { userAgent } : {}),
    ...(accept !== undefined ? { accept } : {}),
    referer: refererRelation(one(h.referer, 2048), host),
    secFetch: { ...(site !== undefined ? { site } : {}), ...(mode !== undefined ? { mode } : {}), ...(dest !== undefined ? { dest } : {}) },
    ...(tls ? { tls } : {}),
    ...(form !== undefined ? { form } : {}),
  };
}

export type ClientKind = "browser" | "tool" | "other" | "unstated";

/** The client that a User-Agent states. A claim: any client can send any User-Agent. */
export interface StatedClient {
  kind: ClientKind;
  /** a `BrowserFamily` for a browser, the tool's name for a tool, else `other` or `unstated` */
  family: string;
  /** the browser's major version, when the User-Agent states the version of its engine */
  version?: number;
}

const TOOLS: [RegExp, string][] = [
  [/HeadlessChrome\//, "headless-chrome"],
  // a crawler names itself as a product token or gives its page; a phone model can hold "bot"
  [/(?:bot|crawler|spider)\/|\+https?:/i, "crawler"],
  [/^curl\//i, "curl"],
  [/^wget\//i, "wget"],
  [/^python-requests\//i, "python-requests"],
  [/^python-urllib\//i, "python-urllib"],
  [/^python-httpx\//i, "python-httpx"],
  [/aiohttp\//i, "aiohttp"],
  [/^go-http-client\//i, "go-http-client"],
  [/^(node|node-fetch|undici)\b/i, "node"],
  [/^axios\//i, "axios"],
  [/^okhttp\//i, "okhttp"],
  [/^(java|apache-httpclient)\//i, "java"],
  [/^postmanruntime\//i, "postman"],
];

/**
 * The client family that the User-Agent states. A browser on iOS is `safari` whatever its name, because it runs
 * WebKit; without a `Version/` token its version is unknown, and the rules that depend on a version do not apply.
 */
export function statedClient(userAgent: string | undefined): StatedClient {
  const ua = (userAgent ?? "").slice(0, MAX_USER_AGENT).trim();
  if (!ua) return { kind: "unstated", family: "unstated" };
  for (const [pattern, family] of TOOLS) if (pattern.test(ua)) return { kind: "tool", family };
  if (!ua.startsWith("Mozilla/5.0 ")) return { kind: "other", family: "other" };
  const major = (pattern: RegExp) => {
    const m = pattern.exec(ua);
    return m ? { version: Number(m[1]) } : {};
  };
  if (/(CriOS|FxiOS|EdgiOS)\//.test(ua)) return { kind: "browser", family: "safari", ...major(/Version\/(\d{1,4})/) };
  if (/(Chrome|Chromium)\/\d/.test(ua)) return { kind: "browser", family: "chromium", ...major(/(?:Chrome|Chromium)\/(\d{1,4})/) };
  if (ua.includes("Gecko/") && /Firefox\/\d/.test(ua)) return { kind: "browser", family: "firefox", ...major(/Firefox\/(\d{1,4})/) };
  if (ua.includes("AppleWebKit/") && ua.includes("Safari/")) return { kind: "browser", family: "safari", ...major(/Version\/(\d{1,4})/) };
  return { kind: "other", family: "other" };
}

/**
 * Chromium inside an application: it does not always send client hints, so `sec-ch-ua` is not expected. A false flag on
 * a real browser costs more than a missed program, so a doubtful form is in this list. The forms: an Android WebView
 * (`; wv)`), a WebView browser that drops that token (`Version/4.0 Chrome/110`), Electron, a browser that says it is
 * like Chrome (Silk's `like Chrome/120`), and an application that names itself before `Chrome/`
 * (`Claude/4.4212.0 Chrome/152.0.7977.167`). For the last form, the header model that scripts/door-rule-check.ts reads
 * has such User-Agents, and none of their requests has `sec-ch-ua`.
 */
const EMBEDDED_CHROMIUM = /; wv\)|Electron\/|Version\/\d{1,4}\.\d{1,4} Chrome\/|like Chrome\/|\(KHTML, like Gecko\) (?!Chrome\/|HeadlessChrome\/|Version\/)[^\s/]{1,64}\/\S{1,64} Chrome\//;

export interface HeaderFingerprint {
  /** a hash of the header names in the order received; absent when the host cannot see the order */
  order?: string;
  /** how many headers the door received, without its own; absent when the host does not receive the full set */
  count?: number;
  client: ClientKind;
  family: string;
  version?: number;
  /** true when the User-Agent states a browser and the request lacks a header that this browser always sends */
  mismatch: boolean;
  /** the missing header names, separated by a space; only when `mismatch` is true */
  missing?: string;
}

/**
 * The header fingerprint. `mismatch` reads only rules that hold for every request of a browser family, so that a real
 * browser is not flagged: `accept-language` always, and, when the host knows that the client used https, `sec-fetch-*`
 * and (Chromium) `sec-ch-ua` from the versions in `SEC_FETCH_SINCE` and `SEC_CH_UA_SINCE`. Browsers send these only to
 * an https site. For an OPTIONS request and an upgrade, only `accept-language` is checked. A proxy in front of the door that drops one of
 * these headers makes every browser a mismatch: the door records what it received.
 */
export function headerFingerprint(o: Observation): HeaderFingerprint {
  const c = statedClient(o.userAgent);
  const out: HeaderFingerprint = { client: c.kind, family: c.family, ...(c.version !== undefined ? { version: c.version } : {}), mismatch: false };
  if (!o.headers) return out;
  const names = o.headers.names.slice(0, MAX_HEADER_NAMES).map((n) => String(n).toLowerCase().slice(0, MAX_HEADER_NAME_LENGTH));
  if (o.headers.ordered) out.order = sha256Hex(names.join("\n")).slice(0, 16);
  out.count = names.length;
  if (c.kind !== "browser") return out;
  const family = c.family as BrowserFamily;
  const version = c.version ?? 0;
  const present = new Set(names);
  const expected = [...BROWSER_HEADERS];
  if (o.secure === true && o.method !== "OPTIONS" && !present.has("upgrade")) {
    if (version >= SEC_FETCH_SINCE[family]) expected.push(...SEC_FETCH_HEADERS);
    if (family === "chromium" && version >= SEC_CH_UA_SINCE && !EMBEDDED_CHROMIUM.test(o.userAgent ?? "")) expected.push("sec-ch-ua");
  }
  const missing = expected.filter((n) => !present.has(n));
  if (missing.length) {
    out.mismatch = true;
    out.missing = missing.join(" ");
  }
  return out;
}

// section a of a JA4: protocol, TLS version, SNI, cipher count, extension count, first ALPN; then two truncated hashes
const JA4 = /^([tqd])(13|12|11|10|s3|s2|d1|d2|d3|00)([di])(\d\d)(\d\d)([0-9A-Za-z]{2})_[0-9a-f]{12}_[0-9a-f]{12}$/;
const NEGOTIATED: Record<string, string> = { "TLSv1.3": "13", "TLSv1.2": "12", "TLSv1.1": "11", TLSv1: "10", SSLv3: "s3" };
const PROTOCOLS = { t: "tcp", q: "quic", d: "dtls" } as const;

export interface TlsFingerprint {
  /** the JA4 string, when a well-formed one arrived */
  ja4?: string;
  /** true when a JA4 value arrived that does not have the shape of a JA4; the proxy did not set it, or did not overwrite the client's */
  malformed: boolean;
  /** from the JA4: the transport of the ClientHello */
  protocol?: "tcp" | "quic" | "dtls";
  /** from the JA4: the highest TLS version that the client offered, as JA4 writes it (`13`, `12`) */
  version?: string;
  /** from the JA4: true when the ClientHello named a domain */
  sni?: boolean;
  /** from the JA4: how many cipher suites the client offered */
  ciphers?: number;
  /** from the JA4: how many extensions the client sent */
  extensions?: number;
  /** from the JA4: the first and last character of the first ALPN value, `00` when there is none */
  alpn?: string;
  /** the negotiated TLS version in the same form as `version`, when the host gives it */
  negotiated?: string;
  cipher?: string;
  extensionsSha1?: string;
  helloLength?: number;
  /** true when the User-Agent states a browser and the JA4 shows a ClientHello that this browser does not send */
  mismatch: boolean;
  /** true when the JA4 is in `KNOWN_TOOL_JA4` */
  knownTool: boolean;
}

/**
 * The TLS fingerprint, or undefined when the host gave nothing that has the right shape. `mismatch` needs no
 * fingerprint database: a browser at or after `TLS13_SINCE` offers TLS 1.3 and sends ALPN, and the first section of a
 * JA4 states both. A TLS-inspecting proxy between the person and the site (a company network, some antivirus products)
 * sends its own ClientHello, so a real browser behind one can be a mismatch.
 */
export function tlsFingerprint(o: Observation): TlsFingerprint | undefined {
  const t = o.tls;
  if (!t || typeof t !== "object") return undefined;
  const out: TlsFingerprint = { malformed: false, mismatch: false, knownTool: false };
  let seen = false;
  if (t.ja4 !== undefined) {
    seen = true;
    const m = typeof t.ja4 === "string" && t.ja4.length <= MAX_TLS_VALUE ? JA4.exec(t.ja4) : null;
    if (!m) out.malformed = true;
    else {
      out.ja4 = m[0];
      out.protocol = PROTOCOLS[m[1] as keyof typeof PROTOCOLS];
      out.version = m[2]!;
      out.sni = m[3] === "d";
      out.ciphers = Number(m[4]);
      out.extensions = Number(m[5]);
      out.alpn = m[6]!;
      const c = statedClient(o.userAgent);
      out.mismatch = c.kind === "browser" && c.version !== undefined && c.version >= TLS13_SINCE[c.family as BrowserFamily] && m[1] === "t" && (m[2] !== "13" || m[6] === "00");
      out.knownTool = KNOWN_TOOL_JA4.has(m[0]);
    }
  }
  if (typeof t.negotiated === "string" && Object.hasOwn(NEGOTIATED, t.negotiated)) {
    seen = true;
    out.negotiated = NEGOTIATED[t.negotiated]!;
  }
  if (typeof t.cipher === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(t.cipher)) {
    seen = true;
    out.cipher = t.cipher;
  }
  if (typeof t.extensionsSha1 === "string" && /^[A-Za-z0-9+/]{27}=$/.test(t.extensionsSha1)) {
    seen = true;
    out.extensionsSha1 = t.extensionsSha1;
  }
  if (Number.isSafeInteger(t.helloLength) && t.helloLength! >= 0 && t.helloLength! <= 65_535) {
    seen = true;
    out.helloLength = t.helloLength!;
  }
  return seen ? out : undefined;
}

/** What the door remembers of one source when an arrival comes. */
export interface SourceHistory {
  /** the times of the source's latest arrivals inside the window, oldest first, this arrival included */
  times: number[];
  /** the time of the source's latest page load before this arrival, when it is inside the window */
  pageAt?: number;
}

export interface HistoryLimits {
  /** sources kept at once; past this the least recently seen is forgotten. Default 10000 */
  maxSources?: number;
  /** a source key longer than this is kept as its sha256. Default 256 */
  maxKeyLength?: number;
}

export interface HistoryTracker {
  /** records the arrival and returns the source's history as the signals read it */
  record(source: string, o: Observation): SourceHistory;
  /** sources kept now */
  size(): number;
}

/** True when the arrival loads an HTML document: a GET that names `document` in `sec-fetch-dest`, or without that header accepts `text/html`. */
export function isPageLoad(o: Observation): boolean {
  if (o.method !== "GET") return false;
  const dest = o.secFetch?.dest;
  return typeof dest === "string" ? dest.toLowerCase() === "document" : typeof o.accept === "string" && o.accept.toLowerCase().includes("text/html");
}

/**
 * Keeps each source's history, with the same limits style as the rate tracker: at most `maxSources` keys, none longer
 * than `maxKeyLength`, the least recently seen forgotten first, at most `HISTORY_MAX_ARRIVALS` times per source, and
 * nothing older than `HISTORY_WINDOW_MS`. One process's memory: the history starts empty when the door starts, two doors
 * do not share it, and in a Worker each isolate has its own. A source forgotten early starts again, so a client that
 * sends from many new addresses can make another source look new. The time is `Observation.at`; a time that goes back
 * is held at the last time seen. No timer runs: stale sources are dropped from `record`, at most once a minute.
 */
export function createHistoryTracker(limits: HistoryLimits = {}): HistoryTracker {
  const maxSources = Math.max(1, limits.maxSources ?? 10_000);
  const maxKeyLength = limits.maxKeyLength ?? 256;
  // least recently seen first: a record moves its key to the end
  const seen = new Map<string, { times: number[]; pageAt?: number }>();
  let last = -Infinity;
  let swept = -Infinity;
  return {
    record(source, o) {
      const key = source.length > maxKeyLength ? `sha256:${sha256Hex(source)}` : source;
      const t = (last = Math.max(last, Number.isFinite(o.at) ? Math.floor(o.at) : 0));
      const cutoff = t - HISTORY_WINDOW_MS;
      if (t - swept >= 60_000) {
        swept = t;
        for (const [k, v] of seen) if (v.times[v.times.length - 1]! <= cutoff) seen.delete(k);
      }
      const prior = seen.get(key);
      const times = (prior?.times ?? []).filter((x) => x > cutoff);
      times.push(t);
      if (times.length > HISTORY_MAX_ARRIVALS) times.splice(0, times.length - HISTORY_MAX_ARRIVALS);
      const pageAt = prior?.pageAt !== undefined && prior.pageAt > cutoff ? prior.pageAt : undefined;
      const now = isPageLoad(o) ? t : pageAt;
      seen.delete(key);
      seen.set(key, { times, ...(now !== undefined ? { pageAt: now } : {}) });
      while (seen.size > maxSources) seen.delete(seen.keys().next().value!);
      return { times: [...times], ...(pageAt !== undefined ? { pageAt } : {}) };
    },
    size: () => seen.size,
  };
}

export interface TimingSignals {
  /** how many gaps between the source's remembered arrivals, at most `HISTORY_MAX_ARRIVALS - 1` */
  gaps: number;
  /** the median gap in milliseconds; absent when there is no gap */
  medianGapMs?: number;
  /** true when the source arrives at a steady pace */
  regular: boolean;
}

/**
 * The pace of the source. `regular` is true when there are at least `TIMING_MIN_GAPS` gaps, the median gap is at least
 * `TIMING_REGULAR_MIN_MEDIAN_MS`, and the longest gap minus the shortest is at most `TIMING_REGULAR_SPREAD_PERCENT` of
 * the median. A page that polls on a timer in a person's browser is regular too.
 */
export function timingSignals(history: SourceHistory): TimingSignals {
  const times = (Array.isArray(history?.times) ? history.times : []).slice(-HISTORY_MAX_ARRIVALS);
  const gaps: number[] = [];
  for (let i = 1; i < times.length; i++) {
    const gap = Math.floor(times[i]! - times[i - 1]!);
    gaps.push(Number.isFinite(gap) && gap > 0 ? gap : 0);
  }
  if (gaps.length === 0) return { gaps: 0, regular: false };
  gaps.sort((a, b) => a - b);
  const mid = gaps.length >> 1;
  const median = gaps.length % 2 ? gaps[mid]! : Math.floor((gaps[mid - 1]! + gaps[mid]!) / 2);
  const spread = gaps[gaps.length - 1]! - gaps[0]!;
  const regular = gaps.length >= TIMING_MIN_GAPS && median >= TIMING_REGULAR_MIN_MEDIAN_MS && spread * 100 <= median * TIMING_REGULAR_SPREAD_PERCENT;
  return { gaps: gaps.length, medianGapMs: median, regular };
}

export interface NavigationSignals {
  /** true when the source loaded an HTML document earlier, inside `HISTORY_WINDOW_MS` */
  pageLoaded: boolean;
  referer: RefererRelation;
  /** `sec-fetch-site` as sent, lowercase; `other` when it is not a token */
  site?: string;
  mode?: string;
  dest?: string;
  /** true when a POST, PUT, PATCH, or DELETE arrives with no earlier page load from the source, no same-origin referer, and no `sec-fetch-site: same-origin` */
  directWrite: boolean;
}

/** the methods that `directWrite` reads as a write */
export const STATE_CHANGING: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const token = (v: unknown): string | undefined => (typeof v !== "string" ? undefined : /^[a-z-]{1,24}$/.test(v.toLowerCase()) ? v.toLowerCase() : "other");

/**
 * How the arrival fits the source's navigation. `directWrite` is true for every API client that never loads a page,
 * a verified agent included. A person whose page load came from another address, another door process, or before the
 * window is not flagged when the browser sends a same-origin `Referer` or `Sec-Fetch-Site: same-origin`; a site with
 * `Referrer-Policy: no-referrer` still gets the second. Both headers are the client's word: a program can send them.
 */
export function navigationSignals(o: Observation, history: SourceHistory): NavigationSignals {
  const pageAt = history?.pageAt;
  const pageLoaded = typeof pageAt === "number" && o.at - pageAt <= HISTORY_WINDOW_MS;
  const referer: RefererRelation = o.referer === "same-origin" || o.referer === "cross-origin" ? o.referer : "absent";
  const site = token(o.secFetch?.site);
  const mode = token(o.secFetch?.mode);
  const dest = token(o.secFetch?.dest);
  return {
    pageLoaded,
    referer,
    ...(site !== undefined ? { site } : {}),
    ...(mode !== undefined ? { mode } : {}),
    ...(dest !== undefined ? { dest } : {}),
    directWrite: STATE_CHANGING.has(o.method) && !pageLoaded && referer !== "same-origin" && site !== "same-origin",
  };
}

/** What a well-formed form report states. Counts only: the script reads no field value and no key identity. */
export interface FormReport {
  /** milliseconds from the first key press, pointer press, click, or paste in the form to the submit; 0 when there was none */
  fillMs: number;
  keys: number;
  pointers: number;
  pasted: boolean;
  /** false when one of the events did not come from the browser's own input handling (`event.isTrusted`) */
  trusted: boolean;
}

const FORM_REPORT = /^v=1;ms=(\d{1,8});k=(\d{1,5});p=(\d{1,5});paste=([01]);trusted=([01])$/;

/** The form report from its header value, or null when the value is not exactly a report: its length, its fields, and its ranges are fixed. */
export function parseFormReport(value: unknown): FormReport | null {
  if (typeof value !== "string" || value.length > MAX_FORM_REPORT) return null;
  const m = FORM_REPORT.exec(value);
  if (!m) return null;
  const fillMs = Number(m[1]);
  if (fillMs > MAX_FORM_FILL_MS) return null;
  return { fillMs, keys: Number(m[2]), pointers: Number(m[3]), pasted: m[4] === "1", trusted: m[5] === "1" };
}

export interface FormSignals extends Partial<FormReport> {
  /** `claimed`: the form protector script reports from the client's browser, and any client can send the header */
  report: "claimed" | "malformed";
  /** true when the report states more key presses than a person makes in the stated time */
  fast: boolean;
  /** true when the report states a submit with no key press and no pointer press */
  noInput: boolean;
}

/**
 * What the form report says, or undefined when the arrival sent none. A claim by the client: a program can send any
 * report, so the flags catch only a client that runs the script and does not act as a person does. `fast` is true when
 * there are at least `FORM_FAST_MIN_KEYS` key presses and the fill took less than `FORM_FAST_MS_PER_KEY` for each; a
 * device that types for a person (a security key, a scanner) is fast too. `noInput` is true when there is no key press
 * and no pointer press. A malformed report sets no flag.
 */
export function formSignals(o: Observation): FormSignals | undefined {
  if (o.form === undefined) return undefined;
  const r = parseFormReport(o.form);
  if (!r) return { report: "malformed", fast: false, noInput: false };
  return { report: "claimed", ...r, fast: r.keys >= FORM_FAST_MIN_KEYS && r.fillMs < r.keys * FORM_FAST_MS_PER_KEY, noInput: r.keys === 0 && r.pointers === 0 };
}

/** `arrival.fingerprint`: what the request and its connection look like */
export interface ArrivalFingerprint {
  headers: HeaderFingerprint;
  /** present only when the host gave a TLS fingerprint */
  tls?: TlsFingerprint;
}

/** `arrival.behaviour`: how the source acts over time */
export interface ArrivalBehaviour {
  timing: TimingSignals;
  navigation: NavigationSignals;
  /** present only when the arrival sent a form report */
  form?: FormSignals;
}

export interface Signals {
  fingerprint: ArrivalFingerprint;
  behaviour: ArrivalBehaviour;
}

/** Every signal of one arrival, from its observation and the history that `HistoryTracker.record` returned for it. */
export function signalsOf(o: Observation, history: SourceHistory): Signals {
  const tls = tlsFingerprint(o);
  const form = formSignals(o);
  return {
    fingerprint: { headers: headerFingerprint(o), ...(tls ? { tls } : {}) },
    behaviour: { timing: timingSignals(history), navigation: navigationSignals(o, history), ...(form ? { form } : {}) },
  };
}

/** The boolean signals that mark an arrival, by their path in the arrival fact. */
export const FLAG_SIGNALS = [
  "fingerprint.headers.mismatch",
  "fingerprint.tls.mismatch",
  "fingerprint.tls.knownTool",
  "behaviour.timing.regular",
  "behaviour.navigation.directWrite",
  "behaviour.form.fast",
  "behaviour.form.noInput",
] as const;
export type FlagSignal = (typeof FLAG_SIGNALS)[number];

/** The value of a flag in the signals, or undefined when its group is absent (no TLS fingerprint, no form report). */
export function flagOf(signals: Signals, name: FlagSignal): boolean | undefined {
  let at: unknown = signals;
  for (const part of name.split(".")) at = at && typeof at === "object" ? (at as Record<string, unknown>)[part] : undefined;
  return typeof at === "boolean" ? at : undefined;
}

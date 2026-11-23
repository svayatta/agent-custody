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
export const MAX_FORM_REPORT = 96;
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
/** the header that a browser from `SEC_FETCH_SINCE` sends on every POST, PUT, PATCH, and DELETE; its value can be `null` */
export const WRITE_HEADERS = ["origin"];
/** the `sec-fetch-dest` values of a navigation; `sec-fetch-mode: navigate` with another one is not a browser's */
export const NAVIGATE_DESTS: ReadonlySet<string> = new Set(["document", "iframe", "frame", "embed", "object", "fencedframe"]);
/** how long `fingerprint.seen` counts arrivals with the same fingerprint */
export const SEEN_WINDOW_MS = 60_000;
/** a `sec-ch-ua` value is read up to this length */
export const MAX_CLIENT_HINT = 256;
export const SEC_FETCH_HEADERS = ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"];
/**
 * Only the JA4 TLS client fingerprint is used here and in scripts/ja4.ts: it is BSD-3-Clause. JA4H, JA4S, JA4T, and
 * the rest of JA4+ are under the FoxIO License 1.1, which restricts commercial use, so the header fingerprint is the
 * door's own hash and not JA4H.
 *
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

/** The network that the client's address belongs to, as the host gives it. */
export interface NetworkObservation {
  /** the autonomous system number */
  asn?: number;
  /** the name of the organisation that holds it */
  organization?: string;
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
  /** the relation of the `Origin` header to the host; `Origin: null` is `cross-origin`. Absent in a recording made before the door read it */
  origin?: RefererRelation;
  /** `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest`, and `sec-fetch-user`, as sent */
  secFetch: { site?: string; mode?: string; dest?: string; user?: string };
  /** the `sec-ch-ua` header, as sent: brand names and major versions. It names a browser build, not a person */
  clientHints?: string;
  /** the HTTP version between the client and the edge (`HTTP/2`), when the host knows it: a Worker's `request.cf` */
  http?: string;
  /** the network of the client's address, when the host knows it: a Worker's `request.cf` */
  network?: NetworkObservation;
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
  transport?: { secure?: boolean; tls?: TlsObservation; http?: string; network?: NetworkObservation } | undefined;
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
  const user = one(h["sec-fetch-user"], 32);
  const clientHints = one(h["sec-ch-ua"], MAX_CLIENT_HINT);
  const { http, network } = req.transport ?? {};
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
    origin: refererRelation(one(h.origin, 2048), host),
    secFetch: { ...(site !== undefined ? { site } : {}), ...(mode !== undefined ? { mode } : {}), ...(dest !== undefined ? { dest } : {}), ...(user !== undefined ? { user } : {}) },
    ...(clientHints !== undefined ? { clientHints } : {}),
    ...(http !== undefined ? { http } : {}),
    ...(network ? { network } : {}),
    ...(tls ? { tls } : {}),
    ...(form !== undefined ? { form } : {}),
  };
}

/** the methods that `directWrite` and the `origin` rule read as a write */
export const STATE_CHANGING: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export type ClientKind = "browser" | "agent" | "tool" | "other" | "unstated";

/** What a vendor says its agent fetches for: to train a model, to build a search index, or because one user asked. */
export type AgentPurpose = "training" | "search" | "user";

/**
 * AI agents that name themselves in the User-Agent, by product token. Each entry is from the vendor's own page, read on
 * 2026-11-23, and never from memory. A token that a vendor documents for another purpose (an ads check, a crawl that the
 * site owner asked for) is not here, and reads as a crawler. A claim: any client can send any of these names.
 */
export const AI_AGENTS: ReadonlyMap<string, { vendor: string; purpose: AgentPurpose }> = new Map([
  // https://developers.openai.com/api/docs/bots
  ["GPTBot", { vendor: "openai", purpose: "training" }],
  ["OAI-SearchBot", { vendor: "openai", purpose: "search" }],
  ["ChatGPT-User", { vendor: "openai", purpose: "user" }],
  // https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
  ["ClaudeBot", { vendor: "anthropic", purpose: "training" }],
  ["Claude-SearchBot", { vendor: "anthropic", purpose: "search" }],
  ["Claude-User", { vendor: "anthropic", purpose: "user" }],
  // https://docs.perplexity.ai/guides/bots
  ["PerplexityBot", { vendor: "perplexity", purpose: "search" }],
  ["Perplexity-User", { vendor: "perplexity", purpose: "user" }],
  // https://developers.google.com/search/docs/crawling-indexing/google-user-triggered-fetchers
  ["Google-GeminiNotebook", { vendor: "google", purpose: "user" }],
  ["Google-Agent", { vendor: "google", purpose: "user" }],
]);
const AI_AGENT = new RegExp(`(?<![A-Za-z0-9-])(${[...AI_AGENTS.keys()].join("|")})(?![A-Za-z0-9-])`);

/** The client that a User-Agent states. A claim: any client can send any User-Agent. */
export interface StatedClient {
  kind: ClientKind;
  /** a `BrowserFamily` for a browser, the tool's name for a tool, else `other` or `unstated` */
  family: string;
  /** the browser's major version, when the User-Agent states the version of its engine */
  version?: number;
  /** for an `agent`: the vendor, and what the vendor says the agent fetches for */
  vendor?: string;
  purpose?: AgentPurpose;
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
  const agent = AI_AGENT.exec(ua);
  if (agent) return { kind: "agent", family: agent[1]!.toLowerCase(), ...AI_AGENTS.get(agent[1]!)! };
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
  /** for a client that states an AI agent: the vendor and the purpose that the vendor documents. A claim, like the User-Agent */
  vendor?: string;
  purpose?: AgentPurpose;
  /** true when the User-Agent states a browser and the request lacks a header that this browser always sends */
  mismatch: boolean;
  /** the missing header names, separated by a space; only when `mismatch` is true */
  missing?: string;
  /** from `sec-ch-ua`, when the arrival sent it: the major version of the `Chromium` brand, when there is one */
  hints?: { version?: number };
  /** true when `sec-ch-ua` and the User-Agent do not state the same browser */
  hintsMismatch: boolean;
  /** true when the `sec-fetch-*` headers have a combination that no browser sends */
  fetchInvalid: boolean;
  /** the HTTP version between the client and the edge (`1.1`, `2`, `3`), when the host knows it */
  http?: string;
}

/**
 * The header fingerprint. `mismatch` reads only rules that hold for every request of a browser family, so that a real
 * browser is not flagged: `accept-language` always, and, when the host knows that the client used https, `sec-fetch-*`
 * and (Chromium) `sec-ch-ua` from the versions in `SEC_FETCH_SINCE` and `SEC_CH_UA_SINCE`. Browsers send these only to
 * an https site. On a write, a browser from `SEC_FETCH_SINCE` also sends `origin`, to any site. For an OPTIONS request and an upgrade, only `accept-language` is checked. A proxy in front of the door that drops one of
 * these headers makes every browser a mismatch: the door records what it received.
 */
export function headerFingerprint(o: Observation): HeaderFingerprint {
  const c = statedClient(o.userAgent);
  const out: HeaderFingerprint = { client: c.kind, family: c.family, ...(c.version !== undefined ? { version: c.version } : {}), ...(c.vendor !== undefined ? { vendor: c.vendor, purpose: c.purpose! } : {}), mismatch: false, hintsMismatch: false, fetchInvalid: false };
  const http = typeof o.http === "string" ? /^HTTP\/(1\.0|1\.1|2|3)$/.exec(o.http) : null;
  if (http) out.http = http[1]!;
  // A Chromium that is given another User-Agent keeps its own `sec-ch-ua`, so the two can name different browsers.
  // The rule reads no brand name: in the labelled capture, headless Chrome sends the brands of Chrome.
  if (typeof o.clientHints === "string") {
    const version = /"Chromium";\s*v="(\d{1,4})"/.exec(o.clientHints.slice(0, MAX_CLIENT_HINT));
    out.hints = version ? { version: Number(version[1]) } : {};
    // Firefox and Safari send no `sec-ch-ua`; a Chromium sends the major version that its User-Agent states
    out.hintsMismatch = c.kind === "browser" && (c.family !== "chromium" || (out.hints.version !== undefined && c.version !== undefined && out.hints.version !== c.version));
  }
  // From the Fetch Metadata specification, not from data: `sec-fetch-user` is sent only on a navigation, and a
  // navigation has a document destination. `sec-fetch-site: none` on a write is not in the rule, because a browser
  // extension sends it.
  const fetchMode = o.secFetch?.mode?.toLowerCase();
  const fetchDest = o.secFetch?.dest?.toLowerCase();
  out.fetchInvalid = (o.secFetch?.user !== undefined && fetchMode !== "navigate") || (fetchMode === "navigate" && fetchDest !== undefined && !NAVIGATE_DESTS.has(fetchDest));
  if (!o.headers) return out;
  const names = o.headers.names.slice(0, MAX_HEADER_NAMES).map((n) => String(n).toLowerCase().slice(0, MAX_HEADER_NAME_LENGTH));
  if (o.headers.ordered) out.order = sha256Hex(names.join("\n")).slice(0, 16);
  out.count = names.length;
  if (c.kind !== "browser") return out;
  const family = c.family as BrowserFamily;
  const version = c.version ?? 0;
  const present = new Set(names);
  const expected = [...BROWSER_HEADERS];
  if (STATE_CHANGING.has(o.method) && version >= SEC_FETCH_SINCE[family]) expected.push(...WRITE_HEADERS);
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

/**
 * The key of an unverified source in the history: the address, and for IPv6 its /64, because one client uses many
 * addresses of its /64 (privacy extensions). An IPv4-mapped address and anything that is not an IPv6 address stay as
 * they are. The door keys by address alone, not by address and User-Agent: a client that changes its User-Agent would
 * else look new each time. So clients behind one address (NAT) share one history.
 */
export function historySource(address: string): string {
  const a = address.trim().toLowerCase().replace(/%.*$/, "");
  if (!a.includes(":") || a.includes(".") || !/^[0-9a-f:]{2,39}$/.test(a)) return address;
  const [head, tail, more] = a.split("::");
  if (more !== undefined) return address;
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = tail === undefined ? left : [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return address;
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":")}::/64`;
}

/** What the door remembers of one source when an arrival comes. */
export interface SourceHistory {
  /** the times of the source's latest arrivals inside the window, oldest first, this arrival included */
  times: number[];
  /** the time of the source's latest page load before this arrival, when it is inside the window */
  pageAt?: number;
  /** how many GET requests that are not page loads the source sent after that page load and before this arrival, at most `HISTORY_MAX_ARRIVALS` */
  subresources?: number;
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
  const seen = new Map<string, { times: number[]; pageAt?: number; subresources?: number }>();
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
      const page = isPageLoad(o);
      const now = page ? t : pageAt;
      const subresources = pageAt !== undefined ? (prior?.subresources ?? 0) : undefined;
      const next = page ? 0 : subresources !== undefined ? Math.min(HISTORY_MAX_ARRIVALS, subresources + (o.method === "GET" ? 1 : 0)) : undefined;
      seen.delete(key);
      seen.set(key, { times, ...(now !== undefined ? { pageAt: now } : {}), ...(next !== undefined ? { subresources: next } : {}) });
      while (seen.size > maxSources) seen.delete(seen.keys().next().value!);
      return { times: [...times], ...(pageAt !== undefined ? { pageAt, subresources: subresources! } : {}) };
    },
    size: () => seen.size,
  };
}

export interface TimingSignals {
  /** how many gaps between the source's remembered arrivals, at most `HISTORY_MAX_ARRIVALS - 1` */
  gaps: number;
  /** the median gap in milliseconds; absent when there is no gap */
  medianGapMs?: number;
  /** the shortest and the longest gap in milliseconds; absent when there is no gap */
  minGapMs?: number;
  maxGapMs?: number;
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
  return { gaps: gaps.length, medianGapMs: median, minGapMs: gaps[0]!, maxGapMs: gaps[gaps.length - 1]!, regular };
}

export interface NavigationSignals {
  /** true when the source loaded an HTML document earlier, inside `HISTORY_WINDOW_MS` */
  pageLoaded: boolean;
  /** milliseconds from that page load to this arrival; only when `pageLoaded` is true */
  sincePageMs?: number;
  /** GET requests that are not page loads, from the source, after that page load and before this arrival; only when `pageLoaded` is true. It counts only what goes through the door */
  subresources?: number;
  referer: RefererRelation;
  /** the relation of the `Origin` header to the host; `Origin: null` is `cross-origin` */
  origin: RefererRelation;
  /** `sec-fetch-site` as sent, lowercase; `other` when it is not a token */
  site?: string;
  mode?: string;
  dest?: string;
  /** true when a POST, PUT, PATCH, or DELETE arrives with no earlier page load from the source, no same-origin referer, no same-origin `Origin`, and no `sec-fetch-site: same-origin` */
  directWrite: boolean;
}

const token = (v: unknown): string | undefined => (typeof v !== "string" ? undefined : /^[a-z-]{1,24}$/.test(v.toLowerCase()) ? v.toLowerCase() : "other");

/**
 * How the arrival fits the source's navigation. `directWrite` is true for every API client that never loads a page,
 * a verified agent included. A person whose page load came from another address, another door process, or before the
 * window is not flagged when the browser sends a same-origin `Referer`, a same-origin `Origin`, or
 * `Sec-Fetch-Site: same-origin`; a site with `Referrer-Policy: no-referrer` still gets the last. The three headers are
 * the client's word: a program can send them. A program that loads the page first is not flagged; `sincePageMs` is
 * then the time that it took to read and fill the page.
 */
export function navigationSignals(o: Observation, history: SourceHistory): NavigationSignals {
  const pageAt = history?.pageAt;
  const pageLoaded = typeof pageAt === "number" && o.at - pageAt <= HISTORY_WINDOW_MS;
  const relation = (v: unknown): RefererRelation => (v === "same-origin" || v === "cross-origin" ? v : "absent");
  const referer = relation(o.referer);
  const origin = relation(o.origin);
  const since = pageLoaded ? Math.floor(o.at - pageAt) : NaN;
  const subresources = history?.subresources;
  const site = token(o.secFetch?.site);
  const mode = token(o.secFetch?.mode);
  const dest = token(o.secFetch?.dest);
  return {
    pageLoaded,
    ...(Number.isFinite(since) && since >= 0 ? { sincePageMs: since } : {}),
    ...(pageLoaded && Number.isSafeInteger(subresources) && subresources! >= 0 ? { subresources: Math.min(subresources!, HISTORY_MAX_ARRIVALS) } : {}),
    referer,
    origin,
    ...(site !== undefined ? { site } : {}),
    ...(mode !== undefined ? { mode } : {}),
    ...(dest !== undefined ? { dest } : {}),
    directWrite: STATE_CHANGING.has(o.method) && !pageLoaded && referer !== "same-origin" && origin !== "same-origin" && site !== "same-origin",
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
  /** pointer and touch moves over the form */
  moves: number;
  /** the longest gap between two key presses minus the shortest, in milliseconds; 0 with fewer than three key presses */
  keySpreadMs: number;
  /** milliseconds from the start of the script to the first key press, pointer press, click, or paste; 0 when there was none */
  readyMs: number;
}

const FORM_REPORT = /^v=2;ms=(\d{1,8});k=(\d{1,5});p=(\d{1,5});paste=([01]);trusted=([01]);mv=(\d{1,5});ks=(\d{1,8});rd=(\d{1,8})$/;

/** The form report from its header value, or null when the value is not exactly a report: its length, its fields, and its ranges are fixed. */
export function parseFormReport(value: unknown): FormReport | null {
  if (typeof value !== "string" || value.length > MAX_FORM_REPORT) return null;
  const m = FORM_REPORT.exec(value);
  if (!m) return null;
  const fillMs = Number(m[1]);
  const [keySpreadMs, readyMs] = [Number(m[7]), Number(m[8])];
  if (fillMs > MAX_FORM_FILL_MS || keySpreadMs > MAX_FORM_FILL_MS || readyMs > MAX_FORM_FILL_MS) return null;
  return { fillMs, keys: Number(m[2]), pointers: Number(m[3]), pasted: m[4] === "1", trusted: m[5] === "1", moves: Number(m[6]), keySpreadMs, readyMs };
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
  /** present only when the host knows the network of the address: `asn`, and `organization` cut to 64 characters */
  network?: NetworkObservation;
  /**
   * How many arrivals in the last `SEEN_WINDOW_MS` had this fingerprint, from every source, this one included. A number
   * for the policy and not a flag: thousands of people share the fingerprint of one browser build.
   */
  seen?: number;
}

/** The key of `fingerprint.seen`: the JA4 and the header order. Undefined when the arrival has neither. */
export function fingerprintKey(f: ArrivalFingerprint): string | undefined {
  return f.tls?.ja4 === undefined && f.headers.order === undefined ? undefined : `${f.tls?.ja4 ?? ""}|${f.headers.order ?? ""}`;
}

export interface SeenCounter {
  /** counts the arrival and returns how many arrivals had the key in the last `SEEN_WINDOW_MS` */
  hit(key: string, at: number): number;
  size(): number;
}

/**
 * Counts arrivals for each fingerprint across sources, so that a client that changes its address and keeps its TLS
 * stack and header order is still counted as one. One process's memory, with the limits of the history: at most
 * `maxKeys` fingerprints, the least recently seen forgotten first, and at most `maxPerKey` times for each, so the
 * count stops there.
 */
export function createSeenCounter(limits: { maxKeys?: number; maxPerKey?: number } = {}): SeenCounter {
  const maxKeys = Math.max(1, limits.maxKeys ?? 10_000);
  const maxPerKey = Math.max(1, limits.maxPerKey ?? 1_000);
  const seen = new Map<string, number[]>();
  let last = -Infinity;
  return {
    hit(key, at) {
      const t = (last = Math.max(last, Number.isFinite(at) ? Math.floor(at) : 0));
      const times = (seen.get(key) ?? []).filter((x) => x > t - SEEN_WINDOW_MS);
      times.push(t);
      if (times.length > maxPerKey) times.splice(0, times.length - maxPerKey);
      seen.delete(key);
      seen.set(key, times);
      while (seen.size > maxKeys) seen.delete(seen.keys().next().value!);
      return times.length;
    },
    size: () => seen.size,
  };
}

function networkOf(o: Observation): NetworkObservation | undefined {
  const n = o.network;
  if (!n || typeof n !== "object") return undefined;
  const asn = Number.isSafeInteger(n.asn) && n.asn! > 0 && n.asn! <= 4_294_967_295 ? n.asn! : undefined;
  const organization = typeof n.organization === "string" && n.organization.trim() ? n.organization.trim().slice(0, 64) : undefined;
  return asn === undefined && organization === undefined ? undefined : { ...(asn !== undefined ? { asn } : {}), ...(organization !== undefined ? { organization } : {}) };
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
  const network = networkOf(o);
  return {
    fingerprint: { headers: headerFingerprint(o), ...(tls ? { tls } : {}), ...(network ? { network } : {}) },
    behaviour: { timing: timingSignals(history), navigation: navigationSignals(o, history), ...(form ? { form } : {}) },
  };
}

/** The boolean signals that mark an arrival, by their path in the arrival fact. */
export const FLAG_SIGNALS = [
  "fingerprint.headers.mismatch",
  "fingerprint.headers.hintsMismatch",
  "fingerprint.headers.fetchInvalid",
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

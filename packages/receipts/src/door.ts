// The door: a reverse proxy in front of a business's own HTTP surface, where the gateway is a proxy in front of an
// agent's tools. Every arrival, a browser, an API client, or an agent, is classified by what it presented, decided by
// the Cedar policy for its route, forwarded to the origin or refused, and receipted either way. Nothing here detects
// an agent: `unknown` means nothing was presented, `claimed` means something was asserted and could not be checked,
// and `verified` means a grant signed by a trusted principal names this agent for this route, or a Web Bot Auth
// signature checked against the key its agent's directory publishes. The same key, policy language, issuer, log, and
// verifier as the gateway; the receipt's issuer kind is `door`. A partner engine's detection verdict, when configured,
// is a fact beside the arrival, and only one the engine signed for this arrival (door-partner.ts).
import { randomUUID } from "node:crypto";
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { DoorConfig, DoorRouteConfig } from "./config.ts";
import { captureKeyFrom } from "./capture.ts";
import { digestOf, loadPrivateKey, loadPublicKey, publicKeyFromPem, sha256Hex, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { DID_KEY_PREFIX, publicKeyFromDidKey } from "./did-key.ts";
import { decodeDelegation, delegationValidAt, grantChainDigests, verifyDelegation, type Delegation } from "./delegation.ts";
import { parseGrantHeader, GRANT_HEADER } from "./gateway-http.ts";
import { createIssuer, ReceiptPending, type FlushResult } from "./issue.ts";
import { createWebBotAuthVerifier, normalizeAuthority, type SignatureCheck, type SignedRequest } from "./web-bot-auth.ts";
import { createPartnerEngine, PARTNER_FACT, PARTNER_TOOL, type ArrivalPartner, type PartnerVerdict } from "./door-partner.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { createRevocationList } from "./revocation.ts";
import { openExporter, type ReceiptExporter } from "./otel.ts";
import { evaluate, hasPermitRule, policyDigest, policyParseErrors, type PolicyDecision } from "./policy.ts";
import type { AuthorizationBundle, FactRecord, ReceiptPredicate } from "./receipt.ts";

export const DOOR_VERSION = "0.1.0";
/** on every answer the door gives: the receipt that records the decision */
export const RECEIPT_HEADER = "x-agent-custody-receipt";
/** on every answer: `verified`, `claimed`, or `unknown`, what the door made of the arrival */
export const CLASS_HEADER = "x-agent-custody-class";
/** the fact the door records for every arrival, and the policy reads as `context.facts.arrival` */
export const ARRIVAL_FACT = "arrival";
/** the header an agent may use to name itself without a grant; recorded as claimed, never checked */
export const AGENT_HEADER = "x-agent-custody-agent";
/** in authz mode: the original request's method and target, as nginx `auth_request` and Envoy `ext_authz` are configured to send them */
export const ORIGINAL_METHOD_HEADER = "x-original-method";
export const ORIGINAL_URI_HEADER = "x-original-uri";
/** the reason an allowed authz receipt carries: the door decided, and the proxy, not the door, relays */
export const AUTHZ_ALLOWED_REASON = "allowed; the door answered the proxy's authz check and relays nothing: the proxy relays the request, and the door sees neither its body nor the origin's answer";

export type ArrivalClass = "verified" | "claimed" | "unknown";

/** What the door observed about one arrival. Every field is the door's own observation; none is the caller's claim about itself except `declared`, which says so. */
export interface Arrival {
  class: ArrivalClass;
  /** the agent named in a verified grant, else the signature agent of a verified signature, else the name the caller declared, else "unknown" */
  subject: string;
  /**
   * What became of the grant header: a trusted grant in scope for this route, one out of scope, one that did not verify,
   * one revoked (`revoked`: it, or a grant above it in its chain, is in `revokedGrants`, or that file cannot be read),
   * one presented by another agent (`wrong-sender`: the request is signed by a signature agent the grant does not name),
   * or none.
   */
  grant: "verified" | "out-of-scope" | "invalid" | "revoked" | "wrong-sender" | "absent";
  grantError?: string;
  /** What became of an RFC 9421 signature tagged `web-bot-auth`: see `SignatureCheck`. `unchecked` when the door has no `webBotAuth` config */
  signature: SignatureCheck["outcome"];
  /** the `Signature-Agent` origin; checked only when `signature` is `verified` */
  signatureAgent?: string;
  /** the signature's keyid, the RFC 7638 thumbprint of the agent's key; checked only when `signature` is `verified` */
  signatureKeyid?: string;
  signatureError?: string;
  /** the agent name from the `x-agent-custody-agent` header, when sent; a claim */
  declared?: string;
  remote: string;
  method: string;
  path: string;
  route: string;
  /** how often this source has arrived lately, counted by this door process; set by the door, absent from `classifyArrival` alone */
  rate?: ArrivalRate;
  /** what became of the challenge token, when the door is configured to challenge; absent otherwise, and from `classifyArrival` alone */
  challenge?: ArrivalChallenge;
  /** what became of the question to the partner engine, when the door asks one about this route; absent otherwise, and from `classifyArrival` alone. The verdict itself is the `partner` fact, present only when `outcome` is `verified` */
  partner?: ArrivalPartner;
}

/**
 * The outcome of a human challenge. `passed`: the provider confirmed the token, so the provider judged a person present
 * at the time it was solved. `failed`: the provider refused it, with its error codes. `unavailable`: the provider did
 * not answer in time. `absent`: no token was sent. A passed challenge does not change `class`: it says nothing about who
 * the arrival is, only that a provider's test was passed in front of it.
 */
export interface ArrivalChallenge {
  provider: "turnstile" | "hcaptcha";
  outcome: "passed" | "failed" | "unavailable" | "absent";
  error?: string;
}

const CHALLENGE_VERIFY_URL = { turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify", hcaptcha: "https://api.hcaptcha.com/siteverify" } as const;
/** a provider token is about 2 KB; a longer value is refused as failed without calling the provider */
export const MAX_CHALLENGE_TOKEN = 4096;
/**
 * Error codes that are the provider's or the operator's fault, not the token's: a rotated secret, a site key that does not
 * match it, an outage. Every person would get one, so they are `unavailable`, which a policy handles as the provider's
 * state, and never `failed`, which a policy may treat as an attack. Token faults (`invalid-input-response`,
 * `timeout-or-duplicate`, `expired-input-response`, `already-seen-response`, `missing-input-response`) stay `failed`.
 */
const PROVIDER_FAULT_CODES = new Set(["internal-error", "missing-input-secret", "invalid-input-secret", "bad-request", "sitekey-secret-mismatch", "invalid-sitekey", "missing-sitekey", "invalid-remoteip"]);

export interface ChallengeCheck {
  provider: "turnstile" | "hcaptcha";
  secret: string;
  token: string;
  /** the client's address, sent as `remoteip` only when the door knows it is the client's and not a proxy's */
  remoteIp?: string;
  /** the hostnames of the pages that render the widget, lowercase */
  hostnames: string[];
  /** the widget's action, when one is required (Turnstile) */
  action?: string;
  /** the public site key; sent to hCaptcha, whose secret belongs to the account, so a token from another of its site keys is refused */
  siteKey?: string;
  timeoutMs: number;
}

/**
 * Asks the provider whether the token is good. The token and the secret go to the provider only; neither is recorded,
 * and a redirect is never followed, since it would resend both to the Location's host. `success` is not enough: the
 * token must have been issued on one of the site's own hostnames, and for the configured action, or a token solved on
 * another site with this site key, or for another widget, would pass.
 */
export async function verifyChallengeToken(check: ChallengeCheck, f: typeof fetch): Promise<ArrivalChallenge> {
  const { provider } = check;
  // any client can send a value in the header: one no provider would issue costs no call
  if (check.token.length > MAX_CHALLENGE_TOKEN) return { provider, outcome: "failed", error: `the token is longer than ${MAX_CHALLENGE_TOKEN} characters and was not sent to the provider` };
  const body = new URLSearchParams({ secret: check.secret, response: check.token, ...(check.remoteIp ? { remoteip: check.remoteIp } : {}), ...(provider === "hcaptcha" && check.siteKey ? { sitekey: check.siteKey } : {}) });
  try {
    const res = await f(CHALLENGE_VERIFY_URL[provider], { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, redirect: "manual", signal: AbortSignal.timeout(check.timeoutMs) });
    if (res.status >= 300 && res.status < 400) return { provider, outcome: "unavailable", error: `the provider answered a redirect (${res.status}); the secret is not resent` };
    if (!res.ok) return { provider, outcome: "unavailable", error: `the provider answered ${res.status}` };
    const answer = (await res.json()) as { success?: boolean; "error-codes"?: string[]; hostname?: unknown; action?: unknown };
    if (answer.success !== true) {
      const codes = Array.isArray(answer["error-codes"]) ? answer["error-codes"].filter((c): c is string => typeof c === "string") : [];
      if (codes.some((c) => PROVIDER_FAULT_CODES.has(c))) return { provider, outcome: "unavailable", error: `the provider could not check the token: ${codes.join(", ")}` };
      return { provider, outcome: "failed", error: codes.join(", ") || "the provider refused the token" };
    }
    const host = typeof answer.hostname === "string" ? answer.hostname.toLowerCase() : undefined;
    if (!host || !check.hostnames.includes(host)) return { provider, outcome: "failed", error: `the token was issued on ${host ?? "no hostname"}, not a hostname this door serves` };
    if (check.action !== undefined && answer.action !== check.action) return { provider, outcome: "failed", error: `the token was issued for action ${typeof answer.action === "string" ? answer.action : "(none)"}, not ${check.action}` };
    return { provider, outcome: "passed" };
  } catch (e) {
    return { provider, outcome: "unavailable", error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Arrivals from one source in the last 10 seconds (`burst`) and 60 seconds (`minute`), this one included, whatever the
 * policy decided about them. The source is the agent a verified grant names, else the arrival's address. One process's
 * memory: the count starts at one when the door starts, and two doors do not share it.
 */
export interface ArrivalRate {
  by: "agent" | "remote";
  burst: number;
  minute: number;
}

export const RATE_BURST_MS = 10_000;
export const RATE_MINUTE_MS = 60_000;

export interface RateTrackerLimits {
  /** sources kept at once; past this the least recently seen is forgotten. Default 10000 */
  maxSources?: number;
  /** a source key longer than this is kept as its sha256. Default 256 */
  maxKeyLength?: number;
}

export interface RateTracker {
  hit(source: string): { burst: number; minute: number };
  /** sources kept now */
  size(): number;
  /** stops the sweep */
  close(): void;
}

/** One source's arrival times, oldest first, with the index of the first inside each window: both only move forward. */
interface SourceTimes {
  times: number[];
  minuteHead: number;
  burstHead: number;
}

/**
 * Counts arrivals per source over the two windows. Each source keeps its arrival times in order with two heads that only
 * move forward, so one arrival costs the same however many came before it in the window; the array is compacted once
 * half of it is behind the minute head. The source key comes from the arrival, and with `trustProxy` the client may
 * choose it, so the map bounds itself: at most `maxSources` keys, none longer than `maxKeyLength`, and a source with no
 * arrival in the last minute is dropped every minute whether or not traffic goes on. A source forgotten early counts
 * again from 1, which only lowers what a pace rule sees for a client that floods the map. The clock is monotonic
 * (`performance.now`), so a step of the wall clock (an NTP correction, a VM resume) neither keeps old arrivals inside
 * the windows nor drops new ones; an injected clock that goes back is held at the last time seen. `now` is for tests.
 */
export function createRateTracker(now: () => number = () => performance.now(), limits: RateTrackerLimits = {}): RateTracker {
  const maxSources = limits.maxSources ?? 10_000;
  const maxKeyLength = limits.maxKeyLength ?? 256;
  // least recently seen first: a hit moves its key to the end
  const seen = new Map<string, SourceTimes>();
  let last = -Infinity;
  const clock = () => (last = Math.max(last, now()));
  const sweep = () => {
    const cutoff = clock() - RATE_MINUTE_MS;
    for (const [k, v] of seen) if (v.times[v.times.length - 1]! <= cutoff) seen.delete(k);
  };
  const timer = setInterval(sweep, RATE_MINUTE_MS);
  timer.unref();
  return {
    hit(source) {
      const key = source.length > maxKeyLength ? `sha256:${sha256Hex(source)}` : source;
      const t = clock();
      const s = seen.get(key) ?? { times: [], minuteHead: 0, burstHead: 0 };
      s.times.push(t);
      while (s.times[s.minuteHead]! <= t - RATE_MINUTE_MS) s.minuteHead += 1;
      if (s.burstHead < s.minuteHead) s.burstHead = s.minuteHead;
      while (s.times[s.burstHead]! <= t - RATE_BURST_MS) s.burstHead += 1;
      if (s.minuteHead > 64 && s.minuteHead * 2 > s.times.length) {
        s.times = s.times.slice(s.minuteHead);
        s.burstHead -= s.minuteHead;
        s.minuteHead = 0;
      }
      seen.delete(key);
      seen.set(key, s);
      if (seen.size > maxSources) sweep();
      while (seen.size > maxSources) seen.delete(seen.keys().next().value!);
      return { burst: s.times.length - s.burstHead, minute: s.times.length - s.minuteHead };
    },
    size: () => seen.size,
    close: () => clearInterval(timer),
  };
}

export interface Classified {
  arrival: Arrival;
  /** set when the arrival is verified by a grant: the grant, as presented */
  delegation?: { envelope: Envelope; grant: Delegation; principalKeyid: string };
  /** set when a verified signature names the arrival's agent: alone, or bound to the grant that names the same agent */
  signer?: { agent: string; keyid: string };
}

const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"]);
/** request headers the receipt records in clear; everything else is relayed and not recorded */
const RECORDED_HEADERS = ["user-agent", "content-type", "accept", "host"];
/** a JSON body up to this size is recorded in the receipt's arguments; a larger or non-JSON body is recorded by digest and size only */
const RECORDED_BODY_BYTES = 64 * 1024;
/**
 * Headers that name the client's address or the scheme and host it used. Without trustProxy the client wrote them, and an
 * origin that reads one (an allowlist on `X-Real-IP`, a rate limit on `Forwarded`) would trust the client's word: they
 * are dropped, and the door sets `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` itself.
 */
const CLIENT_ADDRESS_HEADERS = new Set(["forwarded", "x-real-ip", "true-client-ip", "cf-connecting-ip", "x-client-ip", "x-cluster-client-ip", "fastly-client-ip"]);
/** connection failures in which the request never left the door: the origin cannot have acted on it */
const UNREACHED_CODES = new Set(["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH", "ENETUNREACH", "EAI_AGAIN"]);

/**
 * The record of the call keeps what arrived; the policy reads a copy Cedar accepts. Cedar has no `null` and no
 * non-integer number, and refuses the whole request on either, so a body with `"coupon": null` or `"price": 9.99` would
 * be denied whatever the policy says. In the copy a `null` is dropped and a number that is not a safe integer becomes its
 * string; a rule that compares `price` as a number then errors, and the call is denied by that rule rather than by Cedar.
 */
export function cedarArgs(value: unknown): unknown {
  if (Array.isArray(value)) return value.filter((v) => v !== null).map(cedarArgs);
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : String(value);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) if (v !== null) Object.defineProperty(out, k, { value: cedarArgs(v), enumerable: true, writable: true, configurable: true });
    return out;
  }
  return value;
}

/**
 * What a receipt records of an arrival when the config gives its route no capture rule: the method, the path, the
 * recorded headers, and the body's size in clear; the query and the body withheld, each a salted commitment. A query can
 * carry an API key and a form body a password. Set a rule for the route (or `"*"`) to record more in clear.
 */
export const DOOR_DEFAULT_CAPTURE = { args: { mode: "digest" as const, clear: ["method", "path", "headers", "bodyBytes", "bodyOversized"] }, result: { mode: "clear" as const }, facts: { mode: "clear" as const } };

/**
 * The path as the origin will read it: each segment percent-decoded once, so that `/%61dmin` falls under `/admin/*`, and
 * empty segments merged, so that `//admin/users` and `/admin//users` fall under it too (nginx, Apache, and many
 * frameworks merge them, and the origin would serve the admin page to an arrival the door matched as something else).
 * A trailing slash is kept. Refused when a segment does not decode, or decodes to a slash, a backslash, or a dot
 * segment: the origin would then read a path the door did not match. `relay` is the merged, decoded path encoded once
 * more, the form the origin is sent, so the door and the origin read one path.
 */
export function normalizePath(pathname: string): { path: string; relay: string } | { problem: string } {
  const segments: string[] = [];
  for (const raw of pathname.split("/")) {
    if (raw === "") continue;
    let segment: string;
    try {
      segment = decodeURIComponent(raw);
    } catch {
      return { problem: `the path segment "${raw}" does not percent-decode` };
    }
    if (segment.includes("/") || segment.includes("\\")) return { problem: `the path segment "${raw}" decodes to a slash` };
    if (segment === "." || segment === "..") return { problem: `the path segment "${raw}" decodes to a dot segment` };
    if (segment === "") return { problem: `the path segment "${raw}" decodes to nothing` };
    segments.push(segment);
  }
  const tail = segments.length > 0 && pathname.endsWith("/") ? "/" : "";
  return { path: `/${segments.join("/")}${tail}`, relay: `/${segments.map(encodeSegment).join("/")}${tail}` };
}

/** A path segment encoded once: what `encodeURIComponent` does, except that the characters a path segment may carry in clear stay in clear. */
function encodeSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/%(3A|40|24|26|2B|2C|3B|3D)/gi, (m) => decodeURIComponent(m));
}

/** What the door reads of a request: its method, its target, its headers, and the socket's address. A Node `IncomingMessage` is one; the in-process door builds one from a fetch `Request`. */
export interface DoorRequest {
  method?: string | undefined;
  url?: string | undefined;
  headers: IncomingHttpHeaders;
  /** every value of each field, as Node keeps them; read for an HTTP message signature */
  headersDistinct?: Record<string, string[] | undefined>;
  socket: { remoteAddress?: string | undefined };
}

/** The request target as a URL whose host is the door's own: an origin-form target `//x/y` is a path, never a scheme-relative URL. */
function requestUrl(req: DoorRequest): URL {
  const raw = req.url ?? "/";
  return raw.startsWith("/") ? new URL(`http://door${raw}`) : new URL(raw, "http://door");
}

/**
 * The original request an authz check asks about, from `X-Original-Method` and `X-Original-URI`, with the check's own
 * headers and address. The check request's own method and path are the proxy's (nginx sends GET to a fixed location),
 * so both headers are required, and a check without them is refused rather than decided on the proxy's request.
 */
export function authzTarget(req: DoorRequest): DoorRequest | { problem: string } {
  const method = req.headers[ORIGINAL_METHOD_HEADER];
  const uri = req.headers[ORIGINAL_URI_HEADER];
  if (typeof method !== "string" || !/^[A-Za-z]+$/.test(method)) return { problem: `an authz check needs ${ORIGINAL_METHOD_HEADER}, the original request's method` };
  if (typeof uri !== "string" || !uri.startsWith("/")) return { problem: `an authz check needs ${ORIGINAL_URI_HEADER}, the original request's path and query` };
  return { method: method.toUpperCase(), url: uri, headers: req.headers, ...(req.headersDistinct ? { headersDistinct: req.headersDistinct } : {}), socket: req.socket };
}

/** A path without its trailing slash: `/refunds/` and `/refunds` are one route. */
const bare = (p: string) => (p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p);

/** The route an arrival falls under: the first configured route whose methods and decoded path match, else the unmatched name. A trailing slash matches as no trailing slash. */
export function matchRoute(routes: DoorRouteConfig[], unmatched: string, method: string, pathname: string): string {
  const path = bare(pathname);
  for (const r of routes) {
    if (r.methods && !(r.methods as string[]).includes(method)) continue;
    if (r.path === "*") return r.name;
    if (r.path.endsWith("/*")) {
      const prefix = bare(r.path.slice(0, -2)) || "/";
      if (path === prefix || path.startsWith(prefix === "/" ? "/" : `${prefix}/`)) return r.name;
    } else if (bare(r.path) === path) return r.name;
  }
  return unmatched;
}

/**
 * The arrival's address: the socket's, or with trustProxy the last address in `X-Forwarded-For`, the one the proxy in
 * front of the door appended. Everything before it was sent by the client, which may write what it likes there.
 */
export function remoteOf(req: DoorRequest, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    const last = (Array.isArray(xff) ? xff.join(",") : xff)?.split(",").map((a) => a.trim()).filter(Boolean).pop();
    if (last) return last;
  }
  return req.socket.remoteAddress ?? "unknown";
}

/**
 * The request as RFC 9421 reads it: the target as received, the `Host` as the authority, and every value of each field.
 * A request without `headersDistinct` (a fetch request, which joins repeated fields with ", ") gives each field's value as
 * it holds it.
 */
export function signedRequestOf(req: DoorRequest): SignedRequest {
  const distinct: Record<string, string[] | undefined> = req.headersDistinct ?? Object.fromEntries(Object.entries(req.headers).filter((e): e is [string, string | string[]] => e[1] !== undefined).map(([k, v]) => [k, Array.isArray(v) ? v : [v]]));
  return {
    method: (req.method ?? "GET").toUpperCase(),
    target: req.url ?? "/",
    authority: normalizeAuthority(typeof req.headers.host === "string" ? req.headers.host : ""),
    header: (name) => (Object.hasOwn(distinct, name) ? distinct[name] : undefined),
  };
}

/**
 * What the arrival presented, checked where it can be. A grant signed by a trusted principal, in its window, naming this
 * route among its scopes, makes the arrival `verified` and its principal attested. A grant that is out of scope, expired,
 * or signed by a stranger leaves the arrival `claimed`: it asserted an identity the door could not accept for this route.
 * Without a grant, a Web Bot Auth signature the door verified (`signature`, from `createWebBotAuthVerifier`) makes the
 * arrival `verified` as its signature agent. With both, the signature binds the grant to its sender when the grant names
 * that signature agent; a grant presented under another agent's signature is `wrong-sender` and the arrival `claimed`.
 * An `x-agent-custody-agent` header or a signature that did not verify alone is `claimed`. Nothing at all is `unknown`.
 * Without `signature`, a `Signature-Input` header is recorded as `unchecked`. `revoked`, when given, says why a grant
 * that verified is revoked (from its chain's digests, leaf first), or null when it is not; a revoked grant is `claimed`.
 */
export function classifyArrival(req: DoorRequest, trusted: PublicKeyRef[], route: string, trustProxy: boolean, at: string, signature?: SignatureCheck, revoked?: (chainDigests: string[]) => string | null): Classified {
  const url = requestUrl(req);
  const method = (req.method ?? "GET").toUpperCase();
  const declaredRaw = req.headers[AGENT_HEADER];
  const declared = typeof declaredRaw === "string" && declaredRaw.trim() ? declaredRaw.trim().slice(0, 200) : undefined;
  const sig: SignatureCheck = signature ?? (req.headers["signature-input"] !== undefined ? { outcome: "unchecked" } : { outcome: "absent" });
  const signer = sig.outcome === "verified" ? { agent: sig.agent, keyid: sig.keyid } : undefined;
  const sigFields = {
    signature: sig.outcome,
    ...("agent" in sig && sig.agent ? { signatureAgent: sig.agent } : {}),
    ...("keyid" in sig && sig.keyid ? { signatureKeyid: sig.keyid } : {}),
    ...("error" in sig ? { signatureError: sig.error } : {}),
  };
  const norm = normalizePath(url.pathname);
  const base = { ...sigFields, ...(declared ? { declared } : {}), remote: remoteOf(req, trustProxy), method, path: "path" in norm ? norm.path : url.pathname, route };
  const envelope = parseGrantHeader(req);
  if (!envelope) {
    if (signer) return { arrival: { class: "verified", subject: signer.agent, grant: "absent", ...base }, signer };
    const claimed = !!declared || sig.outcome !== "absent";
    return { arrival: { class: claimed ? "claimed" : "unknown", subject: declared ?? "unknown", grant: "absent", ...base } };
  }
  const checked = verifyDelegation(envelope, trusted);
  const asserted = decodeDelegation(envelope)?.agent;
  const subject = declared ?? asserted ?? "unknown";
  if (!checked.ok) return { arrival: { class: "claimed", subject, grant: "invalid", grantError: checked.error, ...base } };
  const grant = checked.delegation;
  const revocation = revoked?.(grantChainDigests(envelope));
  if (revocation) return { arrival: { class: "claimed", subject: grant.agent, grant: "revoked", grantError: revocation, ...base } };
  // An agent named by a did:key is its key: the identifier must decode to an Ed25519 key, and the grant's agentKey, if
  // it names one, must be that key, or the grant says two things about who the agent is.
  if (grant.agent.startsWith(DID_KEY_PREFIX)) {
    const named = didKeyAgent(grant.agent, grant.agentKey);
    if (named) return { arrival: { class: "claimed", subject: grant.agent, grant: "invalid", grantError: named, ...base } };
  }
  if (!delegationValidAt(grant, at)) return { arrival: { class: "claimed", subject: grant.agent, grant: "invalid", grantError: "the grant is outside its validity window", ...base } };
  if (!grant.scopes.includes(route)) return { arrival: { class: "claimed", subject: grant.agent, grant: "out-of-scope", grantError: `route "${route}" is not in the grant's scopes`, ...base } };
  // The signature proves who sent the request. A grant for one agent in a request another agent signed was handed on or taken.
  if (signer && signer.agent !== grant.agent) return { arrival: { class: "claimed", subject: grant.agent, grant: "wrong-sender", grantError: `the grant names agent "${grant.agent}", and the request is signed by ${signer.agent}`, ...base } };
  return { arrival: { class: "verified", subject: grant.agent, grant: "verified", ...base }, delegation: { envelope, grant, principalKeyid: checked.keyid }, ...(signer ? { signer } : {}) };
}

/** Why a did:key agent does not check out, or null when it decodes and agrees with the grant's agentKey. */
function didKeyAgent(did: string, agentKey: string | undefined): string | null {
  let named: PublicKeyRef;
  try {
    named = publicKeyFromDidKey(did);
  } catch (e) {
    return `the grant's did:key agent does not decode: ${e instanceof Error ? e.message : String(e)}`;
  }
  if (agentKey === undefined) return null;
  try {
    if (publicKeyFromPem(agentKey).keyid === named.keyid) return null;
  } catch {
    return "the grant's agentKey is not a public key";
  }
  return "the grant's agentKey is not the key its did:key agent names";
}

export interface DoorOptions {
  /** the log to append to, in place of the one the config names; for embedding and tests */
  log?: LogSink;
  exporter?: ReceiptExporter;
  fetch?: typeof fetch;
  /** appends the outbox at start and every 30 seconds; only a serving door sets it */
  autoFlush?: boolean;
}

export interface DoorHost {
  keyid: string;
  policyDigest(): string;
  /** decides, forwards or refuses, and receipts one arrival; answers the response */
  handle(req: IncomingMessage, res: ServerResponse): Promise<void>;
  flushOutbox(): Promise<FlushResult>;
  pendingReceipts(): number;
  close(): Promise<void>;
}

/** methods that must not change anything at the origin; every other method is relayed only after its receipt is committed to the log */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** The body as the door read it: whole, or how many bytes had arrived when it passed the limit. */
export type BodyRead = { body: Buffer } | { oversized: true; bytes: number };

/** The body, or how many bytes had arrived when it passed the limit; the rest is drained and dropped. */
export function readBody(req: IncomingMessage, max: number): Promise<BodyRead> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) {
        resolve({ oversized: true, bytes: size });
        req.removeAllListeners("data");
        req.resume();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve({ body: Buffer.concat(chunks) }));
    req.on("error", reject);
  });
}

/** A fetch body, or how many bytes had arrived when it passed the limit; the rest is not read. */
export async function readStream(stream: ReadableStream<Uint8Array> | null, max: number): Promise<BodyRead> {
  if (!stream) return { body: Buffer.alloc(0) };
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return { body: Buffer.concat(chunks) };
    size += value.length;
    if (size > max) {
      await reader.cancel().catch(() => undefined);
      return { oversized: true, bytes: size };
    }
    chunks.push(value);
  }
}

/** The query as own properties: a parameter named `constructor` or `__proto__` is a parameter, never an inherited member or the prototype. */
export function queryOf(url: URL): Record<string, string | string[]> {
  const pairs = new Map<string, string | string[]>();
  for (const [k, v] of url.searchParams) {
    const prior = pairs.get(k);
    pairs.set(k, prior === undefined ? v : Array.isArray(prior) ? [...prior, v] : [prior, v]);
  }
  return Object.fromEntries(pairs);
}

/** Whether a failed fetch never left the door: a refused or unresolved connection. Anything else (a timeout, a reset) may have reached the origin. */
function unreached(e: unknown): boolean {
  const cause = (e as { cause?: { code?: unknown; message?: unknown; errors?: { code?: unknown }[] } } | undefined)?.cause;
  if (!cause) return false;
  if (typeof cause.code === "string") return UNREACHED_CODES.has(cause.code);
  // fetch refuses a port on its blocked list before it connects
  if (cause.message === "bad port") return true;
  return Array.isArray(cause.errors) && cause.errors.length > 0 && cause.errors.every((x) => typeof x?.code === "string" && UNREACHED_CODES.has(x.code));
}

type Execution = ReceiptPredicate["execution"];
type ReceiptHead = Omit<ReceiptPredicate, "session" | "model" | "execution" | "authorization">;

/** One arrival as the door decided it, before anything was relayed or passed on. */
export interface DoorDecision {
  receiptId: string;
  arrival: Arrival;
  method: string;
  url: URL;
  route: string;
  /** the path decoded and encoded once, the form the origin is sent; absent when the path did not decode cleanly */
  relay?: string;
  /** the body, or null when it passed `maxBodyBytes` */
  body: Buffer | null;
  /** set when the door refuses the arrival: what the receipt records, and the status the arrival is answered */
  refused?: { execution: Execution; status: number };
  head: ReceiptHead;
  authorization?: AuthorizationBundle;
}

/** An answer the door gives itself, in place of the origin's or the app's. */
export interface DoorAnswer {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * The door's decision loop, shared by the proxy and the in-process door: classify the arrival, read its body, run the
 * policy, commit the authorization of a request that can change something, and write the receipt once the outcome is
 * known. What happens between the decision and the receipt, relaying to an origin or passing the request to the app in
 * the same process, is the caller's.
 */
export interface DoorCore {
  keyid: string;
  policyDigest(): string;
  /** false when `maxInFlight` arrivals are already being handled: answer `busy()` before the body is read. Every admitted arrival is released */
  admit(): boolean;
  release(): void;
  busy(): DoorAnswer;
  /** `framework`, when given, is the receipt's `issuer.framework` in place of the core's. `read` is null when the door never sees the body (an authz check): the receipt then records none */
  decide(req: DoorRequest, receiptId: string, read: ((max: number) => Promise<BodyRead>) | null, framework?: string): Promise<DoorDecision>;
  /** a header the door consumed and never passes on: the grant (and `Authorization` when it carried it), the declared agent, the challenge token */
  consumed(name: string, req: DoorRequest, arrival: Arrival): boolean;
  /** writes the receipt; null when it could not be written, after saying why on stderr */
  record(d: DoorDecision, execution: Execution): Promise<{ logPending: boolean } | null>;
  /** the door's headers on every answer */
  mark(d: DoorDecision, logPending: boolean): Record<string, string>;
  /** the answer to an arrival the door refused */
  refusal(d: DoorDecision, logPending: boolean): DoorAnswer;
  /** the answer when the receipt could not be written: what happened, so that nobody retries a refund that went through */
  unrecorded(d: DoorDecision, execution: Execution, notSent: boolean): DoorAnswer;
  flushOutbox(): Promise<FlushResult>;
  pendingReceipts(): number;
  close(): void;
}

const json = (status: number, headers: Record<string, string>, body: unknown): DoorAnswer => ({ status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers }, body: JSON.stringify(body) });

/** The decision loop for a door config; `framework` is the receipt's `issuer.framework`. Throws when the config cannot be served. */
export function createDoorCore(cfg: DoorConfig, options: Omit<DoorOptions, "fetch"> & { fetch?: typeof fetch }, framework: string): DoorCore {
  const key = loadPrivateKey(cfg.identity.keyFile);
  const trusted = cfg.trustedPrincipalKeys.map(loadPublicKey);
  const revocations = createRevocationList(cfg.revokedGrants);
  revocations.reload();
  const revoked = (chainDigests: string[]): string | null => {
    try {
      revocations.reload();
    } catch (e) {
      // fail closed: a revocation list that cannot be read revokes every grant until it can
      return `the grant cannot be checked against the revocation list (${e instanceof Error ? e.message : String(e)})`;
    }
    if (!revocations.has(chainDigests)) return null;
    return revocations.has(chainDigests.slice(0, 1)) ? "the grant has been revoked" : "a grant above it in its chain has been revoked";
  };
  const captureKey = cfg.captureKeyEnv ? captureKeyFrom(process.env[cfg.captureKeyEnv] ?? (() => { throw new Error(`capture key: environment variable ${cfg.captureKeyEnv} is not set`); })()) : undefined;
  for (const [route, rule] of Object.entries(cfg.capture ?? {})) {
    for (const side of [rule.args, rule.result, rule.facts]) if (side?.mode === "encrypted" && !captureKey) throw new Error(`capture for ${route} uses mode encrypted, which needs captureKeyEnv`);
  }
  const f = options.fetch ?? fetch;
  const challengeSecret = cfg.challenge ? process.env[cfg.challenge.secretEnv] : undefined;
  if (cfg.challenge && !challengeSecret) throw new Error(`challenge: environment variable ${cfg.challenge.secretEnv} is not set`);
  const challengeHeader = cfg.challenge?.header.toLowerCase();
  let challengesInFlight = 0;
  const sink = options.log ?? openLog(cfg, key);
  // a route the config gives no rule falls to "*", and without a "*" rule of the config's own, to the door's default
  const rules = cfg.capture && Object.hasOwn(cfg.capture, "*") ? cfg.capture : { ...(cfg.capture ?? {}), "*": DOOR_DEFAULT_CAPTURE };
  const issuer = createIssuer(key, cfg.receiptsDir, sink, { exporter: options.exporter ?? openExporter(cfg), capture: { rules, key: captureKey } });
  const issuedBy = { kind: "door" as const, keyid: issuer.keyid, version: DOOR_VERSION, framework };
  const precommit = new Set(cfg.precommit);
  const rates = createRateTracker();
  const webBotAuth = cfg.webBotAuth ? createWebBotAuthVerifier(cfg.webBotAuth, f) : undefined;
  const partner = cfg.partner ? createPartnerEngine(cfg.partner, f) : undefined;

  // The policy, re-read when the file changes, as the gateway does; a file that does not parse is refused and the
  // policy in force stays. The bytes and the metadata come from one open file.
  const readPolicy = () => {
    const fd = openSync(cfg.policyFile, "r");
    try {
      const st = fstatSync(fd);
      return { text: readFileSync(fd, "utf8"), key: `${st.ino}:${st.mtimeMs}:${st.ctimeMs}:${st.size}` };
    } finally {
      closeSync(fd);
    }
  };
  const first = readPolicy();
  const errors = policyParseErrors(first.text);
  if (errors.length) throw new Error(`policy ${cfg.policyFile} does not parse: ${errors.join("; ")}`);
  if (!hasPermitRule(first.text)) console.error(`agent-custody door: ${cfg.policyFile} has no permit rule, so every arrival is refused`);
  let policyNow = { text: first.text, digest: policyDigest(first.text), key: first.key };
  const currentPolicy = () => {
    try {
      const next = readPolicy();
      if (next.key !== policyNow.key) {
        const problems = policyParseErrors(next.text);
        if (problems.length) console.error(`agent-custody door: POLICY NOT RELOADED: ${cfg.policyFile} ${problems.join("; ")}; policy ${policyNow.digest} stays in force`);
        else policyNow = { text: next.text, digest: policyDigest(next.text), key: next.key };
      }
    } catch (e) {
      console.error(`agent-custody door: cannot read ${cfg.policyFile}: ${e instanceof Error ? e.message : String(e)}; policy ${policyNow.digest} stays in force`);
    }
    return policyNow;
  };

  async function decide(req: DoorRequest, receiptId: string, readArrivalBody: ((max: number) => Promise<BodyRead>) | null, framework?: string): Promise<DoorDecision> {
    const timestamp = new Date().toISOString();
    const url = requestUrl(req);
    const method = (req.method ?? "GET").toUpperCase();
    // A path that does not decode cleanly is never relayed; it falls under the unmatched route for the receipt.
    const norm = normalizePath(url.pathname);
    const path = "path" in norm ? norm.path : url.pathname;
    const route = "path" in norm ? matchRoute(cfg.routes, cfg.unmatchedRoute, method, path) : cfg.unmatchedRoute;
    const signature = webBotAuth ? await webBotAuth.verify(signedRequestOf(req)) : undefined;
    const { arrival, delegation, signer } = classifyArrival(req, trusted, route, !!cfg.trustProxy, timestamp, signature, revoked);
    const checkedAgent = arrival.class === "verified";
    const by = checkedAgent ? "agent" : "remote";
    arrival.rate = { by, ...rates.hit(`${by}:${checkedAgent ? arrival.subject : arrival.remote}`) };
    if (cfg.challenge && challengeHeader) {
      const c = cfg.challenge;
      const token = req.headers[challengeHeader];
      if (typeof token !== "string" || !token.trim()) arrival.challenge = { provider: c.provider, outcome: "absent" };
      // every arrival with a token waits on the provider, so the checks at once are bounded; past that, unavailable
      else if (challengesInFlight >= c.maxInFlight) arrival.challenge = { provider: c.provider, outcome: "unavailable", error: `${c.maxInFlight} challenge checks are already waiting on the provider` };
      else {
        challengesInFlight++;
        try {
          // without trustProxy the socket's address may be a proxy's, and the provider would refuse the client's token on it
          arrival.challenge = await verifyChallengeToken({ provider: c.provider, secret: challengeSecret!, token: token.trim(), ...(cfg.trustProxy ? { remoteIp: arrival.remote } : {}), hostnames: c.hostnames, ...(c.action ? { action: c.action } : {}), siteKey: c.siteKey, timeoutMs: c.timeoutMs }, f);
        } finally {
          challengesInFlight--;
        }
      }
    }
    const { text: policyText, digest: pDigest } = currentPolicy();

    const read = readArrivalBody ? await readArrivalBody(cfg.maxBodyBytes) : null;
    const body = read === null ? Buffer.alloc(0) : "body" in read ? read.body : null;
    const headers: Record<string, string> = {};
    for (const name of RECORDED_HEADERS) {
      const v = req.headers[name];
      if (typeof v === "string") headers[name] = v;
    }
    // A verdict reaches the policy and the receipt only when its signature verified for this receipt and route. Without
    // one, onFailure "deny" refuses the arrival whatever the policy says, and "absent" leaves the policy without the fact.
    let verdict: { value: PartnerVerdict; signature: Envelope } | undefined;
    let partnerRefusal: string | undefined;
    if (partner && cfg.partner && partner.applies(route)) {
      const asked = await partner.ask({ receiptId, route, method, path, remote: arrival.remote, class: arrival.class, headers });
      arrival.partner = asked.check;
      if (asked.verdict) verdict = { value: asked.verdict, signature: asked.signature };
      else if (cfg.partner.onFailure === "deny") partnerRefusal = `the partner engine ${cfg.partner.engine} gave no verified verdict (${asked.check.outcome}: ${asked.check.error ?? "no detail"}), and partner.onFailure is deny`;
    }
    const contentType = req.headers["content-type"] ?? "";
    let recordedBody: unknown;
    if (body && body.length > 0 && body.length <= RECORDED_BODY_BYTES && /^application\/json\b/i.test(contentType)) {
      try { recordedBody = JSON.parse(body.toString("utf8")); } catch { recordedBody = undefined; }
    }
    // An oversized body is dropped before anything is decided: the receipt records how far it was read and that there
    // is no digest of it, rather than a digest of nothing.
    const args: Record<string, unknown> = {
      method,
      path,
      query: queryOf(url),
      headers,
      ...(recordedBody !== undefined ? { body: recordedBody } : {}),
      ...(read === null ? {} : body ? { bodyBytes: body.length, bodyDigest: sha256Hex(body) } : { bodyBytes: (read as { bytes: number }).bytes, bodyOversized: true }),
    };
    const facts: Record<string, FactRecord> = {
      [ARRIVAL_FACT]: { tool: "door.arrival", args: {}, value: arrival, resultDigest: digestOf(arrival), provenance: "observed" },
      ...(verdict ? { [PARTNER_FACT]: { tool: PARTNER_TOOL, args: {}, value: verdict.value, resultDigest: digestOf(verdict.value), provenance: "attested" as const, attestation: verdict.signature } } : {}),
    };

    // The Cedar principal is an agent the door checked: the one a verified grant names, or the signature agent of a
    // verified signature. A declared name, or the agent a rejected grant names, stays in the arrival fact as a claim, so
    // a permit on `principal == Agent::"x"` cannot be satisfied by sending a header.
    let policy: PolicyDecision;
    try {
      policy = evaluate(policyText, {
        agentId: checkedAgent ? arrival.subject : "unknown",
        tool: route,
        context: { args: cedarArgs(args), facts: { [ARRIVAL_FACT]: arrival, ...(verdict ? { [PARTNER_FACT]: verdict.value } : {}) }, ...(delegation ? { grant: { principal: delegation.grant.principal, scopes: delegation.grant.scopes } } : {}) },
      });
    } catch (e) {
      policy = { decision: "deny", reasons: [], errors: [String(e instanceof Error ? e.message : e)], policyDigest: pDigest };
    }
    if (cfg.mode === "observe") policy = { ...policy, enforced: false };
    const forward = policy.decision === "allow" || policy.enforced === false;

    const head: ReceiptHead = {
      receiptId,
      timestamp,
      issuer: framework ? { ...issuedBy, framework } : issuedBy,
      principal: delegation ? { id: delegation.grant.principal, keyid: delegation.principalKeyid, provenance: "attested" as const } : { id: null, provenance: "claimed" as const },
      // a signature alone is the door's own check against a directory it fetched, which a reader of the receipt cannot repeat
      agent: { id: arrival.subject, provenance: delegation ? "attested" as const : signer ? "observed" as const : "claimed" as const },
      ...(delegation ? { delegation: { envelope: delegation.envelope, provenance: "attested" as const } } : {}),
      tool: { name: route, provenance: "observed" as const },
      request: { args, argsDigest: digestOf(args), provenance: "claimed" as const },
      facts,
      policy: { ...policy, provenance: "observed" as const },
    };
    const decision: DoorDecision = { receiptId, arrival, method, url, route, ...("relay" in norm ? { relay: norm.relay } : {}), body, head };
    // observe mode records the missing verdict in the arrival fact and relays, as it does a deny
    if (partnerRefusal && cfg.mode === "observe") console.error(`agent-custody door (observe mode): ${partnerRefusal}; not enforced, receipt ${receiptId}`);

    if (!forward) {
      decision.refused = { status: 403, execution: { status: "denied", reason: [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched", provenance: "observed" } };
    } else if (partnerRefusal && cfg.mode !== "observe") {
      decision.refused = { status: 503, execution: { status: "withheld", reason: `not relayed: ${partnerRefusal}`, provenance: "observed" } };
    } else if ("problem" in norm) {
      decision.refused = { status: 400, execution: { status: "withheld", reason: `the path was not relayed: ${norm.problem}`, provenance: "observed" } };
    } else if (body === null) {
      decision.refused = { status: 413, execution: { status: "withheld", reason: `the request body is larger than ${cfg.maxBodyBytes} bytes and was not relayed`, provenance: "observed" } };
    } else if (!SAFE_METHODS.has(method) || precommit.has("*") || precommit.has(route)) {
      // A request that can change something is committed to the log before it goes on, so that evidence of the side
      // effect exists before the side effect does. If the log will not take it, the request does not go on; in observe
      // mode it goes on and the missing authorization is printed.
      try {
        decision.authorization = await issuer.authorize(head);
      } catch (e) {
        if (cfg.mode === "observe") console.error(`agent-custody door (observe mode): the log did not commit the authorization for ${route}, receipt ${receiptId}; the request was relayed without it: ${String(e instanceof Error ? e.message : e)}`);
        else decision.refused = { status: 503, execution: { status: "withheld", reason: `the log did not commit the authorization, so the request was not relayed: ${String(e instanceof Error ? e.message : e)}`, provenance: "observed" } };
      }
    }
    return decision;
  }

  const mark = (d: DoorDecision, logPending: boolean): Record<string, string> => ({ [RECEIPT_HEADER]: d.receiptId, [CLASS_HEADER]: d.arrival.class, ...(logPending ? { "x-agent-custody-log-pending": "true" } : {}) });

  let inFlight = 0;
  let timer: ReturnType<typeof setInterval> | undefined;
  if (options.autoFlush) {
    const flush = () => void issuer.flushOutbox().catch((e: unknown) => console.error(`agent-custody door: outbox flush failed: ${e instanceof Error ? e.message : String(e)}`));
    flush();
    timer = setInterval(flush, 30_000);
    timer.unref?.();
  }

  return {
    keyid: issuer.keyid,
    policyDigest: () => currentPolicy().digest,
    // Each arrival holds its body (up to maxBodyBytes) in memory until it is decided. Past maxInFlight arrivals at once,
    // the next is answered 503 before its body is read: it is not decided, passed on, or receipted.
    admit: () => (inFlight >= cfg.maxInFlight ? false : (inFlight += 1, true)),
    release: () => void (inFlight -= 1),
    busy: () => json(503, { "retry-after": "1" }, { error: `the door is handling ${cfg.maxInFlight} requests; this one was not read, decided, or relayed. Retry` }),
    decide,
    consumed: (name, req, arrival) =>
      name === GRANT_HEADER || name === AGENT_HEADER || name === challengeHeader ||
      // the grant travelled in Authorization: it is the door's credential, not the origin's
      (name === "authorization" && arrival.grant !== "absent" && !req.headers[GRANT_HEADER]),
    async record(d, execution) {
      try {
        await issuer.issue({
          ...d.head,
          session: { id: null, toolUseId: null, provenance: "claimed" },
          model: { id: null, provenance: "claimed" },
          ...(d.authorization ? { authorization: d.authorization } : {}),
          execution,
        }, undefined, undefined, { deferLog: true });
        return { logPending: false };
      } catch (e) {
        if (e instanceof ReceiptPending) {
          console.error(`agent-custody door: ${e.message}`);
          return { logPending: true };
        }
        console.error(`agent-custody door: receipt ${d.receiptId} was not written: ${e instanceof Error ? e.message : String(e)}`);
        return null;
      }
    },
    mark,
    refusal(d, logPending) {
      const execution = d.refused!.execution as { status: "denied" | "withheld"; reason: string };
      // A refused arrival that could have passed a challenge is told how: the provider, the public site key, and the header
      if (execution.status === "denied") return json(403, mark(d, logPending), { error: "refused by the door's policy", reason: execution.reason, receipt: d.receiptId, ...(cfg.challenge && d.arrival.challenge?.outcome !== "passed" ? { challenge: { provider: cfg.challenge.provider, siteKey: cfg.challenge.siteKey, header: cfg.challenge.header } } : {}) });
      return json(d.refused!.status, mark(d, logPending), { error: "not relayed", reason: execution.reason, receipt: d.receiptId });
    },
    unrecorded(d, execution, notSent) {
      // The decision was carried out and the receipt of it could not be written. The client is told what happened
      // rather than "not relayed", which would invite a retry of a refund that went through.
      const outcome = execution.status === "executed" || execution.status === "failed" ? "the origin acted on the request; its answer is not relayed because there is no receipt of it. Do not retry" : execution.status === "error" ? (notSent ? "the origin could not be reached" : "the origin may have acted on the request. Do not retry") : "nothing was relayed";
      return json(500, { [CLASS_HEADER]: d.arrival.class }, { error: "the door could not record this request", outcome, receipt: d.receiptId });
    },
    flushOutbox: () => issuer.flushOutbox(),
    pendingReceipts: () => issuer.pending(),
    close() {
      if (timer) clearInterval(timer);
      rates.close();
    },
  };
}

export const sendAnswer = (res: ServerResponse, a: DoorAnswer) => {
  res.writeHead(a.status, a.headers);
  res.end(a.body);
};

/** The door as a reverse proxy: decides each arrival with the shared core, relays an allowed one to the origin, and receipts it before answering. */
export async function createDoorHost(cfg: DoorConfig, options: DoorOptions = {}): Promise<DoorHost> {
  if (cfg.authz) return createAuthzHost(cfg, options);
  if (!cfg.origin) throw new Error("the door proxy needs origin.url: the site it relays to, or authz: true to answer a proxy's authz checks. A config without either is for the door in-process (@agent-custody/receipts/door)");
  const originCfg = cfg.origin;
  const originHeaders: Record<string, string> = { ...(originCfg.headers ?? {}) };
  for (const [header, variable] of Object.entries(originCfg.headerEnv ?? {})) {
    const v = process.env[variable];
    if (!v) throw new Error(`origin: environment variable ${variable} is not set`);
    originHeaders[header] = v;
  }
  const origin = new URL(originCfg.url);
  const originPath = origin.pathname.replace(/\/$/, "");
  const f = options.fetch ?? fetch;
  const core = createDoorCore(cfg, options, "http");

  // Each arrival also holds the origin's answer (up to maxResponseBytes) in memory until it is answered.
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!core.admit()) {
      req.resume();
      return sendAnswer(res, core.busy());
    }
    try {
      await decideAndAnswer(req, res);
    } finally {
      core.release();
    }
  }

  async function decideAndAnswer(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const receiptId = randomUUID();
    res.setHeader(RECEIPT_HEADER, receiptId);
    const d = await core.decide(req, receiptId, (max) => readBody(req, max));
    const { arrival, method, url } = d;

    let execution: Execution | undefined = d.refused?.execution;
    let answer: { status: number; headers: Record<string, string | string[]>; body: Buffer } | undefined;
    // set when the relay failed before the request left the door; any other relay failure leaves the outcome unknown
    let notSent = false;
    if (!execution) {
      let upstream: Response | undefined;
      try {
        // The path is set on a copy of the origin's URL, never resolved against it: resolving `//evil.example/x` would
        // move the relay, with the origin's credentials, to another host.
        const target = new URL(origin);
        target.pathname = originPath + d.relay!;
        target.search = url.search;
        const out = new Headers();
        for (const [name, value] of Object.entries(req.headers)) {
          // `expect` is the client's conversation with the door, which Node answered; fetch refuses to carry it
          if (value === undefined || HOP_BY_HOP.has(name) || name === "host" || name === "expect" || name === "accept-encoding" || core.consumed(name, req, arrival)) continue;
          if (!cfg.trustProxy && (CLIENT_ADDRESS_HEADERS.has(name) || name.startsWith("x-forwarded-"))) continue;
          out.set(name, Array.isArray(value) ? value.join(", ") : value);
        }
        out.set("accept-encoding", "identity");
        // Behind a trusted proxy the chain it sent is kept and the socket's address appended, as any proxy does; otherwise
        // whatever the client wrote in these headers is replaced.
        const inbound = (name: string) => (cfg.trustProxy ? (Array.isArray(req.headers[name]) ? (req.headers[name] as string[]).join(", ") : req.headers[name] as string | undefined) : undefined);
        const socketAddress = req.socket.remoteAddress ?? "unknown";
        const chain = inbound("x-forwarded-for");
        out.set("x-forwarded-for", chain ? `${chain}, ${socketAddress}` : socketAddress);
        out.set("x-forwarded-host", inbound("x-forwarded-host") || req.headers.host || "");
        out.set("x-forwarded-proto", inbound("x-forwarded-proto") || "http");
        if (!cfg.trustProxy) out.set("x-real-ip", socketAddress);
        out.set(RECEIPT_HEADER, receiptId);
        out.set(CLASS_HEADER, arrival.class);
        for (const [h, v] of Object.entries(originHeaders)) out.set(h, v);
        upstream = await f(target, { method, headers: out, ...(method === "GET" || method === "HEAD" ? {} : { body: new Uint8Array(d.body!) }), redirect: "manual", signal: AbortSignal.timeout(originCfg.timeoutMs) });
        const got = await readStream(upstream.body, cfg.maxResponseBytes);
        const back: Record<string, string | string[]> = {};
        upstream.headers.forEach((v, k) => { if (!HOP_BY_HOP.has(k) && k !== "content-length" && k !== "content-encoding" && k !== "set-cookie") back[k] = v; });
        // every cookie the origin set, not the last one: `forEach` gives them one at a time under the same name
        const cookies = upstream.headers.getSetCookie();
        if (cookies.length) back["set-cookie"] = cookies;
        // A redirect to the origin's own host would take the client's next request around the door: it is rewritten to a
        // path on the door, which the client follows back through it, whatever the scheme or port. A path under the
        // origin's path loses that prefix; any other path, including one the parser normalised out of it (`/shop/../admin`),
        // is kept as it is, so the request still arrives at the door and meets its route and policy there.
        if (typeof back.location === "string") {
          try {
            const loc = new URL(back.location, target);
            if (loc.hostname === origin.hostname) {
              const inside = loc.pathname === originPath || loc.pathname.startsWith(`${originPath}/`);
              back.location = (inside ? loc.pathname.slice(originPath.length) || "/" : loc.pathname) + loc.search + loc.hash;
            }
          } catch { /* not a URL: relayed as the origin sent it */ }
        }
        const contentType = typeof back["content-type"] === "string" ? { contentType: back["content-type"] } : {};
        // The origin has answered either way, so the request happened: a response too large to relay is still recorded
        // as executed, by its size, so that nobody retries a refund on the strength of the 502 the client gets.
        const result = "body" in got
          ? { status: upstream.status, ...contentType, bodyBytes: got.body.length, bodyDigest: sha256Hex(got.body) }
          : { status: upstream.status, ...contentType, bodyBytes: got.bytes, bodyOversized: true };
        if ("body" in got) answer = { status: upstream.status, headers: back, body: got.body };
        execution = { status: upstream.status >= 500 ? "failed" : "executed", result, resultDigest: digestOf(result), provenance: "observed" };
      } catch (e) {
        // The request may have reached the origin unless the connection was refused or the host did not resolve: a
        // timeout while the origin works, a reset, or a body that stops after the headers all leave the outcome unknown,
        // and the client is told not to retry rather than that the origin could not be reached.
        const message = String(e instanceof Error ? e.message : e);
        notSent = !upstream && unreached(e);
        execution = { status: "error", error: notSent ? `the origin could not be reached: ${message}` : `the origin may have acted on the request${upstream ? ` (it answered ${upstream.status} and its body did not arrive)` : ""}: ${message}`, provenance: "observed" };
      }
    }

    const recorded = await core.record(d, execution);
    if (!recorded) return sendAnswer(res, core.unrecorded(d, execution, notSent));
    const mark = core.mark(d, recorded.logPending);
    switch (execution.status) {
      case "denied":
      case "withheld":
        return sendAnswer(res, core.refusal(d, recorded.logPending));
      case "error":
        return sendAnswer(res, notSent
          ? json(502, mark, { error: "the origin could not be reached", detail: execution.error, receipt: receiptId })
          : json(504, mark, { error: "the origin may have acted on the request; its answer did not arrive. Do not retry", detail: execution.error, receipt: receiptId }));
      default: {
        if (!answer) return sendAnswer(res, json(502, mark, { error: `the origin answered, but its response is larger than ${cfg.maxResponseBytes} bytes and was not relayed. Do not retry`, receipt: receiptId }));
        res.writeHead(answer.status, { ...answer.headers, ...mark });
        res.end(answer.body);
      }
    }
  }

  return {
    keyid: core.keyid,
    policyDigest: core.policyDigest,
    handle,
    flushOutbox: core.flushOutbox,
    pendingReceipts: core.pendingReceipts,
    async close() {
      core.close();
    },
  };
}

/**
 * The door behind nginx `auth_request` or Envoy `ext_authz`: decides each check about the original request with the
 * shared core, receipts the decision, and answers 200 with the receipt id and class, or the refusal. It relays nothing,
 * so the receipt records the decision, not the result: an allow is `withheld` with `AUTHZ_ALLOWED_REASON`.
 */
function createAuthzHost(cfg: DoorConfig, options: DoorOptions): DoorHost {
  const core = createDoorCore(cfg, options, "authz");

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // a check carries no body: the proxy holds the original's and relays it after the answer
    req.resume();
    if (!core.admit()) return sendAnswer(res, core.busy());
    try {
      await answerCheck(req, res);
    } finally {
      core.release();
    }
  }

  async function answerCheck(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // a check that does not say what it is checking is the proxy's misconfiguration, not an arrival: nothing to decide or receipt
    const original = authzTarget(req);
    if ("problem" in original) return sendAnswer(res, json(400, {}, { error: original.problem }));
    const d = await core.decide(original, randomUUID(), null);
    const execution: Execution = d.refused?.execution ?? { status: "withheld", reason: d.head.policy?.decision === "allow" ? AUTHZ_ALLOWED_REASON : `${AUTHZ_ALLOWED_REASON}. Observe mode: the policy denied it and the denial was not enforced`, provenance: "observed" };
    const recorded = await core.record(d, execution);
    if (!recorded) return sendAnswer(res, core.unrecorded(d, execution, true));
    if (d.refused) return sendAnswer(res, core.refusal(d, recorded.logPending));
    return sendAnswer(res, json(200, core.mark(d, recorded.logPending), { allowed: true, receipt: d.receiptId }));
  }

  return {
    keyid: core.keyid,
    policyDigest: core.policyDigest,
    handle,
    flushOutbox: core.flushOutbox,
    pendingReceipts: core.pendingReceipts,
    async close() {
      core.close();
    },
  };
}

export interface DoorServerOptions {
  port: number;
  host?: string;
  log?: (message: string) => void;
}

export interface RunningDoor {
  url: string;
  close(): Promise<void>;
}

/** Serves a door host over plain HTTP. Bind to loopback or put TLS in front. `GET /.well-known/agent-custody-door` answers the key id and the policy digest. */
export async function serveDoor(host: DoorHost, opts: DoorServerOptions): Promise<RunningDoor> {
  const bind = opts.host ?? "127.0.0.1";
  const log = opts.log ?? ((m) => console.error(m));
  const server: HttpServer = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/.well-known/agent-custody-door") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ keyid: host.keyid, policyDigest: host.policyDigest(), version: DOOR_VERSION, pendingReceipts: host.pendingReceipts() }));
      return;
    }
    host.handle(req, res).catch((e: unknown) => {
      log(`agent-custody door: ${e instanceof Error ? e.message : String(e)}`);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "the door failed before it could answer; whether the origin acted on the request is unknown", receipt: res.getHeader(RECEIPT_HEADER) ?? null }));
      } else res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(opts.port, bind, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://${bind}:${port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

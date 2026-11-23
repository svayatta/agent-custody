// The door as a Cloudflare Worker: the same decision core as the Node door (door-core.ts), with its I/O from the Worker's
// bindings. The signing key and the log token are secrets; the door config, the policy, the origin, and the log are
// variables; receipts go to an R2 bucket and to the log over HTTP; Web Bot Auth nonces go to a Durable Object. Built for workerd by scripts/build-door-worker.ts,
// deployed from deploy/door/cloudflare-worker/.
import { createPrivateKey, createPublicKey } from "node:crypto";
import { DoorConfigSchema, type DoorConfig } from "./config.ts";
import { keyidOf, publicKeyFromPem, type KeyPair, type PublicKeyRef } from "./crypto.ts";
import { createDoorCoreWith, DOOR_VERSION, jsonAnswer, readStream, RECEIPT_HEADER, relayedAnswer, relayToOrigin, type DoorAnswer, type DoorCore, type DoorIO, type DoorRequest, type ObservedFact, type OriginTarget } from "./door-core.ts";
import { FORM_SCRIPT_PATH, formScript } from "./door-form.ts";
import type { TlsObservation } from "./door-signals.ts";
import { httpLog } from "./log-http.ts";
import { createObjectIssuer, type ObjectStore } from "./object-issuer.ts";
import type { NonceStore } from "./web-bot-auth.ts";

/** What the Worker needs of an R2 bucket binding. */
export interface R2BucketLike {
  put(key: string, value: string): Promise<unknown>;
  get(key: string): Promise<{ text(): Promise<string> } | null>;
  list(options: { prefix: string; cursor?: string }): Promise<{ objects: { key: string }[]; truncated: boolean; cursor?: string }>;
  delete(key: string): Promise<void>;
}

/** What the Worker needs of a Durable Object namespace binding. */
export interface DurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: never): { fetch(url: string, init: RequestInit): Promise<Response> };
}

/** What a Durable Object is given of its own state. */
export interface DurableObjectStateLike {
  storage: {
    get(key: string): Promise<unknown>;
    put(key: string, value: unknown): Promise<void>;
    setAlarm(at: number): Promise<void>;
    deleteAll(): Promise<void>;
  };
  blockConcurrencyWhile<T>(f: () => Promise<T>): Promise<T>;
}

/** The Worker's bindings. Any other string binding is a secret the door config may name (`challenge.secretEnv`, `captureKeyEnv`, `origin.headerEnv`). */
export interface DoorWorkerEnv {
  /** the door config as JSON: routes, policy mode, precommit, capture, challenge, webBotAuth, limits. Not the fields that name files */
  DOOR_CONFIG: string;
  /** the Cedar policy text */
  DOOR_POLICY: string;
  /** where allowed requests go */
  ORIGIN_URL: string;
  /** the hosted log (or any agent-custody log) */
  LOG_URL: string;
  /** the log's public keys, SPKI PEM, pinned: every append's answer is checked against them before a request is relayed */
  LOG_KEYS: string;
  /** the tenant's log id, which every tree head must name */
  LOG_ID?: string;
  /** "true": send the log leaf hashes only */
  LOG_HASH_ONLY?: string;
  /** principal keys whose grants are a passport, SPKI PEM */
  TRUSTED_PRINCIPAL_KEYS?: string;
  /** a JSON array of revoked grant digests, as in a gateway's or door's `revokedGrants` file */
  REVOKED_GRANTS?: string;
  /** secret: the door's signing key, PKCS8 PEM (`agent-custody keygen`) */
  DOOR_KEY: string;
  /** secret: the log token */
  LOG_TOKEN?: string;
  /** the bucket the receipt bundles, authorizations, salts, and outbox go to */
  RECEIPTS: R2BucketLike;
  /** the `DoorNonce` Durable Object namespace that remembers Web Bot Auth nonces for every isolate; needed with `webBotAuth` */
  NONCES?: DurableObjectNamespaceLike;
  [binding: string]: unknown;
}

/** What a request's `cf` object may carry: Bot Management, only where the zone has it, and what Cloudflare saw of the TLS handshake. */
interface CfProperties {
  botManagement?: { score?: unknown; verifiedBot?: unknown; ja4?: unknown };
  tlsVersion?: unknown;
  tlsCipher?: unknown;
  tlsClientExtensionsSha1?: unknown;
  tlsClientHelloLength?: unknown;
  httpProtocol?: unknown;
  asn?: unknown;
  asOrganization?: unknown;
}

/** the fact the Worker records when Cloudflare Bot Management scored the request */
export const CLOUDFLARE_FACT = "cloudflare";

/** Config fields that name files or a Node door's modes: in a Worker each comes from a binding, or does not apply. */
const NOT_IN_A_WORKER: Record<string, string> = {
  identity: "the signing key is the DOOR_KEY secret",
  policyFile: "the policy is the DOOR_POLICY variable",
  receiptsDir: "receipts go to the RECEIPTS bucket",
  logFile: "the log is LOG_URL",
  log: "the log is LOG_URL, LOG_KEYS, LOG_ID, LOG_TOKEN",
  trustedPrincipalKeys: "trusted principal keys are the TRUSTED_PRINCIPAL_KEYS variable",
  revokedGrants: "revoked grants are the REVOKED_GRANTS variable",
  authz: "a Worker relays; nginx and Envoy ask a Node door",
  trustProxy: "the Worker reads the client's address from Cloudflare (CF-Connecting-IP)",
  partner: "a partner engine needs its verdict key on disk; not supported in a Worker yet",
  otel: "export is not supported in a Worker yet",
  splunk: "export is not supported in a Worker yet",
};

/** Every SPKI PEM block in a variable. */
export function pemKeys(text: string | undefined): PublicKeyRef[] {
  return [...(text ?? "").matchAll(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/g)].map((m) => publicKeyFromPem(m[0]));
}

/**
 * The door config from the Worker's bindings, checked by the same schema as a Node door's. The fields that name files
 * are refused in DOOR_CONFIG, and the placeholders put in their place say where the Worker gets each one; nothing reads them.
 */
export function workerDoorConfig(env: DoorWorkerEnv): DoorConfig {
  for (const name of ["DOOR_CONFIG", "DOOR_POLICY", "ORIGIN_URL", "LOG_URL", "LOG_KEYS", "DOOR_KEY"] as const) if (typeof env[name] !== "string" || !env[name]) throw new Error(`the Worker needs ${name}`);
  if (!env.RECEIPTS) throw new Error("the Worker needs the RECEIPTS bucket binding");
  const raw = JSON.parse(env.DOOR_CONFIG) as Record<string, unknown>;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("DOOR_CONFIG must be a JSON object");
  for (const [field, why] of Object.entries(NOT_IN_A_WORKER)) if (Object.hasOwn(raw, field)) throw new Error(`DOOR_CONFIG has ${field}, which a Worker does not take: ${why}`);
  const origin = (raw.origin ?? {}) as Record<string, unknown>;
  if (Object.hasOwn(origin, "url")) throw new Error("DOOR_CONFIG has origin.url: the origin is the ORIGIN_URL variable");
  if (raw.behaviour && typeof raw.behaviour === "object" && Object.hasOwn(raw.behaviour, "tlsHeader")) throw new Error("DOOR_CONFIG has behaviour.tlsHeader, which a Worker does not take: the Worker reads the TLS fingerprint from Cloudflare (request.cf)");
  if (raw.webBotAuth && !env.NONCES) throw new Error("DOOR_CONFIG has webBotAuth, which needs the NONCES Durable Object binding: one isolate's memory cannot refuse a signature replayed to another");
  return DoorConfigSchema.parse({
    ...raw,
    identity: { keyFile: "(the DOOR_KEY secret)" },
    policyFile: "(the DOOR_POLICY variable)",
    receiptsDir: "(the RECEIPTS bucket)",
    log: { url: env.LOG_URL, keys: ["(the LOG_KEYS variable)"], ...(env.LOG_ID ? { logId: env.LOG_ID } : {}) },
    origin: { ...origin, url: env.ORIGIN_URL },
  });
}

/** An R2 bucket as the object store the issuer writes to; a listing follows the bucket's cursor to the end. */
export function r2Store(bucket: R2BucketLike): ObjectStore {
  return {
    put: async (key, text) => void (await bucket.put(key, text)),
    get: async (key) => (await bucket.get(key))?.text() ?? null,
    async list(prefix) {
      const keys: string[] = [];
      let cursor: string | undefined;
      do {
        const page = await bucket.list({ prefix, ...(cursor ? { cursor } : {}) });
        keys.push(...page.objects.map((o) => o.key));
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);
      return keys;
    },
    delete: (key) => bucket.delete(key),
  };
}

/** how long the door waits for the nonce store before it calls a signature `unavailable` */
const NONCE_STORE_TIMEOUT_MS = 3000;

/**
 * Web Bot Auth nonces in Durable Objects, one object per `<agent> <keyid> <nonce>`: every isolate that claims a key
 * reaches the same object, wherever it runs, and that object answers one claim at a time. An object that cannot be
 * reached, or answers anything but a claim, throws, and the verifier calls the signature `unavailable`.
 */
export function durableNonceStore(ns: DurableObjectNamespaceLike, timeoutMs = NONCE_STORE_TIMEOUT_MS): NonceStore {
  return {
    async claim(key, until) {
      const stub = ns.get(ns.idFromName(key) as never);
      const res = await stub.fetch("https://door-nonce/claim", { method: "POST", body: JSON.stringify({ until }), signal: AbortSignal.timeout(timeoutMs) });
      const body = (await res.json().catch(() => null)) as { claim?: unknown } | null;
      if (!res.ok || (body?.claim !== "claimed" && body?.claim !== "replayed")) throw new Error(`the nonce object answered ${res.status}${body?.claim === undefined ? "" : ` ${String(body.claim)}`}`);
      return body.claim;
    },
  };
}

/**
 * how much longer than the isolate's deadline the object holds a nonce: `until` is on the isolate's clock and the object
 * reads its own, so an object whose clock runs ahead would otherwise forget a nonce the isolate still accepts
 */
const NONCE_CLOCK_MARGIN_MS = 60_000;

/**
 * The Durable Object behind `durableNonceStore`: it holds one nonce until the signature it came with could no longer be
 * accepted, and a minute more, then an alarm empties it. Claims are answered one at a time, so of two arrivals with one
 * nonce, one is `claimed` and the other `replayed`.
 */
export class DoorNonce {
  state: DurableObjectStateLike;
  constructor(state: DurableObjectStateLike) {
    this.state = state;
  }
  async fetch(request: Request): Promise<Response> {
    const { until } = (await request.json()) as { until?: unknown };
    if (typeof until !== "number" || !Number.isFinite(until)) return Response.json({ error: "until must be a time in milliseconds" }, { status: 400 });
    const claim = await this.state.blockConcurrencyWhile(async () => {
      const held = await this.state.storage.get("until");
      if (typeof held === "number" && held > Date.now()) return "replayed";
      await this.state.storage.put("until", until + NONCE_CLOCK_MARGIN_MS);
      await this.state.storage.setAlarm(until + NONCE_CLOCK_MARGIN_MS);
      return "claimed";
    });
    return Response.json({ claim });
  }
  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}

/** The door's I/O from the Worker's bindings: the key from a secret, the policy and keys from variables, receipts to R2 and the log. */
export function workerDoorIO(env: DoorWorkerEnv, f: typeof fetch): DoorIO {
  const privateKey = createPrivateKey(env.DOOR_KEY);
  const publicKey = createPublicKey(privateKey);
  const key: KeyPair = { privateKey, publicKey, keyid: keyidOf(publicKey) };
  const logKeys = pemKeys(env.LOG_KEYS);
  if (!logKeys.length) throw new Error("LOG_KEYS holds no public key");
  const list = env.REVOKED_GRANTS ? (JSON.parse(env.REVOKED_GRANTS) as unknown) : [];
  if (!Array.isArray(list)) throw new Error("REVOKED_GRANTS must be a JSON array of grant digests");
  const revoked = new Set(list.filter((d): d is string => typeof d === "string"));
  const sink = httpLog(env.LOG_URL, { keys: logKeys, fetch: f, ...(env.LOG_TOKEN ? { token: env.LOG_TOKEN } : {}), ...(env.LOG_ID ? { logId: env.LOG_ID } : {}), ...(env.LOG_HASH_ONLY === "true" ? { hashOnly: true } : {}) });
  const store = r2Store(env.RECEIPTS);
  return {
    key,
    trustedPrincipalKeys: pemKeys(env.TRUSTED_PRINCIPAL_KEYS),
    readPolicy: () => ({ text: env.DOOR_POLICY, key: "DOOR_POLICY" }),
    policySource: "the DOOR_POLICY variable",
    revoked: (digests) => (!digests.some((d) => revoked.has(d)) ? null : revoked.has(digests[0]!) ? "the grant has been revoked" : "a grant above it in its chain has been revoked"),
    secret: (name) => (typeof env[name] === "string" ? (env[name] as string) : undefined),
    issuer: (capture) => createObjectIssuer(key, store, sink, { capture }),
    fetch: f,
    timers: false,
    ...(env.NONCES ? { nonceStore: durableNonceStore(env.NONCES) } : {}),
  };
}

/**
 * The request as the door reads it: the target, the headers as fetch joins them, and the client's address as Cloudflare
 * gives it. The host is the request URL's, which Cloudflare builds from the client's `Host`: it is the authority a Web
 * Bot Auth signature covers. Cloudflare's own headers (`cf-*`, `cdn-loop`) are its, not the client's: they are not
 * relayed, and `cdn-loop` sent on to a subrequest would count as a loop.
 */
export function doorRequestOf(request: Request): DoorRequest {
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => { if (!k.startsWith("cf-") && k !== "cdn-loop") headers[k] = v; });
  headers.host = url.host;
  const cf = (request as { cf?: CfProperties }).cf;
  const tls = cloudflareTls(cf);
  // what every zone gets of the connection and of the address's network; the door's signal code checks their shape
  const http = typeof cf?.httpProtocol === "string" && cf.httpProtocol.length <= 16 ? cf.httpProtocol : undefined;
  const network = { ...(typeof cf?.asn === "number" ? { asn: cf.asn } : {}), ...(typeof cf?.asOrganization === "string" ? { organization: cf.asOrganization.slice(0, 256) } : {}) };
  return { method: request.method, url: url.pathname + url.search, headers, transport: { secure: url.protocol === "https:", ...(tls ? { tls } : {}), ...(http ? { http } : {}), ...(Object.keys(network).length ? { network } : {}) }, socket: { remoteAddress: request.headers.get("cf-connecting-ip") ?? undefined } };
}

/**
 * What Cloudflare saw of the client's TLS handshake, for the door's TLS fingerprint: the JA4 where the zone has Bot
 * Management, and the version, the cipher, the extensions hash, and the ClientHello length that every zone gets. Only
 * strings of a bounded length are taken; the door's signal code checks their shape.
 */
export function cloudflareTls(cf: CfProperties | undefined): TlsObservation | undefined {
  if (!cf || typeof cf !== "object") return undefined;
  const text = (v: unknown) => (typeof v === "string" && v !== "" && v.length <= 64 ? v : undefined);
  const ja4 = text(cf.botManagement?.ja4);
  const negotiated = text(cf.tlsVersion);
  const cipher = text(cf.tlsCipher);
  const extensionsSha1 = text(cf.tlsClientExtensionsSha1);
  const length = typeof cf.tlsClientHelloLength === "number" ? cf.tlsClientHelloLength : /^\d{1,5}$/.test(text(cf.tlsClientHelloLength) ?? "") ? Number(cf.tlsClientHelloLength) : undefined;
  const out: TlsObservation = { ...(ja4 ? { ja4 } : {}), ...(negotiated ? { negotiated } : {}), ...(cipher ? { cipher } : {}), ...(extensionsSha1 ? { extensionsSha1 } : {}), ...(length !== undefined ? { helloLength: length } : {}) };
  return Object.keys(out).length ? out : undefined;
}

/** Cloudflare Bot Management's score and verified-bot flag, when the zone has it and they are what Cloudflare documents; nothing otherwise. Cloudflare does not sign them: they enter as observed. */
export function cloudflareFacts(cf: CfProperties | undefined): Record<string, ObservedFact> {
  const bm = cf?.botManagement;
  if (!bm || !Number.isSafeInteger(bm.score) || typeof bm.verifiedBot !== "boolean") return {};
  return { [CLOUDFLARE_FACT]: { tool: "cloudflare.botManagement", value: { score: bm.score as number, verifiedBot: bm.verifiedBot } } };
}

const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

function toResponse(a: { status: number; headers: Record<string, string | string[]>; body: Buffer | string }): Response {
  const headers = new Headers();
  for (const [k, v] of Object.entries(a.headers)) for (const one of Array.isArray(v) ? v : [v]) headers.append(k, one);
  return new Response(NULL_BODY_STATUS.has(a.status) ? null : typeof a.body === "string" ? a.body : new Uint8Array(a.body), { status: a.status, headers });
}

const answer = (a: DoorAnswer) => toResponse(a);

interface Door {
  core: DoorCore;
  cfg: DoorConfig;
  target: Omit<OriginTarget, "proto">;
}

export interface DoorWorkerOptions {
  /** the fetch for the origin, the log, the challenge provider, and Web Bot Auth directories; the Worker's own by default */
  fetch?: typeof fetch;
}

/**
 * The Worker: `fetch` decides, relays or refuses, and receipts each request; `scheduled` (a cron trigger) appends the
 * receipts whose log append was pending. The door is built on the first request of an isolate from that request's
 * bindings, and built again on the next request if that failed, so a config error answers 500 with the reason and
 * relays nothing.
 */
export function createDoorWorker(options: DoorWorkerOptions = {}) {
  let door: Door | undefined;
  const build = (env: DoorWorkerEnv): Door => {
    if (door) return door;
    const cfg = workerDoorConfig(env);
    const f = options.fetch ?? ((input, init) => fetch(input, init));
    const core = createDoorCoreWith(cfg, workerDoorIO(env, f), "cloudflare-worker");
    const headers: Record<string, string> = { ...(cfg.origin!.headers ?? {}) };
    for (const [header, binding] of Object.entries(cfg.origin!.headerEnv ?? {})) {
      const v = env[binding];
      if (typeof v !== "string" || !v) throw new Error(`origin: the secret ${binding} is not set`);
      headers[header] = v;
    }
    door = { core, cfg, target: { url: new URL(cfg.origin!.url), headers, timeoutMs: cfg.origin!.timeoutMs } };
    return door;
  };

  return {
    async fetch(request: Request, env: DoorWorkerEnv): Promise<Response> {
      let d: Door;
      try {
        d = build(env);
      } catch (e) {
        console.error(`agent-custody door: the Worker cannot serve: ${e instanceof Error ? e.message : String(e)}`);
        return answer(jsonAnswer(500, {}, { error: "the door is not configured, so nothing was relayed", detail: e instanceof Error ? e.message : String(e) }));
      }
      const { core, cfg } = d;
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/.well-known/agent-custody-door") return answer(jsonAnswer(200, {}, { keyid: core.keyid, policyDigest: core.policyDigest(), version: DOOR_VERSION, pendingReceipts: core.pendingReceipts() }));
      if (request.method === "GET" && url.pathname === FORM_SCRIPT_PATH) {
        if (!cfg.challenge) return answer(jsonAnswer(404, {}, { error: "this door has no challenge configured, so it has no form protector" }));
        return new Response(formScript(cfg.challenge, !!cfg.behaviour), { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=300", "x-content-type-options": "nosniff" } });
      }
      if (!core.admit()) return answer(core.busy());
      const receiptId = crypto.randomUUID();
      try {
        const req = doorRequestOf(request);
        const decision = await core.decide(req, receiptId, (max) => readStream(request.body, max), undefined, cloudflareFacts((request as { cf?: CfProperties }).cf));
        const relayed = await relayToOrigin(core, cfg, decision, req, { ...d.target, proto: url.protocol.slice(0, -1) }, options.fetch ?? ((input, init) => fetch(input, init)));
        const recorded = await core.record(decision, relayed.execution);
        if (!recorded) return answer(core.unrecorded(decision, relayed.execution, relayed.notSent));
        return toResponse(relayedAnswer(core, cfg, decision, relayed, recorded.logPending));
      } catch (e) {
        console.error(`agent-custody door: ${e instanceof Error ? e.message : String(e)}`);
        return answer(jsonAnswer(500, { [RECEIPT_HEADER]: receiptId }, { error: "the door failed before it could answer; whether the origin acted on the request is unknown", receipt: receiptId }));
      } finally {
        core.release();
      }
    },
    async scheduled(_event: unknown, env: DoorWorkerEnv, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<void> {
      const d = build(env);
      ctx.waitUntil(d.core.flushOutbox().then((r) => { if (r.sent || r.pending || r.error) console.error(`agent-custody door: outbox: ${r.sent} sent, ${r.pending} pending${r.error ? `; ${r.error}` : ""}`); }));
    },
  };
}

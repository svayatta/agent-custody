// The door: a reverse proxy in front of a business's own HTTP surface, where the gateway is a proxy in front of an
// agent's tools. Every arrival, a browser, an API client, or an agent, is classified by what it presented, decided by
// the Cedar policy for its route, forwarded to the origin or refused, and receipted either way. Nothing here detects
// an agent: `unknown` means nothing was presented, `claimed` means something was asserted and could not be checked,
// and `verified` means a grant signed by a trusted principal names this agent for this route. The same key, policy
// language, issuer, log, and verifier as the gateway; the receipt's issuer kind is `door`.
import { randomUUID } from "node:crypto";
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { DoorConfig, DoorRouteConfig } from "./config.ts";
import { captureKeyFrom } from "./capture.ts";
import { digestOf, loadPrivateKey, loadPublicKey, sha256Hex, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { decodeDelegation, delegationValidAt, verifyDelegation, type Delegation } from "./delegation.ts";
import { parseGrantHeader, GRANT_HEADER } from "./gateway-http.ts";
import { createIssuer, ReceiptPending, type FlushResult } from "./issue.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { openExporter, type ReceiptExporter } from "./otel.ts";
import { evaluate, hasPermitRule, policyDigest, policyParseErrors, type PolicyDecision } from "./policy.ts";
import type { FactRecord, ReceiptPredicate } from "./receipt.ts";

export const DOOR_VERSION = "0.1.0";
/** on every answer the door gives: the receipt that records the decision */
export const RECEIPT_HEADER = "x-agent-custody-receipt";
/** on every answer: `verified`, `claimed`, or `unknown`, what the door made of the arrival */
export const CLASS_HEADER = "x-agent-custody-class";
/** the fact the door records for every arrival, and the policy reads as `context.facts.arrival` */
export const ARRIVAL_FACT = "arrival";
/** the header an agent may use to name itself without a grant; recorded as claimed, never checked */
export const AGENT_HEADER = "x-agent-custody-agent";

export type ArrivalClass = "verified" | "claimed" | "unknown";

/** What the door observed about one arrival. Every field is the door's own observation; none is the caller's claim about itself except `declared`, which says so. */
export interface Arrival {
  class: ArrivalClass;
  /** the agent named in a verified grant, else the name the caller declared, else "unknown" */
  subject: string;
  /** what became of the grant header: a trusted grant in scope for this route, one out of scope, one that did not verify, or none */
  grant: "verified" | "out-of-scope" | "invalid" | "absent";
  grantError?: string;
  /** an RFC 9421 `Signature-Input` header was present; the door does not check it yet */
  signature: boolean;
  /** the agent name from the `x-agent-custody-agent` header, when sent; a claim */
  declared?: string;
  remote: string;
  method: string;
  path: string;
  route: string;
}

export interface Classified {
  arrival: Arrival;
  /** set when the arrival is verified: the grant, as presented */
  delegation?: { envelope: Envelope; grant: Delegation; principalKeyid: string };
}

const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"]);
/** request headers the receipt records in clear; everything else is relayed and not recorded */
const RECORDED_HEADERS = ["user-agent", "content-type", "accept", "host"];
/** a JSON body up to this size is recorded in the receipt's arguments; a larger or non-JSON body is recorded by digest and size only */
const RECORDED_BODY_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

/** The route an arrival falls under: the first configured route whose methods and path match, else the unmatched name. */
export function matchRoute(routes: DoorRouteConfig[], unmatched: string, method: string, pathname: string): string {
  for (const r of routes) {
    if (r.methods && !(r.methods as string[]).includes(method)) continue;
    if (r.path === "*" || r.path === pathname || (r.path.endsWith("/*") && (pathname === r.path.slice(0, -2) || pathname.startsWith(r.path.slice(0, -1))))) return r.name;
  }
  return unmatched;
}

/** The arrival's address: the socket's, or with trustProxy the first address a proxy appended. */
export function remoteOf(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    const first = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim();
    if (first) return first;
  }
  return req.socket.remoteAddress ?? "unknown";
}

/**
 * What the arrival presented, checked where it can be. A grant signed by a trusted principal, in its window, naming this
 * route among its scopes, makes the arrival `verified` and its principal attested. A grant that is out of scope, expired,
 * or signed by a stranger leaves the arrival `claimed`: it asserted an identity the door could not accept for this route.
 * An `x-agent-custody-agent` header or an HTTP signature header alone is `claimed`. Nothing at all is `unknown`.
 */
export function classifyArrival(req: IncomingMessage, trusted: PublicKeyRef[], route: string, trustProxy: boolean, at: string): Classified {
  const url = new URL(req.url ?? "/", "http://door");
  const method = (req.method ?? "GET").toUpperCase();
  const declaredRaw = req.headers[AGENT_HEADER];
  const declared = typeof declaredRaw === "string" && declaredRaw.trim() ? declaredRaw.trim().slice(0, 200) : undefined;
  const signature = typeof req.headers["signature-input"] === "string";
  const base = { signature, ...(declared ? { declared } : {}), remote: remoteOf(req, trustProxy), method, path: url.pathname, route };
  const envelope = parseGrantHeader(req);
  if (!envelope) {
    const claimed = !!declared || signature;
    return { arrival: { class: claimed ? "claimed" : "unknown", subject: declared ?? "unknown", grant: "absent", ...base } };
  }
  const checked = verifyDelegation(envelope, trusted);
  const asserted = decodeDelegation(envelope)?.agent;
  const subject = declared ?? asserted ?? "unknown";
  if (!checked.ok) return { arrival: { class: "claimed", subject, grant: "invalid", grantError: checked.error, ...base } };
  const grant = checked.delegation;
  if (!delegationValidAt(grant, at)) return { arrival: { class: "claimed", subject: grant.agent, grant: "invalid", grantError: "the grant is outside its validity window", ...base } };
  if (!grant.scopes.includes(route)) return { arrival: { class: "claimed", subject: grant.agent, grant: "out-of-scope", grantError: `route "${route}" is not in the grant's scopes`, ...base } };
  return { arrival: { class: "verified", subject: grant.agent, grant: "verified", ...base }, delegation: { envelope, grant, principalKeyid: checked.keyid } };
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

function readBody(req: IncomingMessage, max: number): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) {
        resolve(null);
        req.removeAllListeners("data");
        req.resume();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function queryOf(url: URL): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of url.searchParams) {
    const prior = out[k];
    out[k] = prior === undefined ? v : Array.isArray(prior) ? [...prior, v] : [prior, v];
  }
  return out;
}

export async function createDoorHost(cfg: DoorConfig, options: DoorOptions = {}): Promise<DoorHost> {
  const key = loadPrivateKey(cfg.identity.keyFile);
  const trusted = cfg.trustedPrincipalKeys.map(loadPublicKey);
  const captureKey = cfg.captureKeyEnv ? captureKeyFrom(process.env[cfg.captureKeyEnv] ?? (() => { throw new Error(`capture key: environment variable ${cfg.captureKeyEnv} is not set`); })()) : undefined;
  for (const [route, rule] of Object.entries(cfg.capture ?? {})) {
    for (const side of [rule.args, rule.result, rule.facts]) if (side?.mode === "encrypted" && !captureKey) throw new Error(`capture for ${route} uses mode encrypted, which needs captureKeyEnv`);
  }
  const originHeaders: Record<string, string> = { ...(cfg.origin.headers ?? {}) };
  for (const [header, variable] of Object.entries(cfg.origin.headerEnv ?? {})) {
    const v = process.env[variable];
    if (!v) throw new Error(`origin: environment variable ${variable} is not set`);
    originHeaders[header] = v;
  }
  const origin = new URL(cfg.origin.url);
  const f = options.fetch ?? fetch;
  const sink = options.log ?? openLog(cfg, key);
  const issuer = createIssuer(key, cfg.receiptsDir, sink, { exporter: options.exporter ?? openExporter(cfg), capture: { rules: cfg.capture, key: captureKey } });
  const issuedBy = { kind: "door" as const, keyid: issuer.keyid, version: DOOR_VERSION, framework: "http" };

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

  const json = (res: ServerResponse, status: number, headers: Record<string, string>, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
    res.end(JSON.stringify(body));
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const receiptId = randomUUID();
    const timestamp = new Date().toISOString();
    const url = new URL(req.url ?? "/", "http://door");
    const method = (req.method ?? "GET").toUpperCase();
    const route = matchRoute(cfg.routes, cfg.unmatchedRoute, method, url.pathname);
    const { arrival, delegation } = classifyArrival(req, trusted, route, !!cfg.trustProxy, timestamp);
    const { text: policyText, digest: pDigest } = currentPolicy();

    const body = await readBody(req, cfg.maxBodyBytes);
    const headers: Record<string, string> = {};
    for (const name of RECORDED_HEADERS) {
      const v = req.headers[name];
      if (typeof v === "string") headers[name] = v;
    }
    const contentType = req.headers["content-type"] ?? "";
    let recordedBody: unknown;
    if (body && body.length > 0 && body.length <= RECORDED_BODY_BYTES && /^application\/json\b/i.test(contentType)) {
      try { recordedBody = JSON.parse(body.toString("utf8")); } catch { recordedBody = undefined; }
    }
    const args: Record<string, unknown> = {
      method,
      path: url.pathname,
      query: queryOf(url),
      headers,
      ...(recordedBody !== undefined ? { body: recordedBody } : {}),
      bodyBytes: body ? body.length : 0,
      bodyDigest: sha256Hex(body ?? Buffer.alloc(0)),
    };
    const facts: Record<string, FactRecord> = { [ARRIVAL_FACT]: { tool: "door.arrival", args: {}, value: arrival, resultDigest: digestOf(arrival), provenance: "observed" } };

    let policy: PolicyDecision;
    try {
      policy = evaluate(policyText, {
        agentId: arrival.subject,
        tool: route,
        context: { args, facts: { [ARRIVAL_FACT]: arrival }, ...(delegation ? { grant: { principal: delegation.grant.principal, scopes: delegation.grant.scopes } } : {}) },
      });
    } catch (e) {
      policy = { decision: "deny", reasons: [], errors: [String(e instanceof Error ? e.message : e)], policyDigest: pDigest };
    }
    if (cfg.mode === "observe") policy = { ...policy, enforced: false };
    const forward = policy.decision === "allow" || policy.enforced === false;

    let execution: ReceiptPredicate["execution"];
    let answer: { status: number; headers: Record<string, string>; body: Buffer } | undefined;
    if (body === null) {
      execution = { status: "withheld", reason: `the request body is larger than ${cfg.maxBodyBytes} bytes and was not relayed`, provenance: "observed" };
    } else if (!forward) {
      execution = { status: "denied", reason: [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched", provenance: "observed" };
    } else {
      try {
        const target = new URL(url.pathname + url.search, origin);
        const out = new Headers();
        for (const [name, value] of Object.entries(req.headers)) {
          if (value === undefined || HOP_BY_HOP.has(name) || name === "host" || name === GRANT_HEADER || name === AGENT_HEADER || name === "accept-encoding") continue;
          // the grant travelled in Authorization: it is the door's credential, not the origin's
          if (name === "authorization" && arrival.grant !== "absent" && !req.headers[GRANT_HEADER]) continue;
          out.set(name, Array.isArray(value) ? value.join(", ") : value);
        }
        out.set("accept-encoding", "identity");
        out.set("x-forwarded-for", arrival.remote);
        out.set("x-forwarded-host", req.headers.host ?? "");
        out.set("x-forwarded-proto", "http");
        out.set(RECEIPT_HEADER, receiptId);
        out.set(CLASS_HEADER, arrival.class);
        for (const [h, v] of Object.entries(originHeaders)) out.set(h, v);
        const upstream = await f(target, { method, headers: out, ...(method === "GET" || method === "HEAD" ? {} : { body: new Uint8Array(body) }), redirect: "manual", signal: AbortSignal.timeout(cfg.origin.timeoutMs) });
        const relayed = Buffer.from(await upstream.arrayBuffer());
        if (relayed.length > MAX_RESPONSE_BYTES) throw new Error(`the origin's response is larger than ${MAX_RESPONSE_BYTES} bytes`);
        const back: Record<string, string> = {};
        upstream.headers.forEach((v, k) => { if (!HOP_BY_HOP.has(k) && k !== "content-length" && k !== "content-encoding") back[k] = v; });
        answer = { status: upstream.status, headers: back, body: relayed };
        const result = { status: upstream.status, ...(back["content-type"] ? { contentType: back["content-type"] } : {}), bodyBytes: relayed.length, bodyDigest: sha256Hex(relayed) };
        execution = { status: upstream.status >= 500 ? "failed" : "executed", result, resultDigest: digestOf(result), provenance: "observed" };
      } catch (e) {
        execution = { status: "error", error: String(e instanceof Error ? e.message : e), provenance: "observed" };
      }
    }

    let logPending = false;
    try {
      await issuer.issue({
        receiptId,
        timestamp,
        issuer: issuedBy,
        principal: delegation ? { id: delegation.grant.principal, keyid: delegation.principalKeyid, provenance: "attested" } : { id: null, provenance: "claimed" },
        agent: { id: arrival.subject, provenance: delegation ? "attested" : "claimed" },
        ...(delegation ? { delegation: { envelope: delegation.envelope, provenance: "attested" } } : {}),
        session: { id: null, toolUseId: null, provenance: "claimed" },
        model: { id: null, provenance: "claimed" },
        tool: { name: route, provenance: "observed" },
        request: { args, argsDigest: digestOf(args), provenance: "claimed" },
        facts,
        policy: { ...policy, provenance: "observed" },
        execution,
      }, undefined, undefined, { deferLog: true });
    } catch (e) {
      if (!(e instanceof ReceiptPending)) throw e;
      console.error(`agent-custody door: ${e.message}`);
      logPending = true;
    }

    const mark = { [RECEIPT_HEADER]: receiptId, [CLASS_HEADER]: arrival.class, ...(logPending ? { "x-agent-custody-log-pending": "true" } : {}) };
    switch (execution.status) {
      case "denied":
        return json(res, 403, mark, { error: "refused by the door's policy", reason: execution.reason, receipt: receiptId });
      case "withheld":
        return json(res, 413, mark, { error: "not relayed", reason: execution.reason, receipt: receiptId });
      case "error":
        return json(res, 502, mark, { error: "the origin could not be reached", detail: execution.error, receipt: receiptId });
      default: {
        res.writeHead(answer!.status, { ...answer!.headers, ...mark });
        res.end(answer!.body);
      }
    }
  }

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
    handle,
    flushOutbox: () => issuer.flushOutbox(),
    pendingReceipts: () => issuer.pending(),
    async close() {
      if (timer) clearInterval(timer);
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
        res.end(JSON.stringify({ error: "the door could not record this request, so it was not relayed" }));
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

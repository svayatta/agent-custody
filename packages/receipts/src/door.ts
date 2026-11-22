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
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { DoorConfig } from "./config.ts";
import { loadPrivateKey, loadPublicKey } from "./crypto.ts";
import { createIssuer, type FlushResult } from "./issue.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { FORM_SCRIPT_PATH, formScript } from "./door-form.ts";
import { createRevocationList } from "./revocation.ts";
import { openExporter, type ReceiptExporter } from "./otel.ts";
import { AUTHZ_ALLOWED_REASON, DOOR_VERSION, RECEIPT_HEADER, authzTarget, createDoorCoreWith, jsonAnswer as json, relayedAnswer, relayToOrigin, type BodyRead, type DoorAnswer, type DoorCore, type DoorIO, type Execution, type OriginTarget } from "./door-core.ts";

export * from "./door-core.ts";

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
  /** the form protector script, when the door has a challenge to protect forms with */
  formScript?(): string | null;
  close(): Promise<void>;
}

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

/**
 * The door's I/O from a config's files and the process environment: the key file, the trusted principal key files, the
 * policy file re-read when it changes, the revocation file re-read when it changes, and receipts written by the file
 * issuer to the receipts directory and the config's log.
 */
export function nodeDoorIO(cfg: DoorConfig, options: Omit<DoorOptions, "fetch"> & { fetch?: typeof fetch } = {}): DoorIO {
  const key = loadPrivateKey(cfg.identity.keyFile);
  const revocations = createRevocationList(cfg.revokedGrants);
  revocations.reload();
  return {
    key,
    trustedPrincipalKeys: cfg.trustedPrincipalKeys.map(loadPublicKey),
    // the bytes and the metadata come from one open file
    readPolicy() {
      const fd = openSync(cfg.policyFile, "r");
      try {
        const st = fstatSync(fd);
        return { text: readFileSync(fd, "utf8"), key: `${st.ino}:${st.mtimeMs}:${st.ctimeMs}:${st.size}` };
      } finally {
        closeSync(fd);
      }
    },
    policySource: cfg.policyFile,
    revoked(chainDigests) {
      try {
        revocations.reload();
      } catch (e) {
        // fail closed: a revocation list that cannot be read revokes every grant until it can
        return `the grant cannot be checked against the revocation list (${e instanceof Error ? e.message : String(e)})`;
      }
      if (!revocations.has(chainDigests)) return null;
      return revocations.has(chainDigests.slice(0, 1)) ? "the grant has been revoked" : "a grant above it in its chain has been revoked";
    },
    secret: (name) => process.env[name],
    issuer: (capture) => createIssuer(key, cfg.receiptsDir, options.log ?? openLog(cfg, key), { exporter: options.exporter ?? openExporter(cfg), capture }),
    fetch: options.fetch ?? fetch,
    timers: true,
  };
}

/** The decision loop for a door config, reading its files and the environment; `framework` is the receipt's `issuer.framework`. Throws when the config cannot be served. */
export function createDoorCore(cfg: DoorConfig, options: Omit<DoorOptions, "fetch"> & { fetch?: typeof fetch }, framework: string): DoorCore {
  return createDoorCoreWith(cfg, nodeDoorIO(cfg, options), framework, { autoFlush: options.autoFlush });
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
  const target: OriginTarget = { url: new URL(originCfg.url), headers: originHeaders, timeoutMs: originCfg.timeoutMs, proto: "http" };
  const f = options.fetch ?? fetch;
  const core = createDoorCore(cfg, options, "http");

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
    const relayed = await relayToOrigin(core, cfg, d, req, target, f);
    const recorded = await core.record(d, relayed.execution);
    if (!recorded) return sendAnswer(res, core.unrecorded(d, relayed.execution, relayed.notSent));
    const answer = relayedAnswer(core, cfg, d, relayed, recorded.logPending);
    res.writeHead(answer.status, answer.headers);
    res.end(answer.body);
  }

  return {
    keyid: core.keyid,
    policyDigest: core.policyDigest,
    handle,
    flushOutbox: core.flushOutbox,
    pendingReceipts: core.pendingReceipts,
    formScript: () => (cfg.challenge ? formScript(cfg.challenge, !!cfg.behaviour) : null),
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
    formScript: () => (cfg.challenge ? formScript(cfg.challenge, !!cfg.behaviour) : null),
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

/**
 * Serves a door host over plain HTTP. Bind to loopback or put TLS in front. `GET /.well-known/agent-custody-door` answers
 * the key id and the policy digest; with a challenge configured, `GET /.well-known/agent-custody-door/form.js` is the
 * form protector script.
 */
export async function serveDoor(host: DoorHost, opts: DoorServerOptions): Promise<RunningDoor> {
  const bind = opts.host ?? "127.0.0.1";
  const log = opts.log ?? ((m) => console.error(m));
  const server: HttpServer = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/.well-known/agent-custody-door") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ keyid: host.keyid, policyDigest: host.policyDigest(), version: DOOR_VERSION, pendingReceipts: host.pendingReceipts() }));
      return;
    }
    if (req.method === "GET" && (req.url ?? "").split("?")[0] === FORM_SCRIPT_PATH) {
      const script = host.formScript?.() ?? null;
      if (!script) {
        res.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ error: "this door has no challenge configured, so it has no form protector" }));
        return;
      }
      res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=300", "x-content-type-options": "nosniff" });
      res.end(script);
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

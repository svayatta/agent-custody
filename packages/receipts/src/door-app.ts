// The door in-process: the same decision loop as the proxy, run inside a Node site instead of in front of it. Express
// (or any Connect-style server) takes it as middleware, `app.use(door("door.json"))`; a fetch-style route handler, as
// Next.js App Router routes are, takes it as a wrapper, `export const POST = guard.route(handler)`. Neither framework is
// imported: the middleware is typed on `node:http` and the wrapper on the fetch `Request` and `Response`, so the receipts
// package depends on neither and works with any version that hands it those.
import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { loadDoorConfig, type DoorConfig } from "./config.ts";
import { digestOf } from "./crypto.ts";
import { CLASS_HEADER, RECEIPT_HEADER, createDoorCore, readBody, readStream, sendAnswer, type Arrival, type DoorAnswer, type DoorCore, type DoorDecision, type DoorOptions, type DoorRequest } from "./door.ts";
import type { FlushResult } from "./issue.ts";
import type { ReceiptPredicate } from "./receipt.ts";

type Execution = ReceiptPredicate["execution"];

/** The receipt's `issuer.framework` for an arrival the middleware decided */
export const MIDDLEWARE_FRAMEWORK = "node-middleware";
/** The receipt's `issuer.framework` for an arrival a wrapped route handler decided */
export const ROUTE_FRAMEWORK = "fetch-route";

export interface DoorAppOptions extends Omit<DoorOptions, "autoFlush"> {
  /** appends the outbox at start and every 30 seconds. Default true: the app is serving */
  autoFlush?: boolean;
}

/** A Connect-style middleware that is also the door's handle: one config, one key, one log, one rate count for the process. */
export interface InProcessDoor {
  (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void): void;
  /** wraps a fetch-style route handler (a Next.js App Router `GET` or `POST`): the handler runs only for an arrival the policy allows */
  route<R extends Request, C extends unknown[]>(handler: (req: R, ...rest: C) => Response | Promise<Response>): (req: R, ...rest: C) => Promise<Response>;
  keyid: string;
  policyDigest(): string;
  flushOutbox(): Promise<FlushResult>;
  pendingReceipts(): number;
  close(): void;
}

/** What a passed request's receipt records of the app's answer: its status, its content type, and the bytes the app wrote, by size and digest. */
function answered(status: number, contentType: unknown, bytes: number, digest: string): Execution {
  const result = { status, ...(typeof contentType === "string" ? { contentType } : {}), bodyBytes: bytes, bodyDigest: digest };
  return { status: status >= 500 ? "failed" : "executed", result, resultDigest: digestOf(result), provenance: "observed" };
}

const mayHaveActed = (what: string): Execution => ({ status: "error", error: `${what}; the app may have acted on the request`, provenance: "observed" });

/**
 * Makes a request whose body the door read readable again, so that what runs after the door (`express.json()`, a
 * multipart parser, `for await (const chunk of req)`) reads the bytes the door decided on. Only the members that read
 * the body move to the copy; every other event, `close` and `aborted` among them, stays on the request.
 */
function replayBody(req: IncomingMessage, body: Buffer): void {
  const copy = Readable.from(body.length ? [body] : []);
  const flow = new Set<string | symbol>(["data", "end", "readable", "pause", "resume"]);
  const target = req as unknown as Record<string | symbol, unknown>;
  for (const name of ["on", "addListener", "once", "prependListener", "prependOnceListener", "removeListener", "off"] as const) {
    const own = req[name].bind(req) as (event: string | symbol, listener: (...a: unknown[]) => void) => unknown;
    const moved = copy[name].bind(copy) as typeof own;
    target[name] = (event: string | symbol, listener: (...a: unknown[]) => void) => {
      (flow.has(event) ? moved : own)(event, listener);
      return req;
    };
  }
  for (const name of ["read", "pipe", "unpipe", "pause", "resume", "isPaused", "setEncoding"] as const) {
    const fn = (copy[name] as (...a: unknown[]) => unknown).bind(copy);
    target[name] = (...a: unknown[]) => {
      const r = fn(...a);
      return r === copy ? req : r;
    };
  }
  target[Symbol.asyncIterator] = () => copy[Symbol.asyncIterator]();
  Object.defineProperty(req, "readable", { configurable: true, get: () => copy.readable });
  Object.defineProperty(req, "readableEnded", { configurable: true, get: () => copy.readableEnded });
}

/** The request as the app receives it: the door's credentials gone, the receipt id and the class set, in `headers` and `rawHeaders` alike. */
function passHeaders(core: DoorCore, req: IncomingMessage, arrival: Arrival, receiptId: string): void {
  const gone = new Set(Object.keys(req.headers).filter((name) => core.consumed(name, req, arrival)));
  gone.add(RECEIPT_HEADER).add(CLASS_HEADER);
  for (const name of gone) delete req.headers[name];
  req.headers[RECEIPT_HEADER] = receiptId;
  req.headers[CLASS_HEADER] = arrival.class;
  const raw: string[] = [];
  for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) if (!gone.has(req.rawHeaders[i]!.toLowerCase())) raw.push(req.rawHeaders[i]!, req.rawHeaders[i + 1]!);
  raw.push(RECEIPT_HEADER, receiptId, CLASS_HEADER, arrival.class);
  req.rawHeaders = raw;
  // Node builds headersDistinct from rawHeaders with the parser's original count, which no longer matches raw.
  const distinct: Record<string, string[]> = {};
  for (let i = 0; i + 1 < raw.length; i += 2) (distinct[raw[i]!.toLowerCase()] ??= []).push(raw[i + 1]!);
  Object.defineProperty(req, "headersDistinct", { configurable: true, enumerable: true, value: distinct });
}

/** Hashes every byte the app writes, as it writes it; the answer streams as it would without the door. */
function watchAnswer(res: ServerResponse): () => { bytes: number; digest: string } {
  const hash = createHash("sha256");
  let bytes = 0;
  const see = (chunk: unknown, encoding: unknown) => {
    if (chunk === undefined || chunk === null || typeof chunk === "function") return;
    const b = typeof chunk === "string" ? Buffer.from(chunk, typeof encoding === "string" ? (encoding as BufferEncoding) : "utf8") : Buffer.from((chunk as Uint8Array).buffer, (chunk as Uint8Array).byteOffset, (chunk as Uint8Array).byteLength);
    hash.update(b);
    bytes += b.length;
  };
  const write = res.write;
  const end = res.end;
  res.write = function (this: ServerResponse, chunk: unknown, ...rest: unknown[]) {
    see(chunk, rest[0]);
    return (write as (...a: unknown[]) => boolean).call(this, chunk, ...rest);
  } as ServerResponse["write"];
  res.end = function (this: ServerResponse, chunk?: unknown, ...rest: unknown[]) {
    see(chunk, rest[0]);
    return (end as (...a: unknown[]) => ServerResponse).call(this, chunk, ...rest);
  } as ServerResponse["end"];
  return () => ({ bytes, digest: hash.digest("hex") });
}

/** The fetch request as the door reads it. Without a socket the address is the proxy's `X-Forwarded-For` under `trustProxy`, else `unknown`. */
function fetchRequest(request: Request): DoorRequest {
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => { headers[k] = v; });
  return { method: request.method, url: url.pathname + url.search, headers, socket: {} };
}

const toResponse = (a: DoorAnswer) => new Response(a.body, { status: a.status, headers: a.headers });

/**
 * The door in-process, from a door config without `origin` (a path, read with `loadDoorConfig`, or a config already
 * loaded). Throws at once on a config the door cannot serve: a missing key, a policy that does not parse, an `origin`.
 */
export function door(config: string | DoorConfig, options: DoorAppOptions = {}): InProcessDoor {
  const cfg = typeof config === "string" ? loadDoorConfig(config) : config;
  if (cfg.origin) throw new Error("the in-process door passes an allowed request to the app it runs in, so its config names no origin; origin.url is for the door proxy (`agent-custody door`)");
  const core = createDoorCore(cfg, { ...options, autoFlush: options.autoFlush ?? true }, MIDDLEWARE_FRAMEWORK);

  const middleware = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void): void => {
    if (!core.admit()) {
      req.resume();
      return sendAnswer(res, core.busy());
    }
    let released = false;
    const release = () => {
      if (!released) core.release();
      released = true;
    };
    const receiptId = randomUUID();
    res.setHeader(RECEIPT_HEADER, receiptId);
    void (async () => {
      const d = await core.decide(req, receiptId, (max) => readBody(req, max), MIDDLEWARE_FRAMEWORK);
      if (d.refused) {
        const recorded = await core.record(d, d.refused.execution);
        sendAnswer(res, recorded ? core.refusal(d, recorded.logPending) : core.unrecorded(d, d.refused.execution, false));
        return release();
      }
      // The receipt of a passed request is written once the app has answered, so the answer cannot say whether the log
      // took it: there is no X-Agent-Custody-Log-Pending here, and the outbox holds what the log did not take.
      for (const [h, v] of Object.entries(core.mark(d, false))) res.setHeader(h, v);
      passHeaders(core, req, d.arrival, receiptId);
      replayBody(req, d.body!);
      const seen = watchAnswer(res);
      let settled = false;
      const settle = (finished: boolean) => {
        if (settled) return;
        settled = true;
        const { bytes, digest } = seen();
        const execution = finished ? answered(res.statusCode, res.getHeader("content-type"), bytes, digest) : mayHaveActed(`the connection closed before the app finished its answer${res.headersSent ? ` (it had sent ${res.statusCode})` : ""}`);
        void core.record(d, execution).finally(release);
      };
      res.once("finish", () => settle(true));
      res.once("close", () => settle(res.writableFinished));
      next();
    })().catch((e: unknown) => {
      release();
      next(e);
    });
  };

  const route = <R extends Request, C extends unknown[]>(handler: (req: R, ...rest: C) => Response | Promise<Response>) => async (request: R, ...rest: C): Promise<Response> => {
    if (!core.admit()) {
      await request.body?.cancel().catch(() => undefined);
      return toResponse(core.busy());
    }
    let release = true;
    try {
      const receiptId = randomUUID();
      const seen = fetchRequest(request);
      // The door reads a copy of the body; the handler reads the request itself, as it would without the door.
      const copy = request.clone();
      const d = await core.decide(seen, receiptId, (max) => readStream(copy.body, max), ROUTE_FRAMEWORK);
      if (d.refused) {
        await request.body?.cancel().catch(() => undefined);
        const recorded = await core.record(d, d.refused.execution);
        return toResponse(recorded ? core.refusal(d, recorded.logPending) : core.unrecorded(d, d.refused.execution, false));
      }
      const passed = new Headers(request.headers);
      for (const name of Object.keys(seen.headers)) if (core.consumed(name, seen, d.arrival)) passed.delete(name);
      passed.set(RECEIPT_HEADER, receiptId);
      passed.set(CLASS_HEADER, d.arrival.class);
      // The request the framework made keeps its own type (a NextRequest's `nextUrl`, `cookies`); its headers are
      // changed in place. A framework that seals them gets a plain Request with the same body in its place.
      let onward: R = request;
      try {
        for (const name of [...request.headers.keys()]) if (!passed.has(name)) request.headers.delete(name);
        passed.forEach((v, k) => request.headers.set(k, v));
      } catch {
        onward = new Request(request, { headers: passed }) as R;
      }
      let response: Response;
      try {
        response = await handler(onward, ...rest);
      } catch (e) {
        await core.record(d, mayHaveActed(`the handler threw: ${e instanceof Error ? e.message : String(e)}`));
        throw e;
      }
      const headers = new Headers(response.headers);
      for (const [h, v] of Object.entries(core.mark(d, false))) headers.set(h, v);
      const contentType = response.headers.get("content-type") ?? undefined;
      if (!response.body) {
        await core.record(d, answered(response.status, contentType, 0, createHash("sha256").digest("hex")));
        return new Response(null, { status: response.status, statusText: response.statusText, headers });
      }
      // The answer streams to the client while a second branch of it is hashed; the receipt is written when the app's
      // body has ended, or records that it did not.
      const [toClient, toDigest] = response.body.tee();
      release = false;
      void (async () => {
        const hash = createHash("sha256");
        let bytes = 0;
        let execution: Execution;
        try {
          for await (const chunk of toDigest as unknown as AsyncIterable<Uint8Array>) {
            hash.update(chunk);
            bytes += chunk.length;
          }
          execution = answered(response.status, contentType, bytes, hash.digest("hex"));
        } catch (e) {
          execution = mayHaveActed(`the app's answer (${response.status}) stopped after ${bytes} bytes: ${e instanceof Error ? e.message : String(e)}`);
        }
        await core.record(d, execution);
      })().finally(() => core.release());
      return new Response(toClient, { status: response.status, statusText: response.statusText, headers });
    } finally {
      if (release) core.release();
    }
  };

  return Object.assign(middleware, {
    route,
    keyid: core.keyid,
    policyDigest: core.policyDigest,
    flushOutbox: core.flushOutbox,
    pendingReceipts: core.pendingReceipts,
    close: core.close,
  });
}

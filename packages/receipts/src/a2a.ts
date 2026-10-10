// Agents that delegate to agents. The A2A protocol is how one agent hands a task to another over HTTP: the remote
// agent publishes an agent card, the caller sends a message, and gets back a task with its status and artifacts.
// Here that delegation goes through the gateway, two ways.
//
// As an upstream, the remote agent is a tool: `<prefix>.send` delegates a task, `<prefix>.card` reads its card so a
// policy can decide on the agent it is actually talking to. Everything the gateway does for any upstream applies:
// scope, policy on facts it fetched itself, pre-commit for consequential delegations, a receipt either way.
//
// As a front door (`serveA2a`), the gateway speaks A2A itself. An A2A client such as Google ADK's RemoteA2aAgent is
// pointed at the gateway instead of at the remote agent; the gateway serves the agent card with its own address,
// turns every SendMessage into a `<prefix>.send` call, and answers in A2A: a task that was allowed carries the receipt
// id in its metadata, a task the policy refused comes back rejected with the reason and the receipt id, and nothing
// reached the remote agent. Both the 1.0 wire format (SendMessage, ROLE_USER) and the 0.3 one (message/send, kind)
// are understood; the remote agent's card says which it speaks.
//
// A streamed delegation is relayed once the remote agent has finished: the receipt records the task's final state,
// and the events the remote agent produced are then replayed to the caller in order.
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { A2aUpstreamConfig } from "./config.ts";
import type { Envelope } from "./crypto.ts";
import { RECEIPT_META_KEY, type Gateway, type GatewayHost } from "./gateway.ts";
import { GRANT_HEADER, parseGrantHeader } from "./gateway-http.ts";
import type { UpstreamClient } from "./rest.ts";

export const A2A_CARD_PATH = "/.well-known/agent-card.json";
/** where cards lived before 0.3 */
export const A2A_LEGACY_CARD_PATH = "/.well-known/agent.json";
/** the key under which a task or message answered through the gateway names its receipt, in `metadata` */
export const A2A_RECEIPT_METADATA_KEY = "agent-custody/receipt";
/** on a `.send` result for a streamed delegation: the events the remote agent produced, in order */
export const A2A_STREAM_META_KEY = "agent-custody/a2a-stream";

const SEND_METHODS = new Set(["SendMessage", "message/send"]);
const STREAM_METHODS = new Set(["SendStreamingMessage", "message/stream"]);
const LEGACY_METHODS = new Set(["message/send", "message/stream"]);

export interface AgentInterface {
  url: string;
  protocolBinding?: string;
  protocolVersion?: string;
}
export interface AgentCard {
  name: string;
  description?: string;
  /** 0.3: the JSON-RPC endpoint */
  url?: string;
  protocolVersion?: string;
  /** 1.0: the endpoints, the first preferred */
  supportedInterfaces?: AgentInterface[];
  skills?: { id: string; name?: string; description?: string; tags?: string[] }[];
  capabilities?: Record<string, unknown>;
  signatures?: unknown[];
  [k: string]: unknown;
}

export interface ResolvedCard {
  card: AgentCard;
  cardUrl: string;
  /** the JSON-RPC endpoint the card names */
  endpoint: string;
  /** true for a 0.3 card and wire format */
  legacy: boolean;
}

export interface A2aOptions {
  fetch?: typeof fetch;
  env?: Record<string, string | undefined>;
}

function resolveHeaders(name: string, cfg: A2aUpstreamConfig, env: Record<string, string | undefined>): Record<string, string> {
  const headers: Record<string, string> = { ...(cfg.headers ?? {}) };
  for (const [header, variable] of Object.entries(cfg.headerEnv ?? {})) {
    const v = env[variable];
    if (!v) throw new Error(`upstream ${name}: environment variable ${variable} is not set`);
    headers[header] = v;
  }
  return headers;
}

/** Fetches an agent card from a base URL or a card URL and works out the endpoint and wire format. */
export async function fetchAgentCard(url: string, headers: Record<string, string>, f: typeof fetch, timeoutMs: number): Promise<ResolvedCard> {
  const u = new URL(url);
  const candidates = u.pathname.endsWith(".json") ? [u.toString()] : [new URL(A2A_CARD_PATH, u).toString(), new URL(A2A_LEGACY_CARD_PATH, u).toString()];
  let last = "";
  for (const cardUrl of candidates) {
    const res = await f(cardUrl, { headers: { accept: "application/json", ...headers }, signal: AbortSignal.timeout(timeoutMs) });
    if (res.status === 404) {
      last = `${cardUrl}: 404`;
      continue;
    }
    if (!res.ok) throw new Error(`agent card ${cardUrl}: HTTP ${res.status}`);
    const card = (await res.json()) as AgentCard;
    if (!card || typeof card !== "object" || typeof card.name !== "string") throw new Error(`agent card ${cardUrl}: not an agent card`);
    const iface = card.supportedInterfaces?.find((i) => !i.protocolBinding || i.protocolBinding === "JSONRPC") ?? null;
    const endpoint = iface?.url ?? card.url;
    if (!endpoint) throw new Error(`agent card ${cardUrl}: no JSON-RPC endpoint (neither supportedInterfaces nor url)`);
    return { card, cardUrl, endpoint, legacy: !card.supportedInterfaces };
  }
  throw new Error(`no agent card at ${candidates.join(" or ")} (${last})`);
}

type Part = { text?: string; kind?: string; [k: string]: unknown };
type Message = { messageId?: string; role?: string; parts?: Part[]; taskId?: string; contextId?: string; metadata?: Record<string, unknown>; kind?: string; [k: string]: unknown };

/** The text parts of a message, joined; what a policy reads as `context.args.text`. */
export function textOf(message: Message | undefined): string {
  return (message?.parts ?? []).filter((p) => typeof p.text === "string").map((p) => p.text as string).join("\n");
}

function buildMessage(text: string, legacy: boolean, taskId?: string, contextId?: string): Message {
  const ids = { ...(taskId ? { taskId } : {}), ...(contextId ? { contextId } : {}) };
  return legacy
    ? { kind: "message", role: "user", messageId: randomUUID(), parts: [{ kind: "text", text }], ...ids }
    : { role: "ROLE_USER", messageId: randomUUID(), parts: [{ text }], ...ids };
}

/** Parses an SSE body into the JSON objects of its `data:` lines. */
export function parseSse(body: string): unknown[] {
  const out: unknown[] = [];
  for (const block of body.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .join("\n");
    if (!data) continue;
    try {
      out.push(JSON.parse(data));
    } catch {
      // a line that is not JSON is not an event
    }
  }
  return out;
}

/** The final state of a streamed task: the first task snapshot, updated by every status and artifact event. */
export function finalOfStream(events: unknown[]): unknown {
  let task: Record<string, unknown> | null = null;
  let message: unknown = null;
  for (const raw of events) {
    const ev = (raw ?? {}) as Record<string, unknown>;
    // 1.0 wraps each event in a StreamResponse; 0.3 tags the object with `kind`
    const snapshot = (ev.task ?? (ev.kind === "task" ? ev : null)) as Record<string, unknown> | null;
    const status = (ev.statusUpdate ?? (ev.kind === "status-update" ? ev : null)) as Record<string, unknown> | null;
    const artifact = (ev.artifactUpdate ?? (ev.kind === "artifact-update" ? ev : null)) as Record<string, unknown> | null;
    const msg = ev.message ?? (ev.kind === "message" ? ev : null);
    if (snapshot) task = { ...snapshot };
    if (status && task) task = { ...task, status: status.status };
    if (artifact && task) {
      const artifacts: unknown[] = Array.isArray(task.artifacts) ? [...(task.artifacts as unknown[])] : [];
      artifacts.push(artifact.artifact);
      task = { ...task, artifacts };
    }
    if (msg) message = msg;
  }
  return task ?? message ?? events.at(-1) ?? null;
}

/** A remote agent as an upstream: `<prefix>.send` delegates a task to it, `<prefix>.card` reads its card. */
export function a2aUpstream(name: string, cfg: A2aUpstreamConfig, opts: A2aOptions = {}): UpstreamClient & { resolved(): Promise<ResolvedCard> } {
  const f = opts.fetch ?? fetch;
  const headers = resolveHeaders(name, cfg, opts.env ?? process.env);
  const sendTool = `${cfg.prefix}.send`;
  const cardTool = `${cfg.prefix}.card`;
  let resolved: Promise<ResolvedCard> | null = null;
  const card = () => (resolved ??= fetchAgentCard(cfg.url, headers, f, cfg.timeoutMs));
  const text = (v: unknown, isError = false): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(v) }], ...(isError ? { isError: true } : {}) });

  return {
    resolved: card,
    async listTools() {
      const { card: c } = await card();
      const skills = (c.skills ?? []).map((s) => `${s.id}${s.description ? `: ${s.description}` : ""}`).join("; ");
      const tools: Tool[] = [
        {
          name: sendTool,
          description: `Delegate a task to the agent "${c.name}"${c.description ? `: ${c.description}` : ""}${skills ? `. Skills: ${skills}` : ""}`,
          inputSchema: {
            type: "object",
            properties: {
              text: { type: "string", description: "the task, as text" },
              message: { type: "object", description: "a full A2A message, forwarded as is; text is derived from it" },
              taskId: { type: "string" },
              contextId: { type: "string" },
              configuration: { type: "object" },
              metadata: { type: "object" },
            },
          },
        },
        { name: cardTool, description: `The agent card of "${c.name}", fetched by the gateway`, inputSchema: { type: "object", properties: {} } },
      ];
      return { tools };
    },
    async callTool(params): Promise<CallToolResult> {
      const r = await card();
      if (params.name === cardTool) {
        const fresh = await fetchAgentCard(r.cardUrl, headers, f, cfg.timeoutMs);
        return text(fresh.card);
      }
      if (params.name !== sendTool) throw new Error(`upstream ${name} has no tool "${params.name}"`);
      const args = params.arguments ?? {};
      const method = typeof args.method === "string" ? args.method : r.legacy ? "message/send" : "SendMessage";
      const stream = STREAM_METHODS.has(method);
      const message = (args.message as Message | undefined) ?? buildMessage(typeof args.text === "string" ? args.text : "", r.legacy, args.taskId as string | undefined, args.contextId as string | undefined);
      const rpc = { jsonrpc: "2.0", id: randomUUID(), method, params: { message, ...(args.configuration ? { configuration: args.configuration } : {}), ...(args.metadata ? { metadata: args.metadata } : {}) } };
      const res = await f(r.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", accept: stream ? "text/event-stream" : "application/json", ...(r.legacy ? {} : { "a2a-version": "1.0" }), ...headers },
        body: JSON.stringify(rpc),
        signal: AbortSignal.timeout(cfg.timeoutMs),
      });
      const body = await res.text();
      if (!res.ok) return text({ code: -32000, message: `HTTP ${res.status} from ${r.endpoint}`, data: body.slice(0, 2000) }, true);
      if (stream) {
        const envelopes = parseSse(body) as { result?: unknown; error?: unknown }[];
        const failed = envelopes.find((e) => e.error);
        if (failed) return text(failed.error, true);
        const events = envelopes.map((e) => e.result).filter((e) => e !== undefined);
        return { ...text(finalOfStream(events)), _meta: { [A2A_STREAM_META_KEY]: events } };
      }
      let parsed: { result?: unknown; error?: unknown };
      try {
        parsed = JSON.parse(body) as { result?: unknown; error?: unknown };
      } catch {
        return text({ code: -32700, message: "the agent did not answer with JSON", data: body.slice(0, 2000) }, true);
      }
      if (parsed.error) return text(parsed.error, true);
      return text(parsed.result ?? null);
    },
    async close() {},
  };
}

export interface A2aServerOptions {
  port: number;
  host?: string;
  /** the grant every request without a grant header runs under; without it, a grant header is required */
  grant?: Envelope;
  log?: (message: string) => void;
}

export interface RunningA2aServer {
  /** the base URL: the card is at /.well-known/agent-card.json, JSON-RPC at / */
  url: string;
  close(): Promise<void>;
}

const sendBody = (res: ServerResponse, status: number, type: string, body: string) => {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  res.end(body);
};

/** Receipt id and reason out of a result the gateway refused: "Denied by policy: ... (receipt <id>)". */
function refusalOf(result: CallToolResult): { kind: "rejected" | "failed"; reason: string } | null {
  if (!result.isError) return null;
  const first = result.content.find((c) => c.type === "text");
  const t = first && first.type === "text" ? first.text : "";
  const m = /^(Denied by policy|Not executed|Upstream error): (.*) \(receipt [0-9a-f-]+\)$/s.exec(t);
  if (!m) return null;
  return { kind: m[1] === "Upstream error" ? "failed" : "rejected", reason: m[2]! };
}

function refusedTask(legacy: boolean, message: Message, kind: "rejected" | "failed", reason: string, receiptId: string): Record<string, unknown> {
  const id = message.taskId ?? randomUUID();
  const contextId = message.contextId ?? randomUUID();
  const timestamp = new Date().toISOString();
  const metadata = { [A2A_RECEIPT_METADATA_KEY]: receiptId };
  const text = `agent-custody: ${reason} (receipt ${receiptId})`;
  return legacy
    ? { kind: "task", id, contextId, status: { state: kind, message: { kind: "message", role: "agent", messageId: randomUUID(), parts: [{ kind: "text", text }] }, timestamp }, metadata }
    : { id, contextId, status: { state: kind === "rejected" ? "TASK_STATE_REJECTED" : "TASK_STATE_FAILED", message: { role: "ROLE_AGENT", messageId: randomUUID(), parts: [{ text }] }, timestamp }, metadata };
}

/** Names the receipt on whatever object the remote agent answered with, if it is a task, message or event. */
function withReceipt(value: unknown, receiptId: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const v = { ...(value as Record<string, unknown>) };
  const mark = (o: unknown) => (o && typeof o === "object" ? { ...(o as Record<string, unknown>), metadata: { ...((o as Record<string, unknown>).metadata as Record<string, unknown> | undefined), [A2A_RECEIPT_METADATA_KEY]: receiptId } } : o);
  // 1.0 stream events wrap the object; a plain task, message or 0.3 event is the object itself
  for (const k of ["task", "message", "statusUpdate", "artifactUpdate"]) if (k in v) v[k] = mark(v[k]);
  if ("status" in v || "parts" in v || "kind" in v) return mark(v);
  return v;
}

/**
 * Serves the gateway as an A2A agent in front of the A2A upstream `cfg` describes. Point an A2A client at the
 * returned URL: the card is served there with the gateway's own address, every SendMessage becomes a
 * `<prefix>.send` call under the grant (the default one, or the one in the request's grant header), and the
 * remaining methods are forwarded as they are.
 */
export async function serveA2a(host: GatewayHost, cfg: A2aUpstreamConfig, opts: A2aServerOptions): Promise<RunningA2aServer> {
  const bind = opts.host ?? "127.0.0.1";
  const log = opts.log ?? ((m) => console.error(m));
  const f = fetch;
  const headers = resolveHeaders("a2a", cfg, process.env);
  const upstream = await fetchAgentCard(cfg.url, headers, f, cfg.timeoutMs);
  const sendTool = `${cfg.prefix}.send`;
  const sessions = new Map<string, Gateway>();
  let self = "";

  const session = (req: IncomingMessage): Gateway => {
    const raw = (typeof req.headers[GRANT_HEADER] === "string" && req.headers[GRANT_HEADER]) || (req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization : "");
    const key = raw || "default";
    const existing = sessions.get(key);
    if (existing) return existing;
    const envelope = raw ? parseGrantHeader(req) : opts.grant;
    if (!envelope) throw new Error(raw ? "the grant header is not a delegation envelope" : `a grant is required: send the delegation envelope as base64url in Authorization: Bearer or ${GRANT_HEADER}`);
    const gw = host.open(envelope);
    sessions.set(key, gw);
    log(`agent-custody gateway (a2a): session for agent=${gw.agentId} principal=${gw.delegation.principal}`);
    return gw;
  };

  const servedCard = async (): Promise<AgentCard> => {
    const { card } = await fetchAgentCard(upstream.cardUrl, headers, f, cfg.timeoutMs);
    const out: AgentCard = { ...card };
    if (card.supportedInterfaces) {
      const first = card.supportedInterfaces.find((i) => !i.protocolBinding || i.protocolBinding === "JSONRPC") ?? card.supportedInterfaces[0]!;
      out.supportedInterfaces = [{ ...first, url: self, protocolBinding: "JSONRPC" }];
    }
    if (card.url) out.url = self;
    // the card has been changed, so its signatures no longer apply
    delete out.signatures;
    return out;
  };

  const forward = async (req: IncomingMessage, res: ServerResponse, body: string): Promise<void> => {
    const r = await f(upstream.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", accept: req.headers.accept ?? "application/json", ...(typeof req.headers["a2a-version"] === "string" ? { "a2a-version": req.headers["a2a-version"] } : {}), ...headers },
      body,
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
    res.writeHead(r.status, { "content-type": r.headers.get("content-type") ?? "application/json", "cache-control": "no-store" });
    if (!r.body) return void res.end();
    Readable.fromWeb(r.body as import("node:stream/web").ReadableStream).pipe(res);
  };

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", self);
    if (req.method === "GET" && url.pathname === "/health") return sendBody(res, 200, "application/json", JSON.stringify({ ok: true, agent: upstream.card.name, keyid: host.keyid }));
    if (req.method === "GET" && (url.pathname === A2A_CARD_PATH || url.pathname === A2A_LEGACY_CARD_PATH)) return sendBody(res, 200, "application/json", JSON.stringify(await servedCard()));
    if (req.method !== "POST") return sendBody(res, 405, "application/json", JSON.stringify({ error: "POST JSON-RPC here; the agent card is at /.well-known/agent-card.json" }));
    let body = "";
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 16_777_216) return sendBody(res, 413, "application/json", JSON.stringify({ error: "body larger than 16 MB" }));
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return sendBody(res, 400, "application/json", JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }));
    }
    // the HTTP+JSON binding of 1.0 puts the request directly in the body
    const restSend = url.pathname === "/message:send" ? "SendMessage" : url.pathname === "/message:stream" ? "SendStreamingMessage" : null;
    const method = restSend ?? (typeof parsed.method === "string" ? parsed.method : "");
    const id = restSend ? null : (parsed.id as string | number | null | undefined) ?? null;
    const params = (restSend ? parsed : (parsed.params as Record<string, unknown> | undefined)) ?? {};
    if (!SEND_METHODS.has(method) && !STREAM_METHODS.has(method)) return forward(req, res, body);

    const legacy = LEGACY_METHODS.has(method);
    const stream = STREAM_METHODS.has(method);
    const message = (params.message ?? {}) as Message;
    let gw: Gateway;
    try {
      gw = session(req);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return sendBody(res, 403, "application/json", JSON.stringify(restSend ? { error: msg } : { jsonrpc: "2.0", id, error: { code: -32000, message: msg } }));
    }
    const args: Record<string, unknown> = { text: textOf(message), message, method, ...(message.taskId ? { taskId: message.taskId } : {}), ...(message.contextId ? { contextId: message.contextId } : {}), ...(params.configuration ? { configuration: params.configuration } : {}), ...(params.metadata ? { metadata: params.metadata } : {}) };
    const result = await gw.handleCall({ name: sendTool, arguments: args });
    const receiptId = String(result._meta?.[RECEIPT_META_KEY] ?? "");
    const refusal = refusalOf(result);
    const first = result.content.find((c) => c.type === "text");
    const answered: unknown = refusal ? null : first && first.type === "text" ? JSON.parse(first.text) : null;

    const wrap = (v: unknown) => (restSend ? v : { jsonrpc: "2.0", id, result: v });
    if (stream) {
      const events: unknown[] = refusal
        ? [legacy ? refusedTask(true, message, refusal.kind, refusal.reason, receiptId) : { task: refusedTask(false, message, refusal.kind, refusal.reason, receiptId) }]
        : result.isError
          ? []
          : ((result._meta?.[A2A_STREAM_META_KEY] as unknown[] | undefined) ?? [legacy ? answered : { task: answered }]);
      if (!refusal && result.isError) return sendBody(res, 200, "application/json", JSON.stringify(restSend ? { error: { ...(answered as object), data: { receipt: receiptId } } } : { jsonrpc: "2.0", id, error: { ...(answered as object), data: { receipt: receiptId } } }));
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      for (const ev of events) res.write(`data: ${JSON.stringify(wrap(withReceipt(ev, receiptId)))}\n\n`);
      return void res.end();
    }
    if (refusal) return sendBody(res, 200, "application/json", JSON.stringify(wrap(refusedTask(legacy, message, refusal.kind, refusal.reason, receiptId))));
    if (result.isError) return sendBody(res, 200, "application/json", JSON.stringify(restSend ? { error: { ...(answered as object), data: { receipt: receiptId } } } : { jsonrpc: "2.0", id, error: { ...(answered as object), data: { receipt: receiptId } } }));
    return sendBody(res, 200, "application/json", JSON.stringify(wrap(withReceipt(answered, receiptId))));
  };

  const server: HttpServer = createServer((req, res) => {
    handler(req, res).catch((e) => {
      log(`agent-custody gateway (a2a): ${e instanceof Error ? e.message : String(e)}`);
      if (!res.headersSent) sendBody(res, 500, "application/json", JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32603, message: e instanceof Error ? e.message : String(e) } }));
      else res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(opts.port, bind, resolve));
  const { port } = server.address() as AddressInfo;
  self = `http://${bind}:${port}`;
  return {
    url: self,
    async close() {
      for (const gw of sessions.values()) await gw.close();
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

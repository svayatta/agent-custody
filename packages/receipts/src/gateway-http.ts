// The gateway over HTTP: one process, many agents, each connection under its own grant. A platform team runs one
// gateway in front of the tools; every agent connects with MCP over Streamable HTTP and presents the grant its
// principal signed, and the gateway opens a session for exactly that grant. Sessions share the upstreams, the policy,
// the key, and the log; each has its own consumed facts and its own receipts, and none can see another's tools.
// The grant is the credential: it is signed by a principal key the gateway trusts, so nothing else is needed to
// authenticate a connection, and a grant that is expired, revoked by time, or signed by a stranger gets 403 with the
// reason in the body. (Not 401: the MCP client transport treats 401 as an OAuth challenge and hides the body.)
// Bind to loopback or put TLS in front; the transport itself is plain HTTP.
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, isInitializeRequest, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Envelope } from "./crypto.ts";
import { GATEWAY_VERSION, type CallParams, type Gateway, type GatewayHost } from "./gateway.ts";

export const GRANT_HEADER = "x-agent-custody-grant";

/** The header value that presents a grant: the DSSE envelope as base64url JSON. Send it as `Authorization: Bearer <value>` or as `X-Agent-Custody-Grant`. */
export function grantHeader(envelope: Envelope): string {
  return Buffer.from(JSON.stringify(envelope)).toString("base64url");
}

export function parseGrantHeader(req: IncomingMessage): Envelope | null {
  const explicit = req.headers[GRANT_HEADER];
  const auth = req.headers.authorization ?? "";
  const raw = typeof explicit === "string" && explicit ? explicit : auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Envelope;
    return parsed && typeof parsed === "object" && typeof parsed.payload === "string" && Array.isArray(parsed.signatures) ? parsed : null;
  } catch {
    return null;
  }
}

export interface HttpGatewayOptions {
  port: number;
  host?: string;
  /** the MCP endpoint path; default /mcp */
  path?: string;
  /** a session with no request for this long is closed; default thirty minutes */
  idleMs?: number;
  /** where session events are reported; default stderr */
  log?: (message: string) => void;
}

export interface RunningHttpGateway {
  url: string;
  /** live sessions by MCP session id */
  sessions(): { id: string; agent: string; principal: string; since: string }[];
  close(): Promise<void>;
}

interface Session {
  gateway: Gateway;
  transport: StreamableHTTPServerTransport;
  server: Server;
  since: string;
  lastSeen: number;
}

/** Serves a gateway host as an MCP server over Streamable HTTP, a session per grant. */
export async function serveHttp(host: GatewayHost, opts: HttpGatewayOptions): Promise<RunningHttpGateway> {
  const bind = opts.host ?? "127.0.0.1";
  const path = opts.path ?? "/mcp";
  const idleMs = opts.idleMs ?? 30 * 60_000;
  const log = opts.log ?? ((m) => console.error(m));
  const sessions = new Map<string, Session>();

  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  };
  const rpcError = (res: ServerResponse, status: number, message: string) => json(res, status, { jsonrpc: "2.0", error: { code: -32000, message }, id: null });

  const readBody = async (req: IncomingMessage): Promise<unknown> => {
    let text = "";
    for await (const chunk of req) {
      text += chunk;
      if (text.length > 4_194_304) throw new Error("body larger than 4 MB");
    }
    return text ? JSON.parse(text) : undefined;
  };

  const closeSession = async (id: string, why: string) => {
    const s = sessions.get(id);
    if (!s) return;
    sessions.delete(id);
    log(`agent-custody gateway: session ${id.slice(0, 8)} for ${s.gateway.agentId} closed (${why})`);
    await s.gateway.close();
    await s.transport.close().catch(() => {});
  };

  const openSession = async (req: IncomingMessage, res: ServerResponse, body: unknown): Promise<void> => {
    const envelope = parseGrantHeader(req);
    if (!envelope) return rpcError(res, 403, `a grant is required: send the delegation envelope as base64url in Authorization: Bearer or ${GRANT_HEADER}`);
    let gateway: Gateway;
    try {
      gateway = host.open(envelope);
    } catch (e) {
      return rpcError(res, 403, e instanceof Error ? e.message : String(e));
    }
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, { gateway, transport, server, since: new Date().toISOString(), lastSeen: Date.now() });
        log(`agent-custody gateway: session ${id.slice(0, 8)} opened for agent=${gateway.agentId} principal=${gateway.delegation.principal} scopes=[${gateway.delegation.scopes.join(", ")}]`);
      },
      onsessionclosed: (id) => void closeSession(id, "closed by the client"),
    });
    const server = new Server({ name: "agent-custody-gateway", version: GATEWAY_VERSION }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: await gateway.listTools() }));
    server.setRequestHandler(CallToolRequestSchema, async (r) => gateway.handleCall(r.params as CallParams));
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  };

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/health") return json(res, 200, { ok: true, sessions: sessions.size, keyid: host.keyid });
    if (url.pathname !== path) return json(res, 404, { error: "not found" });
    try {
      const sid = req.headers["mcp-session-id"];
      const existing = typeof sid === "string" ? sessions.get(sid) : undefined;
      if (existing) {
        // the grant is checked again on every request of a session; an expired or revoked one ends the session here
        const problem = existing.gateway.grantProblem();
        if (problem) {
          await closeSession(sid as string, `grant ${problem}`);
          return rpcError(res, 403, `the grant for this session ${problem}; initialize again with a current grant`);
        }
        existing.lastSeen = Date.now();
        const body = req.method === "POST" ? await readBody(req) : undefined;
        await existing.transport.handleRequest(req, res, body);
        return;
      }
      if (typeof sid === "string") return rpcError(res, 404, "unknown or expired session; initialize again with your grant");
      if (req.method !== "POST") return rpcError(res, 400, "initialize first: POST an initialize request with your grant");
      const body = await readBody(req);
      if (!isInitializeRequest(body)) return rpcError(res, 400, "the first request of a session must be initialize");
      await openSession(req, res, body);
    } catch (e) {
      if (!res.headersSent) rpcError(res, 500, e instanceof Error ? e.message : String(e));
    }
  };

  const server: HttpServer = createServer((req, res) => void handler(req, res));
  const reaper = setInterval(() => {
    const cutoff = Date.now() - idleMs;
    for (const [id, s] of sessions) {
      if (s.lastSeen < cutoff) void closeSession(id, "idle");
      else {
        const problem = s.gateway.grantProblem();
        if (problem) void closeSession(id, `grant ${problem}`);
      }
    }
  }, Math.min(idleMs, 60_000));
  reaper.unref?.();

  await new Promise<void>((resolve) => server.listen(opts.port, bind, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://${bind}:${port}${path}`,
    sessions: () => [...sessions.entries()].map(([id, s]) => ({ id, agent: s.gateway.agentId, principal: s.gateway.delegation.principal, since: s.since })),
    async close() {
      clearInterval(reaper);
      for (const id of [...sessions.keys()]) await closeSession(id, "server closing");
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

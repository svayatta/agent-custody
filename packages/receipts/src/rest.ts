// The REST connector: an upstream that is not an MCP server but a plain HTTP API, described in the gateway config as
// a list of tools. The agent calls the tool through the gateway; the gateway builds the request, sends it with the
// credentials the agent never sees, and returns the response as a tool result. Everything the gateway does for an
// MCP upstream applies unchanged: scope, policy on facts it fetched itself, pre-commit for consequential tools, and a
// receipt per call. This is how an agent's direct HTTP calls come under custody: they become tool calls.
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { RestToolConfig, RestUpstreamConfig } from "./config.ts";
import { OPERATION_META_KEY } from "./operations.ts";

/** The part of an MCP client the gateway uses, so a REST connector can stand where an MCP upstream stands. */
export interface UpstreamClient {
  listTools(): Promise<{ tools: Tool[] }>;
  callTool(params: { name: string; arguments?: Record<string, unknown>; _meta?: Record<string, unknown> }): Promise<unknown>;
  close(): Promise<void>;
}

export interface RestOptions {
  fetch?: typeof fetch;
  /** the environment the header secrets are read from; default process.env */
  env?: Record<string, string | undefined>;
}

const encode = (v: unknown) => encodeURIComponent(typeof v === "string" ? v : JSON.stringify(v));

/** Builds the request for one tool call: path parameters substituted, the rest of the arguments as query or body. */
export function buildRequest(base: string, tool: RestToolConfig, args: Record<string, unknown>): { url: URL; method: string; body: string | null } {
  const rest = { ...args };
  const path = tool.path.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name: string) => {
    if (!(name in rest) || rest[name] === undefined) throw new Error(`tool ${tool.name}: path needs argument "${name}", which is missing`);
    const v = rest[name];
    delete rest[name];
    return encode(v);
  });
  const url = new URL(path.replace(/^\//, ""), base.endsWith("/") ? base : `${base}/`);
  const method = tool.method;
  const queryNames = tool.query ?? (method === "GET" || method === "DELETE" ? Object.keys(rest) : []);
  for (const name of queryNames) {
    if (rest[name] === undefined) continue;
    url.searchParams.set(name, typeof rest[name] === "string" ? (rest[name] as string) : JSON.stringify(rest[name]));
    delete rest[name];
  }
  const body = method === "GET" || method === "DELETE" || tool.body === "none" ? null : JSON.stringify(rest);
  return { url, method, body };
}

/** A REST API as an upstream. Tools are what the config declares; credentials come from the environment at startup, never from the agent. */
export function restUpstream(name: string, cfg: RestUpstreamConfig, opts: RestOptions = {}): UpstreamClient {
  const f = opts.fetch ?? fetch;
  const env = opts.env ?? process.env;
  const headers: Record<string, string> = { ...(cfg.headers ?? {}) };
  for (const [header, variable] of Object.entries(cfg.headerEnv ?? {})) {
    const v = env[variable];
    if (!v) throw new Error(`upstream ${name}: environment variable ${variable} is not set`);
    headers[header] = v;
  }
  const tools = new Map(cfg.tools.map((t) => [t.name, t]));
  return {
    async listTools() {
      return { tools: cfg.tools.map((t) => ({ name: t.name, description: t.description ?? `${t.method} ${t.path}`, inputSchema: t.inputSchema as Tool["inputSchema"] })) };
    },
    async callTool(params): Promise<CallToolResult> {
      const tool = tools.get(params.name);
      if (!tool) throw new Error(`upstream ${name} has no tool "${params.name}"`);
      const { url, method, body } = buildRequest(cfg.baseUrl, tool, params.arguments ?? {});
      const requestHeaders = new Headers({ accept: "application/json", ...(body !== null ? { "content-type": "application/json" } : {}), ...headers });
      if (tool.idempotencyHeader) {
        const operation = params._meta?.[OPERATION_META_KEY];
        if (!operation || typeof operation !== "object" || !Object.hasOwn(operation, "id") || !Object.hasOwn(operation, "idempotencyKey")) throw new Error(`tool ${tool.name}: durable operation metadata is required`);
        const { id, idempotencyKey } = operation as { id?: unknown; idempotencyKey?: unknown };
        if (typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || typeof idempotencyKey !== "string" || !/^[0-9a-f]{64}$/.test(idempotencyKey)) throw new Error(`tool ${tool.name}: malformed durable operation metadata`);
        // Set after static/environment headers, case-insensitively, so a configured header cannot replace
        // the durable key. The metadata itself never enters the provider's body or query arguments.
        requestHeaders.set(tool.idempotencyHeader, idempotencyKey);
      }
      const res = await f(url, { method, headers: requestHeaders, ...(body !== null ? { body } : {}), signal: AbortSignal.timeout(cfg.timeoutMs) });
      const text = await res.text();
      // The result is what the API returned, as text. JSON stays JSON so policy facts and consumers can read it.
      return { content: [{ type: "text", text: text.length ? text : JSON.stringify({ status: res.status }) }], ...(res.ok ? {} : { isError: true }) };
    },
    async close() {},
  };
}

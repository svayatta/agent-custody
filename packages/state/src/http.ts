// The memory server over HTTP: one ledger shared by several gateways and, if allowed, direct writers. This is what
// makes quarantine a live deployment: attested writes arrive through gateways, self-reported ones directly, and the
// ledger tells them apart. Stateless Streamable HTTP, one MCP server instance per request over the shared ledger.
//
// The two kinds of caller hold different tokens, and the token decides what the server believes. A caller with a
// gateway token is a gateway: its `_meta` (receipt id, agent, observed facts) is what makes a write attested or
// verified, and is believed. A caller with a direct token is a direct writer: its `_meta` is dropped before the
// server looks at it, so it can claim a fact but never attest one, whatever it puts in the call. A direct writer is
// therefore never given the gateway's token.
import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Ledger } from "./ledger.ts";
import { createMemoryServer, type MemoryServerOptions } from "./server.ts";

export interface MemoryHttpOptions extends MemoryServerOptions {
  port: number;
  host?: string;
  /** the gateways' bearer tokens: a caller presenting one is believed about receipts, agents, and observed facts. When no tokens of either kind are set, anyone who can reach the port is taken for a gateway; bind to loopback. */
  tokens?: string[];
  /** direct writers' bearer tokens: a caller presenting one is a direct writer, its `_meta` is dropped, and what it writes is claimed. Required when `requireGateway` is false. */
  directTokens?: string[];
}

export interface RunningMemoryServer {
  url: string;
  close(): Promise<void>;
}

export function memoryHttpHandler(ledger: Ledger, opts: MemoryHttpOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const tokens = opts.tokens ?? [];
  const directTokens = opts.directTokens ?? [];
  if (opts.requireGateway === false && directTokens.length === 0) throw new Error("memory server: direct writers need their own tokens (directTokens); a direct writer holding a gateway token could attest its own writes");
  if (tokens.some((t) => directTokens.includes(t))) throw new Error("memory server: a token cannot be both a gateway token and a direct token");
  const matches = (list: string[], given: Buffer) => list.some((t) => Buffer.from(t).length === given.length && timingSafeEqual(Buffer.from(t), given));
  /** Which kind of caller this is, by the token it presented; null when it presented none that is known. */
  const callerOf = (req: IncomingMessage): "gateway" | "direct" | null => {
    if (tokens.length === 0 && directTokens.length === 0) return "gateway";
    const h = req.headers.authorization ?? "";
    const given = Buffer.from(h.startsWith("Bearer ") ? h.slice(7) : "");
    if (matches(tokens, given)) return "gateway";
    if (matches(directTokens, given)) return "direct";
    return null;
  };
  return async (req, res) => {
    const caller = callerOf(req);
    if (!caller) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    // A direct writer's _meta is dropped: with requireGateway it is then refused outright, without it its writes are claimed.
    const server = createMemoryServer(ledger, { ...opts, trustMeta: caller === "gateway" });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res);
  };
}

/** Starts the memory server over HTTP. Port 0 picks a free port. Host defaults to loopback; bind wider only behind auth. */
export async function serveMemoryHttp(ledger: Ledger, opts: MemoryHttpOptions): Promise<RunningMemoryServer> {
  const host = opts.host ?? "127.0.0.1";
  const handler = memoryHttpHandler(ledger, opts);
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve) => {
    server.listen(opts.port, host, () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://${host}:${port}/mcp`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

// The memory server over HTTP: one ledger shared by several gateways and, if allowed, direct writers. This is what
// makes quarantine a live deployment: attested writes arrive through gateways, self-reported ones directly, and the
// ledger tells them apart. Gateways and direct writers hold different tokens: only a gateway token may name a receipt,
// an agent, or observed facts in _meta. Stateless Streamable HTTP, one MCP server instance per request over the shared ledger.
import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Ledger } from "./ledger.ts";
import { createMemoryServer, type MemoryServerOptions } from "./server.ts";

export interface MemoryHttpOptions extends MemoryServerOptions {
  port: number;
  host?: string;
  /** gateway tokens: a caller with one may set the receipt, agent, and observed keys in _meta */
  tokens?: string[];
  /** direct-writer tokens: accepted, but the caller's _meta is dropped, so its writes are claimed. When both lists are empty, anyone who can reach the port may call, as a direct writer. */
  directTokens?: string[];
}

export interface RunningMemoryServer {
  url: string;
  close(): Promise<void>;
}

export function memoryHttpHandler(ledger: Ledger, opts: MemoryHttpOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const tokens = opts.tokens ?? [];
  const directTokens = opts.directTokens ?? [];
  const open = tokens.length === 0 && directTokens.length === 0;
  const matches = (list: string[], given: Buffer) => list.some((t) => Buffer.from(t).length === given.length && timingSafeEqual(Buffer.from(t), given));
  const caller = (req: IncomingMessage): "gateway" | "direct" | null => {
    const h = req.headers.authorization ?? "";
    const given = Buffer.from(h.startsWith("Bearer ") ? h.slice(7) : "");
    if (matches(tokens, given)) return "gateway";
    return open || matches(directTokens, given) ? "direct" : null;
  };
  return async (req, res) => {
    const who = caller(req);
    if (!who) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const server = createMemoryServer(ledger, { ...opts, trustMeta: who === "gateway" });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res);
  };
}

/** Starts the memory server over HTTP. Port 0 picks a free port. Host defaults to loopback; bind wider only behind auth. */
export function serveMemoryHttp(ledger: Ledger, opts: MemoryHttpOptions): Promise<RunningMemoryServer> {
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

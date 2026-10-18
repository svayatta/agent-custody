// Offline payments provider for the financial-operations example and fault-injection tests.
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { buildFixture } from "./fixture.ts";

export async function financialFixture(directory: string, limit = 100) {
  const fx = buildFixture(directory);
  const records = new Map<string, { status: string; amount: number; idempotencyKey: string; note?: string }>();
  const api = {
    posts: 0, drop: false, responseStatus: 200,
    onAccept: undefined as (() => void) | undefined,
  };
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      const send = (status: number, value: unknown) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(value)); };
      if (req.method === "POST" && req.url === "/refunds") {
        const key = req.headers["idempotency-key"];
        if (typeof key !== "string") return send(400, { error: "missing idempotency key" });
        api.posts++;
        // Only the first request creates a refund. Count requests separately so tests also catch unsafe retries.
        if (!records.has(key)) records.set(key, { ...JSON.parse(body), idempotencyKey: key, status: "pending" });
        api.onAccept?.();
        if (api.drop) { req.socket.destroy(); return; }
        return send(api.responseStatus, records.get(key));
      }
      const key = /^\/refunds\/([^/?]+)$/.exec(req.url ?? "")?.[1];
      if (req.method === "GET" && key) return records.has(key) ? send(200, records.get(key)) : send(404, { error: "unknown operation" });
      return send(404, { error: "unknown route" });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const config = JSON.parse(readFileSync(fx.configFile, "utf8"));
  config.facts = [];
  config.upstream = { rest: { baseUrl, timeoutMs: 10_000, tools: [
    { name: "stripe.refund", method: "POST", path: "/refunds" },
    { name: "refund.lookup", method: "GET", path: "/refunds/{key}" },
  ] } };
  config.operations = {
    database: "operations/operations.sqlite",
    budgets: [{ id: "refunds", currency: "GBP", limit }],
    tools: [{ tool: "stripe.refund", budget: "refunds", reconcile: {
      tool: "refund.lookup", args: { key: "$operation.idempotencyKey" }, statusPath: "status",
      confirmed: ["succeeded"], failed: ["failed"], pending: ["pending"],
    } }],
  };
  writeFileSync(fx.configFile, JSON.stringify(config));
  writeFileSync(`${directory}/policy.cedar`, 'permit(principal, action == Action::"stripe.refund", resource);');
  return { ...fx, records, api, config, async close() { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); } };
}

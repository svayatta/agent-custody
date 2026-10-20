// deploy/gateway/example: the config directory shipped for people to copy must work as written. It is copied, pointed at a
// local stand-in for the API, given a principal key and grants the way its README says, checked, and then driven: the
// support agent refunds within the policy, and the policy, the fact lookup, and the grant scopes each refuse what they should.
import { createServer, type Server } from "node:http";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkConfig } from "../src/check.ts";
import { loadConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, writeKeyPair } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { createGatewayHost, type GatewayHost } from "../src/gateway.ts";

const example = join(import.meta.dirname, "..", "..", "..", "deploy", "gateway", "example", "config");
const text = (r: { content: unknown[] }) => (r.content[0] as { text: string }).text;

let dir: string;
let api: Server;
let host: GatewayHost;
let configFile: string;
let refunds: unknown[];
let grants: { support: ReturnType<typeof createDelegation>; report: ReturnType<typeof createDelegation> };

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "example-config-"));
  refunds = [];
  api = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.method === "GET" && req.url === "/v1/orders/o-1") res.end(JSON.stringify({ id: "o-1", status: "delivered", total: 20000 }));
      else if (req.method === "GET" && req.url === "/v1/orders/o-2") res.end(JSON.stringify({ id: "o-2", status: "processing", total: 20000 }));
      else if (req.method === "POST" && req.url?.endsWith("/refund")) {
        refunds.push(JSON.parse(Buffer.concat(chunks).toString() || "{}"));
        res.end(JSON.stringify({ refunded: true }));
      } else {
        res.statusCode = 404;
        res.end("{}");
      }
    });
  });
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  const port = (api.address() as { port: number }).port;

  // the layout the README describes: the example config, the principal's public key beside it, the data directory somewhere writable
  const config = join(dir, "config");
  cpSync(example, config, { recursive: true });
  const data = join(dir, "data");
  // the image creates the gateway key on first start; here it is made the way the README's plain-host path would
  writeKeyPair(generateKeyPair(), join(data, "keys"), "gateway");
  const principal = generateKeyPair();
  writeKeyPair(principal, join(dir, "principal"), "principal");
  cpSync(join(dir, "principal", "principal.pub"), join(config, "keys", "principal.pub"));
  configFile = join(config, "gateway.json");
  writeFileSync(configFile, readFileSync(configFile, "utf8").replaceAll("/data/", `${data}/`).replace("https://api.example.com", `http://127.0.0.1:${port}`));
  process.env.APP_API_AUTHORIZATION = "Bearer test";

  const now = Date.now();
  const grant = (agent: string, scopes: string[]) => createDelegation(loadPrivateKey(join(dir, "principal", "principal.key")), { version: "0.1", principal: "acme-support", agent, scopes, issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() });
  grants = { support: grant("support-agent", ["orders.get", "orders.refund"]), report: grant("report-agent", ["orders.get"]) };
});

afterAll(async () => {
  await host?.close();
  api.close();
  delete process.env.APP_API_AUTHORIZATION;
});

describe("deploy/gateway/example", () => {
  it("passes check --connect as the README sets it up, with the tools it describes", async () => {
    const findings = await checkConfig(configFile, { connect: true });
    expect(findings.filter((f) => f.level === "error")).toEqual([]);
    expect(findings.find((f) => f.check === "upstreams")?.message).toContain("orders.refund");
    expect(findings.find((f) => f.check === "tool names")?.level).toBe("ok");
  });

  it("the support agent refunds a delivered order within its total and the cap", async () => {
    host = await createGatewayHost(loadConfig(configFile));
    const r = await host.open(grants.support).handleCall({ name: "orders.refund", arguments: { order_id: "o-1", amount: 10000 } });
    expect(r.isError, text(r as { content: unknown[] })).toBeFalsy();
    expect(refunds).toEqual([{ amount: 10000 }]);
  });

  it("the policy refuses more than the order's total, more than the cap, and an order the gateway found not delivered", async () => {
    const support = host.open(grants.support);
    const before = refunds.length;
    for (const [order, amount] of [["o-1", 30000], ["o-2", 100]] as const) {
      const r = await support.handleCall({ name: "orders.refund", arguments: { order_id: order, amount } });
      expect(r.isError, `${order} ${amount}`).toBe(true);
      expect(text(r as { content: unknown[] })).toContain("Denied by policy");
    }
    expect(refunds.length).toBe(before);
  });

  it("the report agent's grant does not offer the refund tool, and a refund it tries anyway is denied", async () => {
    const report = host.open(grants.report);
    expect((await report.listTools()).map((t) => t.name)).toEqual(["orders.get"]);
    const r = await report.handleCall({ name: "orders.refund", arguments: { order_id: "o-1", amount: 100 } });
    expect(r.isError).toBe(true);
    expect(text(r as { content: unknown[] })).toContain("Denied");
  });

  it("a grant signed by a key the config does not list is refused when the agent connects", () => {
    const stranger = generateKeyPair();
    const forged = createDelegation(stranger, { version: "0.1", principal: "acme-support", agent: "support-agent", scopes: ["orders.refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    expect(() => host.open(forged)).toThrow(/rejected/);
  });
});

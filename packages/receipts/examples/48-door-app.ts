// Aspect: the door in-process, as Express middleware and as a Next.js route-handler wrapper. Source: src/door-app.ts, src/door.ts
// Run:    node examples/48-door-app.ts
//
// Tutorial 40 puts the door in front of a site as a reverse proxy. A Node site can run the same decision loop inside its
// own process instead: `app.use(door("door.json"))` in Express, or `export const POST = guard.route(handler)` in a
// Next.js App Router route. The config is the proxy's without `origin`. An allowed request reaches the app with the
// receipt id and the arrival's class in its headers and the grant removed; a refused one never reaches it; a refund is
// in the log before the app runs; and the receipt records the status and a digest of what the app answered.
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import express from "express";
import { loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { door } from "../src/door-app.ts";
import { CLASS_HEADER, RECEIPT_HEADER } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

step(1, "door.json without an origin: the door runs inside the app, so there is nothing to relay to");
const fx = buildDoorFixture(out("48-door-app"), "http://unused.invalid", { origin: undefined });
const config = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
console.log("   config keys:", Object.keys(config).join(", "));
const guard = door(fx.configFile);

step(2, "an Express shop: app.use(door) first, then express.json(), then the routes");
const ranAt: string[] = [];
const app = express();
app.use(guard);
app.use(express.json());
app.get("/catalogue/:item", (req, res) => {
  ranAt.push(`GET ${req.path} (${req.get(CLASS_HEADER)})`);
  res.json({ item: req.params.item, price: 4500 });
});
app.post("/refunds", (req, res) => {
  ranAt.push(`POST ${req.path} amount ${(req.body as { amount: number }).amount}, authorization header ${req.get("authorization") ? "PRESENT" : "absent"} (${req.get(CLASS_HEADER)})`);
  res.json({ refunded: (req.body as { amount: number }).amount });
});
const server: Server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const receipt = async (id: string) => {
  const file = join(fx.receiptsDir, `${id}.json`);
  // the receipt of an answer the app gave is written once the answer has gone out
  for (let i = 0; i < 200; i++) {
    try {
      return JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
    } catch {
      await new Promise((r) => setTimeout(r, 10));
    }
  }
  throw new Error(`no receipt ${id}`);
};
const show = async (label: string, res: Response) => {
  await res.text();
  const id = res.headers.get(RECEIPT_HEADER)!;
  const p = decode(await receipt(id)).predicate;
  const result = p.execution.status === "executed" || p.execution.status === "failed" ? ` app answered ${(p.execution.result as { status: number }).status}, ${(p.execution.result as { bodyBytes: number }).bodyBytes} bytes,` : "";
  console.log(`   ${label}: HTTP ${res.status}, class ${res.headers.get(CLASS_HEADER)}, ${p.execution.status},${result} framework ${p.issuer.framework}; receipt ${id.slice(0, 8)}`);
  return id;
};

step(3, "an unknown arrival reads the catalogue and is refused a refund; the app never sees the refusal");
const ids: string[] = [];
ids.push(await show("GET /catalogue/shoes  ", await fetch(`${base}/catalogue/shoes`)));
ids.push(await show("POST /refunds unknown ", await fetch(`${base}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_1", amount: 1000 }) })));

step(4, "an agent with a grant from the shop's principal refunds £45: in the log before the app runs, the grant stripped");
const grant = createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
const passport = { authorization: `Bearer ${grantHeader(grant)}`, "content-type": "application/json" };
ids.push(await show("POST /refunds £45     ", await fetch(`${base}/refunds`, { method: "POST", headers: passport, body: JSON.stringify({ order: "o_2", amount: 4500 }) })));
console.log("   what ran in the app:\n" + ranAt.map((r) => `     ${r}`).join("\n"));

step(5, "the same door wraps a Next.js App Router handler: app/api/refunds/route.ts exports guard.route(POST)");
const POST = guard.route(async (req: Request) => Response.json({ refunded: ((await req.json()) as { amount: number }).amount, via: "route handler" }));
ids.push(await show("route POST unknown    ", await POST(new Request("http://shop.example/refunds", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ amount: 100 }) }))));
ids.push(await show("route POST £10 agent  ", await POST(new Request("http://shop.example/refunds", { method: "POST", headers: passport, body: JSON.stringify({ amount: 1000 }) }))));

step(6, "every receipt verifies with the door's and the principal's public keys");
const keys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
const reports = await Promise.all(ids.map(async (id) => verifyBundle(await receipt(id), keys)));
console.log(`   ${reports.filter((r) => r.ok).length} of ${reports.length} verified`);

guard.close();
server.closeAllConnections();
await new Promise<void>((r) => server.close(() => r()));
if (!reports.every((r) => r.ok) || ranAt.length !== 2 || ranAt.some((r) => r.includes("PRESENT"))) throw new Error("the in-process door did not do what this tutorial says");
console.log("\nOK");

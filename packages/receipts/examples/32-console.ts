// Aspect: the admin console for a gateway. Source: src/console.ts, src/check.ts
// Run:    node examples/32-console.ts
//
// A gateway has been running and has made receipts. Its operator opens the console, which is a separate service with a
// token of its own: it shows the receipts and whether each verifies, replays them against a stricter policy before that
// policy is saved, saves it with the old one kept and the change recorded, inspects a grant and revokes it, and the
// gateway then refuses that grant. The console holds no principal key and signs nothing.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "../src/config.ts";
import { serveConsole } from "../src/console.ts";
import { createGateway, createGatewayHost } from "../src/gateway.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("32-console"));
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.revokedGrants = "revoked.json";
writeFileSync(fx.configFile, JSON.stringify(cfg));
const TOKEN = "demo-console-token";

step(1, "a gateway has been serving a support agent: two refunds, 25.00 (allowed) and one far over the limit (denied)");
const gw = await createGateway(loadConfig(fx.configFile));
await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 9_999_999 } });
await gw.close();

step(2, "the console starts as its own service, behind a token read from the environment");
const con = await serveConsole({ configFile: fx.configFile, token: TOKEN, port: 0, log: () => {} });
const api = async (path: string, method = "GET", body?: unknown, token: string | null = TOKEN) => {
  const r = await fetch(new URL(path, con.url), { method, headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: r.status, body: (await r.json()) as any };
};
console.log(`   ${con.url}  no token: ${(await api("/api/overview", "GET", undefined, null)).status}, wrong token: ${(await api("/api/overview", "GET", undefined, "nope")).status}, right token: ${(await api("/api/overview")).status}`);

step(3, "the overview and the receipts: what is configured, and every receipt with its decision and whether it verifies");
const overview = (await api("/api/overview")).body;
console.log(`   upstreams: ${overview.upstreams.map((u: { name: string; kind: string }) => `${u.name} (${u.kind})`).join(", ")}; trusted principal keys: ${overview.principals.length}; receipts: ${overview.receiptCount}`);
const receipts = (await api("/api/receipts")).body.receipts as { tool: string; decision: string; status: string; verified: boolean }[];
for (const r of receipts) console.log(`   ${r.tool}: ${r.decision} -> ${r.status}, verifies: ${r.verified}`);

step(4, "a stricter policy is replayed against the recorded calls before it is saved");
const current = (await api("/api/policy")).body;
const stricter = `// refunds of at most 10.00\npermit(principal, action == Action::"customer.lookup", resource);\npermit(principal, action == Action::"stripe.refund", resource) when { context.args.amount > 0 && context.args.amount <= 1000 };\n`;
const replay = (await api("/api/policy/simulate", "POST", { text: stricter })).body;
console.log(`   ${replay.replayed} receipts replayed; ${replay.report.changeCount} would change: ${replay.report.changes.map((c: { tool: string; from: string; to: string }) => `${c.tool} ${c.from} -> ${c.to}`).join(", ") || "none"}`);

step(5, "it is saved: the old version is kept, the change is in the audit trail, and a stale edit is refused");
const saved = await api("/api/policy", "PUT", { text: stricter, expectDigest: current.digest });
console.log(`   ${saved.body.note}`);
const stale = await api("/api/policy", "PUT", { text: `${stricter}// again\n`, expectDigest: current.digest });
console.log(`   a second edit from the old copy: ${stale.status} ${stale.body.error}`);
console.log(`   audit: ${(await api("/api/audit")).body.entries.map((e: { action: string }) => e.action).join(", ")}`);

step(6, "the operator inspects the support agent's grant and revokes it; the gateway refuses it from then on");
const grant = readFileSync(join(fx.dir, "grant.json"), "utf8");
const seen = (await api("/api/grants/inspect", "POST", { grant })).body;
console.log(`   before: ${seen.agent}, scopes ${seen.scopes.join(", ")}, ${seen.status}`);
await api("/api/grants/revoke", "POST", { grant });
console.log(`   after:  ${((await api("/api/grants/inspect", "POST", { grant })).body as { status: string }).status}`);
const host = await createGatewayHost(loadConfig(fx.configFile));
let refused = "";
try {
  host.open(JSON.parse(grant));
} catch (e) {
  refused = (e as Error).message;
}
await host.close();
console.log(`   the gateway: ${refused}`);

await con.close();
const ok =
  overview.receiptCount === 2 && receipts.every((r) => r.verified) && receipts.some((r) => r.decision === "deny") &&
  replay.report.changeCount === 1 && saved.status === 200 && stale.status === 409 && seen.status === "valid" && /revoked/.test(refused);
if (!ok) throw new Error("unexpected result");
console.log("\nOK");

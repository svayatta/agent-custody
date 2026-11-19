// Aspect: the door behind stock nginx or Envoy, answering their authz checks instead of relaying. Source: src/door.ts, src/config.ts
// Run:    node examples/47-door-authz.ts
//
// A site that already runs nginx (`auth_request`) or Envoy (`ext_authz`) keeps its proxy and its routing: the proxy asks
// the door about each request, with the original method and path in `X-Original-Method` and `X-Original-URI`, and
// relays it only on a 200. The door classifies the arrival, runs the Cedar policy, writes the receipt, and answers 200
// with the receipt id and class for the proxy to pass upstream, or 403. It never sees the body or the origin's answer,
// so its receipts record the decision, not the result, and say so: `issuer.framework` is `authz`, an allow is
// `withheld` (the door relayed nothing), and the verifier's `door authz decided, relayed nothing` check fails a receipt
// that claims more. This example plays the proxy with fetch; deploy/door/demo.sh runs the real nginx and Envoy.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { CLASS_HEADER, ORIGINAL_METHOD_HEADER, ORIGINAL_URI_HEADER, RECEIPT_HEADER, createDoorHost, serveDoor } from "../src/door.ts";
import { GRANT_HEADER, grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildDoorFixture } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

step(1, "a door with authz: true behind the proxy, no origin of its own, and a policy that reads who arrived (it never sees a body)");
const fx = buildDoorFixture(out("47-door-authz"), "http://unused.invalid", { authz: true, trustProxy: true });
const config = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
delete config.origin;
writeFileSync(fx.configFile, JSON.stringify(config, null, 2));
writeFileSync(join(fx.dir, "policy.cedar"), `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"refund", resource) when { context.facts.arrival.class == "verified" };
`);
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });
console.log("   door:", door.url, "(answering authz checks)");

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
/** What nginx's auth_request subrequest sends: its own GET to a fixed location, the original request in two headers, the client's other headers. */
const ask = async (label: string, method: string, uri: string, headers: Record<string, string> = {}) => {
  const res = await fetch(`${door.url}/_agent_custody`, { headers: { [ORIGINAL_METHOD_HEADER]: method, [ORIGINAL_URI_HEADER]: uri, "x-forwarded-for": "203.0.113.7", ...headers } });
  await res.arrayBuffer();
  const id = res.headers.get(RECEIPT_HEADER)!;
  const p = decode(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle).predicate;
  console.log(`   ${label}: HTTP ${res.status} (the proxy ${res.status === 200 ? "relays it" : "refuses it"}), class ${res.headers.get(CLASS_HEADER)}, route ${p.tool.name}, receipt ${p.execution.status}, framework ${p.issuer.framework}; receipt ${id.slice(0, 8)}`);
  return { res, id };
};

step(2, "the proxy asks about a catalogue read and an unknown arrival's refund");
const read = await ask("GET /catalogue/shoes", "GET", "/catalogue/shoes?colour=red");
const refused = await ask("POST /refunds      ", "POST", "/refunds");

step(3, "a verified agent's refund: a POST, so its authorization is in the log before the door answers 200");
const grant = createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
const refund = await ask("POST /refunds grant", "POST", "/refunds", { [GRANT_HEADER]: grantHeader(grant) });
console.log("   committed before the allow:", existsSync(join(fx.receiptsDir, `${refund.id}.authorization.json`)) ? "receipts/<id>.authorization.json is on disk" : "MISSING");

step(4, "a check that does not name the original request is refused, with no receipt: the door never decides on the proxy's own request");
const bare = await fetch(`${door.url}/catalogue/shoes`);
console.log(`   GET /catalogue/shoes with no X-Original-*: HTTP ${bare.status}, receipt header ${bare.headers.get(RECEIPT_HEADER) ?? "none"}`);

step(5, "the receipts verify, and the report says each records a decision, not the origin's answer");
const keys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
const reports = [read, refused, refund].map(({ id }) => verifyBundle(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")), keys));
const lines = formatReport(reports[2]!).split("\n");
console.log(lines.filter((l) => l.includes("door authz") || l.startsWith("RESULT") || l.startsWith("ISSUER") || l.startsWith("execution")).map((l) => "   " + l).join("\n"));

await door.close();
await host.close();
if (!reports.every((r) => r.ok) || bare.status !== 400 || read.res.status !== 200 || refused.res.status !== 403 || refund.res.status !== 200) throw new Error("the door did not answer the authz checks as expected");
console.log("\nOK");

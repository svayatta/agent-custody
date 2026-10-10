// Aspect: an agent delegating to an agent over A2A, with a receipt per delegation. Source: src/a2a.ts, src/gateway.ts
// Run:    node examples/25-a2a-delegation.ts
//
// An engagement agent hands work to a document agent over the A2A protocol, the way Google ADK's RemoteA2aAgent
// hands work to a remote agent. The gateway stands between them as an A2A agent itself: it serves the document
// agent's card with its own address, and every SendMessage becomes a `docs.send` call under the engagement lead's
// grant. The policy decides on a fact the gateway fetched itself, the document agent's card, and on the task text.
// An allowed delegation comes back as the document agent's task with the receipt id in its metadata; a refused one
// comes back rejected, with the reason and the receipt id, and the document agent never hears of it. Both verify.
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { A2A_CARD_PATH, A2A_RECEIPT_METADATA_KEY, serveA2a } from "../src/a2a.ts";
import { loadConfig } from "../src/config.ts";
import { loadPrivateKey, loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { createGatewayHost } from "../src/gateway.ts";
import type { ReceiptBundle } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

step(1, "a stand-in document agent that speaks A2A 1.0: a card, and SendMessage answered with a completed task");
let agentUrl = "";
const agent = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const json = (v: unknown) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(v));
    };
    if (req.method === "GET" && req.url === A2A_CARD_PATH) {
      return json({ name: "document_agent", description: "Reads and summarises engagement documents.", supportedInterfaces: [{ url: agentUrl, protocolBinding: "JSONRPC", protocolVersion: "1.0" }], version: "1", capabilities: { streaming: false }, defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"], skills: [{ id: "summarise", name: "Summarise", description: "Summarise the documents of one matter", tags: ["docs"] }] });
    }
    const { id, params } = JSON.parse(body) as { id: string; params: { message: { parts: { text?: string }[] } } };
    const asked = params.message.parts.map((p) => p.text ?? "").join("");
    json({ jsonrpc: "2.0", id, result: { id: "task-1", contextId: "ctx-1", status: { state: "TASK_STATE_COMPLETED", timestamp: new Date().toISOString() }, artifacts: [{ artifactId: "a1", parts: [{ text: `Summary of ${asked.replace(/^summarise /, "")}: three documents, two findings, no exceptions.` }] }] } });
  });
});
await new Promise<void>((r) => agent.listen(0, "127.0.0.1", r));
agentUrl = `http://127.0.0.1:${(agent.address() as { port: number }).port}`;
console.log("   document agent:", agentUrl);

step(2, "keys, the engagement lead's grant to the engagement agent, a policy that decides on the card and the task, and the gateway config");
const fx = buildFixture(out("25-a2a-delegation"));
const principalKey = loadPrivateKey(join(fx.dir, "keys", "principal.key"));
const now = Date.now();
const grant = createDelegation(principalKey, { version: "0.1", principal: "engagement_lead_12", agent: "engagement-agent", scopes: ["docs.send", "docs.card"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() });
writeFileSync(join(fx.dir, "grant.json"), JSON.stringify(grant, null, 2));
const policy = `// The card is a fact the gateway fetched itself: delegate only to the document agent, and never a privileged matter.
permit(principal, action == Action::"docs.card", resource);
permit(principal, action == Action::"docs.send", resource)
when {
  context.facts.card.name == "document_agent" &&
  !(context.args.text like "*privileged*")
};
`;
writeFileSync(join(fx.dir, "policy.cedar"), policy);
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.upstream = { a2a: { url: agentUrl, prefix: "docs" } };
cfg.facts = [{ name: "card", tool: "docs.card", args: {}, forTools: ["docs.send"] }];
cfg.precommit = ["docs.send"];
writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
console.log(policy.trim().split("\n").map((l) => `   ${l}`).join("\n"));

step(3, "the gateway as an A2A agent in front of the document agent; its card now carries the gateway's address");
const loaded = loadConfig(fx.configFile);
const host = await createGatewayHost(loaded);
const proxy = await serveA2a(host, (loaded.upstream as { a2a: Parameters<typeof serveA2a>[1] }).a2a, { port: 0, grant: grant as Envelope, log: () => {} });
const card = (await (await fetch(`${proxy.url}${A2A_CARD_PATH}`)).json()) as { name: string; supportedInterfaces: { url: string }[] };
console.log(`   ${card.name} via ${card.supportedInterfaces[0]!.url}   (an ADK RemoteA2aAgent would be given this card URL)`);

step(4, "the engagement agent delegates twice, as an A2A client would: one task is allowed, one is refused before the document agent hears of it");
const send = async (text: string) => {
  const res = await fetch(proxy.url, { method: "POST", headers: { "content-type": "application/json", "a2a-version": "1.0" }, body: JSON.stringify({ jsonrpc: "2.0", id: "1", method: "SendMessage", params: { message: { messageId: crypto.randomUUID(), role: "ROLE_USER", parts: [{ text }] } } }) });
  return ((await res.json()) as { result: { status: { state: string; message?: { parts: { text: string }[] } }; artifacts?: { parts: { text: string }[] }[]; metadata: Record<string, string> } }).result;
};
const allowed = await send("summarise the audit evidence for matter M-1042");
console.log(`   ${allowed.status.state}: ${allowed.artifacts![0]!.parts[0]!.text}`);
console.log(`   receipt ${allowed.metadata[A2A_RECEIPT_METADATA_KEY]}`);
const refused = await send("summarise the privileged legal memo for matter M-1042");
console.log(`   ${refused.status.state}: ${refused.status.message!.parts[0]!.text}`);
await proxy.close();
await host.close();
agent.close();

step(5, "both receipts verify with the public keys; the allowed one carries the card the gateway read and the authorization logged before the task went out");
let ok = true;
for (const id of [allowed.metadata[A2A_RECEIPT_METADATA_KEY]!, refused.metadata[A2A_RECEIPT_METADATA_KEY]!]) {
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
  const v = await verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
  const predicate = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()).predicate as { execution: { status: string }; facts: Record<string, { value: { name: string } }>; authorization?: unknown };
  console.log(`   ${id}: ${predicate.execution.status}, card fact = ${predicate.facts.card?.value.name ?? "none"}, authorization ${predicate.authorization ? "logged before the call" : "none"}`);
  console.log(formatReport(v).split("\n").filter((l) => /delegation|policy decision|authorization precedes|RESULT/.test(l)).map((l) => `      ${l}`).join("\n"));
  ok &&= v.ok;
}
if (!ok || allowed.status.state !== "TASK_STATE_COMPLETED" || refused.status.state !== "TASK_STATE_REJECTED") throw new Error("expected one completed and one rejected delegation, both verifying");
console.log("\nOK");

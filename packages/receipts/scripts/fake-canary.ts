// A stand-in upstream that repeats whatever it is given in every place a result can carry a value: the content, the
// structured content, the metadata, an error answer, a thrown message, and a provider's delivery body. The canary
// test drives it with a secret in the arguments and checks that the secret reaches nothing a capture rule guards.
// Behaviour is chosen by the arguments: a customer id starting with cust_throw makes the lookup throw, cust_error makes
// it answer isError; a refund with reason "throw" throws, "error" answers isError, anything else succeeds.
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { loadPrivateKey } from "../src/crypto.ts";
import { RECEIPT_META_KEY } from "../src/gateway.ts";
import { dsseSign } from "../src/crypto.ts";
import { attachProviderAttestation, contentDigest, stripeSignature, UPSTREAM_SIG_META_KEY, UPSTREAM_TYPE } from "../src/upstream.ts";

const tools = [
  { name: "customer.lookup", description: "Look up a customer", inputSchema: { type: "object", properties: { customer_id: { type: "string" } }, required: ["customer_id"] } },
  { name: "stripe.refund", description: "Refund a customer", inputSchema: { type: "object", properties: { customer_id: { type: "string" }, amount: { type: "number" }, reason: { type: "string" } }, required: ["customer_id", "amount"] } },
  { name: "stripe.payout", description: "Pay out", inputSchema: { type: "object", properties: { amount: { type: "number" } }, required: ["amount"] } },
];
const keyArg = process.argv.indexOf("--key");
const signingKey = keyArg >= 0 ? loadPrivateKey(process.argv[keyArg + 1]!) : null;
const secretArg = process.argv.indexOf("--webhook-secret");
const webhookSecret = secretArg >= 0 ? process.argv[secretArg + 1]! : null;

/** every place a result can carry a value, carrying the same text (and the record's fields, when there is a record) */
const everywhere = (text: string, isError = false, record: Record<string, unknown> = {}): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify({ ...record, said: text, [`key_${text}`]: true }) }], structuredContent: { ...record, said: text, [`key_${text}`]: true }, _meta: { "fake/trace": text, [`meta_${text}`]: true, "agent-custody/facts": [`fact:${text}`] }, isError, [`top_${text}`]: true } as CallToolResult);

function handle(name: string, a: Record<string, unknown>): CallToolResult {
  const id = String(a.customer_id ?? "");
  switch (name) {
    case "customer.lookup":
      if (id.startsWith("cust_throw")) throw new Error(`no customer ${id}`);
      if (id.startsWith("cust_error")) return everywhere(`no such customer ${id}`, true);
      return everywhere(`record of ${id}`, false, { id, email: `${id}@example.com`, verified: true });
    case "stripe.refund":
      if (a.reason === "throw") throw new Error(`refund declined for ${id}`);
      if (a.reason === "error") return everywhere(`refund refused for ${id}`, true);
      return everywhere(`refunded ${String(a.amount)} to ${id}`);
    case "stripe.payout":
      return everywhere(`paid ${String(a.amount)} to ${id}`);
    default:
      return everywhere(`unknown tool ${name}`, true);
  }
}

const server = new Server({ name: "fake-canary", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
  const args = (params.arguments ?? {}) as Record<string, unknown>;
  const result = handle(params.name, args);
  const receiptId = (params._meta as Record<string, unknown> | undefined)?.[RECEIPT_META_KEY];
  if (webhookSecret && params.name === "stripe.refund" && !result.isError) {
    const rawBody = JSON.stringify({ id: `evt_${randomUUID().slice(0, 8)}`, type: "charge.refunded", data: { object: { id: `re_${randomUUID().slice(0, 8)}`, object: "refund", customer: args.customer_id, status: "succeeded" } } });
    return attachProviderAttestation(result, { provider: "stripe-webhook", rawBody, signature: stripeSignature(rawBody, webhookSecret, Math.floor(Date.now() / 1000)), bind: "data.object.id" });
  }
  // the signed payload carries an extra claim with the id, as an upstream may: a valid attestation that repeats the secret
  if (signingKey && typeof receiptId === "string") {
    const payload = { receiptId, tool: params.name, contentDigest: contentDigest(result), customer_id: args.customer_id };
    return { ...result, _meta: { ...result._meta, [UPSTREAM_SIG_META_KEY]: dsseSign(UPSTREAM_TYPE, payload, signingKey) } };
  }
  return result;
});
await server.connect(new StdioServerTransport());

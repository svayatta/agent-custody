// A stand-in upstream MCP server: a customer directory and a payments API. Without --key nothing here is signed,
// which is exactly why the receipt marks its results "observed"; with --key it signs each result for the receipt the
// gateway named, and a verifier holding the key sees the execution as attested.
import { randomUUID } from "node:crypto";
import { loadPrivateKey } from "../src/crypto.ts";
import { RECEIPT_META_KEY } from "../src/gateway.ts";
import { attachProviderAttestation, signResult, stripeSignature } from "../src/upstream.ts";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult, type Tool } from "@modelcontextprotocol/sdk/types.js";

const CUSTOMERS: Record<string, { id: string; email: string; verified: boolean }> = {
  cust_123: { id: "cust_123", email: "alex@example.com", verified: true },
  cust_999: { id: "cust_999", email: "sam@example.com", verified: false },
};

const tools: Tool[] = [
  {
    name: "customer.lookup",
    description: "Look up a customer record",
    inputSchema: { type: "object", properties: { customer_id: { type: "string" } }, required: ["customer_id"] },
  },
  {
    name: "stripe.refund",
    description: "Refund a customer. amount is in minor units (pence).",
    inputSchema: { type: "object", properties: { customer_id: { type: "string" }, amount: { type: "integer" } }, required: ["customer_id", "amount"] },
  },
  {
    name: "stripe.payout",
    description: "Pay out funds to the connected bank account. amount in minor units.",
    inputSchema: { type: "object", properties: { amount: { type: "integer" } }, required: ["amount"] },
  },
];

const json = (v: unknown): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(v) }] });
const fail = (msg: string): CallToolResult => ({ isError: true, content: [{ type: "text", text: msg }] });

const keyArg = process.argv.indexOf("--key");
const signingKey = keyArg >= 0 ? loadPrivateKey(process.argv[keyArg + 1]!) : null;
// With --webhook-secret, refunds carry the webhook Stripe would send for them, signed the way Stripe signs it.
const secretArg = process.argv.indexOf("--webhook-secret");
const webhookSecret = secretArg >= 0 ? process.argv[secretArg + 1]! : null;

const server = new Server({ name: "fake-stripe", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
  const result = handle(params.name, (params.arguments ?? {}) as Record<string, unknown>);
  const receiptId = (params._meta as Record<string, unknown> | undefined)?.[RECEIPT_META_KEY];
  if (webhookSecret && params.name === "stripe.refund" && !result.isError) {
    const refund = JSON.parse((result.content[0] as { text: string }).text) as { refund_id: string; amount: unknown };
    const rawBody = JSON.stringify({ id: `evt_${randomUUID().slice(0, 8)}`, type: "charge.refunded", data: { object: { id: refund.refund_id, object: "refund", amount: refund.amount, status: "succeeded" } } });
    return attachProviderAttestation(result, { provider: "stripe-webhook", rawBody, signature: stripeSignature(rawBody, webhookSecret, Math.floor(Date.now() / 1000)), bind: "data.object.id" });
  }
  return signingKey && typeof receiptId === "string" ? signResult(result, signingKey, receiptId, params.name) : result;
});

function handle(name: string, a: Record<string, unknown>): CallToolResult {
  switch (name) {
    case "customer.lookup": {
      // an id starting with cust_throw makes the server throw, as many MCP servers do on a failure, instead of answering isError
      if (String(a.customer_id).startsWith("cust_throw")) throw new Error(`no customer ${String(a.customer_id)}`);
      const c = CUSTOMERS[String(a.customer_id)];
      return c ? json(c) : fail(`no such customer ${String(a.customer_id)}`);
    }
    case "stripe.refund":
      if (a.reason === "decline") throw new Error(`refund declined for ${String(a.customer_id)}`);
      return json({ refund_id: `re_${randomUUID().slice(0, 8)}`, customer_id: a.customer_id, amount: a.amount, status: "succeeded" });
    case "stripe.payout":
      return json({ payout_id: `po_${randomUUID().slice(0, 8)}`, amount: a.amount, status: "paid" });
    default:
      return fail(`unknown tool ${name}`);
  }
}
await server.connect(new StdioServerTransport());

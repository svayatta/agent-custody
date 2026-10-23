// A persistent, simulated billing service. No provider credentials and no real money.
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { loadPrivateKey, RECEIPT_META_KEY, signResult } from "@agent-custody/receipts";
import { z } from "zod";

export interface Credit {
  id: string;
  amount: number;
  status: "active" | "reversed";
  receiptId: string;
  reversalReceiptId?: string;
}
export interface BillingState { customer_id: string; currency: "GBP"; credits: Credit[] }
export const readBilling = (dir: string): BillingState => JSON.parse(readFileSync(join(dir, "billing.json"), "utf8"));
const json = (value: unknown): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(value) }] });

export function billingCall(dir: string, tool: string, args: unknown, receiptId: string): CallToolResult {
  if (!receiptId) throw new Error("billing requires a gateway receipt id");
  const state = readBilling(dir);
  const customer = z.object({ customer_id: z.literal("cust_123") });
  if (tool === "billing.account") {
    customer.strict().parse(args);
    return json({ ...state, active_credit: state.credits.filter(c => c.status === "active").reduce((sum, c) => sum + c.amount, 0) });
  }
  if (tool === "billing.credit") {
    const a = customer.extend({ incident_id: z.literal("INC-42"), amount: z.number().int().positive().max(2500) }).strict().parse(args);
    // One credit per incident, even if the client retries after a lost reply.
    if (!state.credits.length) state.credits.push({ id: `cr_${randomUUID()}`, amount: a.amount, status: "active", receiptId });
    writeFileSync(join(dir, "billing.json"), JSON.stringify(state, null, 2) + "\n");
    return json({ simulated: true, credit: state.credits[0] });
  }
  if (tool === "billing.reverseCredit") {
    const a = z.object({ credit_id: z.string(), reason: z.string().min(1) }).strict().parse(args);
    const credit = state.credits.find(c => c.id === a.credit_id);
    if (!credit) throw new Error("unknown credit");
    if (credit.status !== "reversed") {
      credit.status = "reversed";
      credit.reversalReceiptId = receiptId;
      writeFileSync(join(dir, "billing.json"), JSON.stringify(state, null, 2) + "\n");
    }
    return json({ simulated: true, credit });
  }
  throw new Error(`unknown billing tool ${tool}`);
}

async function serve(dir: string) {
  const key = loadPrivateKey(join(dir, "keys", "billing.key"));
  const server = new Server({ name: "simulated-billing", version: "1.0.0" }, { capabilities: { tools: {} } });
  const customer = { customer_id: { type: "string", enum: ["cust_123"] } };
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
    { name: "billing.account", description: "Read this demo account's simulated GBP credits; amounts are integer pence.", inputSchema: { type: "object", properties: customer, required: ["customer_id"], additionalProperties: false } },
    { name: "billing.credit", description: "Apply a simulated service credit for INC-42. Integer pence, at most 2500. Idempotent: one credit per incident.", inputSchema: { type: "object", properties: { ...customer, incident_id: { type: "string", enum: ["INC-42"] }, amount: { type: "integer", minimum: 1, maximum: 2500 } }, required: ["customer_id", "incident_id", "amount"], additionalProperties: false } },
    { name: "billing.reverseCredit", description: "Operator compensation: reverse an existing simulated credit, preserving the original record. Idempotent.", inputSchema: { type: "object", properties: { credit_id: { type: "string" }, reason: { type: "string" } }, required: ["credit_id", "reason"], additionalProperties: false } },
  ] }));
  server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
    const receiptId = params._meta?.[RECEIPT_META_KEY];
    if (typeof receiptId !== "string") return { isError: true, content: [{ type: "text", text: "gateway receipt required" }] };
    let result: CallToolResult;
    try { result = billingCall(dir, params.name, params.arguments ?? {}, receiptId); }
    catch (error) { result = { isError: true, content: [{ type: "text", text: String(error) }] }; }
    return signResult(result, key, receiptId, params.name);
  });
  await server.connect(new StdioServerTransport());
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { values } = parseArgs({ options: { dir: { type: "string" } } });
  if (!values.dir) throw new Error("billing.ts --dir <demo directory>");
  await serve(values.dir);
}

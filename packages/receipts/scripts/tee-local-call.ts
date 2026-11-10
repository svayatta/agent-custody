// One tool call through a gateway over HTTP, for deploy/gateway/tee/local-simulated.sh: prints the receipt id.
// Usage: node scripts/tee-local-call.ts <gateway url> <grant.json> <tool> [<json arguments>]
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { grantHeader } from "../src/gateway-http.ts";
import { RECEIPT_META_KEY } from "../src/gateway.ts";

const [url, grantFile, tool, args] = process.argv.slice(2);
if (!url || !grantFile || !tool) throw new Error("usage: tee-local-call.ts <gateway url> <grant.json> <tool> [<json arguments>]");
const client = new Client({ name: "tee-local", version: "0" });
await client.connect(new StreamableHTTPClientTransport(new URL("/mcp", url), { requestInit: { headers: { authorization: `Bearer ${grantHeader(JSON.parse(readFileSync(grantFile, "utf8")))}` } } }));
const res = await client.callTool({ name: tool, arguments: args ? JSON.parse(args) : {} });
await client.close();
const id = res._meta?.[RECEIPT_META_KEY];
if (typeof id !== "string") throw new Error(`the gateway answered without a receipt id: ${JSON.stringify(res).slice(0, 300)}`);
console.log(id);

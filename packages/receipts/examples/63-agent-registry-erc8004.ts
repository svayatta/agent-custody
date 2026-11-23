// Aspect: linking a registered agent to its ERC-8004 identity, checked on chain by the registry and carried in its passport. Source: src/erc8004.ts, src/registry.ts, src/portal.ts
// Run:    node examples/63-agent-registry-erc8004.ts
//
// An agent-commerce company already has its shopping agent in an ERC-8004 Identity Registry: token 7 on Base, whose
// registration file lists the agent's did:key as a DID service. It registers the agent on the portal and links that
// token. The registry reads the chain and the file, and stores the link only because they agree; a link to a token
// whose file names another key is refused. Every passport then carries the link, so a door's policy can require an
// on-chain identity without the door reading any chain. The chain and the file host are stand-ins on this machine.
import { PGlite } from "@electric-sql/pglite";
import { generateKeyPair } from "../src/crypto.ts";
import { didKeyOf } from "../src/did-key.ts";
import { createErc8004Resolver, ERC8004_REGISTRATION_TYPE } from "../src/erc8004.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { servePortal } from "../src/portal.ts";
import { verifyPassport } from "../src/registry.ts";
import { localSigner } from "../src/signer.ts";
import { step } from "./_out.ts";

const REGISTRY = "0x0000000000000000000000000000000000008004";
const AGENT_REGISTRY = `eip155:8453:${REGISTRY}`;
const OWNER = "0x00000000000000000000000000000000000000b0";

step(1, "a stand-in Base node and file host: token 7's file lists the agent's did:key, token 8's lists someone else's");
const agentKey = generateKeyPair();
const did = didKeyOf(agentKey.publicKey);
const file = (id: number, key: string) => JSON.stringify({ type: ERC8004_REGISTRATION_TYPE, name: "Carted shopper", description: "Returns things for Carted's customers", image: "https://carted.example/a.png", services: [{ name: "DID", endpoint: key }], x402Support: false, active: true, registrations: [{ agentId: id, agentRegistry: AGENT_REGISTRY }], supportedTrust: [] });
const files: Record<string, string> = { "https://carted.example/7.json": file(7, did), "https://carted.example/8.json": file(8, didKeyOf(generateKeyPair().publicKey)) };
const abiString = (s: string) => { const h = Buffer.from(s).toString("hex"); return `0x${"20".padStart(64, "0")}${(h.length / 2).toString(16).padStart(64, "0")}${h.padEnd(Math.ceil(h.length / 64) * 64, "0")}`; };
const chain: typeof fetch = async (_url, init) => {
  const { method, params } = JSON.parse(String(init?.body)) as { method: string; params: [{ data: string }] };
  const result = method === "eth_blockNumber" ? "0x1a2b3c"
    : params[0].data.startsWith("0x6352211e") ? `0x${OWNER.slice(2).padStart(64, "0")}`
    : abiString(`https://carted.example/${BigInt(`0x${params[0].data.slice(10)}`)}.json`);
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), { headers: { "content-type": "application/json" } });
};
const erc8004 = createErc8004Resolver({ rpc: { "8453": "https://base.example/" }, fetch: chain, fetchFile: async (url) => Buffer.from(files[url] ?? "") });

step(2, "the portal's registry reads Base through that node");
const db = new PGlite();
const registryKey = generateKeyPair();
const portal = await servePortal({ tenancy: new PostgresTenancy(db), client: db, secret: "an-example-session-secret-of-32-chars", publicUrl: "https://log.example.test/", portalUrl: "https://app.example.test/", registry: { signer: localSigner(registryKey), erc8004 }, log: () => {} }, { port: 0 });
let cookie = "";
const call = async (path: string, body: unknown) => {
  const res = await fetch(new URL(path, portal.url), { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const set = res.headers.get("set-cookie");
  if (set) cookie = set.split(";")[0]!;
  return { status: res.status, json: (await res.json()) as any };
};
await call("/api/register", { email: "ops@carted.example", password: "a-long-enough-password", tenant: "carted", name: "Ana", company: "Carted" });

step(3, "the company registers its agent and links token 7: the chain and the file agree");
const expiresAt = new Date(Date.now() + 90 * 86_400_000).toISOString();
const linked = await call("/api/agents", { name: "Carted shopper", contact: "agents@carted.example", capabilities: ["refunds"], agent: did, expiresAt, erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "7" } });
const l = linked.json.agent.erc8004;
console.log(`   ${linked.status}: linked to ${l.agentRegistry} token ${l.agentId}, owner ${l.owner}, read at block ${l.block}`);
const v = verifyPassport(linked.json.passport, [registryKey], new Date().toISOString());
console.log(`   the passport carries it: ${v.ok ? JSON.stringify(v.passport.erc8004) : v.error}`);

step(4, "a link to token 8, whose file names another key, is refused");
const refused = await call("/api/agents", { name: "Impostor", contact: "x@carted.example", agent: didKeyOf(generateKeyPair().publicKey), expiresAt, erc8004: { agentRegistry: AGENT_REGISTRY, agentId: "8" } });
console.log(`   ${refused.status}: ${refused.json.error}`);

await portal.close();
await db.close();
if (linked.status !== 200 || l.agentId !== "7" || l.owner !== OWNER || !v.ok || v.passport.erc8004?.agentId !== "7" || refused.status !== 400 || !String(refused.json.error).includes("no DID service")) throw new Error("the ERC-8004 link did not behave as described");
console.log("\nOK");

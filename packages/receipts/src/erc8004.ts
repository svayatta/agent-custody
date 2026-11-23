// An ERC-8004 identity for a registered agent. The registry links an agent to its token in an ERC-8004 Identity
// Registry only when the chain and the token's registration file agree with the registry's own entry: the token
// exists, its registration file is a v1 file that is active, names that very token among its registrations, and lists
// the agent's did:key as a DID service. The check runs on the registry, never at the door: a door reads the link from
// the passport the registry signed. The chain is read through JSON-RPC (eth_call at one block), and the file is
// fetched once, over https or through a configured IPFS gateway, with a timeout and a size cap, never from an internal
// address. ERC-8004 is a draft, so only the registration-v1 file type is accepted.
import { request as httpsRequest } from "node:https";
import { z } from "zod";
import { sha256Hex } from "./crypto.ts";
import { internalAddress, isAddressLiteral } from "./addresses.ts";
import { publicOnlyLookup } from "./egress.ts";

export { ERC8004_REGISTRATION_TYPE, ERC8004_REGISTRY, Erc8004LinkSchema, type Erc8004Check, type Erc8004Checked, type Erc8004Link } from "./erc8004-link.ts";
import { ERC8004_REGISTRATION_TYPE, ERC8004_REGISTRY, type Erc8004Check, type Erc8004Checked, type Erc8004Link } from "./erc8004-link.ts";

export interface Erc8004ResolverOptions {
  /** a JSON-RPC URL for each chain id the registry reads; from the environment, since a provider's URL often carries its key */
  rpc: Record<string, string>;
  /** an https IPFS gateway (`https://ipfs.io`); without one an `ipfs://` registration file is refused */
  ipfsGateway?: string;
  timeoutMs?: number;
  maxFileBytes?: number;
  /** for the JSON-RPC calls; the global fetch by default */
  fetch?: typeof fetch;
  /** fetches an https registration file; by default over node:https, refusing internal addresses and redirects. For tests */
  fetchFile?: (url: string, o: { timeoutMs: number; maxBytes: number; signal: AbortSignal }) => Promise<Buffer>;
}

export interface Erc8004Resolver {
  /** the chain ids it has an RPC URL for */
  chains: string[];
  check(link: Erc8004Link, didKey: string, now?: Date): Promise<Erc8004Check>;
}

const OWNER_OF = "0x6352211e";
const TOKEN_URI = "0xc87b56dd";
const word = (n: bigint) => n.toString(16).padStart(64, "0");

class ChainError extends Error {}

/** The string an ABI-encoded `string` return value holds; throws when the encoding does not hold together. */
export function decodeAbiString(hex: string, maxBytes: number): string {
  const h = hex.replace(/^0x/, "");
  if (!/^[0-9a-f]*$/i.test(h) || h.length < 128) throw new ChainError("the answer is not an ABI-encoded string");
  const offset = Number.parseInt(h.slice(0, 64), 16) * 2;
  const length = Number.parseInt(h.slice(offset, offset + 64), 16);
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset + 64 > h.length) throw new ChainError("the answer is not an ABI-encoded string");
  if (length > maxBytes) throw new ChainError(`the token URI is longer than ${maxBytes} bytes`);
  const data = h.slice(offset + 64, offset + 64 + length * 2);
  if (data.length !== length * 2) throw new ChainError("the answer is shorter than the string it encodes");
  return Buffer.from(data, "hex").toString("utf8");
}

/** An https GET that never dials an internal address for a host name, follows no redirect, and stops at the size cap. */
function httpsFile(url: string, o: { timeoutMs: number; maxBytes: number; signal: AbortSignal }): Promise<Buffer> {
  // an address literal is never looked up, so the lookup's filter does not see it
  const host = new URL(url).hostname.replace(/^\[|\]$/g, "");
  if (isAddressLiteral(host) && internalAddress(host)) return Promise.reject(new Error(`${host} is an internal address; the registry does not fetch from it`));
  return new Promise((resolve, reject) => {
    const req = httpsRequest(url, { method: "GET", headers: { accept: "application/json" }, lookup: publicOnlyLookup(), timeout: o.timeoutMs, signal: o.signal }, (res) => {
      if ((res.statusCode ?? 0) >= 300) {
        res.resume();
        return reject(new Error(`${url} answered ${res.statusCode}${res.headers.location ? `, a redirect, which the registry does not follow` : ""}`));
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > o.maxBytes) {
          req.destroy();
          reject(new Error(`${url} is larger than ${o.maxBytes} bytes`));
        } else chunks.push(c);
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error(`${url} did not answer within ${o.timeoutMs} ms`)));
    req.on("error", reject);
    req.end();
  });
}

const RegistrationSchema = z.object({
  type: z.literal(ERC8004_REGISTRATION_TYPE),
  active: z.boolean(),
  services: z.array(z.object({ name: z.string(), endpoint: z.string() }).passthrough()).max(256),
  registrations: z.array(z.object({ agentId: z.union([z.string(), z.number()]), agentRegistry: z.string() }).passthrough()).max(256),
}).passthrough();

export function createErc8004Resolver(o: Erc8004ResolverOptions): Erc8004Resolver {
  const timeoutMs = o.timeoutMs ?? 5_000;
  const maxFileBytes = o.maxFileBytes ?? 64 * 1024;
  const f = o.fetch ?? fetch;
  const fetchFile = o.fetchFile ?? httpsFile;
  // `timeout` on node:https is the socket's idle time, so a host that sends a byte now and then would never trip it;
  // the whole fetch ends at the deadline, whatever the fetcher does with the signal
  const fileWithin = (url: string): Promise<Buffer> => {
    const signal = AbortSignal.timeout(timeoutMs);
    const late = new Promise<never>((_, reject) => {
      const stop = () => reject(new Error(`${url} did not finish within ${timeoutMs} ms`));
      if (signal.aborted) stop();
      else signal.addEventListener("abort", stop, { once: true });
    });
    return Promise.race([fetchFile(url, { timeoutMs, maxBytes: maxFileBytes, signal }), late]);
  };
  for (const [chain, url] of Object.entries(o.rpc)) {
    if (!/^[1-9][0-9]{0,11}$/.test(chain)) throw new Error(`ERC-8004: "${chain}" is not a chain id`);
    if (!/^https?:\/\//.test(url)) throw new Error(`ERC-8004: the RPC URL for chain ${chain} is not http(s)`);
  }
  if (o.ipfsGateway && !o.ipfsGateway.startsWith("https://")) throw new Error("ERC-8004: the IPFS gateway must be https");
  const gateway = o.ipfsGateway?.replace(/\/+$/, "");

  const rpc = async (url: string, method: string, params: unknown[]): Promise<string> => {
    let res: Response;
    try {
      res = await f(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      throw new ChainError(`the chain's RPC could not be reached: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!res.ok) throw new ChainError(`the chain's RPC answered ${res.status}`);
    const body = (await res.json().catch(() => null)) as { result?: unknown; error?: { message?: unknown } } | null;
    if (body?.error) throw new ChainError(`the chain refused ${method}: ${String(body.error.message ?? "no message").slice(0, 200)}`);
    if (typeof body?.result !== "string") throw new ChainError(`the chain's answer to ${method} is not a hex string`);
    return body.result;
  };

  /** The registration file's bytes for a token URI: inline, over https, or through the IPFS gateway. */
  const fileOf = async (uri: string): Promise<Buffer> => {
    const inline = /^data:application\/json(;charset=utf-8)?(;base64)?,(.*)$/is.exec(uri);
    if (inline) {
      const bytes = inline[2] ? Buffer.from(inline[3]!, "base64") : Buffer.from(decodeURIComponent(inline[3]!), "utf8");
      if (bytes.length > maxFileBytes) throw new Error(`the inline registration file is larger than ${maxFileBytes} bytes`);
      return bytes;
    }
    if (uri.startsWith("ipfs://")) {
      if (!gateway) throw new Error("the registration file is on IPFS, and this registry has no IPFS gateway configured");
      const path = uri.slice("ipfs://".length).replace(/^ipfs\//, "");
      const [cid, ...segments] = path.split("/");
      // the token's owner writes this path: a "." or ".." segment would climb out of /ipfs/ to any path on the gateway
      if (!cid || !/^[A-Za-z0-9]+$/.test(cid) || segments.some((p) => !/^[A-Za-z0-9._~-]+$/.test(p) || p === "." || p === "..")) throw new Error("the IPFS URI is not a CID and a path of plain segments");
      const prefix = `${new URL(gateway).pathname.replace(/\/+$/, "")}/ipfs/${cid}`;
      const url = new URL(`${gateway}/ipfs/${path}`);
      if (url.origin !== new URL(gateway).origin || (url.pathname !== prefix && !url.pathname.startsWith(`${prefix}/`))) throw new Error("the IPFS URI leaves the gateway's /ipfs/ path");
      return fileWithin(url.toString());
    }
    if (uri.startsWith("https://")) {
      const u = new URL(uri);
      if (u.username || u.password) throw new Error("the registration file's URL carries credentials");
      return fileWithin(u.toString());
    }
    throw new Error(`the token URI is not https, ipfs, or an inline JSON data URI: ${uri.slice(0, 60)}`);
  };

  async function check(link: Erc8004Link, didKey: string, now = new Date()): Promise<Erc8004Check> {
    const m = ERC8004_REGISTRY.exec(link.agentRegistry);
    if (!m) return { ok: false, error: "agentRegistry is not eip155:<chain id>:<registry address>" };
    const [, chain, registry] = m;
    const url = o.rpc[chain!];
    if (!url) return { ok: false, error: `this registry reads no ERC-8004 registry on chain ${chain}; it reads chains ${Object.keys(o.rpc).join(", ") || "none"}` };
    const token = word(BigInt(link.agentId));
    try {
      const blockHex = await rpc(url, "eth_blockNumber", []);
      const block = Number.parseInt(blockHex, 16);
      if (!Number.isSafeInteger(block)) throw new ChainError("the chain's block number is not a number");
      let ownerWord: string;
      try {
        ownerWord = await rpc(url, "eth_call", [{ to: registry, data: `${OWNER_OF}${token}` }, blockHex]);
      } catch (e) {
        if (e instanceof ChainError && e.message.startsWith("the chain refused")) return { ok: false, error: `token ${link.agentId} does not exist in ${link.agentRegistry} (${e.message})` };
        throw e;
      }
      const owner = `0x${ownerWord.replace(/^0x/, "").slice(-40)}`.toLowerCase();
      if (!/^0x[0-9a-f]{40}$/.test(owner) || /^0x0{40}$/.test(owner)) return { ok: false, error: `token ${link.agentId} in ${link.agentRegistry} has no owner` };
      const uri = decodeAbiString(await rpc(url, "eth_call", [{ to: registry, data: `${TOKEN_URI}${token}` }, blockHex]), Math.ceil(maxFileBytes * 1.4) + 64);
      let bytes: Buffer;
      try {
        bytes = await fileOf(uri.trim());
      } catch (e) {
        return { ok: false, error: `the registration file could not be read: ${e instanceof Error ? e.message : String(e)}` };
      }
      let raw: unknown;
      try {
        raw = JSON.parse(bytes.toString("utf8"));
      } catch {
        return { ok: false, error: "the registration file is not JSON" };
      }
      const parsed = RegistrationSchema.safeParse(raw);
      if (!parsed.success) return { ok: false, error: `the registration file is not an ERC-8004 registration-v1 file: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "file"} ${i.message}`).join("; ")}` };
      const file = parsed.data;
      if (!file.active) return { ok: false, error: "the registration file says the agent is not active" };
      if (!file.registrations.some((r) => String(r.agentId) === link.agentId && r.agentRegistry.toLowerCase() === link.agentRegistry)) return { ok: false, error: `the registration file does not list token ${link.agentId} of ${link.agentRegistry} among its registrations` };
      if (!file.services.some((s) => s.name === "DID" && s.endpoint === didKey)) return { ok: false, error: `the registration file lists no DID service with the agent's key ${didKey}` };
      return { ok: true, link: { agentRegistry: link.agentRegistry, agentId: link.agentId, owner, block, fileDigest: sha256Hex(bytes), checkedAt: now.toISOString() } };
    } catch (e) {
      if (e instanceof ChainError) return { ok: false, error: e.message };
      throw e;
    }
  }

  return { chains: Object.keys(o.rpc), check };
}

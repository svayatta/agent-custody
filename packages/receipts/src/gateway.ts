// The MCP gateway: sits between an agent and its upstreams, MCP servers or REST APIs, enforces scope + Cedar policy,
// and emits a signed, logged receipt for every tool call, allowed or denied.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult, type Tool } from "@modelcontextprotocol/sdk/types.js";
import type { FactConfig, GatewayConfig, UpstreamConfig } from "./config.ts";
import { digestOf, loadPrivateKey, loadPublicKey, type Envelope } from "./crypto.ts";
import { delegationValidAt, verifyDelegation, type Delegation } from "./delegation.ts";
import { createIssuer } from "./issue.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { openExporter, type ReceiptExporter } from "./otel.ts";
import { upstreamEvidenceOf } from "./upstream.ts";
import { restUpstream, type UpstreamClient } from "./rest.ts";
import { a2aUpstream } from "./a2a.ts";
import { evaluate, policyDigest, type PolicyDecision } from "./policy.ts";
import type { AuthorizationBundle, FactRecord, ReceiptPredicate } from "./receipt.ts";

export const GATEWAY_VERSION = "0.1.0";
export const RECEIPT_META_KEY = "agent-custody/receipt";
export const MODEL_META_KEY = "agent-custody/model";
/** Set by the gateway on the call it forwards upstream: the receipt id, and the agent and principal from the attested grant. */
export const AGENT_META_KEY = "agent-custody/agent";
export const PRINCIPAL_META_KEY = "agent-custody/principal";
/** Set by the gateway on the forwarded call: the values of the facts it fetched itself for this call, by name, so an upstream can check a claimed value against what the gateway observed. */
export const OBSERVED_META_KEY = "agent-custody/observed";
/** Set by an upstream on its result: the ids of the facts it served in this call. The gateway remembers them for the session. */
export const FACTS_META_KEY = "agent-custody/facts";

export interface CallParams {
  name: string;
  arguments?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
}

export interface Gateway {
  agentId: string;
  delegation: Delegation;
  listTools(): Promise<Tool[]>;
  handleCall(params: CallParams): Promise<CallToolResult>;
  close(): Promise<void>;
}

/** Returns null when an optional lookup references a call argument that is absent. */
function resolveFactArgs(template: Record<string, string>, args: Record<string, unknown>, optional = false): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(template)) {
    if (v.startsWith("$args.")) {
      const key = v.slice("$args.".length);
      if (!(key in args) || args[key] === undefined) {
        if (optional) return null;
        throw new Error(`fact argument "${k}" needs call argument "${key}", which is missing`);
      }
      out[k] = args[key];
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** First text content item, JSON-parsed when possible. Tool results carry no signature, so this is "observed", never "attested". */
function extractValue(result: CallToolResult): unknown {
  const text = result.content.find((c) => c.type === "text");
  if (!text || text.type !== "text") return null;
  try {
    return JSON.parse(text.text);
  } catch {
    return text.text;
  }
}

/**
 * The environment a stdio upstream is started with: what a child process needs to run, plus what the config names.
 * Never the gateway's own environment, which holds the tokens other upstreams and the log are given. An explicit
 * `env` in the config is added to this base, not to the gateway's variables.
 */
export function upstreamEnv(extra?: Record<string, string>): Record<string, string> {
  const base: Record<string, string> = {};
  for (const k of ["PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SystemRoot", "SYSTEMROOT", "USERPROFILE", "APPDATA", "NODE_OPTIONS"]) {
    const v = process.env[k];
    if (v !== undefined) base[k] = v;
  }
  return { ...base, ...(extra ?? {}) };
}

export interface GatewayOptions {
  /** the log to append to, in place of the one the config names; for embedding and tests */
  log?: LogSink;
  /** told about every receipt after it is written, in place of the exporter the config names */
  exporter?: ReceiptExporter;
}

/**
 * The shared part of a gateway: the key, the policy, the issuer, the log, the upstreams, and the fact lookups. One host
 * serves many sessions, each opened with its own grant; over stdio there is exactly one, over HTTP one per connection.
 */
export interface GatewayHost {
  keyid: string;
  /** a session for this grant: the grant is verified against the trusted principal keys and its validity window first */
  open(grantEnvelope: Envelope): Gateway;
  /** closes the upstreams; every session opened from this host is finished with */
  close(): Promise<void>;
}

export async function createGatewayHost(cfg: GatewayConfig, options: GatewayOptions = {}): Promise<GatewayHost> {
  const gatewayKey = loadPrivateKey(cfg.identity.keyFile);
  const trusted = cfg.trustedPrincipalKeys.map(loadPublicKey);
  const policyText = readFileSync(cfg.policyFile, "utf8");
  const pDigest = policyDigest(policyText);
  const issuer = createIssuer(gatewayKey, cfg.receiptsDir, options.log ?? openLog(cfg, gatewayKey), { exporter: options.exporter ?? openExporter(cfg) });
  const precommit = new Set(cfg.precommit);
  const consequential = (tool: string) => precommit.has("*") || precommit.has(tool);
  // A fact lookup runs before the policy can decide, because the policy decides on it. It is therefore a read the
  // gateway makes on the agent's request, never a consequential call: a fact tool named in precommit is a config error.
  // "*" covers the tools the agent calls; a lookup is the gateway's own read, so only an explicit name makes it consequential.
  for (const f of cfg.facts) {
    if (precommit.has(f.tool)) throw new Error(`fact "${f.name}" uses tool ${f.tool}, which precommit names as consequential; a fact lookup runs before the policy decides and must be a read`);
  }

  // One host, as many upstreams as the agents' jobs need. Each tool name belongs to exactly one upstream, decided at
  // startup, so a receipt's tool is unambiguous and consumed facts flow across them.
  const upstreamConfigs: { name: string; cfg: UpstreamConfig }[] = cfg.upstreams ? cfg.upstreams.map((u) => ({ name: u.name, cfg: u })) : [{ name: "upstream", cfg: cfg.upstream! }];
  const upstreams = new Map<string, UpstreamClient>();
  const owner = new Map<string, string>();
  const advertised: Tool[] = [];
  for (const { name, cfg: u } of upstreamConfigs) {
    let client: UpstreamClient;
    if ("rest" in u) {
      client = restUpstream(name, u.rest);
    } else if ("a2a" in u) {
      client = a2aUpstream(name, u.a2a);
    } else if ("url" in u) {
      client = new Client({ name: "agent-custody-gateway", version: GATEWAY_VERSION });
      const token = u.tokenEnv ? process.env[u.tokenEnv] : undefined;
      if (u.tokenEnv && !token) throw new Error(`upstream ${name}: environment variable ${u.tokenEnv} is not set`);
      await (client as Client).connect(new StreamableHTTPClientTransport(new URL(u.url), token ? { requestInit: { headers: { authorization: `Bearer ${token}` } } } : {}));
    } else {
      client = new Client({ name: "agent-custody-gateway", version: GATEWAY_VERSION });
      await (client as Client).connect(new StdioClientTransport({ command: u.command, args: u.args, env: upstreamEnv(u.env), stderr: "inherit" }));
    }
    upstreams.set(name, client);
    const { tools } = await client.listTools();
    for (const t of tools) {
      const other = owner.get(t.name);
      if (other) {
        for (const c of upstreams.values()) await c.close();
        throw new Error(`tool "${t.name}" is offered by both upstream "${other}" and upstream "${name}"; a gateway needs one owner per tool`);
      }
      owner.set(t.name, name);
      advertised.push(t);
    }
  }

  const callUpstream = async (name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<CallToolResult> => {
    const via = owner.get(name);
    if (!via) throw new Error(`no upstream offers tool "${name}"`);
    return (await upstreams.get(via)!.callTool({ name, arguments: args, ...(meta ? { _meta: meta } : {}) })) as CallToolResult;
  };

  async function gatherFacts(tool: string, args: Record<string, unknown>, meta: Record<string, unknown>): Promise<Record<string, FactRecord>> {
    const facts: Record<string, FactRecord> = {};
    for (const f of cfg.facts.filter((f: FactConfig) => f.forTools.includes(tool))) {
      const fargs = resolveFactArgs(f.args, args, f.optional);
      if (fargs === null) continue;
      // Lookups carry the same metadata as the forwarded call: they are the gateway acting for this receipt.
      const result = await callUpstream(f.tool, fargs, meta);
      if (result.isError) throw new Error(`fact "${f.name}" lookup via ${f.tool} failed: ${JSON.stringify(extractValue(result))}`);
      facts[f.name] = { tool: f.tool, args: fargs, value: extractValue(result), resultDigest: digestOf(result), provenance: "observed" };
    }
    return facts;
  }

  function open(grantEnvelope: Envelope): Gateway {
    const grant = verifyDelegation(grantEnvelope, trusted);
    if (!grant.ok) throw new Error(`delegation grant rejected: ${grant.error}`);
    if (!delegationValidAt(grant.delegation, new Date().toISOString())) throw new Error("delegation grant is outside its validity window");
    const delegation = grant.delegation;
    const principalKeyid = grant.keyid;

    /** Every fact id an upstream has declared it served to this session, in order of first sight. A session is one agent under one grant. */
    const consumed: string[] = [];
    const noteServedFacts = (result: CallToolResult) => {
      const ids = result._meta?.[FACTS_META_KEY];
      if (!Array.isArray(ids)) return;
      for (const id of ids) if (typeof id === "string" && !consumed.includes(id)) consumed.push(id);
    };

    async function handleCall(params: CallParams): Promise<CallToolResult> {
      const tool = params.name;
      const args = params.arguments ?? {};
      const receiptId = randomUUID();
      const timestamp = new Date().toISOString();
      const modelClaim = params._meta?.[MODEL_META_KEY];
      // What the agent had been shown before this call; recorded before this call's own result is seen.
      const consumedNow = [...consumed];
      const upstreamMeta = { [RECEIPT_META_KEY]: receiptId, [AGENT_META_KEY]: delegation.agent, [PRINCIPAL_META_KEY]: delegation.principal };

      let facts: Record<string, FactRecord> = {};
      let policy: PolicyDecision;
      let execution: ReceiptPredicate["execution"] | undefined;
      let authorization: AuthorizationBundle | undefined;

      if (!delegation.scopes.includes(tool)) {
        policy = { decision: "deny", reasons: [], errors: [`tool "${tool}" is not in the delegation scopes`], policyDigest: pDigest };
      } else {
        try {
          facts = await gatherFacts(tool, args, upstreamMeta);
          const factValues = Object.fromEntries(Object.entries(facts).map(([k, f]) => [k, f.value]));
          policy = evaluate(policyText, {
            agentId: delegation.agent,
            tool,
            context: { args, facts: factValues, grant: { principal: delegation.principal, scopes: delegation.scopes } },
          });
        } catch (e) {
          policy = { decision: "deny", reasons: [], errors: [String(e instanceof Error ? e.message : e)], policyDigest: pDigest };
        }
      }
      // Observe mode: the decision is recorded, never enforced. The receipt says so on every call, so a verifier can
      // tell a policy that was being tested from one that was in force.
      if (cfg.mode === "observe") policy = { ...policy, enforced: false };
      const forward = policy.decision === "allow" || policy.enforced === false;

      const head = {
        receiptId,
        timestamp,
        issuer: { kind: "gateway" as const, keyid: issuer.keyid, version: GATEWAY_VERSION },
        principal: { id: delegation.principal, keyid: principalKeyid, provenance: "attested" as const },
        agent: { id: delegation.agent, provenance: "attested" as const },
        delegation: { envelope: grantEnvelope, provenance: "attested" as const },
        tool: { name: tool, provenance: "observed" as const, ...(owner.has(tool) && upstreamConfigs.length > 1 ? { upstream: owner.get(tool)! } : {}) },
        request: { args, argsDigest: digestOf(args), provenance: "claimed" as const },
        facts,
        consumed: { factIds: consumedNow, provenance: "observed" as const },
      };

      if (policy.decision === "allow" && consequential(tool)) {
        // A consequential call is committed to the log before it goes out, so that evidence of the side effect exists
        // before the side effect does. If the log will not take the authorization, the call is not forwarded; in
        // observe mode nothing is withheld, and the missing authorization is printed instead.
        try {
          authorization = await issuer.authorize({ ...head, policy: { ...policy, provenance: "observed" } });
        } catch (e) {
          if (cfg.mode === "observe") console.error(`agent-custody gateway (observe mode): the log did not commit the authorization for ${tool}, receipt ${receiptId}; the call was forwarded without it: ${String(e instanceof Error ? e.message : e)}`);
          else execution = { status: "withheld", reason: `the log did not commit the authorization, so the call was not forwarded: ${String(e instanceof Error ? e.message : e)}`, provenance: "observed" };
        }
      }

      if (execution) {
        // withheld: nothing was forwarded
      } else if (forward) {
        try {
          // The upstream learns which receipt this call is, and who the grant says is calling. An upstream that keeps
          // state, such as the memory server, cites the receipt as the source of what it stores.
          const observed = Object.fromEntries(Object.entries(facts).map(([k, f]) => [k, f.value]));
          const result = await callUpstream(tool, args, { ...upstreamMeta, [OBSERVED_META_KEY]: observed });
          const evidence = upstreamEvidenceOf(result);
          execution = { status: result.isError ? "failed" : "executed", result, resultDigest: digestOf(result), provenance: "observed", ...(evidence ? { upstream: evidence } : {}) };
          noteServedFacts(result);
        } catch (e) {
          execution = { status: "error", error: String(e instanceof Error ? e.message : e), provenance: "observed" };
        }
      } else {
        execution = { status: "denied", reason: [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched", provenance: "observed" };
      }

      await issuer.issue({
        ...head,
        session: { id: null, toolUseId: null, provenance: "claimed" },
        model: { id: typeof modelClaim === "string" ? modelClaim : null, provenance: "claimed" },
        policy: { ...policy, provenance: "observed" },
        ...(authorization ? { authorization } : {}),
        execution,
      });

      const meta = { [RECEIPT_META_KEY]: receiptId };
      const refuse = (text: string): CallToolResult => ({ isError: true, content: [{ type: "text", text: `${text} (receipt ${receiptId})` }], _meta: meta });
      switch (execution.status) {
        case "denied":
          return refuse(`Denied by policy: ${execution.reason}`);
        case "error":
          return refuse(`Upstream error: ${execution.error}`);
        case "withheld":
          return refuse(`Not executed: ${execution.reason}`);
        default: {
          const result = execution.result as CallToolResult;
          return { ...result, _meta: { ...result._meta, ...meta } };
        }
      }
    }

    return {
      agentId: delegation.agent,
      delegation,
      async listTools() {
        return advertised.filter((t) => delegation.scopes.includes(t.name));
      },
      handleCall,
      async close() {
        // a session holds nothing of its own beyond what it consumed; the host owns the upstreams
      },
    };
  }

  return {
    keyid: issuer.keyid,
    open,
    async close() {
      for (const c of upstreams.values()) await c.close();
    },
  };
}

/** One gateway for the grant the config names: what `agent-custody gateway` serves over stdio. Closing it closes the host. */
export async function createGateway(cfg: GatewayConfig, options: GatewayOptions = {}): Promise<Gateway> {
  if (!cfg.grantFile) throw new Error("config needs grantFile for a single-grant gateway; over HTTP each connection presents its own grant");
  const host = await createGatewayHost(cfg, options);
  let session: Gateway;
  try {
    session = host.open(JSON.parse(readFileSync(cfg.grantFile, "utf8")) as Envelope);
  } catch (e) {
    await host.close();
    throw e;
  }
  return {
    ...session,
    async close() {
      await session.close();
      await host.close();
    },
  };
}

/** Exposes the gateway as an MCP server over stdio. Everything diagnostic must go to stderr. */
export async function serveStdio(gw: Gateway): Promise<void> {
  const server = new Server({ name: "agent-custody-gateway", version: GATEWAY_VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: await gw.listTools() }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => gw.handleCall(req.params as CallParams));
  await server.connect(new StdioServerTransport());
  await new Promise<void>((resolve) => {
    server.onclose = resolve;
  });
}

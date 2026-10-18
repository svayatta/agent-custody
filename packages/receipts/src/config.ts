import { z } from "zod";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

/** Where receipts are logged: a local file, or a log reached over HTTP whose bearer token comes from an environment variable. */
const LogSchema = z.object({ url: z.string().url(), tokenEnv: z.string().min(1).optional(), /** send leaf hashes only; the log never holds the receipt. Use it for any log run by someone else */ hashOnly: z.boolean().optional(), /** milliseconds one append may take before the log counts as unreachable; default 10000 */ timeoutMs: z.number().int().positive().optional(), /** the log's public key files; every append's answer is checked against them before a call is forwarded. Without them the log's key document is fetched from the log itself on first use and pinned, which catches a log that turns dishonest later but not one dishonest from the start; required with precommit. */ keys: z.array(z.string().min(1)).optional(), /** the id the log must write into every tree head; an answer for another log is refused */ logId: z.string().min(1).optional() });
const oneLog = { message: "exactly one of logFile or log is required" };
/** Optional OpenTelemetry export: every receipt also becomes a span at this OTLP/HTTP collector, after it is issued. Never on the evidence path. */
const OtelSchema = z.object({ url: z.string().url(), headersEnv: z.record(z.string(), z.string().min(1)).optional(), serviceName: z.string().min(1).optional() });
const SplunkSchema = z.object({ url: z.string().url(), tokenEnv: z.string().min(1), index: z.string().min(1).optional(), source: z.string().min(1).optional(), sourcetype: z.string().min(1).optional(), host: z.string().min(1).optional() });
const hasOneLog = (c: { logFile?: string | undefined; log?: unknown }) => (c.logFile ? 1 : 0) + (c.log ? 1 : 0) === 1;

/** What a receipt carries of one side of a call: everything, commitments only, or commitments with the value encrypted under the customer's key; `clear` names the top-level fields kept in clear either way. */
const CaptureSideSchema = z.object({ mode: z.enum(["clear", "digest", "encrypted"]), clear: z.array(z.string().min(1)).optional() });
/** Per tool (or "*"): how the arguments, the result, and the facts are captured. Digests and signatures are always over the whole call. */
const CaptureSchema = z.record(z.string().min(1), z.object({ args: CaptureSideSchema.optional(), result: CaptureSideSchema.optional(), facts: CaptureSideSchema.optional() }));

/** One REST endpoint offered to the agent as a tool. `{name}` segments in the path come from the call's arguments; the rest go to the query on GET and DELETE, or to a JSON body otherwise. */
const RestToolSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
  path: z.string().min(1),
  /** argument names sent as query parameters, when the default placement is not wanted */
  query: z.array(z.string().min(1)).optional(),
  /** "none" sends no body even on POST */
  body: z.enum(["json", "none"]).default("json"),
  /** The gateway supplies its durable operation key in this header; callers cannot choose or override it. */
  idempotencyHeader: z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/).optional(),
  /** the JSON Schema the agent sees; default accepts any object */
  inputSchema: z.record(z.string(), z.unknown()).default({ type: "object" }),
});
export type RestToolConfig = z.infer<typeof RestToolSchema>;

/** A plain HTTP API as an upstream: no MCP server needed. Secrets come from the environment through headerEnv, never from the file or the agent. */
const RestUpstreamSchema = z.object({
  baseUrl: z.string().url(),
  headers: z.record(z.string(), z.string()).optional(),
  /** header name to environment variable, e.g. { "authorization": "STRIPE_BEARER" }; a missing variable fails at startup */
  headerEnv: z.record(z.string(), z.string().min(1)).optional(),
  timeoutMs: z.number().int().positive().default(30_000),
  tools: z.array(RestToolSchema).min(1),
});
export type RestUpstreamConfig = z.infer<typeof RestUpstreamSchema>;

/** Another agent, reached over the A2A protocol, as an upstream. Its agent card is fetched at startup; the gateway offers `<prefix>.send`, which delegates a task to it, and `<prefix>.card`, a read of the card for use as a fact. */
const A2aUpstreamSchema = z.object({
  /** the agent's base URL (its card is at /.well-known/agent-card.json) or the card's URL itself */
  url: z.string().url(),
  headers: z.record(z.string(), z.string()).optional(),
  /** header name to environment variable, as for a REST upstream */
  headerEnv: z.record(z.string(), z.string().min(1)).optional(),
  /** how long one delegated task may take, streamed or not; default two minutes */
  timeoutMs: z.number().int().positive().default(120_000),
  /** the tool names are `<prefix>.send` and `<prefix>.card`; default "a2a". Give each A2A upstream its own prefix. */
  prefix: z.string().min(1).regex(/^[A-Za-z0-9_-]+$/).default("a2a"),
});
export type A2aUpstreamConfig = z.infer<typeof A2aUpstreamSchema>;

const UpstreamSchema = z.union([
  z.object({ command: z.string(), args: z.array(z.string()).default([]), env: z.record(z.string(), z.string()).optional() }),
  z.object({ url: z.string().url(), tokenEnv: z.string().min(1).optional() }),
  z.object({ rest: RestUpstreamSchema }),
  z.object({ a2a: A2aUpstreamSchema }),
]);
export type UpstreamConfig = z.infer<typeof UpstreamSchema>;

const FactSchema = z.object({
  /** key under context.facts */
  name: z.string().min(1),
  /** upstream tool the gateway calls to obtain the fact */
  tool: z.string().min(1),
  /** argument template; values of the form "$args.<key>" are taken from the intercepted call */
  args: z.record(z.string(), z.string()),
  /** which intercepted tools trigger this lookup */
  forTools: z.array(z.string().min(1)).min(1),
  /** when true and a "$args.<key>" the template needs is absent from the call, the lookup is skipped and the fact is simply not present */
  optional: z.boolean().default(false),
});

/** Amounts and limits are integer minor units; one budget is shared by every principal and agent on this database. */
const OperationBudgetSchema = z.object({ id: z.string().min(1).max(128), currency: z.string().regex(/^[A-Z]{3}$/), limit: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) });
const OperationReconcileSchema = z.object({
  tool: z.string().min(1),
  /** Only the gateway-derived idempotency key may be substituted. The agent's operation id never reaches a receipt, and reconciliation never takes new caller arguments. */
  args: z.record(z.string(), z.string()).refine((args) => Object.values(args).every((v) => !v.startsWith("$") || v === "$operation.idempotencyKey"), { message: "reconciliation templates only support $operation.idempotencyKey" }),
  statusPath: z.string().min(1).max(512).refine((path) => path.split(".").every((part) => part.length > 0), { message: "reconciliation statusPath must have nonempty dot-separated parts" }),
  /** The provider record must echo this operation's idempotency key before it may close the reservation. */
  identityPath: z.string().min(1).max(512).refine((path) => path.split(".").every((part) => part.length > 0), { message: "reconciliation identityPath must have nonempty dot-separated parts" }).default("idempotencyKey"),
  confirmed: z.array(z.string().min(1).max(128)).min(1),
  failed: z.array(z.string().min(1).max(128)).min(1),
  pending: z.array(z.string().min(1)).default([]),
}).refine((r) => {
  const statuses = [...r.confirmed, ...r.failed, ...(r.pending ?? [])];
  return new Set(statuses).size === statuses.length;
}, { message: "reconciliation statuses must be distinct" });
const OperationToolSchema = z.object({
  tool: z.string().min(1),
  budget: z.string().min(1),
  amountField: z.string().min(1).default("amount"),
  currencyField: z.string().min(1).default("currency"),
  idempotencyHeader: z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/).default("Idempotency-Key"),
  reconcile: OperationReconcileSchema,
});
const OperationsSchema = z.object({
  database: z.string().min(1),
  budgets: z.array(OperationBudgetSchema).min(1),
  tools: z.array(OperationToolSchema).min(1),
}).superRefine((operations, ctx) => {
  const budgets = new Set<string>();
  for (const [i, budget] of operations.budgets.entries()) {
    if (budgets.has(budget.id)) ctx.addIssue({ code: "custom", path: ["budgets", i, "id"], message: "duplicate operation budget" });
    budgets.add(budget.id);
  }
  const tools = new Set<string>();
  for (const [i, tool] of operations.tools.entries()) {
    if (tools.has(tool.tool)) ctx.addIssue({ code: "custom", path: ["tools", i, "tool"], message: "duplicate financial operation tool" });
    tools.add(tool.tool);
    if (!budgets.has(tool.budget)) ctx.addIssue({ code: "custom", path: ["tools", i, "budget"], message: "unknown operation budget" });
  }
  for (const [i, tool] of operations.tools.entries()) {
    if (tools.has(tool.reconcile.tool)) ctx.addIssue({ code: "custom", path: ["tools", i, "reconcile", "tool"], message: "a reconciliation read cannot be a financial operation tool" });
  }
});
export type OperationsConfig = z.infer<typeof OperationsSchema>;
export type OperationToolConfig = z.infer<typeof OperationToolSchema>;

export const GatewayConfigSchema = z.object({
  identity: z.object({ keyFile: z.string() }),
  /** the upstream: an MCP server to spawn over stdio, an MCP URL to reach over Streamable HTTP with an optional bearer token from the environment, or a REST API described as tools */
  upstream: UpstreamSchema.optional(),
  /** several upstreams behind one gateway and one grant; each tool name must belong to exactly one of them */
  upstreams: z.array(UpstreamSchema.and(z.object({ name: z.string().min(1) }))).min(1).optional(),
  /** the one grant a stdio gateway serves; over HTTP each connection presents its own, and this is not needed */
  grantFile: z.string().optional(),
  trustedPrincipalKeys: z.array(z.string()).min(1),
  policyFile: z.string(),
  facts: z.array(FactSchema).default([]),
  /**
   * Consequential tools, by name or "*" for all: before forwarding one of these, the gateway commits a signed
   * authorization to the log and refuses the call if the log will not take it. Evidence then precedes the side effect.
   */
  precommit: z.array(z.string().min(1)).default([]),
  /** Durable idempotency, daily budget reservations, and provider reconciliation for financial operations. */
  operations: OperationsSchema.optional(),
  /** a JSON file listing digests of revoked grant envelopes (`agent-custody revoke` appends to it); re-read whenever it changes, checked on every call */
  revokedGrants: z.string().min(1).optional(),
  /** private evidence: what the receipt file carries of each tool's arguments, result, and facts */
  capture: CaptureSchema.optional(),
  /** the environment variable holding the 32-byte key (hex or base64) that encrypts withheld fields in mode encrypted; read at startup, never in the file */
  captureKeyEnv: z.string().min(1).optional(),
  /**
   * "enforce" (the default when absent) denies what the policy denies. "observe" forwards every call the grant allows and records the
   * decision the policy would have made, with `enforced: false` on the receipt: the way to run a new policy against
   * real traffic before turning it on. A log that refuses a consequential call's authorization does not withhold the
   * call in observe mode; it is printed.
   */
  mode: z.enum(["enforce", "observe"]).optional(),
  receiptsDir: z.string(),
  logFile: z.string().optional(),
  log: LogSchema.optional(),
  otel: OtelSchema.optional(),
  splunk: SplunkSchema.optional(),
}).refine(hasOneLog, oneLog).refine((c) => (c.upstream ? 1 : 0) + (c.upstreams ? 1 : 0) === 1, { message: "exactly one of upstream or upstreams is required" })
  // a key fetched from the log itself proves nothing about a log that is dishonest from the start, so a remote log that
  // gates consequential calls must have its keys pinned in the config (issue #99)
  .refine((c) => !c.log || (!c.precommit.length && !c.operations) || !!c.log.keys?.length, { message: "precommit with a remote log needs log.keys: the log's public key files, pinned, to check its answer before a consequential call is forwarded" })
  .refine((c) => !c.operations || !c.facts.some((fact) => c.operations!.tools.some((tool) => tool.tool === fact.tool)), { message: "a fact lookup cannot invoke a financial operation tool" });
export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;
export type FactConfig = z.infer<typeof FactSchema>;

/** Loads a config file and resolves every path relative to the file's directory. */
export function loadConfig(path: string): GatewayConfig {
  const cfg = GatewayConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const base = dirname(resolve(path));
  const r = (p: string) => resolve(base, p);
  return {
    ...cfg,
    identity: { keyFile: r(cfg.identity.keyFile) },
    ...(cfg.grantFile ? { grantFile: r(cfg.grantFile) } : {}),
    trustedPrincipalKeys: cfg.trustedPrincipalKeys.map(r),
    policyFile: r(cfg.policyFile),
    receiptsDir: r(cfg.receiptsDir),
    ...(cfg.logFile ? { logFile: r(cfg.logFile) } : {}),
    ...(cfg.log?.keys ? { log: { ...cfg.log, keys: cfg.log.keys.map(r) } } : {}),
    ...(cfg.revokedGrants ? { revokedGrants: r(cfg.revokedGrants) } : {}),
    ...(cfg.operations ? { operations: { ...cfg.operations, database: r(cfg.operations.database) } } : {}),
  };
}

export const SdkConfigSchema = z.object({
  /** identity the receipts will name; nothing checks it, so it is recorded as claimed */
  agentId: z.string().min(1),
  principalId: z.string().min(1).optional(),
  identity: z.object({ keyFile: z.string() }),
  /** optional Cedar policy; when present, wrapped tools and PreToolUse hooks can deny */
  policyFile: z.string().optional(),
  /** "observe" records the policy's decision with `enforced: false` and never blocks; "enforce" (default) blocks a deny */
  mode: z.enum(["enforce", "observe"]).optional(),
  receiptsDir: z.string(),
  logFile: z.string().optional(),
  log: LogSchema.optional(),
  otel: OtelSchema.optional(),
  splunk: SplunkSchema.optional(),
  /** free-text label of the host framework, e.g. "claude-code", "openai-agents" */
  framework: z.string().optional(),
  /** private evidence, as for the gateway */
  capture: CaptureSchema.optional(),
  captureKeyEnv: z.string().min(1).optional(),
}).refine(hasOneLog, oneLog);
export type SdkConfig = z.infer<typeof SdkConfigSchema>;

export function loadSdkConfig(path: string): SdkConfig {
  const cfg = SdkConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const base = dirname(resolve(path));
  const r = (p: string) => resolve(base, p);
  return {
    ...cfg,
    identity: { keyFile: r(cfg.identity.keyFile) },
    ...(cfg.policyFile ? { policyFile: r(cfg.policyFile) } : {}),
    receiptsDir: r(cfg.receiptsDir),
    ...(cfg.logFile ? { logFile: r(cfg.logFile) } : {}),
    ...(cfg.log?.keys ? { log: { ...cfg.log, keys: cfg.log.keys.map(r) } } : {}),
  };
}

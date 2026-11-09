// An OWASP Agent Control Standard (ACS) v0.1 Guardian. The agent's ACS instrumentation sends `steps/toolCallRequest`
// and `steps/toolCallResult` as JSON-RPC 2.0; the Cedar policy decides allow or deny; every decision is a signed,
// logged receipt with issuer kind `guardian`, returned in the answer. The receipt is what ACS's HMAC baseline cannot
// give (ACS §8.6): a decision a third party can attribute to this Guardian's key alone. It is not enforcement. The agent
// chose to ask, reports the call itself, and is trusted to honor the answer; the gateway is the point it cannot skip.
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AcsGuardianConfig } from "./config.ts";
import { canonicalize, digestOf, loadPrivateKey, sha256Hex } from "./crypto.ts";
import { createIssuer } from "./issue.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { evaluate, policyDigest, policyParseErrors, policyReasons, reasonOfRule, type PolicyDecision } from "./policy.ts";
import type { ReceiptBundle, ReceiptPredicate } from "./receipt.ts";

export const ACS_GUARDIAN_VERSION = "0.1.0";
/** the version the Guardian answers with; a request of any 0.x.y is accepted, as ACS §3 asks for the same major */
export const ACS_VERSION = "0.1.0";
/** the key in `policy_data` under which an answer carries its receipt */
export const ACS_RECEIPT_KEY = "agent-custody";
/** the fact every guardian receipt carries: which envelope arrived, and where it sits in the session's ACS chain */
export const ACS_STEP_FACT = "acsStep";
export const ACS_METHODS = ["steps/toolCallRequest", "steps/toolCallResult"] as const;
export type AcsMethod = (typeof ACS_METHODS)[number];

/** JSON-RPC 2.0 codes, and the ACS codes of §17.1 this Guardian raises */
export const ACS_ERROR = { parse: -32700, invalidRequest: -32600, methodNotFound: -32601, invalidParams: -32602, internal: -32603, unsupportedVersion: -32001, replay: -32005 } as const;

export type AcsResponse =
  | { jsonrpc: "2.0"; id: string | number; result: Record<string, unknown> }
  | { jsonrpc: "2.0"; id: string | number | null; error: { code: number; message: string; data?: Record<string, unknown> } };

export interface AcsGuardian {
  keyid: string;
  /** sha256 of the policy in force */
  policyDigest: string;
  /** One JSON-RPC message, or a batch evaluated in order. Never throws: a failure is a JSON-RPC error. */
  handle(message: unknown): Promise<AcsResponse | AcsResponse[]>;
}

/** ACS §8.2: sha256 over the JCS form of the entry without `entry_hash` and `previous_hash`, then the previous hash's 32 bytes. */
export function acsEntryHash(entry: Record<string, unknown>, previousHash: string | null): string {
  const { entry_hash: _h, previous_hash: _p, ...content } = entry;
  return createHash("sha256").update(canonicalize(content)).update(previousHash ? Buffer.from(previousHash, "hex") : Buffer.alloc(0)).digest("hex");
}

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const EXIT = ["success", "failure", "timeout", "blocked"];

interface Session {
  head: string | null;
  seen: Set<string>;
  requests: Map<string, { receiptId: string; decision: PolicyDecision["decision"] }>;
}

export function createAcsGuardian(cfg: AcsGuardianConfig, options: { log?: LogSink } = {}): AcsGuardian {
  const key = loadPrivateKey(cfg.identity.keyFile);
  const issuer = createIssuer(key, cfg.receiptsDir, options.log ?? openLog(cfg, key));
  const policyText = readFileSync(cfg.policyFile, "utf8");
  const parseErrors = policyParseErrors(policyText);
  if (parseErrors.length) throw new Error(`${cfg.policyFile} does not parse: ${parseErrors.join("; ")}`);
  const digest = policyDigest(policyText);
  const named = policyReasons(policyText);
  const sessions = new Map<string, Session>();

  const fail = (id: string | number | null, code: number, message: string, data?: Record<string, unknown>): AcsResponse => ({ jsonrpc: "2.0", id, error: { code, message, ...(data ? { data } : {}) } });

  async function one(msg: unknown): Promise<AcsResponse> {
    const rawId = isObject(msg) ? msg.id : undefined;
    const id = typeof rawId === "string" || typeof rawId === "number" ? rawId : null;
    if (!isObject(msg) || msg.jsonrpc !== "2.0" || typeof msg.method !== "string" || id === null) return fail(id, ACS_ERROR.invalidRequest, "not an ACS request: JSON-RPC 2.0 with a method and an id");
    const p = msg.params;
    // ACS §13: a ping is always allowed and never an ACS error, so liveness survives anything else being wrong
    if (msg.method === "system/ping") {
      const echo = isObject(p) && isObject(p.payload) && typeof p.payload.echo === "string" ? p.payload.echo : undefined;
      return { jsonrpc: "2.0", id, result: { type: "final", acs_version: ACS_VERSION, request_id: isObject(p) && typeof p.request_id === "string" ? p.request_id : "", decision: "allow", payload: { status: "ok", ...(echo === undefined ? {} : { echo }), server_timestamp: new Date().toISOString() } } };
    }
    if (!(ACS_METHODS as readonly string[]).includes(msg.method)) return fail(id, ACS_ERROR.methodNotFound, `this Guardian evaluates ${ACS_METHODS.join(" and ")} only`, { method: msg.method });
    const method = msg.method as AcsMethod;
    if (!isObject(p) || typeof p.acs_version !== "string") return fail(id, ACS_ERROR.invalidParams, "params need acs_version");
    if (!/^0\.\d+\.\d+$/.test(p.acs_version)) return fail(id, ACS_ERROR.unsupportedVersion, `acs_version ${p.acs_version} is not supported`, { supported_versions: [ACS_VERSION] });
    const meta = p.metadata;
    const payload = p.payload;
    if (typeof p.request_id !== "string" || !p.request_id || typeof p.timestamp !== "string" || !isObject(meta) || typeof meta.agent_id !== "string" || !meta.agent_id || typeof meta.session_id !== "string" || !meta.session_id || !isObject(payload)) {
      return fail(id, ACS_ERROR.invalidParams, "params need request_id, timestamp, metadata.agent_id, metadata.session_id, and payload");
    }
    const tool = isObject(payload.tool) && typeof payload.tool.name === "string" && payload.tool.name ? payload.tool.name : null;
    if (!tool) return fail(id, ACS_ERROR.invalidParams, "payload.tool.name is required");
    const requestId = p.request_id;
    const session = sessions.get(meta.session_id) ?? { head: null, seen: new Set<string>(), requests: new Map() };
    if (session.seen.has(requestId)) return fail(id, ACS_ERROR.replay, `request_id ${requestId} was already decided in this session`, { reason: "duplicate_request_id" });

    // What the agent submitted for a decision, as the policy and the receipt see it. Argument and output values are
    // unwrapped from their `{value, provenance}` objects; the provenance is not read.
    let args: Record<string, unknown>;
    let ref: string | undefined;
    if (method === "steps/toolCallRequest") {
      const a = payload.arguments;
      if (!isObject(a) || !Object.values(a).every((v) => isObject(v) && "value" in v)) return fail(id, ACS_ERROR.invalidParams, "payload.arguments must map each name to {value}");
      args = Object.fromEntries(Object.entries(a).map(([k, v]) => [k, (v as { value: unknown }).value]));
    } else {
      const outputs = payload.outputs;
      if (typeof payload.exit_status !== "string" || !EXIT.includes(payload.exit_status) || !Array.isArray(outputs) || !outputs.every((o) => isObject(o) && "value" in o)) {
        return fail(id, ACS_ERROR.invalidParams, `payload needs exit_status (${EXIT.join(", ")}) and outputs, each {value}`);
      }
      ref = typeof payload.request_id_ref === "string" ? payload.request_id_ref : undefined;
      args = { exit_status: payload.exit_status, outputs: outputs.map((o) => (o as { value: unknown }).value), ...(typeof payload.duration_ms === "number" ? { duration_ms: payload.duration_ms } : {}), ...(ref === undefined ? {} : { request_id_ref: ref }) };
    }
    // ACS hooks.md, toolCallResult: a reference the Guardian cannot resolve is recorded, and the policy decides what it means
    const known = ref === undefined ? undefined : session.requests.get(ref);
    const requestRef = ref === undefined ? undefined : { id: ref, resolved: !!known, ...(known ? { decision: known.decision, receiptId: known.receiptId } : {}) };
    const acs = {
      method,
      ...(typeof payload.capability === "string" ? { capability: payload.capability } : {}),
      ...(typeof payload.operation === "string" ? { operation: payload.operation } : {}),
      ...(requestRef ? { requestRef: { resolved: requestRef.resolved, ...(known ? { decision: known.decision } : {}) } } : {}),
    };

    const started = Date.now();
    let policy: PolicyDecision;
    try {
      policy = evaluate(policyText, { agentId: meta.agent_id, tool, context: { args, acs } });
    } catch (e) {
      policy = { decision: "deny", reasons: [], errors: [e instanceof Error ? e.message : String(e)], policyDigest: digest };
    }
    const reasoning = policy.errors.length ? policy.errors.join("; ") : policy.reasons.length ? policy.reasons.map((r) => reasonOfRule(r, named)).join("; ") : "no permit policy matched";

    const timestamp = new Date().toISOString();
    const requestHash = sha256Hex(canonicalize(p));
    const entry = { entry_id: randomUUID(), step_id: requestId, step_type: method, request_hash: requestHash, timestamp };
    const chainHash = acsEntryHash(entry, session.head);
    const step = { method, request_id: requestId, request_hash: requestHash, entry_id: entry.entry_id, previous_hash: session.head, chain_hash: chainHash, ...(requestRef ? { request_ref: requestRef } : {}) };
    const receiptId = randomUUID();
    const predicate: ReceiptPredicate = {
      receiptId,
      timestamp,
      issuer: { kind: "guardian", keyid: issuer.keyid, version: ACS_GUARDIAN_VERSION, framework: `acs ${method}` },
      principal: { id: null, provenance: "claimed" },
      agent: { id: meta.agent_id, provenance: "claimed" },
      session: { id: meta.session_id, toolUseId: requestId, provenance: "claimed" },
      model: { id: null, provenance: "claimed" },
      tool: { name: tool, provenance: "claimed" },
      request: { args, argsDigest: digestOf(args), provenance: "claimed" },
      facts: { [ACS_STEP_FACT]: { tool: "acs.step", args: {}, value: step, resultDigest: digestOf(step), provenance: "observed" } },
      policy: { ...policy, provenance: "observed" },
      execution: policy.decision === "allow"
        ? { status: "withheld", reason: "allowed; a Guardian forwards nothing: the agent carries out the step and is trusted to honor the decision", provenance: "observed" }
        : { status: "denied", reason: reasoning, provenance: "observed" },
    };
    let bundle: ReceiptBundle;
    try {
      bundle = await issuer.issue(predicate);
    } catch (e) {
      return fail(id, ACS_ERROR.internal, "the receipt could not be written, so no decision is given", { reason: "receipt_not_written", message: e instanceof Error ? e.message : String(e) });
    }
    session.head = chainHash;
    session.seen.add(requestId);
    if (method === "steps/toolCallRequest") session.requests.set(requestId, { receiptId, decision: policy.decision });
    sessions.set(meta.session_id, session);

    return {
      jsonrpc: "2.0",
      id,
      result: {
        type: "final",
        acs_version: ACS_VERSION,
        request_id: requestId,
        decision: policy.decision,
        reasoning,
        ...(policy.decision === "deny" ? { reason_codes: [policy.errors.length ? "policy_error" : "policy_denied"] } : {}),
        policy_references: policy.reasons.map((r) => {
          const name = named[Number(r.replace(/^policy/, ""))];
          return { policy_id: `cedar:${policy.policyDigest}`, policy_version: policy.policyDigest, rule_id: r, ...(name ? { policy_name: name } : {}) };
        }),
        chain_hash: chainHash,
        policy_data: { [ACS_RECEIPT_KEY]: { receiptId, keyid: issuer.keyid, receipt: bundle } },
        metadata: { evaluator: "deterministic", evaluator_version: `agent-custody guardian ${ACS_GUARDIAN_VERSION}`, evaluation_duration_ms: Date.now() - started },
      },
    };
  }

  return {
    keyid: issuer.keyid,
    policyDigest: digest,
    async handle(message) {
      if (!Array.isArray(message)) return one(message);
      if (message.length === 0) return fail(null, ACS_ERROR.invalidRequest, "an empty batch");
      const out: AcsResponse[] = [];
      for (const m of message) out.push(await one(m));
      return out;
    },
  };
}

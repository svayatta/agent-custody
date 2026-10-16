// Splunk export. Every receipt is also one event at the HTTP Event Collector the security team already runs, so
// agent actions land in the same index as everything else they watch, with the receipt id on each event to lead
// back to the evidence. Like the OpenTelemetry export it is best effort and happens after the receipt is issued:
// Splunk holds a copy, never the proof, and an outage there must never cost a receipt.
import type { AuthorizationBundle, ReceiptBundle, ReceiptPredicate } from "./receipt.ts";
import type { ReceiptExporter } from "./otel.ts";

export interface SplunkConfig {
  /** the collector's base, e.g. https://splunk.example.com:8088; events go to <url>/services/collector/event */
  url: string;
  /** environment variable holding the HEC token; a missing variable fails at startup */
  tokenEnv: string;
  /** index to write to; omitted, the token's default index */
  index?: string | undefined;
  /** the event's source field; default agent-custody */
  source?: string | undefined;
  /** the event's sourcetype; default agent-custody:receipt */
  sourcetype?: string | undefined;
  /** the event's host field; omitted, the collector fills it in */
  host?: string | undefined;
}

/** The HEC event for one receipt: flat fields Splunk can search without a props stanza. Exported for tests and other transports. */
export function hecEvent(p: ReceiptPredicate, bundle: ReceiptBundle, cfg: SplunkConfig): Record<string, unknown> {
  const auth = p.authorization as AuthorizationBundle | undefined;
  const exec = p.execution as { status: string; reason?: unknown; error?: unknown };
  // under a capture rule a message is a commitment; the event says so rather than carrying it
  const text = (v: unknown) => (typeof v === "string" ? v : v && typeof v === "object" ? "(withheld under the capture rule)" : undefined);
  return {
    time: Date.parse(p.timestamp) / 1000,
    source: cfg.source ?? "agent-custody",
    sourcetype: cfg.sourcetype ?? "agent-custody:receipt",
    ...(cfg.index ? { index: cfg.index } : {}),
    ...(cfg.host ? { host: cfg.host } : {}),
    event: {
      receipt_id: p.receiptId,
      issuer_kind: p.issuer.kind,
      issuer_keyid: p.issuer.keyid,
      tool: p.tool.name,
      upstream: p.tool.upstream ?? null,
      agent: p.agent.id,
      agent_provenance: p.agent.provenance,
      principal: p.principal.id,
      status: exec.status,
      reason: text(exec.reason) ?? text(exec.error) ?? null,
      policy_decision: p.policy?.decision ?? null,
      policy_digest: p.policy?.policyDigest ?? null,
      policy_reasons: p.policy?.reasons ?? [],
      args_digest: p.request.argsDigest,
      log_leaf_index: bundle.inclusion.leafIndex,
      log_tree_size: bundle.inclusion.treeSize,
      authorization_leaf_index: auth ? auth.inclusion.leafIndex : null,
      consumed_count: (Array.isArray(p.consumed?.factIds) ? p.consumed.factIds.length : 0) ?? 0,
      model: text(p.model.id) ?? null,
      session: text(p.session.id) ?? null,
    },
  };
}

export interface SplunkOptions {
  fetch?: typeof fetch;
  env?: Record<string, string | undefined>;
  /** where export failures are reported; default stderr */
  warn?: (message: string) => void;
}

/** An exporter that posts each receipt as one event to a Splunk HTTP Event Collector. Failures are reported, never thrown. */
export function splunkExporter(cfg: SplunkConfig, opts: SplunkOptions = {}): ReceiptExporter {
  const f = opts.fetch ?? fetch;
  const env = opts.env ?? process.env;
  const warn = opts.warn ?? ((m) => console.error(m));
  const token = env[cfg.tokenEnv];
  if (!token) throw new Error(`splunk: environment variable ${cfg.tokenEnv} is not set`);
  const headers = { "content-type": "application/json", authorization: `Splunk ${token}` };
  const base = cfg.url.endsWith("/") ? cfg.url : `${cfg.url}/`;
  const url = new URL("services/collector/event", base);
  return {
    where: cfg.url,
    async exported(p, bundle) {
      try {
        const res = await f(url, { method: "POST", headers, body: JSON.stringify(hecEvent(p, bundle, cfg)), signal: AbortSignal.timeout(5000) });
        if (!res.ok) warn(`agent-custody: splunk export of receipt ${p.receiptId} refused by ${cfg.url}: ${res.status}`);
      } catch (e) {
        warn(`agent-custody: splunk export of receipt ${p.receiptId} failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
  };
}

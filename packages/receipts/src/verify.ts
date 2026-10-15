// Independent verification of a receipt bundle. Needs only public keys, and optionally a copy of the log.
import { canonicalize, digestOf, dsseVerifiers, dsseVerify, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { isCommitment, restore, type CaptureNote, type Restored } from "./capture.ts";
import { delegationHasParent, delegationValidAt, describeChain, verifyDelegation } from "./delegation.ts";
import { leafHash, MerkleLog, verifyConsistency, verifyInclusion } from "./log.ts";
import { checkProvider, checkUpstream, contentDigest, isProviderAttestation, type ProviderSecrets, UPSTREAM_SIG_META_KEY } from "./upstream.ts";
import { AUTHORIZATION_PREDICATE_TYPE, RECEIPT_PREDICATE_TYPE, RECEIPT_TYPE, TREEHEAD_TYPE, type AuthorizationStatement, type ReceiptBundle, type ReceiptStatement, type TreeHead } from "./receipt.ts";

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface VerifyOptions {
  /** keys trusted to have issued receipts: gateway keys, SDK application keys */
  issuerKeys: PublicKeyRef[];
  principalKeys: PublicKeyRef[];
  /** keys of logs run by someone other than the issuer; tree heads are checked against these and the issuer keys */
  logKeys?: PublicKeyRef[];
  /** keys of upstreams that sign their results; with one given, an execution carrying an upstream signature is checked and becomes attested */
  upstreamKeys?: PublicKeyRef[];
  /** shared secrets for provider-native deliveries; with the matching one given, an execution carrying a Stripe or GitHub delivery is checked */
  providerSecrets?: ProviderSecrets;
  /** If given, the root is recomputed from this log file at the receipt's tree size and compared. */
  logFile?: string;
  /** If given, every tree head in the bundle must name this log, so a head from another tenant's log cannot be presented as this one's. */
  logId?: string;
  /** the withheld values, as `agent-custody reveal` writes them or the party that holds them hands them over: the digests are then recomputed and every commitment checked */
  disclosed?: { args?: Record<string, unknown>; result?: unknown; facts?: Record<string, { value?: unknown; args?: Record<string, unknown> }>; upstreamRawBody?: string };
  /** the customer's capture key: encrypted fields are revealed and the digests recomputed */
  captureKey?: Buffer;
}

export interface VerifyResult {
  ok: boolean;
  checks: Check[];
  statement: ReceiptStatement | null;
}

const short = (s: string) => s.slice(0, 12);

export function verifyBundle(bundle: ReceiptBundle, opts: VerifyOptions): VerifyResult {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };
  const done = (statement: ReceiptStatement | null): VerifyResult => ({ ok: checks.every((c) => c.ok), checks, statement });

  const sig = dsseVerify(bundle.envelope, opts.issuerKeys);
  if (!sig.ok) {
    add("receipt signature (issuer key)", false, sig.error);
    return done(null);
  }
  add("receipt signature (issuer key)", true, `keyid ${short(sig.keyid)}`);
  const st = sig.payload as ReceiptStatement;
  if (!add("receipt payload type", bundle.envelope.payloadType === RECEIPT_TYPE && st.predicateType === RECEIPT_PREDICATE_TYPE)) return done(null);
  const p = st.predicate;

  add("issuer kind is known", p.issuer.kind === "gateway" || p.issuer.kind === "sdk", `${p.issuer.kind}${p.issuer.framework ? ` / ${p.issuer.framework}` : ""}`);
  add("issuer keyid matches signer", p.issuer.keyid === sig.keyid);

  if (p.issuer.kind === "gateway") {
    add("gateway receipt carries a delegation", p.delegation !== undefined);
    add("gateway receipt carries a policy decision", p.policy !== null);
  }

  if (p.delegation) {
    const del = verifyDelegation(p.delegation.envelope, opts.principalKeys);
    add("delegation signature (principal key)", del.ok, del.ok ? `signed by ${short(del.keyid)}` : del.error);
    // A chained grant: every link signed by the key its parent names, scopes and windows nested, one principal
    // throughout. The line appears only when the grant embeds a parent, and fails with the link that broke.
    const chained = delegationHasParent(p.delegation.envelope);
    if (chained) add("delegation chain to the principal", del.ok, del.ok ? `${describeChain(del.chain)} (${del.chain.length - 1} delegation(s))` : del.error);
    if (del.ok) {
      const d = del.delegation;
      const principalKeyid = p.principal.provenance === "attested" ? p.principal.keyid : null;
      add("delegation binds principal and agent", d.principal === p.principal.id && d.agent === p.agent.id && del.keyid === principalKeyid);
      const inScope = d.scopes.includes(p.tool.name);
      const executed = p.execution.status === "executed" || p.execution.status === "failed";
      // a call the gateway refused after the grant ran out is still a true record; only an executed call has to sit inside the window
      const valid = delegationValidAt(d, p.timestamp);
      add("delegation valid at receipt time", valid || !executed, valid ? `${d.issuedAt} .. ${d.expiresAt}` : `${d.issuedAt} .. ${d.expiresAt}; the call was ${p.execution.status}, so the grant need not have been in force`);
      add("executed tool within delegated scope", !executed || inScope, inScope ? p.tool.name : `${p.tool.name} not in [${d.scopes.join(", ")}]`);
    }
  } else {
    add("principal is claimed, not attested", p.principal.provenance === "claimed", "no signed delegation in this receipt");
  }

  // Private evidence: a withheld part is committed to by its digest in the signed statement, and the capture note in
  // that statement says what is withheld. A part is recomputed when the receipt carries the values, when they are
  // disclosed, or when the capture key reveals them; otherwise the check passes as a commitment and says so. The note
  // decides, never the shape of the data: a field it names must be a commitment, and commitment-shaped data it does
  // not name is ordinary data, inside the digest.
  const subjectOk = st.subject[0]?.digest.sha256 === p.request.argsDigest;
  const withheldNote = (c: CaptureNote) => `committed, not recomputed: ${c.whole ? "the value is" : `${c.withheld.length} field(s) are`} withheld (${c.mode}); ${c.mode === "encrypted" ? "give the capture key or " : ""}disclose them to recompute`;
  const errorOf = (e: unknown) => (e instanceof Error ? e.message : String(e));
  let argsBack: Restored | null = null;
  try {
    argsBack = restore(p.request.args, p.request.capture, opts.disclosed?.args, opts.captureKey);
    if (argsBack) add("request args digest", digestOf(argsBack.value) === p.request.argsDigest && subjectOk, argsBack.how === "clear" ? undefined : `recomputed from ${argsBack.how} values`);
    else add("request args digest", subjectOk, withheldNote(p.request.capture!));
  } catch (e) {
    add("request args digest", false, errorOf(e));
  }
  // a captured fact: its commitments are checked against a disclosure or the key; the policy decided on the real value
  for (const [name, f] of Object.entries(p.facts)) {
    if (f.capture) {
      try {
        const r = restore(f.value, f.capture, opts.disclosed?.facts?.[name]?.value, opts.captureKey);
        add(`fact ${name} value`, true, r ? `commitments hold against the ${r.how} value` : withheldNote(f.capture));
      } catch (e) {
        add(`fact ${name} value`, false, errorOf(e));
      }
    }
    if (f.argsCapture) {
      try {
        const r = restore(f.args, f.argsCapture, opts.disclosed?.facts?.[name]?.args, opts.captureKey);
        add(`fact ${name} args`, true, r ? `commitments hold against the ${r.how} value` : withheldNote(f.argsCapture));
      } catch (e) {
        add(`fact ${name} args`, false, errorOf(e));
      }
    }
  }
  let resultBack: Restored | null = null;
  const resultNote = p.execution.status === "executed" || p.execution.status === "failed" ? p.execution.capture : undefined;
  const evidence = p.execution.status === "executed" || p.execution.status === "failed" ? p.execution.upstream : undefined;
  // The provider's delivery body is listed on the result's note but lives in the evidence, and the gateway dropped the
  // metadata copy from the view. It is restored first, so the result can be put back together exactly as it was.
  const bodyWithheld = !!resultNote?.withheld.includes("upstream.rawBody");
  let body: string | null = evidence && isProviderAttestation(evidence) && typeof evidence.rawBody === "string" ? evidence.rawBody : null;
  let bodyError: string | null = null;
  if (bodyWithheld && evidence && isProviderAttestation(evidence) && isCommitment(evidence.rawBody) && resultNote) {
    try {
      const r = restore(evidence.rawBody, { mode: resultNote.mode, withheld: ["*"], whole: true }, opts.disclosed?.upstreamRawBody, opts.captureKey);
      if (r) body = String(r.value);
    } catch (e) {
      bodyError = errorOf(e);
    }
  }
  const resultOnlyNote = resultNote ? { ...resultNote, withheld: resultNote.withheld.filter((w) => w !== "upstream.rawBody") } : undefined;
  if (p.execution.status === "executed" || p.execution.status === "failed") {
    try {
      const restored = restore(p.execution.result, resultOnlyNote && (resultOnlyNote.whole || resultOnlyNote.withheld.length) ? resultOnlyNote : undefined, opts.disclosed?.result, opts.captureKey);
      if (restored && bodyWithheld) {
        // the digest was over the result with the delivery in its metadata; without the body it stays a commitment
        if (body === null || bodyError) resultBack = null;
        else {
          const v = restored.value as { _meta?: Record<string, unknown> };
          resultBack = { ...restored, value: { ...v, _meta: { ...(v._meta ?? {}), [UPSTREAM_SIG_META_KEY]: { ...(evidence as object), rawBody: body } } } };
        }
      } else resultBack = restored;
      if (bodyError) add("result digest", false, bodyError);
      else if (resultBack) add("result digest", digestOf(resultBack.value) === p.execution.resultDigest, resultBack.how === "clear" ? undefined : `recomputed from ${resultBack.how} values`);
      else add("result digest", true, withheldNote(resultOnlyNote && (resultOnlyNote.whole || resultOnlyNote.withheld.length) ? resultOnlyNote : { mode: resultNote!.mode, withheld: ["upstream.rawBody"] }));
    } catch (e) {
      add("result digest", false, errorOf(e));
    }
  }
  if ((p.execution.status === "executed" || p.execution.status === "failed") && evidence) {
    const result = resultBack?.value as { content: unknown; isError?: boolean } | undefined;
    if (isProviderAttestation(evidence)) {
      if (opts.providerSecrets) {
        if (bodyError) add("upstream signature (provider secret)", false, bodyError);
        else if (!body || !result) add("upstream signature not checked", true, "the result and the delivery body are withheld; disclose them or give the capture key to check the provider's delivery");
        else {
          const u = checkProvider({ ...evidence, rawBody: body }, opts.providerSecrets, { timestamp: p.timestamp, result });
          add("upstream signature (provider secret)", u.ok, u.ok ? u.keyid : u.error);
        }
      }
    } else if ((opts.upstreamKeys?.length ?? 0) > 0) {
      if (!result) add("upstream signature not checked", true, "the result is withheld; disclose it or give the capture key to check the upstream's signature against it");
      else {
        const u = checkUpstream(evidence.envelope, opts.upstreamKeys!, { receiptId: p.receiptId, tool: p.tool.name, contentDigest: contentDigest(result) });
        add("upstream signature (upstream key)", u.ok, u.ok ? `keyid ${short(u.keyid)}` : u.error);
      }
    }
  }
  if (p.policy) {
    // a deny that was not enforced (observe mode, enforced: false on the receipt) may sit beside an executed call; an enforced one never does
    const consistent = p.policy.decision === "allow" ? p.execution.status !== "denied" : p.policy.enforced === false ? p.execution.status !== "denied" : p.execution.status === "denied";
    add("policy decision consistent with execution", consistent, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} -> ${p.execution.status}`);
    add("no policy errors on an allow", !(p.policy.decision === "allow" && p.policy.errors.length > 0));
  }

  const logKeys = opts.logKeys ?? [];
  if (p.authorization) {
    // The gateway says it committed this call to the log before forwarding it. Check that the committed statement is
    // the issuer's, describes this very call, sits in the log, and sits there before the receipt does.
    const a = p.authorization;
    const asig = dsseVerify(a.envelope, opts.issuerKeys);
    const ast = asig.ok ? (asig.payload as AuthorizationStatement) : null;
    const typed = !!ast && a.envelope.payloadType === RECEIPT_TYPE && ast.predicateType === AUTHORIZATION_PREDICATE_TYPE;
    add("authorization signature (issuer key)", asig.ok && typed && asig.keyid === sig.keyid, asig.ok ? (typed ? `keyid ${short(asig.keyid)}` : "not an authorization statement") : asig.error);
    if (ast && typed) {
      const ap = ast.predicate;
      const same = ap.receiptId === p.receiptId && ap.tool.name === p.tool.name && ap.request.argsDigest === p.request.argsDigest && ap.agent.id === p.agent.id && ap.principal.id === p.principal.id && ap.policy?.decision === "allow";
      add("authorization names this call", same, same ? `${ap.tool.name} for receipt ${short(ap.receiptId)}` : "committed for a different receipt, tool, arguments, agent, or decision");
      const ath = dsseVerify(a.treeHead, [...logKeys, ...opts.issuerKeys]);
      add("authorization tree head signature", ath.ok && a.treeHead.payloadType === TREEHEAD_TYPE, ath.ok ? `keyid ${short(ath.keyid)}` : ath.error);
      if (ath.ok) {
        const ahead = ath.payload as TreeHead;
        const included = ahead.treeSize === a.inclusion.treeSize && verifyInclusion(leafHash(canonicalize(a.envelope)), a.inclusion, ahead.rootHash);
        add("authorization log inclusion proof", included, `leaf ${a.inclusion.leafIndex} of ${a.inclusion.treeSize}`);
        const before = a.inclusion.leafIndex < bundle.inclusion.leafIndex && a.inclusion.treeSize <= bundle.inclusion.treeSize;
        add("authorization logged before execution", before, `authorization leaf ${a.inclusion.leafIndex}, receipt leaf ${bundle.inclusion.leafIndex}`);
      }
    }
  }
  const th = dsseVerify(bundle.treeHead, [...logKeys, ...opts.issuerKeys]);
  const byLog = th.ok && logKeys.some((k) => k.keyid === th.keyid);
  add("tree head signature", th.ok && bundle.treeHead.payloadType === TREEHEAD_TYPE, th.ok ? `${byLog ? "log key" : "issuer key"} ${short(th.keyid)}` : th.error);
  if (th.ok) {
    const head = th.payload as TreeHead;
    if (opts.logId !== undefined) add("tree head names the expected log", head.log === opts.logId, head.log ? `log ${head.log}` : "tree head names no log");
    add("tree head matches inclusion proof size", head.treeSize === bundle.inclusion.treeSize);
    const included = verifyInclusion(leafHash(canonicalize(bundle.envelope)), bundle.inclusion, head.rootHash);
    add("log inclusion proof", included, `leaf ${bundle.inclusion.leafIndex} of ${bundle.inclusion.treeSize}, root ${short(head.rootHash)}`);
    if (opts.logFile) {
      let root = "";
      try {
        root = MerkleLog.rootFromFile(opts.logFile, head.treeSize);
      } catch (e) {
        add("log file root matches tree head", false, String(e instanceof Error ? e.message : e));
      }
      if (root) add("log file root matches tree head", root === head.rootHash, `recomputed ${short(root)}`);
    }
  }
  return done(st);
}

export interface AuditResult {
  ok: boolean;
  checks: Check[];
  older: TreeHead | null;
  newer: TreeHead | null;
}

/**
 * Does the newer tree head extend the older one? Both must be signed by a trusted log or issuer key, and the proof
 * must be the log's consistency proof between the two sizes. A pass means nothing in the older log was rewritten.
 */
export interface AuditOptions {
  /** with these, the newer head must also carry a signature by one of them: a witness that is not the log's operator */
  witnessKeys?: PublicKeyRef[];
}

export function auditExtends(older: Envelope, newer: Envelope, proof: string[], keys: PublicKeyRef[], logId?: string, opts: AuditOptions = {}): AuditResult {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };
  const decode = (label: string, env: Envelope): TreeHead | null => {
    const v = dsseVerify(env, keys);
    add(`${label} tree head signature`, v.ok && env.payloadType === TREEHEAD_TYPE, v.ok ? `keyid ${short(v.keyid)}` : v.error);
    return v.ok ? (v.payload as TreeHead) : null;
  };
  const a = decode("older", older);
  const b = decode("newer", newer);
  if (!a || !b) return { ok: false, checks, older: a, newer: b };
  if (logId !== undefined) add("both tree heads name the expected log", a.log === logId && b.log === logId, `expected ${logId}, got ${a.log ?? "none"} and ${b.log ?? "none"}`);
  else if (a.log !== b.log) add("both tree heads name the same log", false, `${a.log ?? "none"} and ${b.log ?? "none"}`);
  if (!add("older is not larger than newer", a.treeSize <= b.treeSize, `${a.treeSize} -> ${b.treeSize}`)) return { ok: false, checks, older: a, newer: b };
  const consistent = verifyConsistency(a.treeSize, a.rootHash, b.treeSize, b.rootHash, proof);
  add("newer log extends older log", consistent, consistent ? `${proof.length} proof hashes` : "history was rewritten, or the proof is for other tree heads");
  if (opts.witnessKeys && opts.witnessKeys.length > 0) {
    const by = dsseVerifiers(newer, opts.witnessKeys);
    add("newer tree head countersigned by a witness", by.length > 0, by.length ? `witness ${short(by[0]!)}` : "no witness signature on the newer head");
  }
  return { ok: checks.every((c) => c.ok), checks, older: a, newer: b };
}

const ISSUER_NOTE: Record<string, string> = {
  gateway: "enforced outside the agent's process; the agent could neither skip nor forge this receipt",
  sdk: "self-reported by the agent's own process; tamper-evident after issue, but nothing here was enforced outside the agent",
};

/** Human-readable report: checks, then every field with its provenance so the reader knows what was proven vs. claimed. */
export function formatReport(r: VerifyResult): string {
  const lines: string[] = [];
  for (const c of r.checks) lines.push(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  lines.push("");
  lines.push(r.ok ? "RESULT: VERIFIED" : "RESULT: NOT VERIFIED");
  if (!r.statement) return lines.join("\n");
  const p = r.statement.predicate;
  lines.push("");
  lines.push(`ISSUER: ${p.issuer.kind}${p.issuer.framework ? ` (${p.issuer.framework})` : ""}, ${ISSUER_NOTE[p.issuer.kind] ?? "unknown issuer kind"}`);
  lines.push("");
  lines.push("field           provenance  value");
  const row = (f: string, prov: string, v: unknown) => lines.push(`${f.padEnd(15)} ${prov.padEnd(11)} ${typeof v === "string" ? v : JSON.stringify(v)}`);
  row("principal", p.principal.provenance, p.principal.id ?? "(none)");
  row("agent", p.agent.provenance, p.agent.id);
  if (p.session.id || p.session.toolUseId) row("session", p.session.provenance, `${p.session.id ?? "-"} / ${p.session.toolUseId ?? "-"}`);
  row("model", p.model.provenance, p.model.id ?? "(none supplied)");
  row("tool", p.tool.provenance, p.tool.name);
  row("args", p.request.provenance, p.request.args);
  for (const [k, f] of Object.entries(p.facts)) row(`fact.${k}`, f.provenance, f.value);
  if (p.policy) row("policy", p.policy.provenance, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} [${p.policy.reasons.join(",")}] policy ${short(p.policy.policyDigest)}`);
  else row("policy", "-", "(none evaluated)");
  if (p.consumed) row("consumed", p.consumed.provenance, p.consumed.factIds.length === 0 ? "(no facts shown before this call)" : p.consumed.factIds);
  if (p.authorization) {
    const committed = r.checks.filter((c) => c.name.startsWith("authorization ")).every((c) => c.ok);
    row("authorization", "observed", committed ? `committed to the log as leaf ${p.authorization.inclusion.leafIndex}, before the call was forwarded` : "carried, but its checks FAILED");
  } else if (p.execution.status === "withheld") row("authorization", "observed", "the log would not commit it; the call was not forwarded");
  const upstreamCheck = r.checks.find((c) => c.name === "upstream signature (upstream key)" || c.name === "upstream signature (provider secret)");
  const hasUpstream = (p.execution.status === "executed" || p.execution.status === "failed") && !!p.execution.upstream;
  const byProvider = hasUpstream && isProviderAttestation((p.execution as { upstream?: unknown }).upstream);
  const attestedAs = upstreamCheck?.ok ? (byProvider ? "attested (shared secret)" : "attested") : p.execution.provenance;
  const note = !hasUpstream ? "" : upstreamCheck ? (upstreamCheck.ok ? ` (${byProvider ? upstreamCheck.detail : `signed by upstream ${upstreamCheck.detail}`})` : " (upstream signature FAILED)") : byProvider ? " (carries a provider delivery; pass the provider secret to check it)" : " (carries an upstream signature; pass --upstream-key to check it)";
  row("execution", attestedAs, `${p.execution.status}${note}`);
  return lines.join("\n");
}

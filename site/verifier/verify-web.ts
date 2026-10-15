// The receipt verifier for the browser: the same checks as @agent-custody/receipts' verifyBundle, over WebCrypto.
// Asynchronous because WebCrypto is. No dependencies. Conformance is proven by running it against the published
// vectors in the test next to this file, which is how any second implementation should prove itself.
export interface Envelope { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[] }
export interface Bundle { envelope: Envelope; treeHead: Envelope; inclusion: { leafIndex: number; treeSize: number; hashes: string[] } }
export interface Check { name: string; ok: boolean; detail?: string }
export interface PublicKey { key: CryptoKey; keyid: string; pem: string }
export interface Result { ok: boolean; checks: Check[]; statement: any | null; issuerNote: string | null; treeHeadSigner: "log key" | "issuer key" | null }

const RECEIPT_TYPE = "application/vnd.in-toto+json";
const PREDICATE_TYPE = "https://agent-custody.dev/receipt/v0.2";
const TREEHEAD_TYPE = "application/vnd.agent-custody.treehead+json";
const DELEGATION_TYPE = "application/vnd.agent-custody.delegation+json";
const UPSTREAM_TYPE = "application/vnd.agent-custody.upstream+json";
const AUTHORIZATION_TYPE = "https://agent-custody.dev/authorization/v0.1";
const subtle = () => globalThis.crypto.subtle;

type Bytes = Uint8Array<ArrayBuffer>;
const enc = new TextEncoder();
const b64 = { decode: (s: string): Bytes => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) };
const hex = (buf: ArrayBuffer | Uint8Array) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (h: string): Bytes => Uint8Array.from(h.match(/.{2}/g) ?? [], (x) => parseInt(x, 16));
const concat = (...parts: Bytes[]): Bytes => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const sha256 = async (data: Bytes): Promise<Bytes> => new Uint8Array(await subtle().digest("SHA-256", data));

export function canonicalize(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    // null-prototype, so an own property named __proto__ survives (mirrors src/crypto.ts)
    if (v && typeof v === "object") { const o: Record<string, unknown> = Object.create(null); for (const k of Object.keys(v as object).sort()) { const x = (v as any)[k]; if (x !== undefined) o[k] = sort(x); } return o; }
    return v;
  };
  return JSON.stringify(sort(value));
}
export const digestOf = async (v: unknown) => hex(await sha256(enc.encode(canonicalize(v))));

/** Loads an Ed25519 public key from SPKI PEM. keyid is the sha256 of the DER. */
export async function publicKeyFromPem(pem: string): Promise<PublicKey> {
  const der = b64.decode(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const key = await subtle().importKey("spki", der, { name: "Ed25519" }, true, ["verify"]);
  return { key, keyid: hex(await sha256(der)), pem };
}

function pae(payloadType: string, payload: Bytes): Bytes {
  return concat(enc.encode(`DSSEv1 ${enc.encode(payloadType).length} ${payloadType} ${payload.length} `), payload);
}

export async function dsseVerify(env: Envelope, trusted: PublicKey[]): Promise<{ ok: true; payload: any; keyid: string } | { ok: false; error: string }> {
  if (!env || typeof env.payload !== "string" || !Array.isArray(env.signatures) || env.signatures.length === 0) return { ok: false, error: "malformed envelope" };
  const payload = b64.decode(env.payload);
  const data = pae(env.payloadType, payload);
  for (const s of env.signatures) {
    const key = trusted.find((t) => t.keyid === s.keyid);
    if (!key) continue;
    const good = await subtle().verify({ name: "Ed25519" }, key.key, b64.decode(s.sig), data);
    if (good) { try { return { ok: true, payload: JSON.parse(new TextDecoder().decode(payload)), keyid: s.keyid }; } catch { return { ok: false, error: "payload is not JSON" }; } }
    return { ok: false, error: `signature by ${s.keyid.slice(0, 12)} did not verify` };
  }
  return { ok: false, error: `no trusted key matches keyids [${env.signatures.map((s) => s.keyid.slice(0, 12)).join(", ")}]` };
}

// ---- delegation chains ----
const delegationShape = (d: any) => !!d && d.version === "0.1" && typeof d.principal === "string" && typeof d.agent === "string" && Array.isArray(d.scopes) && typeof d.issuedAt === "string" && typeof d.expiresAt === "string";
function decodeDelegationPayload(env: Envelope): any {
  try { const d = JSON.parse(new TextDecoder().decode(b64.decode(env.payload))); return delegationShape(d) ? d : null; } catch { return null; }
}
export function delegationHasParent(env: Envelope): boolean {
  return decodeDelegationPayload(env)?.parent !== undefined;
}
/** Mirrors verifyDelegation in the package: walks a chain to a grant signed by a trusted principal key. */
export async function verifyDelegationChain(env: Envelope, trusted: PublicKey[], depth = 1): Promise<{ ok: true; delegation: any; keyid: string; chain: any[] } | { ok: false; error: string }> {
  if (env.payloadType !== DELEGATION_TYPE) return { ok: false, error: `unexpected payloadType ${env.payloadType}` };
  if (depth > 4) return { ok: false, error: "delegation chain deeper than 4" };
  const unverified = decodeDelegationPayload(env);
  if (!unverified) return { ok: false, error: "malformed delegation" };
  if (unverified.parent === undefined) {
    const r = await dsseVerify(env, trusted);
    if (!r.ok) return r;
    if (!delegationShape(r.payload)) return { ok: false, error: "malformed delegation" };
    return { ok: true, delegation: r.payload, keyid: r.keyid, chain: [r.payload] };
  }
  const up = await verifyDelegationChain(unverified.parent, trusted, depth + 1);
  if (!up.ok) return { ok: false, error: `link ${depth}: ${up.error}` };
  const parent = up.delegation;
  if (typeof parent.agentKey !== "string") return { ok: false, error: `link ${depth}: ${parent.agent} holds no agent key and cannot delegate` };
  let parentKey: PublicKey;
  try { parentKey = await publicKeyFromPem(parent.agentKey); } catch { return { ok: false, error: `link ${depth}: the agent key named for ${parent.agent} is not a public key` }; }
  const r = await dsseVerify(env, [parentKey]);
  if (!r.ok) return { ok: false, error: `link ${depth}: not signed by ${parent.agent}'s key: ${r.error}` };
  const d = r.payload;
  if (!delegationShape(d)) return { ok: false, error: "malformed delegation" };
  if (d.principal !== parent.principal) return { ok: false, error: `link ${depth}: principal changed from ${parent.principal} to ${d.principal}` };
  const extra = (d.scopes as string[]).filter((s) => !parent.scopes.includes(s));
  if (extra.length) return { ok: false, error: `link ${depth}: ${d.agent} was given scopes ${parent.agent} does not hold: ${extra.join(", ")}` };
  const [ci, ce, pi, pe] = [d.issuedAt, d.expiresAt, parent.issuedAt, parent.expiresAt].map((x) => Date.parse(x));
  if ([ci, ce, pi, pe].some(Number.isNaN)) return { ok: false, error: `link ${depth}: a window timestamp is not a date` };
  if (ci < pi || ce > pe) return { ok: false, error: `link ${depth}: ${d.agent}'s window is not inside ${parent.agent}'s` };
  return { ok: true, delegation: d, keyid: up.keyid, chain: [...up.chain, d] };
}

// ---- RFC 6962 / 9162 ----
const leafHash = (data: string) => sha256(concat(new Uint8Array([0]), enc.encode(data)));
const nodeHash = (l: Bytes, r: Bytes) => sha256(concat(new Uint8Array([1]), l, r));
export async function verifyInclusion(leaf: Bytes, proof: Bundle["inclusion"], rootHex: string): Promise<boolean> {
  let fn = proof.leafIndex, sn = proof.treeSize - 1;
  if (fn < 0 || sn < 0 || fn > sn) return false;
  let r = leaf;
  for (const h of proof.hashes) {
    if (sn === 0) return false;
    const p = unhex(h);
    if (fn % 2 === 1 || fn === sn) { r = await nodeHash(p, r); if (fn % 2 === 0) { while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } } }
    else r = await nodeHash(r, p);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && hex(r) === rootHex;
}
export async function verifyConsistency(oldSize: number, oldRoot: string, newSize: number, newRoot: string, proofHex: string[]): Promise<boolean> {
  if (oldSize < 0 || oldSize > newSize) return false;
  if (oldSize === newSize) return proofHex.length === 0 && oldRoot === newRoot;
  if (oldSize === 0) return proofHex.length === 0;
  if (proofHex.length === 0) return false;
  const proof = proofHex.map(unhex);
  if ((oldSize & (oldSize - 1)) === 0) proof.unshift(unhex(oldRoot));
  let fn = oldSize - 1, sn = newSize - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = proof[0]!, sr = proof[0]!;
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) { fr = await nodeHash(c, fr); sr = await nodeHash(c, sr); while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } }
    else sr = await nodeHash(sr, c);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && hex(fr) === oldRoot && hex(sr) === newRoot;
}

const ISSUER_NOTE: Record<string, string> = {
  gateway: "enforced outside the agent's process; the agent could neither skip nor forge this receipt",
  sdk: "self-reported by the agent's own process; tamper-evident after issue, but nothing here was enforced outside the agent",
};
const short = (s: string) => s.slice(0, 12);

export interface Options { issuerKeys: PublicKey[]; principalKeys: PublicKey[]; logKeys?: PublicKey[]; upstreamKeys?: PublicKey[]; providerSecrets?: { stripe?: string; github?: string }; logId?: string; logLeaves?: (string | { pruned?: string; hash?: string })[] }

async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await subtle().importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await subtle().sign("HMAC", key, enc.encode(data)));
}

async function checkProvider(att: any, secrets: { stripe?: string; github?: string }, timestamp: string, result: unknown): Promise<{ ok: boolean; detail: string }> {
  const secret = att.provider === "stripe-webhook" ? secrets.stripe : secrets.github;
  if (!secret) return { ok: false, detail: `no ${att.provider === "stripe-webhook" ? "Stripe" : "GitHub"} secret given` };
  if (att.provider === "stripe-webhook") {
    const parts = Object.fromEntries(String(att.signature).split(",").map((kv: string) => kv.split("=")));
    if (!parts.t || !parts.v1) return { ok: false, detail: "Stripe-Signature header lacks t or v1" };
    if ((await hmacHex(secret, `${parts.t}.${att.rawBody}`)) !== parts.v1) return { ok: false, detail: "Stripe signature does not verify with this secret" };
    const skew = Math.abs(Number(parts.t) * 1000 - Date.parse(timestamp)) / 1000;
    if (!(skew <= 300)) return { ok: false, detail: `Stripe timestamp is ${Math.round(skew)}s from the receipt, beyond tolerance` };
  } else {
    const hexSig = String(att.signature).startsWith("sha256=") ? String(att.signature).slice(7) : "";
    if (!hexSig || (await hmacHex(secret, att.rawBody)) !== hexSig) return { ok: false, detail: "GitHub signature does not verify with this secret" };
  }
  let body: any;
  try { body = JSON.parse(att.rawBody); } catch { return { ok: false, detail: "delivery body is not JSON" }; }
  const bound = String(att.bind).split(".").reduce((v: any, k: string) => (v && typeof v === "object" ? v[k] : undefined), body);
  if (bound === undefined || bound === null || bound === "") return { ok: false, detail: `delivery has no value at ${att.bind}` };
  if (!JSON.stringify(result).includes(JSON.stringify(bound).replace(/^"|"$/g, ""))) return { ok: false, detail: `delivery's ${att.bind} (${String(bound)}) does not appear in the receipt's result` };
  return { ok: true, detail: `shared secret (${att.provider}, bound on ${att.bind})` };
}

/** The same checks, in the same order, with the same names, as the reference verifyBundle. */
export async function verifyBundle(bundle: Bundle, opts: Options): Promise<Result> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => { checks.push(detail === undefined ? { name, ok } : { name, ok, detail }); return ok; };
  let treeHeadSigner: Result["treeHeadSigner"] = null;
  const done = (statement: any | null): Result => ({ ok: checks.every((c) => c.ok), checks, statement, issuerNote: statement ? (ISSUER_NOTE[statement.predicate.issuer.kind] ?? "unknown issuer kind") : null, treeHeadSigner });

  const sig = await dsseVerify(bundle.envelope, opts.issuerKeys);
  if (!sig.ok) { add("receipt signature (issuer key)", false, sig.error); return done(null); }
  add("receipt signature (issuer key)", true, `keyid ${short(sig.keyid)}`);
  const st = sig.payload;
  if (!add("receipt payload type", bundle.envelope.payloadType === RECEIPT_TYPE && st.predicateType === PREDICATE_TYPE)) return done(null);
  const p = st.predicate;
  add("issuer kind is known", p.issuer.kind === "gateway" || p.issuer.kind === "sdk", `${p.issuer.kind}${p.issuer.framework ? ` / ${p.issuer.framework}` : ""}`);
  add("issuer keyid matches signer", p.issuer.keyid === sig.keyid);
  if (p.issuer.kind === "gateway") {
    add("gateway receipt carries a delegation", p.delegation !== undefined);
    add("gateway receipt carries a policy decision", p.policy !== null);
  }
  if (p.delegation) {
    const del = await verifyDelegationChain(p.delegation.envelope, opts.principalKeys);
    const d = del.ok ? del.delegation : null;
    const shape = !!d;
    add("delegation signature (principal key)", del.ok, del.ok ? `signed by ${short(del.keyid)}` : del.error);
    if (delegationHasParent(p.delegation.envelope)) add("delegation chain to the principal", del.ok, del.ok ? `${[del.chain[0].principal, ...del.chain.map((c) => c.agent)].join(" → ")} (${del.chain.length - 1} delegation(s))` : del.error);
    if (del.ok && shape) {
      const principalKeyid = p.principal.provenance === "attested" ? p.principal.keyid : null;
      add("delegation binds principal and agent", d.principal === p.principal.id && d.agent === p.agent.id && del.keyid === principalKeyid);
      const at = Date.parse(p.timestamp);
      const inScope = d.scopes.includes(p.tool.name);
      const executed = p.execution.status === "executed" || p.execution.status === "failed";
      // mirrors src/verify.ts: a call refused after the grant ran out is a true record; only an executed call must sit inside the window
      const valid = !Number.isNaN(at) && Date.parse(d.issuedAt) <= at && at <= Date.parse(d.expiresAt);
      add("delegation valid at receipt time", valid || !executed, valid ? `${d.issuedAt} .. ${d.expiresAt}` : `${d.issuedAt} .. ${d.expiresAt}; the call was ${p.execution.status}, so the grant need not have been in force`);
      add("executed tool within delegated scope", !executed || inScope, inScope ? p.tool.name : `${p.tool.name} not in [${d.scopes.join(", ")}]`);
    }
  } else {
    add("principal is claimed, not attested", p.principal.provenance === "claimed", "no signed delegation in this receipt");
  }
  // Private evidence (mirrors src/verify.ts): a withheld part is committed to by its digest in the signed statement,
  // and the signed capture note says what is withheld. The browser has no key and takes no disclosure, so it
  // recomputes what the receipt carries in clear and reports the rest as committed. The note decides, never the shape
  // of the data: a field the note names must be a commitment (else the check fails), and commitment-shaped data the
  // note does not name is ordinary data, inside the digest.
  const isCommitment = (v: any) => !!v && typeof v === "object" && !Array.isArray(v) && (v.$custody === "withheld" || v.$custody === "encrypted");
  type Note = { mode: string; withheld: string[]; whole?: boolean };
  /** null when the note matches the view; otherwise why it does not */
  const noteProblem = (view: any, note: Note): string | null => {
    if (note.whole) return isCommitment(view) ? null : "the capture note says the value is withheld whole, but the receipt carries no commitment";
    if (!view || typeof view !== "object" || Array.isArray(view)) return "the capture note names withheld fields, but the receipt carries no object";
    for (const name of note.withheld) if (!isCommitment(view[name])) return `the capture note says field "${name}" is withheld, but the receipt carries no commitment for it`;
    return null;
  };
  const withheldNote = (c: Note) => `committed, not recomputed: ${c.whole ? "the value is" : `${c.withheld.length} field(s) are`} withheld (${c.mode}); ${c.mode === "encrypted" ? "give the capture key or " : ""}disclose them with the command-line verifier to recompute`;
  const subjectOk = st.subject[0]?.digest.sha256 === p.request.argsDigest;
  const argsNote = p.request.capture as Note | undefined;
  if (argsNote) {
    const problem = noteProblem(p.request.args, argsNote);
    add("request args digest", !problem && subjectOk, problem ?? withheldNote(argsNote));
  } else add("request args digest", (await digestOf(p.request.args)) === p.request.argsDigest && subjectOk);
  for (const [name, f] of Object.entries(p.facts) as [string, any][]) {
    if (f.capture) { const problem = noteProblem(f.value, f.capture); add(`fact ${name} value`, !problem, problem ?? withheldNote(f.capture)); }
    if (f.argsCapture) { const problem = noteProblem(f.args, f.argsCapture); add(`fact ${name} args`, !problem, problem ?? withheldNote(f.argsCapture)); }
  }
  const executedOrFailed = p.execution.status === "executed" || p.execution.status === "failed";
  const resultNote = executedOrFailed ? (p.execution.capture as Note | undefined) : undefined;
  const resultOnlyNote = resultNote ? { ...resultNote, withheld: resultNote.withheld.filter((w) => w !== "upstream.rawBody") } : undefined;
  const resultWithheld = !!resultOnlyNote && (resultOnlyNote.whole || resultOnlyNote.withheld.length > 0);
  const isProvider = (v: any) => !!v && (v.provider === "stripe-webhook" || v.provider === "github-delivery") && (typeof v.rawBody === "string" || isCommitment(v.rawBody));
  // whether the delivery body is withheld is read from the signed note, as for every field, and the evidence must bear it out
  const bodyWithheld = !!resultNote?.withheld.includes("upstream.rawBody");
  const bodyNoteProblem = bodyWithheld && !(executedOrFailed && p.execution.upstream && isProvider(p.execution.upstream) && isCommitment((p.execution.upstream as any).rawBody)) ? "the capture note says the delivery body is withheld, but the receipt carries no commitment for it" : null;
  if (executedOrFailed) {
    if (bodyNoteProblem) add("execution result digest", false, bodyNoteProblem);
    else if (resultWithheld) { const problem = noteProblem(p.execution.result, resultOnlyNote!); add("execution result digest", !problem, problem ?? withheldNote(resultOnlyNote!)); }
    else if (bodyWithheld) add("execution result digest", true, withheldNote({ mode: resultNote!.mode, withheld: ["upstream.rawBody"] }));
    else add("execution result digest", (await digestOf(p.execution.result)) === p.execution.resultDigest);
  }
  if (executedOrFailed && p.execution.upstream && (resultWithheld || bodyWithheld) && (opts.providerSecrets || (opts.upstreamKeys?.length ?? 0) > 0)) {
    add("upstream signature not checked", true, "the result is withheld; disclose it with the command-line verifier to check the upstream's evidence against it");
  } else if ((p.execution.status === "executed" || p.execution.status === "failed") && p.execution.upstream && isProvider(p.execution.upstream)) {
    if (opts.providerSecrets) {
      const u = await checkProvider(p.execution.upstream, opts.providerSecrets, p.timestamp, p.execution.result);
      add("upstream signature (provider secret)", u.ok, u.detail);
    }
  } else if ((p.execution.status === "executed" || p.execution.status === "failed") && p.execution.upstream && (opts.upstreamKeys?.length ?? 0) > 0) {
    const u = await dsseVerify(p.execution.upstream.envelope, opts.upstreamKeys!);
    let ok = u.ok && p.execution.upstream.envelope.payloadType === UPSTREAM_TYPE;
    let detail = u.ok ? `keyid ${short(u.keyid)}` : u.error;
    if (u.ok) {
      const expectedDigest = await digestOf({ content: p.execution.result.content, isError: !!p.execution.result.isError });
      if (u.payload.receiptId !== p.receiptId) { ok = false; detail = "signed for a different receipt"; }
      else if (u.payload.tool !== p.tool.name) { ok = false; detail = `signed for tool ${u.payload.tool}`; }
      else if (u.payload.contentDigest !== expectedDigest) { ok = false; detail = "signed content differs from the result in the receipt"; }
    }
    add("upstream signature (upstream key)", ok, detail);
  }
  if (p.policy) {
    // a deny that was not enforced (observe mode, enforced: false on the receipt) may sit beside an executed call; an enforced one never does
    const consistent = p.policy.decision === "allow" ? p.execution.status !== "denied" : p.policy.enforced === false ? p.execution.status !== "denied" : p.execution.status === "denied";
    add("policy decision consistent with execution", consistent, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} -> ${p.execution.status}`);
    add("no policy errors on an allow", !(p.policy.decision === "allow" && p.policy.errors.length > 0));
  }
  const logKeys = opts.logKeys ?? [];
  if (p.authorization) {
    const a = p.authorization;
    const asig = await dsseVerify(a.envelope, opts.issuerKeys);
    const ast = asig.ok ? asig.payload : null;
    const typed = !!ast && a.envelope.payloadType === RECEIPT_TYPE && ast.predicateType === AUTHORIZATION_TYPE;
    add("authorization signature (issuer key)", asig.ok && typed && asig.keyid === sig.keyid, asig.ok ? (typed ? `keyid ${short(asig.keyid)}` : "not an authorization statement") : asig.error);
    if (ast && typed) {
      const ap = ast.predicate;
      const same = ap.receiptId === p.receiptId && ap.tool?.name === p.tool.name && ap.request?.argsDigest === p.request.argsDigest && ap.agent?.id === p.agent.id && ap.principal?.id === p.principal.id && ap.policy?.decision === "allow";
      add("authorization names this call", same, same ? `${ap.tool.name} for receipt ${short(ap.receiptId)}` : "committed for a different receipt, tool, arguments, agent, or decision");
      const ath = await dsseVerify(a.treeHead, [...logKeys, ...opts.issuerKeys]);
      add("authorization tree head signature", ath.ok && a.treeHead.payloadType === TREEHEAD_TYPE, ath.ok ? `keyid ${short(ath.keyid)}` : ath.error);
      if (ath.ok) {
        const ahead = ath.payload;
        const included = ahead.treeSize === a.inclusion.treeSize && (await verifyInclusion(await leafHash(canonicalize(a.envelope)), a.inclusion, ahead.rootHash));
        add("authorization log inclusion proof", included, `leaf ${a.inclusion.leafIndex} of ${a.inclusion.treeSize}`);
        const before = a.inclusion.leafIndex < bundle.inclusion.leafIndex && a.inclusion.treeSize <= bundle.inclusion.treeSize;
        add("authorization logged before execution", before, `authorization leaf ${a.inclusion.leafIndex}, receipt leaf ${bundle.inclusion.leafIndex}`);
      }
    }
  }
  const th = await dsseVerify(bundle.treeHead, [...logKeys, ...opts.issuerKeys]);
  const byLog = th.ok && logKeys.some((k) => k.keyid === th.keyid);
  treeHeadSigner = th.ok ? (byLog ? "log key" : "issuer key") : null;
  add("tree head signature", th.ok && bundle.treeHead.payloadType === TREEHEAD_TYPE, th.ok ? `${byLog ? "log key" : "issuer key"} ${short(th.keyid)}` : th.error);
  if (th.ok) {
    const head = th.payload;
    if (opts.logId !== undefined) add("tree head names the expected log", head.log === opts.logId, head.log ? `log ${head.log}` : "tree head names no log");
    add("tree head matches inclusion proof size", head.treeSize === bundle.inclusion.treeSize);
    const included = await verifyInclusion(await leafHash(canonicalize(bundle.envelope)), bundle.inclusion, head.rootHash);
    add("log inclusion proof", included, `leaf ${bundle.inclusion.leafIndex} of ${bundle.inclusion.treeSize}, root ${short(head.rootHash)}`);
    if (opts.logLeaves) {
      const hashes: Bytes[] = [];
      // a log copy holds leaf strings, or {pruned} and {hash} lines that already are the leaf hash
      for (const l of opts.logLeaves) hashes.push(typeof l === "string" ? await leafHash(l) : unhex((l.pruned ?? l.hash)!));
      if (head.treeSize > hashes.length) add("log file root matches tree head", false, `log copy has ${hashes.length} leaves, tree head is at ${head.treeSize}`);
      else { const root = await rootOf(hashes, head.treeSize); add("log file root matches tree head", root === head.rootHash, `recomputed ${short(root)}`); }
    }
  }
  return done(st);
}

async function rootOf(hashes: Bytes[], size: number): Promise<string> {
  const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  const mth = async (lo: number, hi: number): Promise<Bytes> => {
    const n = hi - lo;
    if (n === 0) return sha256(new Uint8Array(0));
    if (n === 1) return hashes[lo]!;
    const k = split(n);
    return nodeHash(await mth(lo, lo + k), await mth(lo + k, hi));
  };
  return hex(await mth(0, size));
}

export interface AuditResult { ok: boolean; checks: Check[] }
export async function auditExtends(older: Envelope, newer: Envelope, proof: string[], keys: PublicKey[], logId?: string, opts: { witnessKeys?: PublicKey[] } = {}): Promise<AuditResult> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => { checks.push(detail === undefined ? { name, ok } : { name, ok, detail }); return ok; };
  const decode = async (label: string, env: Envelope) => { const v = await dsseVerify(env, keys); add(`${label} tree head signature`, v.ok && env.payloadType === TREEHEAD_TYPE, v.ok ? `keyid ${short(v.keyid)}` : v.error); return v.ok ? v.payload : null; };
  const a = await decode("older", older);
  const b = await decode("newer", newer);
  if (!a || !b) return { ok: false, checks };
  if (logId !== undefined) add("both tree heads name the expected log", a.log === logId && b.log === logId, `expected ${logId}, got ${a.log ?? "none"} and ${b.log ?? "none"}`);
  else if (a.log !== b.log) add("both tree heads name the same log", false, `${a.log ?? "none"} and ${b.log ?? "none"}`);
  if (!add("older is not larger than newer", a.treeSize <= b.treeSize, `${a.treeSize} -> ${b.treeSize}`)) return { ok: false, checks };
  const consistent = await verifyConsistency(a.treeSize, a.rootHash, b.treeSize, b.rootHash, proof);
  add("newer log extends older log", consistent, consistent ? `${proof.length} proof hashes` : "history was rewritten, or the proof is for other tree heads");
  if (opts.witnessKeys && opts.witnessKeys.length > 0) {
    // every witness key whose signature on the newer head verifies
    const by: string[] = [];
    for (const s of newer.signatures) {
      const k = opts.witnessKeys.find((w) => w.keyid === s.keyid);
      if (!k) continue;
      const payload = b64.decode(newer.payload);
      if (await subtle().verify({ name: "Ed25519" }, k.key, b64.decode(s.sig), pae(newer.payloadType, payload))) by.push(s.keyid);
    }
    add("newer tree head countersigned by a witness", by.length > 0, by.length ? `witness ${short(by[0]!)}` : "no witness signature on the newer head");
  }
  return { ok: checks.every((c) => c.ok), checks };
}

/** The human-readable report, the same shape the CLI prints. */
export function formatReport(r: Result): string {
  const lines = r.checks.map((c) => `${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  lines.push("", r.ok ? "RESULT: VERIFIED" : "RESULT: NOT VERIFIED");
  if (!r.statement) return lines.join("\n");
  const p = r.statement.predicate;
  lines.push("", `ISSUER: ${p.issuer.kind}${p.issuer.framework ? ` (${p.issuer.framework})` : ""}, ${r.issuerNote}`, "", "field           provenance  value");
  const row = (f: string, prov: string, v: unknown) => lines.push(`${f.padEnd(15)} ${prov.padEnd(11)} ${typeof v === "string" ? v : JSON.stringify(v)}`);
  row("principal", p.principal.provenance, p.principal.id ?? "(none)");
  row("agent", p.agent.provenance, p.agent.id);
  if (p.session.id || p.session.toolUseId) row("session", p.session.provenance, `${p.session.id ?? "-"} / ${p.session.toolUseId ?? "-"}`);
  row("model", p.model.provenance, p.model.id ?? "(none supplied)");
  row("tool", p.tool.provenance, p.tool.name);
  row("args", p.request.provenance, p.request.args);
  for (const [k, f] of Object.entries<any>(p.facts)) row(`fact.${k}`, f.provenance, f.value);
  if (p.policy) row("policy", p.policy.provenance, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} [${p.policy.reasons.join(",")}] policy ${short(p.policy.policyDigest)}`); else row("policy", "-", "(none evaluated)");
  if (p.consumed) row("consumed", p.consumed.provenance, p.consumed.factIds.length === 0 ? "(no facts shown before this call)" : p.consumed.factIds);
  const upstreamCheck = r.checks.find((c) => c.name === "upstream signature (upstream key)" || c.name === "upstream signature (provider secret)");
  const hasUpstream = (p.execution.status === "executed" || p.execution.status === "failed") && !!p.execution.upstream;
  const byProvider = hasUpstream && !!(p.execution.upstream as any).provider;
  const attestedAs = upstreamCheck?.ok ? (byProvider ? "attested (shared secret)" : "attested") : p.execution.provenance;
  const note = !hasUpstream ? "" : upstreamCheck ? (upstreamCheck.ok ? ` (${byProvider ? upstreamCheck.detail : `signed by upstream ${upstreamCheck.detail}`})` : " (upstream signature FAILED)") : byProvider ? " (carries a provider delivery; add the provider secret to check it)" : " (carries an upstream signature; add the upstream key to check it)";
  row("execution", attestedAs, `${p.execution.status}${note}`);
  return lines.join("\n");
}

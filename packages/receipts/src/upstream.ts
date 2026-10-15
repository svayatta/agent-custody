// Attested execution. An upstream that holds a key can sign what it returned, bound to the receipt the gateway is
// issuing, so the receipt's execution is no longer only what the gateway observed but what the upstream itself vouches
// for. The upstream puts a DSSE envelope on its result's _meta; the gateway embeds it; a verifier who trusts the
// upstream's key checks it. Provider-native formats, such as Stripe's webhook signatures, are adapters on top of this.
import { createHmac, timingSafeEqual } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { digestOf, dsseSign, dsseVerify, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";
import { isCommitment, type Commitment } from "./capture.ts";

export const UPSTREAM_SIG_META_KEY = "agent-custody/upstream-signature";
export const UPSTREAM_TYPE = "application/vnd.agent-custody.upstream+json";

export interface UpstreamAttestation {
  receiptId: string;
  tool: string;
  /** digest of { content, isError } of the result: what the agent received, without the _meta the signature lives in */
  contentDigest: string;
}

export function contentDigest(result: { content: unknown; isError?: boolean | undefined }): string {
  return digestOf({ content: result.content, isError: !!result.isError });
}

/** For upstreams: signs the result for this receipt and returns it with the envelope attached. */
export function signResult<R extends CallToolResult>(result: R, key: KeyPair, receiptId: string, tool: string): R {
  const payload: UpstreamAttestation = { receiptId, tool, contentDigest: contentDigest(result) };
  return { ...result, _meta: { ...result._meta, [UPSTREAM_SIG_META_KEY]: dsseSign(UPSTREAM_TYPE, payload, key) } };
}

/** For the gateway: the envelope an upstream attached, if any. */
export function upstreamSignatureOf(result: CallToolResult): Envelope | null {
  const env = result._meta?.[UPSTREAM_SIG_META_KEY] as Envelope | undefined;
  return env && typeof env.payload === "string" && Array.isArray(env.signatures) ? env : null;
}

export type UpstreamCheck = { ok: true; keyid: string } | { ok: false; error: string };

/** For verifiers: the envelope must verify against a trusted upstream key and bind to this receipt, tool, and content. */
export function checkUpstream(envelope: Envelope, keys: PublicKeyRef[], expected: UpstreamAttestation): UpstreamCheck {
  const v = dsseVerify(envelope, keys);
  if (!v.ok) return { ok: false, error: v.error };
  if (envelope.payloadType !== UPSTREAM_TYPE) return { ok: false, error: `payload type ${envelope.payloadType}` };
  const p = v.payload as Partial<UpstreamAttestation>;
  if (p.receiptId !== expected.receiptId) return { ok: false, error: "signed for a different receipt" };
  if (p.tool !== expected.tool) return { ok: false, error: `signed for tool ${String(p.tool)}` };
  if (p.contentDigest !== expected.contentDigest) return { ok: false, error: "signed content differs from the result in the receipt" };
  return { ok: true, keyid: v.keyid };
}

// ---- provider-native signatures ----
// Real providers do not sign per receipt. Stripe signs webhooks and GitHub signs deliveries with an HMAC over the raw
// body under a shared secret, unbound to any receipt. An MCP server wrapping the provider can attach the delivery that
// corresponds to the call; a verifier holding the secret recomputes the HMAC and checks that the delivery names the
// object the receipt's result names. This is a weaker claim than a public-key signature, since anyone holding the
// secret could forge it, and the report says so: "attested by shared secret".

export interface ProviderAttestation {
  provider: "stripe-webhook" | "github-delivery";
  /** the delivery body exactly as received; the HMAC is over these bytes. Under a private result capture the receipt carries a commitment here instead, and the body is disclosed or revealed to check the delivery (capture.ts) */
  rawBody: string | Commitment;
  /** Stripe: the Stripe-Signature header; GitHub: the X-Hub-Signature-256 header */
  signature: string;
  /** dot path into the parsed body whose value must appear in the receipt's result, e.g. data.object.id */
  bind: string;
  /** GitHub: the X-GitHub-Delivery id, for the record */
  deliveryId?: string;
}

/** under a private result rule the envelope, or the delivery body, is a commitment in the receipt, restored by the verifier with the result */
export type UpstreamEvidence = { envelope: Envelope | Commitment } | ProviderAttestation;

export function isProviderAttestation(v: unknown): v is ProviderAttestation {
  const p = v as Partial<ProviderAttestation> | null;
  return !!p && (p.provider === "stripe-webhook" || p.provider === "github-delivery") && (typeof p.rawBody === "string" || isCommitment(p.rawBody)) && typeof p.signature === "string" && typeof p.bind === "string";
}

/** For upstreams wrapping a provider: attaches the provider's own delivery for this call. */
export function attachProviderAttestation<R extends CallToolResult>(result: R, attestation: ProviderAttestation): R {
  return { ...result, _meta: { ...result._meta, [UPSTREAM_SIG_META_KEY]: attestation } };
}

/** For the gateway: whatever upstream evidence the result carries, a signed envelope or a provider delivery. */
export function upstreamEvidenceOf(result: CallToolResult): UpstreamEvidence | null {
  const v = result._meta?.[UPSTREAM_SIG_META_KEY];
  if (isProviderAttestation(v)) return v;
  const env = upstreamSignatureOf(result);
  return env ? { envelope: env } : null;
}

export interface ProviderSecrets {
  stripe?: string;
  github?: string;
}

export interface ProviderCheckContext {
  /** the receipt's timestamp, for Stripe's timestamp tolerance */
  timestamp: string;
  /** the receipt's execution result; the bound value must appear in it */
  result: unknown;
  /** seconds a Stripe timestamp may differ from the receipt's; default 300 */
  toleranceSeconds?: number;
}

const pathValue = (body: unknown, path: string): unknown => path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), body);

/** Stripe: header `t=<unix>,v1=<hex>`, HMAC-SHA256 over `<t>.<rawBody>`; GitHub: header `sha256=<hex>` over rawBody. */
export function checkProvider(att: ProviderAttestation, secrets: ProviderSecrets, ctx: ProviderCheckContext): UpstreamCheck {
  if (typeof att.rawBody !== "string") return { ok: false, error: "the delivery body is withheld; disclose it or give the capture key" };
  const secret = att.provider === "stripe-webhook" ? secrets.stripe : secrets.github;
  if (!secret) return { ok: false, error: `no ${att.provider === "stripe-webhook" ? "Stripe" : "GitHub"} secret given` };
  const hmac = (data: string) => createHmac("sha256", secret).update(data).digest("hex");
  const equal = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
  if (att.provider === "stripe-webhook") {
    const parts = Object.fromEntries(att.signature.split(",").map((kv) => kv.split("=") as [string, string]));
    const t = parts.t;
    const v1 = parts.v1;
    if (!t || !v1) return { ok: false, error: "Stripe-Signature header lacks t or v1" };
    if (!equal(hmac(`${t}.${att.rawBody}`), v1)) return { ok: false, error: "Stripe signature does not verify with this secret" };
    const skew = Math.abs(Number(t) * 1000 - Date.parse(ctx.timestamp)) / 1000;
    if (!(skew <= (ctx.toleranceSeconds ?? 300))) return { ok: false, error: `Stripe timestamp is ${Math.round(skew)}s from the receipt, beyond tolerance` };
  } else {
    const hex = att.signature.startsWith("sha256=") ? att.signature.slice(7) : "";
    if (!hex || !equal(hmac(att.rawBody), hex)) return { ok: false, error: "GitHub signature does not verify with this secret" };
  }
  let body: unknown;
  try {
    body = JSON.parse(att.rawBody);
  } catch {
    return { ok: false, error: "delivery body is not JSON" };
  }
  const bound = pathValue(body, att.bind);
  if (bound === undefined || bound === null || bound === "") return { ok: false, error: `delivery has no value at ${att.bind}` };
  if (!JSON.stringify(ctx.result).includes(JSON.stringify(bound).replace(/^"|"$/g, ""))) return { ok: false, error: `delivery's ${att.bind} (${String(bound)}) does not appear in the receipt's result` };
  return { ok: true, keyid: `shared secret (${att.provider}, bound on ${att.bind})` };
}

/** For fake providers and tests: a Stripe-Signature header for a body at a time. */
export function stripeSignature(rawBody: string, secret: string, unixSeconds: number): string {
  return `t=${unixSeconds},v1=${createHmac("sha256", secret).update(`${unixSeconds}.${rawBody}`).digest("hex")}`;
}

/** For fake providers and tests: an X-Hub-Signature-256 header for a body. */
export function githubSignature(rawBody: string, secret: string): string {
  return `sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`;
}


// Human in the loop for signed approvals. A protected call that arrives without an approval leaves a request
// here; an approver reviews it and signs it with their own key (`agent-custody approvals approve`); the same call sent
// again picks the signed envelope up. The directory is untrusted storage: the gateway verifies every envelope it takes
// from it exactly as it verifies one an agent sends in `_meta`, so a write to it can do no more than an agent can.
import { randomUUID, sign } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { APPROVAL_TYPE, approvalConsumed, approvalStatement, verifyApproval, type ApprovalBinding } from "./approval.ts";
import { canonicalize, digestOf, pae, sha256Hex, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";

/** Where a refusal names the request it opened: `{ requestId, status }` in the result's `_meta`. */
export const APPROVAL_REQUEST_META_KEY = "agent-custody/approval-request";

const Nonempty = z.string().min(1);
const Timestamp = z.iso.datetime({ offset: true });
const RequestId = z.string().regex(/^[0-9a-f]{32}$/);
const RequestSchema = z.strictObject({
  version: z.literal("0.1"),
  requestId: RequestId,
  createdAt: Timestamp,
  binding: z.strictObject({
    principal: Nonempty,
    agent: Nonempty,
    tool: Nonempty,
    args: z.record(z.string(), z.unknown()),
    fields: z.strictObject({ amount: Nonempty.optional(), currency: Nonempty.optional(), beneficiary: Nonempty.optional() }).optional(),
  }),
  argsDigest: z.string().regex(/^[0-9a-f]{64}$/),
  requiredApprovers: z.union([z.literal(1), z.literal(2)]),
  /** the receipt of the refused call that opened the request */
  receiptId: Nonempty,
  status: z.enum(["pending", "approved", "denied"]),
  /** the approval signed so far: one signature while a two-person rule waits for the second */
  envelope: z.strictObject({ payloadType: Nonempty, payload: Nonempty, signatures: z.array(z.strictObject({ keyid: Nonempty, sig: Nonempty })).min(1) }).optional(),
  decidedAt: Timestamp.optional(),
  /** why an approver denied it */
  reason: z.string().max(1000).optional(),
});
export type ApprovalRequest = z.infer<typeof RequestSchema>;

/** One request per exact call: the same principal, agent, tool, field mapping, and arguments always name the same request. */
export function approvalRequestId(binding: ApprovalBinding): string {
  const { principal, agent, tool, fields } = binding;
  return sha256Hex(JSON.stringify({ principal, agent, tool, fields: fields ?? null, argsDigest: digestOf(binding.args) })).slice(0, 32);
}

const fileOf = (dir: string, requestId: string) => join(dir, `${RequestId.parse(requestId)}.json`);

/** The request, or undefined when there is none or the file is not a request. */
export function readApprovalRequest(dir: string, requestId: string): ApprovalRequest | undefined {
  let text: string;
  try {
    text = readFileSync(fileOf(dir, requestId), "utf8");
  } catch {
    return undefined;
  }
  try {
    const parsed = RequestSchema.safeParse(JSON.parse(text));
    return parsed.success && parsed.data.requestId === requestId ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** Every request in the directory, oldest first. Files that are not requests are skipped. */
export function listApprovalRequests(dir: string): ApprovalRequest[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((n) => /^[0-9a-f]{32}\.json$/.test(n))
    .map((n) => readApprovalRequest(dir, n.slice(0, 32)))
    .filter((r): r is ApprovalRequest => r !== undefined)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

function write(dir: string, request: ApprovalRequest): ApprovalRequest {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = fileOf(dir, request.requestId);
  const tmp = `${file}.${randomUUID()}.tmp`;
  writeFileSync(tmp, JSON.stringify(request, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, file);
  return request;
}

export type ApprovalPickup =
  | { envelope: Envelope; requestId: string }
  | { requestId: string; status: "pending" | "denied"; previous?: string };

/**
 * The gateway's side, for a protected call that came without an approval. An approved request whose envelope `usable`
 * accepts, and that `usedDir` has not consumed, gives its envelope. A pending or denied request is reported as it is.
 * Anything else (no request, a file that is not one, an approval used or no longer accepted) opens a new pending
 * request; `previous` says why an approved one was not taken.
 */
export function pickupApproval(
  dir: string,
  usedDir: string,
  binding: ApprovalBinding,
  requiredApprovers: 1 | 2,
  receiptId: string,
  at: string,
  usable: (envelope: Envelope) => { ok: true } | { ok: false; error: string },
): ApprovalPickup {
  const requestId = approvalRequestId(binding);
  const found = readApprovalRequest(dir, requestId);
  let previous: string | undefined;
  // a denial's reason is the file's free text: the gateway reports that the call was denied, not what the file says
  if (found?.status === "denied") return { requestId, status: "denied" };
  if (found?.status === "pending" && found.requiredApprovers === requiredApprovers) return { requestId, status: "pending" };
  if (found?.status === "approved" && found.envelope) {
    const env = found.envelope as Envelope;
    const id = approvalIdOf(env);
    const checked = usable(env);
    if (id && approvalConsumed(usedDir, id)) previous = "has been used";
    else if (!checked.ok) previous = `was not accepted: ${checked.error}`;
    else return { envelope: env, requestId };
  }
  write(dir, { version: "0.1", requestId, createdAt: at, binding: structuredClone(binding), argsDigest: digestOf(binding.args), requiredApprovers, receiptId, status: "pending" });
  return { requestId, status: "pending", ...(previous ? { previous } : {}) };
}

function approvalIdOf(env: Envelope): string | undefined {
  try {
    const id = (JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")) as { approvalId?: unknown }).approvalId;
    return typeof id === "string" ? id : undefined;
  } catch {
    return undefined;
  }
}

function pending(dir: string, requestId: string): ApprovalRequest {
  const request = readApprovalRequest(dir, requestId);
  if (!request) throw new Error(`no approval request ${requestId} in ${dir}`);
  if (request.status !== "pending") throw new Error(`approval request ${requestId} is already ${request.status}`);
  return request;
}

/**
 * The approver's side: sign the request's exact call with `key`. The first signature sets the expiry (`expiresAt`); a
 * second approver countersigns the same payload, whose expiry was set by the first. The request is approved once it
 * carries `requiredApprovers` distinct keys. The key stays where this runs; only the signed envelope is written, and
 * only after the checks of `signApprovalRequest`.
 */
export function approveApprovalRequest(dir: string, requestId: string, key: KeyPair, opts: { expiresAt: string; trusted: PublicKeyRef[]; at?: string; maxLifetimeSeconds?: number }): ApprovalRequest {
  const at = opts.at ?? new Date().toISOString();
  const p = approvalRequestPayload(dir, requestId, { expiresAt: opts.expiresAt, at });
  const sig = sign(null, Buffer.from(p.pae, "base64"), key.privateKey).toString("base64");
  return signApprovalRequest(dir, requestId, { payload: p.payload, keyid: key.keyid, sig }, opts.trusted, { at, ...(opts.maxLifetimeSeconds !== undefined ? { maxLifetimeSeconds: opts.maxLifetimeSeconds } : {}) });
}

/** When the approval a request carries stops being valid, read from its signed payload. */
export function approvalRequestExpiresAt(request: ApprovalRequest): string | undefined {
  try {
    const expiresAt = (JSON.parse(Buffer.from(request.envelope?.payload ?? "", "base64").toString("utf8")) as { expiresAt?: unknown }).expiresAt;
    return typeof expiresAt === "string" ? expiresAt : undefined;
  } catch {
    return undefined;
  }
}

function signed(dir: string, request: ApprovalRequest, envelope: Envelope, at: string): ApprovalRequest {
  const done = new Set(envelope.signatures.map((s) => s.keyid)).size >= request.requiredApprovers;
  return write(dir, { ...request, envelope, ...(done ? { status: "approved" as const, decidedAt: at } : {}) });
}

/**
 * What an approver signs for a pending request, when the signing happens elsewhere (the console signs in the browser):
 * the payload already signed once under a two-person rule, or a new statement expiring at `expiresAt`, and the DSSE
 * bytes a signature is made over. Nothing is written until `signApprovalRequest` gets a signature that verifies.
 */
export function approvalRequestPayload(dir: string, requestId: string, opts: { expiresAt: string; at?: string }): { payloadType: string; payload: string; pae: string; signedBy: string[] } {
  const request = pending(dir, requestId);
  const payload = request.envelope?.payload ?? Buffer.from(canonicalize(approvalStatement({ ...(request.binding as ApprovalBinding), issuedAt: opts.at ?? new Date().toISOString(), expiresAt: opts.expiresAt }))).toString("base64");
  return { payloadType: APPROVAL_TYPE, payload, pae: pae(APPROVAL_TYPE, Buffer.from(payload, "base64")).toString("base64"), signedBy: request.envelope?.signatures.map((s) => s.keyid) ?? [] };
}

/**
 * Add a signature. It is kept only if it verifies with a trusted key and its payload binds this request's exact call,
 * inside the lifetime cap: the same checks the gateway makes. A countersignature is added only to an envelope whose
 * signature already passes them: the directory is untrusted, and a payload planted there must never get a second
 * signature for a call nobody reviewed.
 */
export function signApprovalRequest(dir: string, requestId: string, sig: { payload: string; keyid: string; sig: string }, trusted: PublicKeyRef[], opts: { at?: string; maxLifetimeSeconds?: number } = {}): ApprovalRequest {
  const request = pending(dir, requestId);
  const at = opts.at ?? new Date().toISOString();
  const checks = { at, minApprovers: 1 as const, ...(opts.maxLifetimeSeconds !== undefined ? { maxLifetimeSeconds: opts.maxLifetimeSeconds } : {}) };
  if (request.envelope) {
    if (request.requiredApprovers < 2) throw new Error(`approval request ${requestId} needs one approver, yet carries a signature; delete it, and the gateway opens it again on the next call`);
    const first = verifyApproval(request.envelope, trusted, request.binding as ApprovalBinding, checks);
    if (!first.ok) throw new Error(`approval request ${requestId} carries a signature that does not stand (${first.error}); delete it, and the gateway opens it again on the next call`);
  }
  if (request.envelope && sig.payload !== request.envelope.payload) throw new Error(`approval request ${requestId} already carries a signed payload, and this signature is over another one`);
  if (request.envelope?.signatures.some((s) => s.keyid === sig.keyid)) throw new Error(`approval request ${requestId} is already signed with key ${sig.keyid}; a second approver must use a different key`);
  const one: Envelope = { payloadType: APPROVAL_TYPE, payload: sig.payload, signatures: [{ keyid: sig.keyid, sig: sig.sig }] };
  const checked = verifyApproval(one, trusted, request.binding as ApprovalBinding, checks);
  if (!checked.ok) throw new Error(`the signature was not accepted: ${checked.error}`);
  return signed(dir, request, request.envelope ? { ...(request.envelope as Envelope), signatures: [...request.envelope.signatures, one.signatures[0]!] } : one, at);
}

/** The approver's side: refuse the request. The gateway keeps refusing that exact call, and says so, until the request is deleted. */
export function denyApprovalRequest(dir: string, requestId: string, opts: { reason?: string; at?: string } = {}): ApprovalRequest {
  const request = pending(dir, requestId);
  const { envelope: _signedSoFar, ...rest } = request;
  return write(dir, { ...rest, status: "denied", decidedAt: opts.at ?? new Date().toISOString(), ...(opts.reason ? { reason: opts.reason.slice(0, 1000) } : {}) });
}

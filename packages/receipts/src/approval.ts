// A short-lived human approval signs the exact action, independently of the agent's delegation grant.
import { randomUUID } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import { digestOf, dsseSign, dsseVerifiers, sha256Hex, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";

export const APPROVAL_TYPE = "application/vnd.agent-custody.approval+json";
export const APPROVAL_META_KEY = "agent-custody/approval";

const Nonempty = z.string().min(1);
const Timestamp = z.iso.datetime({ offset: true });
const ApprovalId = z.uuid();

export const ApprovalSchema = z.strictObject({
  version: z.literal("0.1"),
  approvalId: ApprovalId,
  principal: Nonempty,
  agent: Nonempty,
  tool: Nonempty,
  argsDigest: z.string().regex(/^[0-9a-f]{64}$/),
  /** Money is expressed in integer minor units, never a float. */
  amount: z.number().int().min(Number.MIN_SAFE_INTEGER).max(Number.MAX_SAFE_INTEGER).optional(),
  currency: Nonempty.optional(),
  beneficiary: Nonempty.optional(),
  issuedAt: Timestamp,
  expiresAt: Timestamp,
}).refine((a) => Date.parse(a.expiresAt) > Date.parse(a.issuedAt), {
  message: "approval expiry must be after issuance", path: ["expiresAt"],
});
export type Approval = z.infer<typeof ApprovalSchema>;

export interface ApprovalBinding {
  principal: string;
  agent: string;
  tool: string;
  args: Record<string, unknown>;
  /** Argument names for the action fields; each defaults to its own name. */
  fields?: { amount?: string; currency?: string; beneficiary?: string };
}

/** The gateway's observation of its approval check, embedded in the authorization and the receipt. */
export interface ApprovalRecord {
  envelope?: Envelope;
  /** Effective argument names used for the action fields. */
  fields?: ApprovalBinding["fields"];
  requiredApprovers: 1 | 2;
  checkedAt: string;
  status: "approved" | "denied";
  reason?: string;
  approverKeyids: string[];
  consumedAt?: string;
  provenance: "observed";
}

const BindingSchema = z.strictObject({
  principal: Nonempty,
  agent: Nonempty,
  tool: Nonempty,
  args: z.record(z.string(), z.unknown()),
  fields: z.strictObject({ amount: Nonempty.optional(), currency: Nonempty.optional(), beneficiary: Nonempty.optional() }).optional(),
});

// Reject values JSON would silently omit or change. Otherwise two different actions could have the same digest.
function assertJson(value: unknown, ancestors = new Set<object>()): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object" || ancestors.has(value)) throw new Error("approval arguments must be JSON data");
  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new Error("approval arguments must be JSON data");
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) assertJson(value[i], ancestors);
  } else {
    for (const key of Object.keys(value)) assertJson((value as Record<string, unknown>)[key], ancestors);
  }
  ancestors.delete(value);
}

function actionFor(input: ApprovalBinding): Pick<Approval, "principal" | "agent" | "tool" | "argsDigest" | "amount" | "currency" | "beneficiary"> {
  // Validate without replacing args: z.record would copy an own __proto__ property on some runtimes.
  BindingSchema.parse(input);
  assertJson(input.args);
  const action: Pick<Approval, "principal" | "agent" | "tool" | "argsDigest" | "amount" | "currency" | "beneficiary"> = {
    principal: input.principal, agent: input.agent, tool: input.tool, argsDigest: digestOf(input.args),
  };
  for (const field of ["amount", "currency", "beneficiary"] as const) {
    const name = input.fields?.[field] ?? field;
    if (!Object.hasOwn(input.args, name)) continue;
    const value = input.args[name];
    if (field === "amount") {
      if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error("approval amount must be a safe integer in minor units");
      action.amount = value;
    } else {
      if (typeof value !== "string" || !value.length) throw new Error(`approval ${field} must be a nonempty string`);
      action[field] = value;
    }
  }
  return action;
}

/** Sign the exact arguments and their explicit action fields. A second approver uses dsseCountersign. */
export function createApproval(key: KeyPair, input: ApprovalBinding & { approvalId?: string; issuedAt?: string; expiresAt: string }): Envelope {
  const { approvalId = randomUUID(), issuedAt = new Date().toISOString(), expiresAt, ...binding } = input;
  const approval = ApprovalSchema.parse({ version: "0.1", approvalId, ...actionFor(binding), issuedAt, expiresAt });
  return dsseSign(APPROVAL_TYPE, approval, key);
}

function isBase64(value: string): boolean {
  return value.length > 0 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value) && Buffer.from(value, "base64").toString("base64") === value;
}

const EnvelopeSchema = z.strictObject({
  payloadType: z.literal(APPROVAL_TYPE),
  payload: z.string().refine(isBase64, "approval payload must be base64"),
  signatures: z.array(z.strictObject({
    keyid: Nonempty,
    sig: z.string().refine((s) => isBase64(s) && Buffer.from(s, "base64").length === 64, "approval signature must be an Ed25519 signature"),
  })).min(1),
});

export type ApprovalVerifyResult =
  | { ok: true; approval: Approval; approverKeyids: string[] }
  | { ok: false; error: string };

/** Check the signed approval schema and trusted, distinct signatures; the caller must also check its action and validity window. */
export function verifyApprovalStatement(envelope: unknown, trusted: PublicKeyRef[], minApprovers: 1 | 2 = 1): ApprovalVerifyResult {
  try {
    const parsedEnvelope = EnvelopeSchema.safeParse(envelope);
    if (!parsedEnvelope.success) return { ok: false, error: "malformed approval envelope" };
    const env = parsedEnvelope.data;
    if (minApprovers !== 1 && minApprovers !== 2) return { ok: false, error: "approval requires one or two approvers" };
    const approverKeyids = [...new Set(dsseVerifiers(env, trusted))];
    if (approverKeyids.length < minApprovers) return { ok: false, error: `approval requires ${minApprovers} distinct trusted signature${minApprovers === 1 ? "" : "s"}` };
    const parsed = ApprovalSchema.safeParse(JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")));
    if (!parsed.success) return { ok: false, error: `invalid approval: ${parsed.error.message}` };
    return { ok: true, approval: parsed.data, approverKeyids };
  } catch (error) {
    return { ok: false, error: `invalid approval: ${error instanceof Error ? error.message : "could not verify"}` };
  }
}

/** Check trusted, distinct signatures, the whole action binding, and the half-open validity window. Never throws for untrusted input. */
export function verifyApproval(envelope: unknown, trusted: PublicKeyRef[], binding: ApprovalBinding, options: { at?: string; minApprovers?: 1 | 2 } = {}): ApprovalVerifyResult {
  try {
    const signed = verifyApprovalStatement(envelope, trusted, options.minApprovers ?? 1);
    if (!signed.ok) return signed;
    const { approval, approverKeyids } = signed;
    const action = actionFor(binding);
    // Fields must match in both directions: a signed field missing from the call is a mismatch too.
    for (const field of ["principal", "agent", "tool", "argsDigest", "amount", "currency", "beneficiary"] as const) {
      if (approval[field] !== action[field]) return { ok: false, error: `approval ${field} does not match this call` };
    }
    const at = options.at ?? new Date().toISOString();
    if (!Timestamp.safeParse(at).success) return { ok: false, error: "invalid approval check time" };
    if (Date.parse(at) < Date.parse(approval.issuedAt)) return { ok: false, error: "approval is not yet valid" };
    if (Date.parse(at) >= Date.parse(approval.expiresAt)) return { ok: false, error: "approval has expired" };
    return { ok: true, approval, approverKeyids };
  } catch (error) {
    return { ok: false, error: `invalid approval: ${error instanceof Error ? error.message : "could not verify"}` };
  }
}

/**
 * Burn an approval before any side effect. Exclusive creation shares replay protection across processes and restarts.
 * A subsequent write, log, or upstream failure deliberately leaves the marker in place: retry needs a new approval.
 */
export function consumeApproval(usedDir: string, approvalId: string, receiptId: string, at: string): void {
  ApprovalId.parse(approvalId);
  Nonempty.parse(receiptId);
  Timestamp.parse(at);
  mkdirSync(usedDir, { recursive: true, mode: 0o700 });
  const directory = realpathSync(usedDir);
  // UUID spelling is case-insensitive; using its canonical spelling prevents two markers for one logical id.
  const id = approvalId.toLowerCase();
  let fd: number;
  try {
    fd = openSync(join(directory, `${sha256Hex(id)}.json`), "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error(`approval ${approvalId} has already been used`);
    throw error;
  }
  try {
    writeFileSync(fd, JSON.stringify({ approvalId, receiptId, consumedAt: at }) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  // fsync(file) does not persist the new directory entry. Flush the directory and its ancestry, deepest first, so
  // newly created parents survive a machine crash too. Flush existing parents as well: another process may just
  // have created them and not yet synced them. Any failure leaves the id burned and must prevent forwarding.
  for (let path = directory; ; path = dirname(path)) {
    const dirFd = openSync(path, "r");
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
    if (dirname(path) === path) break;
  }
}

// Search only the public signed view. In particular, this reader never restores capture commitments or opens
// the issuer's salts files: an identifier is searchable only when the receipt itself carries it in clear.
import type { ReceiptStatement } from "@agent-custody/receipts";

export interface ReceiptSearch {
  transaction?: string;
  customer?: string;
  agent?: string;
  /** Inclusive ISO 8601 date-time with a UTC offset. */
  from?: string;
  /** Inclusive ISO 8601 date-time with a UTC offset. */
  to?: string;
}

/** Reject ambiguous, invalid, or inverted date ranges. Self-contained so static pages use this exact validator. */
export function validateReceiptSearch(query: ReceiptSearch): void {
  for (const field of ["transaction", "customer", "agent", "from", "to"] as const) {
    const value = query[field];
    if (value !== undefined && typeof value !== "string") throw new Error(`receipt search: ${field} must be a string`);
  }
  for (const field of ["from", "to"] as const) {
    const value = query[field];
    if (value === undefined) continue;
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/.exec(value);
    const [year, month, day, hour, minute, second] = match ? match.slice(1).map((v) => Number(v ?? 0)) : [];
    const leap = year! % 4 === 0 && (year! % 100 !== 0 || year! % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (!match || month! < 1 || month! > 12 || day! < 1 || day! > days[month! - 1]! || hour! > 23 || minute! > 59 || second! > 59 || !Number.isFinite(Date.parse(value))) {
      throw new Error(`receipt search: ${field} must be an ISO 8601 date-time with a UTC offset`);
    }
  }
  if (query.from !== undefined && query.to !== undefined && Date.parse(query.from) > Date.parse(query.to)) {
    throw new Error("receipt search: from must be at or before to");
  }
}

type Predicate = ReceiptStatement["predicate"];
type Kind = "transaction" | "customer";
const TRANSACTION_FIELDS = new Set(["transaction", "transaction_id", "transactionId", "payment_intent", "payment_intent_id", "paymentIntent", "paymentIntentId", "charge", "charge_id", "chargeId", "refund", "refund_id", "refundId"]);
const CUSTOMER_FIELDS = new Set(["customer", "customer_id", "customerId"]);
const TRANSACTION_ID = /^(?:re|pi|ch|txn|tr|py|po)_.+/;
const CUSTOMER_ID = /^cus(?:t)?_.+/;
const kindOf = (field: string): Kind | undefined => TRANSACTION_FIELDS.has(field) ? "transaction" : CUSTOMER_FIELDS.has(field) ? "customer" : undefined;
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Named identifiers in public arguments, results, and fact lookups. Complete JSON objects/arrays in MCP text are
 * inspected too; prose, digests, signatures, metadata outside those values, and encoded envelopes are not searched.
 * Generic result `id` fields count only when they have a known payment or customer id prefix.
 */
export function receiptSearchTerms(predicate: Predicate): { transactionIds: string[]; customerIds: string[] } {
  const transaction = new Set<string>();
  const customer = new Set<string>();
  const terms = { transaction, customer };
  const withheld = new Set((predicate.capture?.withheld ?? []).map((path) => JSON.stringify(path)));
  const hidden = (path: string[]) => path.some((_, i) => withheld.has(JSON.stringify(path.slice(0, i + 1))));

  const add = (value: unknown, kind: Kind, path: string[]) => {
    if (hidden(path)) return;
    if (typeof value === "string" && value.length) terms[kind].add(value);
    else if (object(value) && Object.hasOwn(value, "id") && !hidden([...path, "id"]) && typeof value.id === "string" && value.id.length) terms[kind].add(value.id);
  };
  const walk = (value: unknown, path: string[], result: boolean): void => {
    if (hidden(path)) return;
    if (typeof value === "string") {
      // JSON.parse only accepts the entire text. A sentence that happens to mention an id is not an identifier.
      if (/^\s*[\[{]/.test(value)) {
        try {
          walk(JSON.parse(value), path, result);
        } catch {
          // Ordinary tool text is not JSON.
        }
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, i) => walk(item, [...path, String(i)], result));
      return;
    }
    if (!object(value)) return;
    for (const [field, item] of Object.entries(value)) {
      const next = [...path, field];
      if (hidden(next)) continue;
      const kind = kindOf(field);
      if (kind) add(item, kind, next);
      else if (result && field === "id" && typeof item === "string") {
        if (TRANSACTION_ID.test(item)) transaction.add(item);
        if (CUSTOMER_ID.test(item)) customer.add(item);
      }
      walk(item, next, result);
    }
  };

  walk(predicate.request.args, ["request", "args"], false);
  if (predicate.execution.status === "executed" || predicate.execution.status === "failed") {
    walk(predicate.execution.result, ["execution", "result"], true);
  }
  for (const [name, fact] of Object.entries(predicate.facts)) {
    const path = ["facts", name];
    if (hidden(path)) continue;
    walk(fact.args, [...path, "args"], false);
    const kind = kindOf(name);
    if (kind) add(fact.value, kind, [...path, "value"]);
    walk(fact.value, [...path, "value"], true);
  }
  return { transactionIds: [...transaction].sort(), customerIds: [...customer].sort() };
}

/** Every supplied filter must match; identifiers and agent ids are exact and case sensitive. */
export function matchesReceiptSearch(predicate: Predicate, query: ReceiptSearch): boolean {
  validateReceiptSearch(query);
  if (query.agent !== undefined && predicate.agent.id !== query.agent) return false;
  if (query.from !== undefined || query.to !== undefined) {
    const timestamp = Date.parse(predicate.timestamp);
    if (!Number.isFinite(timestamp)) return false;
    if (query.from !== undefined && timestamp < Date.parse(query.from)) return false;
    if (query.to !== undefined && timestamp > Date.parse(query.to)) return false;
  }
  if (query.transaction !== undefined || query.customer !== undefined) {
    const terms = receiptSearchTerms(predicate);
    if (query.transaction !== undefined && !terms.transactionIds.includes(query.transaction)) return false;
    if (query.customer !== undefined && !terms.customerIds.includes(query.customer)) return false;
  }
  return true;
}

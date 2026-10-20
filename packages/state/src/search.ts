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

// The input is the agent's own text, so the work per receipt has fixed bounds. A walk stops below MAX_DEPTH levels, and
// a string is parsed as JSON only up to MAX_JSON_TEXT characters. A node deeper than that, or in longer text, is not
// searched, and the result says `truncated`, so that a reader never mistakes a skipped value for an absent one.
const MAX_DEPTH = 64;
const MAX_JSON_TEXT = 65_536;
const JSON_START = /^\s*[\[{]/;
interface Trie { end: boolean; kids: Map<string, Trie> }
const HIDDEN = Symbol("hidden");

/** The withheld paths as a trie, so that a walk tracks "hidden" one step at a time. */
function withheldTrie(withheld: unknown): Trie {
  const root: Trie = { end: false, kids: new Map() };
  if (!Array.isArray(withheld)) return root;
  for (const path of withheld) {
    // An empty path, or a path with a step that is not a string, never named a field.
    if (!Array.isArray(path) || !path.length || !path.every((step) => typeof step === "string")) continue;
    let at = root;
    for (const step of path as string[]) {
      let next = at.kids.get(step);
      if (!next) at.kids.set(step, (next = { end: false, kids: new Map() }));
      at = next;
    }
    at.end = true;
  }
  return root;
}
/** The trie node below the keys, `undefined` when no withheld path goes there, or HIDDEN when a withheld path ends on the way. */
const into = (at: Trie | undefined, ...keys: string[]): Trie | undefined | typeof HIDDEN => {
  for (const key of keys) {
    at = at?.kids.get(key);
    if (at?.end) return HIDDEN;
  }
  return at;
};

/**
 * Named identifiers in public arguments, results, and fact lookups. Complete JSON objects/arrays in MCP text are
 * inspected too; prose, digests, signatures, metadata outside those values, and encoded envelopes are not searched.
 * Generic result `id` fields count only when they have a known payment or customer id prefix. Values nested deeper
 * than 64 levels, and JSON text longer than 64 KiB, are not searched, so that one hostile argument cannot stall a reader.
 * When a value is skipped for that reason, the result carries `truncated: true`. Otherwise it has no such field.
 */
export function receiptSearchTerms(predicate: Predicate): { transactionIds: string[]; customerIds: string[]; truncated?: true } {
  let truncated = false;
  const transaction = new Set<string>();
  const customer = new Set<string>();
  const terms = { transaction, customer };
  const trie = withheldTrie(predicate.capture?.withheld);

  const add = (value: unknown, kind: Kind, at: Trie | undefined) => {
    if (typeof value === "string" && value.length) terms[kind].add(value);
    else if (object(value) && Object.hasOwn(value, "id") && into(at, "id") !== HIDDEN && typeof value.id === "string" && value.id.length) terms[kind].add(value.id);
  };
  // `at` is the trie node of the value's path. It is never a withheld node. It is undefined when no withheld path runs below.
  const walk = (value: unknown, at: Trie | undefined, result: boolean, depth: number): void => {
    if (depth > MAX_DEPTH) {
      if ((value !== null && typeof value === "object") || (typeof value === "string" && JSON_START.test(value))) truncated = true;
      return;
    }
    if (typeof value === "string") {
      // JSON.parse only accepts the entire text. A sentence that happens to mention an id is not an identifier.
      if (value.length > MAX_JSON_TEXT && JSON_START.test(value)) truncated = true;
      else if (JSON_START.test(value)) {
        try {
          walk(JSON.parse(value), at, result, depth + 1);
        } catch {
          // Ordinary tool text is not JSON.
        }
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, i) => {
        const next = into(at, String(i));
        if (next !== HIDDEN) walk(item, next, result, depth + 1);
      });
      return;
    }
    if (!object(value)) return;
    for (const [field, item] of Object.entries(value)) {
      const next = into(at, field);
      if (next === HIDDEN) continue;
      const kind = kindOf(field);
      if (kind) add(item, kind, next);
      else if (result && field === "id" && typeof item === "string") {
        if (TRANSACTION_ID.test(item)) transaction.add(item);
        if (CUSTOMER_ID.test(item)) customer.add(item);
      }
      walk(item, next, result, depth + 1);
    }
  };
  const start = (value: unknown, result: boolean, ...path: string[]) => {
    const at = into(trie, ...path);
    if (at !== HIDDEN) walk(value, at, result, 0);
  };

  start(predicate.request.args, false, "request", "args");
  if (predicate.execution.status === "executed" || predicate.execution.status === "failed") {
    start(predicate.execution.result, true, "execution", "result");
  }
  for (const [name, fact] of Object.entries(predicate.facts)) {
    if (into(trie, "facts", name) === HIDDEN) continue;
    start(fact.args, false, "facts", name, "args");
    const valueAt = into(trie, "facts", name, "value");
    if (valueAt === HIDDEN) continue;
    const kind = kindOf(name);
    if (kind) add(fact.value, kind, valueAt);
    walk(fact.value, valueAt, true, 0);
  }
  return { transactionIds: [...transaction].sort(), customerIds: [...customer].sort(), ...(truncated ? { truncated: true as const } : {}) };
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

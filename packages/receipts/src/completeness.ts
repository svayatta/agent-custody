// Completeness from the provider's side. Receipts prove what went through the gateway; nothing on the gateway's side
// can see an action that never did. An auditor with a read-only key of their own lists the provider's objects over a
// window and matches each one to a verified receipt by the provider's object id, which the receipt's result carries.
// A provider object with no receipt is an action taken outside the gateway; a receipt with no provider object is an
// action the provider does not have. Nothing here writes, retries, or calls the provider for anything but a list.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { isCommitment, REST } from "./capture.ts";
import type { AuthorizationBundle, ReceiptBundle, ReceiptPredicate } from "./receipt.ts";
import { verifyOrphanAuthorization } from "./simulate.ts";
import { verifyBundle, type VerifyOptions } from "./verify.ts";

/** One provider object, reduced to what the comparison reads. */
export interface ProviderObject {
  id: string;
  /** when the provider created it, as epoch milliseconds */
  createdMs: number;
  amount?: number;
  currency?: string;
  /** the provider's own object, for beneficiary fields */
  raw: Record<string, unknown>;
}

export interface ProviderSource {
  /** for reports, e.g. "stripe refunds" */
  name: string;
  list(sinceMs: number, untilMs: number): AsyncIterable<ProviderObject>;
}

export type StripeObject = "refunds" | "payouts" | "transfers";

export interface StripeSourceOptions {
  /** a read-only (restricted) key; from the environment, never a flag */
  secretKey: string;
  object: StripeObject;
  baseUrl?: string;
  fetch?: typeof fetch;
}

/** Lists Stripe objects created in the window, every page, with `created[gte]` and `created[lt]`. */
export function stripeSource(o: StripeSourceOptions): ProviderSource {
  const f = o.fetch ?? fetch;
  const base = o.baseUrl ?? "https://api.stripe.com/";
  return {
    name: `stripe ${o.object}`,
    async *list(sinceMs, untilMs) {
      let after: string | undefined;
      for (;;) {
        const url = new URL(`v1/${o.object}`, base);
        url.searchParams.set("limit", "100");
        url.searchParams.set("created[gte]", String(Math.floor(sinceMs / 1000)));
        url.searchParams.set("created[lt]", String(Math.ceil(untilMs / 1000)));
        if (after) url.searchParams.set("starting_after", after);
        const res = await f(url, { headers: { authorization: `Bearer ${o.secretKey}` }, signal: AbortSignal.timeout(15_000) });
        if (!res.ok) throw new Error(`stripe ${o.object}: HTTP ${res.status}`);
        const page = (await res.json()) as { data?: Record<string, unknown>[]; has_more?: boolean };
        const data = Array.isArray(page.data) ? page.data : [];
        for (const obj of data) {
          if (typeof obj.id !== "string" || typeof obj.created !== "number") throw new Error(`stripe ${o.object}: an object without an id or a created time`);
          yield {
            id: obj.id,
            createdMs: obj.created * 1000,
            ...(typeof obj.amount === "number" ? { amount: obj.amount } : {}),
            ...(typeof obj.currency === "string" ? { currency: obj.currency } : {}),
            raw: obj,
          };
        }
        if (!page.has_more || data.length === 0) return;
        after = data[data.length - 1]!.id as string;
      }
    },
  };
}

export interface CompletenessOptions {
  /** the auditor's copy of the receipts directory */
  receiptsDir: string;
  /** how each receipt is verified; only receipts that verify are matched */
  verify: VerifyOptions;
  source: ProviderSource;
  /** the tools whose executed calls create provider objects, e.g. ["stripe.refund"] */
  tools: string[];
  sinceMs: number;
  untilMs: number;
  /** where the provider's object id sits in the JSON of the result's first text item; default "id" */
  idPath?: string;
  /** the call argument that holds the amount in minor units; default "amount" */
  amountField?: string;
  /** the call argument that holds the currency; default "currency", compared case-insensitively when both sides have one */
  currencyField?: string;
  /** call argument → provider field pairs that must be equal, e.g. { charge: "charge" } */
  beneficiary?: Record<string, string>;
  /**
   * provider objects are listed this far either side of the window, so a receipt signed just inside the window still
   * finds an object the provider created just outside it; default fifteen minutes
   */
  marginMs?: number;
}

export interface CompletenessReport {
  provider: string;
  tools: string[];
  window: { since: string; until: string };
  receiptsRead: number;
  matched: { receiptId: string; providerId: string }[];
  /** provider objects in the window with no verified receipt: actions taken outside the gateway */
  providerOnly: { providerId: string; created: string; amount?: number; currency?: string }[];
  /** executed receipts in the window whose provider object the provider does not have */
  receiptOnly: { receiptId: string; providerId: string; timestamp: string }[];
  mismatches: { receiptId: string; providerId: string; field: string; receipt: unknown; provider: unknown }[];
  /** provider objects that more than one verified receipt names: one action recorded twice, or receipts that disagree */
  duplicates: { providerId: string; receiptIds: string[] }[];
  /** receipt files that did not verify, and so were not matched */
  unverified: { file: string; failing: string[] }[];
  /** verified, executed receipts whose provider id cannot be read */
  unmatchable: { receiptId: string; reason: string }[];
  /** calls committed before they were forwarded whose outcome receipt is missing: each may be a provider object above */
  forwardedWithoutOutcome: { receiptId: string; tool: string }[];
  complete: boolean;
}

const AUTHORIZATION = ".authorization.json";
const iso = (ms: number) => new Date(ms).toISOString();

function at(value: unknown, path: string): unknown {
  let v = value;
  for (const part of path.split(".")) {
    if (!v || typeof v !== "object" || !Object.hasOwn(v as object, part)) return undefined;
    v = (v as Record<string, unknown>)[part];
  }
  return v;
}

/** The provider object id that an executed call's result carries, or why it cannot be read. */
function providerIdOf(p: ReceiptPredicate, idPath: string): { id: string } | { reason: string } {
  const result = (p.execution as { result?: unknown }).result;
  if (isCommitment(result)) return { reason: "the result is withheld under a capture rule; the provider's object id cannot be read from the receipt" };
  const r = result as Record<string, unknown> | null;
  // a `$rest` commitment may hold only unrelated fields: the content is withheld only when it is not kept in clear
  if (r && !Object.hasOwn(r, "content") && isCommitment(r[REST])) return { reason: "the result content is withheld under a capture rule; the provider's object id cannot be read from the receipt" };
  const content = r?.content;
  const first = Array.isArray(content) ? content[0] : undefined;
  if (isCommitment(content) || isCommitment(first)) return { reason: "the result content is withheld under a capture rule; the provider's object id cannot be read from the receipt" };
  const text = (first as { text?: unknown } | undefined)?.text;
  if (isCommitment(text)) return { reason: "the result content is withheld under a capture rule; the provider's object id cannot be read from the receipt" };
  if (typeof text !== "string") return { reason: "the result carries no text to read the provider's object id from" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { reason: "the result's text is not JSON" };
  }
  const id = at(parsed, idPath);
  return typeof id === "string" && id.length ? { id } : { reason: `the result has no string at "${idPath}"` };
}

/** A call argument, or that a capture rule withholds it: listed fields stay in clear beside one `$rest` commitment. */
function argOf(args: Record<string, unknown>, field: string): { value: unknown } | { withheld: true } {
  if (Object.hasOwn(args, field)) return isCommitment(args[field]) ? { withheld: true } : { value: args[field] };
  return isCommitment(args[REST]) ? { withheld: true } : { value: undefined };
}

export async function checkCompleteness(o: CompletenessOptions): Promise<CompletenessReport> {
  const idPath = o.idPath ?? "id";
  const amountField = o.amountField ?? "amount";
  const currencyField = o.currencyField ?? "currency";
  const margin = o.marginMs ?? 15 * 60_000;
  const tools = new Set(o.tools);
  const inWindow = (ms: number) => ms >= o.sinceMs && ms < o.untilMs;
  const report: CompletenessReport = {
    provider: o.source.name,
    tools: [...o.tools],
    window: { since: iso(o.sinceMs), until: iso(o.untilMs) },
    receiptsRead: 0,
    matched: [],
    providerOnly: [],
    receiptOnly: [],
    mismatches: [],
    duplicates: [],
    unverified: [],
    unmatchable: [],
    forwardedWithoutOutcome: [],
    complete: false,
  };

  const names = readdirSync(o.receiptsDir, { withFileTypes: true }).filter((e) => (e.isFile() || e.isSymbolicLink()) && e.name.endsWith(".json")).map((e) => e.name).sort();
  const outcomes = new Set<string>();
  const byProviderId = new Map<string, ReceiptPredicate[]>();
  for (const name of names) {
    if (name.endsWith(AUTHORIZATION)) continue;
    report.receiptsRead++;
    let result: ReturnType<typeof verifyBundle>;
    try {
      result = verifyBundle(JSON.parse(readFileSync(join(o.receiptsDir, name), "utf8")) as ReceiptBundle, o.verify);
    } catch (e) {
      report.unverified.push({ file: name, failing: [e instanceof Error ? e.message : String(e)] });
      continue;
    }
    if (!result.ok || !result.statement) {
      report.unverified.push({ file: name, failing: result.checks.filter((c) => !c.ok).map((c) => c.name) });
      continue;
    }
    const p = result.statement.predicate;
    // the gateway names each file by its receipt id: a valid receipt under another name could stand in for a missing outcome
    if (name !== `${p.receiptId}.json`) {
      report.unverified.push({ file: name, failing: [`the file name does not match the signed receipt id ${p.receiptId}`] });
      continue;
    }
    outcomes.add(p.receiptId);
    if (!tools.has(p.tool.name) || p.reconciliation || p.execution.status !== "executed") continue;
    const id = providerIdOf(p, idPath);
    if ("reason" in id) {
      if (inWindow(Date.parse(p.timestamp))) report.unmatchable.push({ receiptId: p.receiptId, reason: id.reason });
      continue;
    }
    byProviderId.set(id.id, [...(byProviderId.get(id.id) ?? []), p]);
  }

  for (const name of names) {
    if (!name.endsWith(AUTHORIZATION)) continue;
    // committed and forwarded, then nothing: the provider may hold an object this report cannot tie to a receipt
    let auth: ReturnType<typeof verifyOrphanAuthorization>;
    try {
      auth = verifyOrphanAuthorization(JSON.parse(readFileSync(join(o.receiptsDir, name), "utf8")) as AuthorizationBundle, o.verify.issuerKeys, o.verify.logKeys ?? []);
    } catch (e) {
      report.unverified.push({ file: name, failing: [e instanceof Error ? e.message : String(e)] });
      continue;
    }
    if (name !== `${auth.receiptId}${AUTHORIZATION}`) report.unverified.push({ file: name, failing: [`the file name does not match the signed receipt id ${auth.receiptId}`] });
    if (outcomes.has(auth.receiptId) || !tools.has(auth.tool.name) || !inWindow(Date.parse(auth.timestamp))) continue;
    report.forwardedWithoutOutcome.push({ receiptId: auth.receiptId, tool: auth.tool.name });
  }

  const seen = new Set<string>();
  for await (const obj of o.source.list(o.sinceMs - margin, o.untilMs + margin)) {
    seen.add(obj.id);
    const receipts = byProviderId.get(obj.id) ?? [];
    // the margin finds a receipt across the window's edge; it does not widen the period reported on
    const inScope = inWindow(obj.createdMs) || receipts.some((p) => inWindow(Date.parse(p.timestamp)));
    if (!inScope) continue;
    if (!receipts.length) {
      report.providerOnly.push({ providerId: obj.id, created: iso(obj.createdMs), ...(obj.amount !== undefined ? { amount: obj.amount } : {}), ...(obj.currency !== undefined ? { currency: obj.currency } : {}) });
      continue;
    }
    if (receipts.length > 1) report.duplicates.push({ providerId: obj.id, receiptIds: receipts.map((p) => p.receiptId) });
    for (const p of receipts) {
      report.matched.push({ receiptId: p.receiptId, providerId: obj.id });
      const args = p.request.args;
      const withheld = (arg: string) => report.unmatchable.push({ receiptId: p.receiptId, reason: `the argument "${arg}" is withheld under a capture rule, so it cannot be compared` });
      const amount = argOf(args, amountField);
      if ("withheld" in amount) {
        if (obj.amount !== undefined) withheld(amountField);
      } else if (obj.amount !== undefined && amount.value !== obj.amount) report.mismatches.push({ receiptId: p.receiptId, providerId: obj.id, field: "amount", receipt: amount.value, provider: obj.amount });
      const currency = argOf(args, currencyField);
      if ("withheld" in currency) {
        if (obj.currency !== undefined) withheld(currencyField);
      } else if (typeof currency.value === "string" && obj.currency !== undefined && currency.value.toLowerCase() !== obj.currency.toLowerCase()) report.mismatches.push({ receiptId: p.receiptId, providerId: obj.id, field: "currency", receipt: currency.value, provider: obj.currency });
      for (const [arg, field] of Object.entries(o.beneficiary ?? {})) {
        const value = argOf(args, arg);
        if ("withheld" in value || value.value === undefined) {
          report.unmatchable.push({ receiptId: p.receiptId, reason: `the beneficiary argument "${arg}" is missing or withheld, so it cannot be compared` });
          continue;
        }
        const provider = at(obj.raw, field);
        if (String(value.value) !== String(provider)) report.mismatches.push({ receiptId: p.receiptId, providerId: obj.id, field: arg, receipt: value.value, provider });
      }
    }
  }
  for (const [providerId, receipts] of byProviderId) {
    if (seen.has(providerId)) continue;
    for (const p of receipts) if (inWindow(Date.parse(p.timestamp))) report.receiptOnly.push({ receiptId: p.receiptId, providerId, timestamp: p.timestamp });
  }
  report.matched.sort((a, b) => a.receiptId.localeCompare(b.receiptId));
  report.complete = [report.providerOnly, report.receiptOnly, report.mismatches, report.duplicates, report.unverified, report.unmatchable, report.forwardedWithoutOutcome].every((l) => l.length === 0);
  return report;
}

export function formatCompleteness(r: CompletenessReport): string {
  const lines = [`${r.provider} for ${r.tools.join(", ")}, ${r.window.since} to ${r.window.until}: ${r.receiptsRead} receipt(s) read, ${r.matched.length} matched`];
  const section = (title: string, rows: string[]) => {
    if (rows.length) lines.push("", `${title} (${rows.length})`, ...rows.map((row) => `  ${row}`));
  };
  section("PROVIDER ACTIONS WITH NO RECEIPT", r.providerOnly.map((x) => `${x.providerId} created ${x.created}${x.amount !== undefined ? ` amount ${x.amount}${x.currency ? ` ${x.currency}` : ""}` : ""}`));
  section("RECEIPTS THE PROVIDER DOES NOT HAVE", r.receiptOnly.map((x) => `${x.receiptId} names ${x.providerId}, signed ${x.timestamp}`));
  section("MISMATCHES", r.mismatches.map((x) => `${x.receiptId} / ${x.providerId}: ${x.field} is ${JSON.stringify(x.receipt)} in the receipt, ${JSON.stringify(x.provider)} at the provider`));
  section("ONE PROVIDER OBJECT, SEVERAL RECEIPTS", r.duplicates.map((x) => `${x.providerId} is named by ${x.receiptIds.join(", ")}`));
  section("FORWARDED WITHOUT AN OUTCOME RECEIPT", r.forwardedWithoutOutcome.map((x) => `${x.receiptId} (${x.tool}): committed and forwarded, no receipt of the outcome`));
  section("UNMATCHABLE", r.unmatchable.map((x) => `${x.receiptId}: ${x.reason}`));
  section("NOT VERIFIED, NOT MATCHED", r.unverified.map((x) => `${x.file}: ${x.failing.join("; ")}`));
  lines.push("", r.complete ? "RESULT: COMPLETE" : "RESULT: INCOMPLETE");
  return lines.join("\n");
}

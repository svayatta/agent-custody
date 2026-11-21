// Completeness from the provider's side. Receipts prove what went through the gateway; nothing on the gateway's side
// can see an action that never did. An auditor with a read-only key of their own lists the provider's objects over a
// window and matches each one to a verified receipt by the provider's object id, which the receipt's result carries.
// A provider object with no receipt is an action taken outside the gateway; a receipt with no provider object is an
// action the provider does not have. A door receipt records the origin's answer by digest only, so it carries no
// provider id: it is matched by its own receipt id, which the origin copies from the door's receipt header into the
// provider object. Nothing here writes, retries, or calls the provider for anything but a list.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { isCommitment, REST } from "./capture.ts";
import type { AuthorizationBundle, IssuerKind, ReceiptBundle, ReceiptPredicate } from "./receipt.ts";
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

export type GitHubObject = "pushes" | "merges" | "releases";

export interface GitHubSourceOptions {
  /** a read-only token; from the environment, never a flag */
  token: string;
  /** the repository, as "owner/name" */
  repo: string;
  object: GitHubObject;
  baseUrl?: string;
  fetch?: typeof fetch;
}

const GITHUB_ACTIVITY: Partial<Record<GitHubObject, string[]>> = { pushes: ["push", "force_push", "branch_creation"], merges: ["pr_merge", "merge_queue_merge"] };

/**
 * Lists one repository's pushes or merged pull requests (from its activity list) or its releases, every page. The id of
 * a push or a merge is the commit the ref moved to (`after`); the id of a release is its numeric id, as a string. A push
 * that creates a branch is listed only as `branch_creation`, so `pushes` reads that kind too.
 */
export function githubSource(o: GitHubSourceOptions): ProviderSource {
  if (!/^[\w.-]+\/[\w.-]+$/.test(o.repo)) throw new Error(`github: the repository is "owner/name"; got "${o.repo}"`);
  const f = o.fetch ?? fetch;
  const base = new URL(o.baseUrl ?? "https://api.github.com/");
  const kinds = GITHUB_ACTIVITY[o.object];
  return {
    name: `github ${o.object} in ${o.repo}`,
    async *list(sinceMs, untilMs) {
      let url: URL | undefined = new URL(`repos/${o.repo}/${kinds ? "activity" : "releases"}?per_page=100`, base);
      const listed = new Set<string>();
      while (url) {
        // the next page comes from a response header: the token goes only to the host it was given for
        if (url.origin !== base.origin) throw new Error(`github ${o.object}: the next page is on another host, ${url.origin}`);
        const res: Response = await f(url, { headers: { authorization: `Bearer ${o.token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" }, signal: AbortSignal.timeout(15_000) });
        if (!res.ok) throw new Error(`github ${o.object}: HTTP ${res.status}`);
        const page = (await res.json()) as Record<string, unknown>[];
        if (!Array.isArray(page)) throw new Error(`github ${o.object}: the answer is not a list`);
        let older = false;
        for (const obj of page) {
          const id = kinds ? obj.after : obj.id;
          const createdMs = Date.parse(String(kinds ? obj.timestamp : (obj.published_at ?? obj.created_at)));
          if (!(typeof id === "string" ? id.length : Number.isSafeInteger(id)) || !Number.isFinite(createdMs)) throw new Error(`github ${o.object}: an object without an id or a time`);
          // the activity list is newest first, so nothing after an older entry is in the window; releases have no such order
          if (kinds && createdMs < sinceMs) older = true;
          if (createdMs < sinceMs || createdMs >= untilMs || (kinds && !kinds.includes(String(obj.activity_type)))) continue;
          if (kinds) {
            // GitHub records some pushes twice: the same ref, commits, and time under two activity ids
            const move = [obj.ref, obj.before, obj.after, obj.timestamp].join(" ");
            if (listed.has(move)) continue;
            listed.add(move);
          }
          yield { id: String(id), createdMs, raw: obj };
        }
        const next: string | undefined = older ? undefined : /<([^>]+)>;\s*rel="next"/.exec(res.headers.get("link") ?? "")?.[1];
        url = next ? new URL(next) : undefined;
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
  /**
   * where a provider object carries the id of the door receipt that relayed its request; default
   * "metadata.agent_custody_receipt". Door receipts are matched only by this field.
   */
  receiptIdPath?: string;
  /** the call argument that holds the amount in minor units; default "amount". For a door receipt, a field of the JSON body */
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
  /** `kind` is the issuer kind of the receipt: `gateway` matched by the provider id, `door` by the receipt id the object carries */
  matched: { receiptId: string; providerId: string; kind: IssuerKind }[];
  /** provider objects in the window with no verified receipt: actions taken outside the gateway */
  providerOnly: { providerId: string; created: string; amount?: number; currency?: string; repeated?: true }[];
  /** executed receipts in the window whose provider object the provider does not have; never a door receipt, which names no provider object */
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
  if (Number.isSafeInteger(id)) return { id: String(id) };
  return typeof id === "string" && id.length ? { id } : { reason: `the result has no string or integer at "${idPath}"` };
}

/** A call argument, or that a capture rule withholds it: listed fields stay in clear beside one `$rest` commitment. */
function argOf(args: Record<string, unknown>, field: string): { value: unknown } | { withheld: true } {
  if (Object.hasOwn(args, field)) return isCommitment(args[field]) ? { withheld: true } : { value: args[field] };
  return isCommitment(args[REST]) ? { withheld: true } : { value: undefined };
}

/** A door receipt's arguments are the HTTP request: the call's own arguments are the JSON body, or withheld with it. */
function doorArgs(args: Record<string, unknown>): Record<string, unknown> {
  if (!Object.hasOwn(args, "body")) return isCommitment(args[REST]) ? { [REST]: args[REST] } : {};
  const body = args.body;
  if (isCommitment(body)) return { [REST]: body };
  return body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
}

export async function checkCompleteness(o: CompletenessOptions): Promise<CompletenessReport> {
  const idPath = o.idPath ?? "id";
  const receiptIdPath = o.receiptIdPath ?? "metadata.agent_custody_receipt";
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
  const doorReceipts = new Map<string, ReceiptPredicate>();
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
    if (p.issuer.kind === "door") {
      doorReceipts.set(p.receiptId, p);
      continue;
    }
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
  const claimed = new Set<string>();
  for await (const obj of o.source.list(o.sinceMs - margin, o.untilMs + margin)) {
    // a second object with an id already listed, or naming a door receipt already claimed, is another action: the
    // receipt accounts for the first one
    const repeated = seen.has(obj.id);
    seen.add(obj.id);
    const tag = at(obj.raw, receiptIdPath);
    const door = typeof tag === "string" ? doorReceipts.get(tag) : undefined;
    const doorRepeated = !!door && claimed.has(door.receiptId);
    if (door) claimed.add(door.receiptId);
    const named = [...(byProviderId.get(obj.id) ?? []), ...(door ? [door] : [])];
    const receipts = [...(repeated ? [] : byProviderId.get(obj.id) ?? []), ...(door && !doorRepeated ? [door] : [])];
    // the margin finds a receipt across the window's edge; it does not widen the period reported on
    const inScope = inWindow(obj.createdMs) || named.some((p) => inWindow(Date.parse(p.timestamp)));
    if (!inScope) continue;
    if (!receipts.length) {
      report.providerOnly.push({ providerId: obj.id, created: iso(obj.createdMs), ...(obj.amount !== undefined ? { amount: obj.amount } : {}), ...(obj.currency !== undefined ? { currency: obj.currency } : {}), ...(named.length ? { repeated: true as const } : {}) });
      continue;
    }
    if (receipts.length > 1) report.duplicates.push({ providerId: obj.id, receiptIds: receipts.map((p) => p.receiptId) });
    for (const p of receipts) {
      report.matched.push({ receiptId: p.receiptId, providerId: obj.id, kind: p.issuer.kind });
      const args = p.issuer.kind === "door" ? doorArgs(p.request.args) : p.request.args;
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

function matchedByKind(r: CompletenessReport): string {
  const counts = new Map<string, number>();
  for (const m of r.matched) counts.set(m.kind, (counts.get(m.kind) ?? 0) + 1);
  return counts.size ? ` (${[...counts].map(([k, n]) => `${n} ${k}`).join(", ")})` : "";
}

export function formatCompleteness(r: CompletenessReport): string {
  const lines = [`${r.provider} for ${r.tools.join(", ")}, ${r.window.since} to ${r.window.until}: ${r.receiptsRead} receipt(s) read, ${r.matched.length} matched${matchedByKind(r)}`];
  const section = (title: string, rows: string[]) => {
    if (rows.length) lines.push("", `${title} (${rows.length})`, ...rows.map((row) => `  ${row}`));
  };
  section("PROVIDER ACTIONS WITH NO RECEIPT", r.providerOnly.map((x) => `${x.providerId} created ${x.created}${x.amount !== undefined ? ` amount ${x.amount}${x.currency ? ` ${x.currency}` : ""}` : ""}${x.repeated ? "; the receipt for this id accounts for another action" : ""}`));
  section("RECEIPTS THE PROVIDER DOES NOT HAVE", r.receiptOnly.map((x) => `${x.receiptId} names ${x.providerId}, signed ${x.timestamp}`));
  section("MISMATCHES", r.mismatches.map((x) => `${x.receiptId} / ${x.providerId}: ${x.field} is ${JSON.stringify(x.receipt)} in the receipt, ${JSON.stringify(x.provider)} at the provider`));
  section("ONE PROVIDER OBJECT, SEVERAL RECEIPTS", r.duplicates.map((x) => `${x.providerId} is named by ${x.receiptIds.join(", ")}`));
  section("FORWARDED WITHOUT AN OUTCOME RECEIPT", r.forwardedWithoutOutcome.map((x) => `${x.receiptId} (${x.tool}): committed and forwarded, no receipt of the outcome`));
  section("UNMATCHABLE", r.unmatchable.map((x) => `${x.receiptId}: ${x.reason}`));
  section("NOT VERIFIED, NOT MATCHED", r.unverified.map((x) => `${x.file}: ${x.failing.join("; ")}`));
  lines.push("", r.complete ? "RESULT: COMPLETE" : "RESULT: INCOMPLETE");
  return lines.join("\n");
}

// The memory server: the ledger as MCP tools, meant to run as an upstream of the receipts gateway.
// Behind the gateway every write and read is policy-checked and receipted, and the gateway tells this server, in the
// call's _meta, which receipt it is and who the attested grant says is calling. Those become the fact's source and
// actor; a caller cannot supply them. Run it directly and the source is null and the actor is whatever the caller
// claims, which is recorded as such.
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { signResult, type KeyPair } from "@agent-custody/receipts";
import type { Fact, Ledger } from "./ledger.ts";
import { entryOf, type RemovalOutcome, type Store, type StoreEntry } from "./stores.ts";

export const SERVER_VERSION = "0.1.0";
/** The same keys the receipts gateway sets on the upstream call. Duplicated here so this package needs no runtime import from receipts. */
export const RECEIPT_META_KEY = "agent-custody/receipt";
export const AGENT_META_KEY = "agent-custody/agent";
/** Set on read results: the ids of the facts served, so the gateway can record what the agent was shown. */
export const FACTS_META_KEY = "agent-custody/facts";
/** Set by the gateway on the forwarded call: the values it fetched itself for this call, by fact name. */
export const OBSERVED_META_KEY = "agent-custody/observed";

const iso = z.string().datetime({ offset: true });
const Write = z.object({
  subject: z.string().min(1),
  predicate: z.string().min(1),
  value: z.unknown(),
  space: z.string().min(1),
  /** ignored behind the gateway, which supplies the attested agent instead */
  actor: z.string().min(1).optional(),
  validFrom: iso.optional(),
  confidence: z.number().min(0).max(1).optional(),
  supersedes: z.string().min(1).optional(),
  /** names a fact the gateway fetched for this call, and optionally a dot path into it, that the value must equal; the write is then verified, or refused */
  evidence: z.object({ fact: z.string().min(1), path: z.string().optional() }).optional(),
});
const Read = z.object({ subject: z.string().min(1).optional(), predicate: z.string().min(1).optional(), space: z.string().min(1).optional(), validAt: iso.optional(), txAt: iso.optional(), includeClaimed: z.boolean().optional(), requireVerified: z.boolean().optional() });
const Confirm = z.object({ factId: z.string().min(1) });
const Retract = z.object({ factId: z.string().min(1), reason: z.string().min(1), actor: z.string().min(1).optional() });
const History = z.object({ factId: z.string().min(1) });
const Get = z.object({ factId: z.string().min(1) });
const Forget = z.object({ factId: z.string().min(1), reason: z.string().min(1), keepDigest: z.boolean().optional() });
const Hold = z.object({ factId: z.string().min(1), reason: z.string().min(1) });
const Sweep = z.object({ before: iso.optional(), space: z.string().min(1).optional(), reason: z.string().min(1), keepDigest: z.boolean().optional() });
const Repair = z.object({ reason: z.string().min(1), before: iso.optional() });

const str = { type: "string" as const };
const isoStr = { type: "string" as const, description: "an ISO 8601 date-time with a UTC offset, for example 2026-10-15T09:00:00Z" };
const actorStr = { type: "string" as const, description: "who acts; ignored behind the gateway, which records the agent named in the signed grant" };
export const TOOLS: Tool[] = [
  {
    name: "memory.write",
    description: "Record a belief: subject, predicate, value, in a space. Optionally supersede an earlier fact. With evidence naming a fact the gateway fetched for this call, the value must equal it (or the field at path) and the write is verified; otherwise it is refused. Returns the new fact with its id, transaction time, actor, provenance, and source receipt.",
    inputSchema: { type: "object", properties: { subject: str, predicate: str, value: {}, space: str, actor: actorStr, validFrom: isoStr, confidence: { type: "number", minimum: 0, maximum: 1 }, supersedes: str, evidence: { type: "object", properties: { fact: str, path: str }, required: ["fact"] } }, required: ["subject", "predicate", "value", "space"] },
  },
  {
    name: "memory.read",
    description: "The facts believed at a moment. validAt asks whether a fact was true then; txAt asks whether the ledger knew it then. Both default to now. Filter by space, subject, predicate. Quarantined (claimed, unconfirmed) facts are left out unless includeClaimed is true; requireVerified returns only facts whose value the gateway checked against its source.",
    inputSchema: { type: "object", properties: { subject: str, predicate: str, space: str, validAt: isoStr, txAt: isoStr, includeClaimed: { type: "boolean" }, requireVerified: { type: "boolean" } } },
  },
  {
    name: "memory.confirm",
    description: "Lift a quarantined (claimed) fact to attested. Only accepted through the gateway, so the confirming actor is the one named in the signed grant.",
    inputSchema: { type: "object", properties: { factId: str }, required: ["factId"] },
  },
  {
    name: "memory.retract",
    description: "Undo a belief: the fact leaves the present, stays visible to questions about the past, and whatever it superseded is believed again.",
    inputSchema: { type: "object", properties: { factId: str, reason: str, actor: actorStr }, required: ["factId", "reason"] },
  },
  {
    name: "memory.forget",
    description: "Erase a fact's value: from the ledger file, keeping only its digest (keyed when the server has a forget key; none when keepDigest is false), and from every store behind the server. The fact stops being believed. The receipt for this call, with the result the gateway observed, is the certificate that the erasure happened.",
    inputSchema: { type: "object", properties: { factId: str, reason: str, keepDigest: { type: "boolean" } }, required: ["factId", "reason"] },
  },
  {
    name: "memory.hold",
    description: "Place a legal hold on a fact. While the hold stands, memory.forget refuses the fact and memory.sweep skips it. The reason is recorded with the hold event. Fails when the fact does not exist, is already forgotten, or is already on hold. Returns the hold event. Lift it with memory.release.",
    inputSchema: { type: "object", properties: { factId: str, reason: str }, required: ["factId", "reason"] },
  },
  {
    name: "memory.release",
    description: "Lift the legal hold on a fact, so that memory.forget and retention sweeps can reach it again. The reason is recorded with the release event. Fails when the fact is not on hold. Returns the release event.",
    inputSchema: { type: "object", properties: { factId: str, reason: str }, required: ["factId", "reason"] },
  },
  {
    name: "memory.sweep",
    description: "Retention: forget every fact the ledger learned of before an instant, in one space or all, skipping held facts, and remove each from every store. Without `before`, the server's configured retention windows decide per space. The receipt is the record of the sweep.",
    inputSchema: { type: "object", properties: { before: isoStr, space: str, reason: str, keepDigest: { type: "boolean" } }, required: ["reason"] },
  },
  {
    name: "memory.repair",
    description: "Find and remove store entries that the ledger has no fact for. A write reaches the stores before the ledger, so a failed ledger append leaves such an entry. For each store that can list its entries: every entry with custody metadata, stored more than ten minutes ago, whose fact id the ledger does not know is removed, a repair event is recorded under that fact id first, and then the removal is made and verified. A write that is still in progress then fails at its ledger append. A repair of an entry that has a repair event adds no second event. `before` can only move the cutoff earlier. Returns { before, repaired, unlisted, stillHeld, unrecorded }: the cutoff, what was removed with the store's answer, the stores that cannot list, the removals and listings that failed, and the entries that stay because the ledger did not take the repair event.",
    inputSchema: { type: "object", properties: { reason: str, before: isoStr }, required: ["reason"] },
  },
  {
    name: "memory.get",
    description: "One fact by id, whatever its state: its space, actor, provenance, source receipt, validity. Meant for the gateway's fact lookups, so policy can decide on the fact a write supersedes or a retraction targets.",
    inputSchema: { type: "object", properties: { factId: str }, required: ["factId"] },
  },
  {
    name: "memory.history",
    description: "Every ledger event for one fact, oldest first: its assert, the assert that superseded it, and its confirm, retract, hold, release, and forget events. Returns { events }. Use it to see how a belief changed; use memory.read for what is believed now, and memory.get for one fact's current state.",
    inputSchema: { type: "object", properties: { factId: str }, required: ["factId"] },
  },
];

export interface MemoryServerOptions {
  /** Refuse calls that did not come through the gateway, i.e. carry no receipt id. On by default when served from the CLI. */
  requireGateway?: boolean;
  /**
   * Believe the `_meta` the call carries: the receipt id, the agent, the principal, and the facts the gateway observed.
   * Only the gateway may be believed, because those keys are what make a write attested or verified. Default: true
   * exactly when `requireGateway` is not false, i.e. when the one caller is the gateway. A server that accepts direct
   * writers must run with it false for them (the HTTP server does this per request, by which token the caller presented),
   * so a direct writer's `_meta` is dropped and its write is claimed, whatever it says about itself.
   */
  trustMeta?: boolean;
  /** Retrieval stores every write goes through to and every retraction reaches. A store that refuses a write fails the write; nothing is recorded. */
  stores?: Store[];
  /** With a key, every result to a gateway call is signed for that receipt, so a verifier holding the public key sees the execution as attested by this server. */
  identity?: KeyPair;
  /** Retention windows by space pattern, ISO 8601 durations: { "org": "P365D", "team:*": "P90D" }. memory.sweep without `before` uses them. */
  retention?: Record<string, string>;
  /** After a removal, how many times to ask a store's search whether the value is gone, and the first wait between asks (doubling). Default 3 and 200 ms. */
  verify?: { attempts?: number; delayMs?: number };
}

/** Parses the ISO 8601 duration subset retention needs: P<n>W, P<n>D, PT<n>H, and combinations of D and H. */
export function durationMs(iso: string): number {
  const m = /^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$/.exec(iso);
  if (!m || iso === "P" || iso === "PT") throw new Error(`retention: cannot parse duration ${iso}; use forms like P90D, P2W, PT12H`);
  const [, w = "0", d = "0", h = "0", min = "0"] = m;
  return ((Number(w) * 7 + Number(d)) * 24 + Number(h)) * 3_600_000 + Number(min) * 60_000;
}

/** The retention cutoff for a space, from the first pattern that matches it; null when none does. */
export function retentionCutoff(retention: Record<string, string>, space: string, now: Date): string | null {
  for (const [pattern, duration] of Object.entries(retention)) {
    const matches = pattern.endsWith("*") ? space.startsWith(pattern.slice(0, -1)) : space === pattern;
    if (matches) return new Date(now.getTime() - durationMs(duration)).toISOString();
  }
  return null;
}

/**
 * How old a store entry must be before repair may remove it. A write whose stores take more than half of it fails
 * before its ledger append, so the entry of a write in progress is never this old.
 */
export const REPAIR_MIN_AGE_MS = 10 * 60_000;

const json = (v: unknown): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(v) }] });
const fail = (msg: string): CallToolResult => ({ isError: true, content: [{ type: "text", text: msg }] });

export function createMemoryServer(ledger: Ledger, opts: MemoryServerOptions = {}): Server {
  const server = new Server({ name: "agent-custody-memory", version: SERVER_VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  const trustMeta = opts.trustMeta ?? opts.requireGateway !== false;
  // A store written for remove(externalId, fact) and verifyRemoved would get an entry where it expects an id, and its
  // check could then report an entry as gone that is still there: a false erasure certificate. Refuse it.
  for (const store of opts.stores ?? []) if (typeof store.delete !== "function") throw new Error(`store ${store.name} has no delete(entry); remove(externalId, fact) and verifyRemoved are now delete(entry) and verifyDeleted(entry)`);
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    // A caller that is not the gateway gets no say in who it is or what was observed: its _meta is dropped whole.
    const meta = trustMeta ? ((req.params._meta ?? {}) as Record<string, unknown>) : {};
    const receiptId = typeof meta[RECEIPT_META_KEY] === "string" ? (meta[RECEIPT_META_KEY] as string) : null;
    const result = await handle(req.params.name, req.params.arguments ?? {}, meta, receiptId);
    return opts.identity && receiptId ? signResult(result, opts.identity, receiptId, req.params.name) : result;
  });
  /**
   * Removes one entry from a store, then asks the store's search whether it is really gone. The outcome is what the
   * receipt records: verified, stillIndexed, unverified (the store cannot say), or failed, with the store's error.
   */
  async function removeEntry(store: Store, entry: StoreEntry): Promise<{ outcome: RemovalOutcome; error?: string }> {
    try {
      await store.delete(entry);
    } catch (e) {
      return { outcome: "failed", error: `${store.name}: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (!store.verifyDeleted) return { outcome: "unverified" };
    const attempts = Math.max(1, opts.verify?.attempts ?? 3);
    const delayMs = opts.verify?.delayMs ?? 200;
    for (let i = 0; i < attempts; i++) {
      if (i > 0) await new Promise((r) => setTimeout(r, delayMs * 2 ** (i - 1)));
      try {
        if (await store.verifyDeleted(entry)) return { outcome: "verified" };
      } catch {
        // The store could not be asked; that is not the same as the value being gone.
        return { outcome: "unverified" };
      }
    }
    return { outcome: "stillIndexed" };
  }

  /** Removes a fact from every store it was written to. */
  async function removeFromStores(fact: Fact | undefined): Promise<{ removedFrom: string[]; stillHeld: string[]; verification: Record<string, RemovalOutcome> }> {
    const removedFrom: string[] = [];
    const stillHeld: string[] = [];
    const verification: Record<string, RemovalOutcome> = {};
    for (const store of opts.stores ?? []) {
      const id = fact?.external?.[store.name];
      if (!id) continue;
      const { outcome, error } = await removeEntry(store, entryOf(fact!, id));
      verification[store.name] = outcome;
      if (error) stillHeld.push(error);
      else removedFrom.push(store.name);
    }
    return { removedFrom, stillHeld, verification };
  }

  async function forgetOne(factId: string, reason: string, who: { actor: string; receiptId: string | null }, keepDigest?: boolean, compact = true) {
    const fact = await ledger.get(factId);
    const ev = await ledger.forget({ factId, actor: who.actor, reason, source: { receiptId: who.receiptId }, ...(keepDigest === undefined ? {} : { keepDigest }), compact });
    const { removedFrom, stillHeld, verification } = await removeFromStores(fact);
    return { factId: ev.factId, valueDigest: ev.valueDigest, digestKind: ev.digestKind, txTime: ev.txTime, actor: ev.actor, reason: ev.reason, source: ev.source, erasedFromLedger: true, removedFrom, stillHeld, verification };
  }
  /** The tail of the sweeps queued in this process. */
  let repairTurn: Promise<void> = Promise.resolve();

  async function repairSweep(a: z.infer<typeof Repair>, who: { actor: string; receiptId: string | null }): Promise<CallToolResult> {
    // `before` can only move the cutoff earlier: a later one would reach the entries of a write in progress.
    const cutoff = Math.min(a.before ? Date.parse(a.before) : Infinity, Date.now() - REPAIR_MIN_AGE_MS);
    const repaired: { store: string; externalId: string; factId: string; outcome: RemovalOutcome; eventId: string }[] = [];
    const unrecorded: { store: string; externalId: string; factId: string; error: string }[] = [];
    const unlisted: string[] = [];
    const stillHeld: string[] = [];
    for (const store of opts.stores ?? []) {
      if (!store.list) {
        unlisted.push(store.name);
        continue;
      }
      let entries: StoreEntry[];
      try {
        entries = await store.list();
      } catch (e) {
        stillHeld.push(`${store.name}: cannot list: ${e instanceof Error ? e.message : String(e)}`);
        continue;
      }
      const seen = new Set<string>();
      for (const entry of entries) {
        if (seen.has(entry.externalId)) continue;
        seen.add(entry.externalId);
        // A young entry may be a write in progress. So is one whose time is missing or does not parse.
        if (!(Date.parse(entry.storedAt ?? "") < cutoff)) continue;
        // The ledger records the repair first, as a retraction does. A write that is still in progress then fails at
        // its own append, and a write that has appended makes this refuse. Either way the first record wins.
        let ev;
        try {
          if (await ledger.get(entry.factId)) continue;
          ev = await ledger.repair({ factId: entry.factId, store: store.name, externalId: entry.externalId, actor: who.actor, reason: a.reason, source: { receiptId: who.receiptId } });
        } catch (e) {
          // The ledger now knows the fact: the write won, and its entry stays. Otherwise nothing was removed. A ledger
          // that cannot answer does not stop the sweep: the entries that it already removed keep their outcomes.
          if (!(await ledger.get(entry.factId).catch(() => undefined))) unrecorded.push({ store: store.name, externalId: entry.externalId, factId: entry.factId, error: e instanceof Error ? e.message : String(e) });
          continue;
        }
        let { outcome, error } = await removeEntry(store, entry);
        // Another server may have removed the entry already, and the store may then fail the delete. The listing of
        // the store, not a similarity search, says whether the entry is gone.
        if (error && (await store.list().then((now) => !now.some((e) => e.externalId === entry.externalId), () => false))) ({ outcome, error } = { outcome: "verified", error: undefined });
        if (error) stillHeld.push(error);
        repaired.push({ store: store.name, externalId: entry.externalId, factId: entry.factId, outcome, eventId: ev.eventId });
      }
    }
    const out = { before: new Date(cutoff).toISOString(), repaired, unlisted, stillHeld, unrecorded };
    if (stillHeld.length > 0 || unrecorded.length > 0) return { isError: true, content: [{ type: "text", text: `repair incomplete: ${[...stillHeld, ...unrecorded.map((u) => `${u.store} ${u.externalId}: not removed, because the ledger did not record the repair: ${u.error}`)].join("; ")}` }, { type: "text", text: JSON.stringify(out) }] };
    return json(out);
  }
  async function handle(name: string, args: Record<string, unknown>, meta: Record<string, unknown>, receiptId: string | null): Promise<CallToolResult> {
    const gatewayAgent = typeof meta[AGENT_META_KEY] === "string" ? (meta[AGENT_META_KEY] as string) : null;
    if (opts.requireGateway && !receiptId) return fail("memory server accepts calls only through the receipts gateway; no receipt id on this call");
    const actorFor = (claimed: string | undefined) => gatewayAgent ?? claimed ?? "anonymous";
    // A write is attested when it came through the gateway: the actor is from a signed grant and the receipt exists.
    const provenance: "attested" | "claimed" = receiptId && gatewayAgent ? "attested" : "claimed";
    const observed = (meta[OBSERVED_META_KEY] ?? {}) as Record<string, unknown>;
    // Who this call is, carried as a value through the awaits below; never shared between concurrent calls.
    const who = { actor: actorFor(undefined), receiptId };
    try {
      switch (name) {
        case "memory.write": {
          const a = Write.parse(args);
          let writeProvenance: "claimed" | "attested" | "verified" = provenance;
          if (a.evidence) {
            // Value-level quarantine: the agent may say where the value came from, and the gateway's own observation decides.
            if (provenance !== "attested") return fail("evidence needs the gateway: only a fact the gateway fetched itself can verify a value");
            if (!(a.evidence.fact in observed)) return fail(`no fact named "${a.evidence.fact}" was fetched by the gateway for this call; configure a fact lookup for memory.write`);
            const expected = a.evidence.path ? a.evidence.path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), observed[a.evidence.fact]) : observed[a.evidence.fact];
            if (JSON.stringify(sortKeys(expected)) !== JSON.stringify(sortKeys(a.value ?? null))) return fail(`value differs from what the gateway observed in "${a.evidence.fact}${a.evidence.path ? "." + a.evidence.path : ""}"; write refused`);
            writeProvenance = "verified";
          }
          const input = { subject: a.subject, predicate: a.predicate, value: a.value ?? null, space: a.space, actor: actorFor(a.actor), source: { receiptId }, provenance: writeProvenance, ...(a.validFrom ? { validFrom: a.validFrom } : {}), ...(a.confidence !== undefined ? { confidence: a.confidence } : {}), ...(a.supersedes ? { supersedes: a.supersedes } : {}) } as const;
          // The stores are written first, so their ids can be recorded on the fact; the ledger's checks run beforehand
          // so a write the ledger would refuse never reaches a store. The fact id is chosen here, before the stores
          // see the fact, so the metadata they keep names the real id and a store may key its row by it.
          await ledger.validateAssert(input);
          const external: Record<string, string> = {};
          const factId = randomUUID();
          const preview: Fact = { ...input, factId, validFrom: input.validFrom ?? new Date().toISOString(), validTo: null, confidence: input.confidence ?? null };
          // A failed append leaves the stores holding a fact the ledger lacks; memory.repair finds and removes it.
          const started = Date.now();
          for (const store of opts.stores ?? []) external[store.name] = await store.put(preview);
          if (Date.now() - started > REPAIR_MIN_AGE_MS / 2) return fail(`the stores took more than ${REPAIR_MIN_AGE_MS / 120_000} minutes; the write is refused, and memory.repair removes what the stores took`);
          const ev = await ledger.assert({ ...input, factId, external });
          return json({ fact: ev.fact, eventId: ev.eventId, txTime: ev.txTime, supersedes: ev.supersedes });
        }
        case "memory.read": {
          const { includeClaimed, requireVerified, ...q } = Read.parse(args);
          const facts = await ledger.asOf({ ...q, include: requireVerified ? "verified" : includeClaimed ? "all" : "attested" });
          return { ...json({ facts }), _meta: { [FACTS_META_KEY]: facts.map((f) => f.factId) } };
        }
        case "memory.retract": {
          const a = Retract.parse(args);
          const fact = await ledger.get(a.factId);
          const ev = await ledger.retract({ factId: a.factId, actor: actorFor(a.actor), reason: a.reason, source: { receiptId } });
          // The ledger is retracted first: custody must not depend on a store being up. A store that fails to remove
          // is reported, so the caller knows recall may still serve the value.
          const { removedFrom, stillHeld, verification } = await removeFromStores(fact);
          const out = { eventId: ev.eventId, factId: ev.factId, txTime: ev.txTime, actor: ev.actor, reason: ev.reason, source: ev.source, removedFrom, verification };
          if (stillHeld.length > 0) return { isError: true, content: [{ type: "text", text: `retracted in the ledger, but still held by ${stillHeld.join("; ")}` }, { type: "text", text: JSON.stringify(out) }] };
          return json(out);
        }
        case "memory.confirm": {
          if (provenance !== "attested") return fail("confirmation must come through the receipts gateway; a self-reported caller cannot lift a fact out of quarantine");
          const a = Confirm.parse(args);
          const ev = await ledger.confirm({ factId: a.factId, actor: actorFor(undefined), source: { receiptId } });
          return json({ eventId: ev.eventId, factId: ev.factId, txTime: ev.txTime, actor: ev.actor, source: ev.source });
        }
        case "memory.forget": {
          const a = Forget.parse(args);
          const out = await forgetOne(a.factId, a.reason, who, a.keepDigest);
          if (out.stillHeld.length > 0) return { isError: true, content: [{ type: "text", text: `erased from the ledger, but still held by ${out.stillHeld.join("; ")}` }, { type: "text", text: JSON.stringify(out) }] };
          return json(out);
        }
        case "memory.hold": {
          const a = Hold.parse(args);
          return json(await ledger.hold({ factId: a.factId, actor: actorFor(undefined), reason: a.reason, source: { receiptId } }));
        }
        case "memory.release": {
          const a = Hold.parse(args);
          return json(await ledger.release({ factId: a.factId, actor: actorFor(undefined), reason: a.reason, source: { receiptId } }));
        }
        case "memory.sweep": {
          const a = Sweep.parse(args);
          if (!a.before && !opts.retention) return fail("sweep needs `before`, or a server started with retention windows");
          // One query per space, each answered by the store's index: the facts learned before that space's cutoff.
          const now = new Date();
          const spaces = a.space !== undefined ? [a.space] : a.before ? [undefined] : await ledger.spaces();
          const targets: Fact[] = [];
          for (const space of spaces) {
            const cutoff = a.before ?? (space === undefined ? null : retentionCutoff(opts.retention ?? {}, space, now));
            if (cutoff !== null) targets.push(...(await ledger.learnedBefore(cutoff, space)));
          }
          const forgotten: Awaited<ReturnType<typeof forgetOne>>[] = [];
          const held: string[] = [];
          for (const f of targets) {
            if (await ledger.held(f.factId)) {
              held.push(f.factId);
              continue;
            }
            forgotten.push(await forgetOne(f.factId, a.reason, who, a.keepDigest, false));
          }
          if (forgotten.length > 0) await ledger.compact();
          const stillHeld = forgotten.flatMap((o) => o.stillHeld);
          const out = { before: a.before ?? null, retention: a.before ? null : (opts.retention ?? null), space: a.space ?? null, forgotten: forgotten.map((o) => ({ factId: o.factId, valueDigest: o.valueDigest, digestKind: o.digestKind, removedFrom: o.removedFrom, verification: o.verification })), held, stillHeld };
          if (stillHeld.length > 0) return { isError: true, content: [{ type: "text", text: `swept the ledger, but some values are still held by stores: ${stillHeld.join("; ")}` }, { type: "text", text: JSON.stringify(out) }] };
          return json(out);
        }
        case "memory.repair": {
          const a = Repair.parse(args);
          // One sweep at a time in this process: a second sweep then lists after the first has removed its entries.
          const turn = repairTurn.then(() => repairSweep(a, who));
          repairTurn = turn.then(() => {}, () => {});
          return await turn;
        }
        case "memory.get": {
          const a = Get.parse(args);
          const f = await ledger.get(a.factId);
          if (!f) return fail(`unknown fact ${a.factId}`);
          const retracted = (await ledger.history(a.factId)).some((e) => e.kind === "retract");
          // Cedar has no null: absent fields stay absent, so a policy tests them with `has`.
          const clean = Object.fromEntries(Object.entries({ ...f, source: f.source.receiptId ?? undefined, retracted }).filter(([, v]) => v !== null && v !== undefined));
          return json(clean);
        }
        case "memory.history":
          return json({ events: await ledger.history(History.parse(args).factId) });
        default:
          return fail(`unknown tool ${name}`);
      }
    } catch (e) {
      return fail(e instanceof z.ZodError ? `invalid arguments: ${e.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}` : String(e instanceof Error ? e.message : e));
    }
  }
  return server;
}

/** Serves over stdio, the way the gateway spawns it. Diagnostics must go to stderr. */
export async function serveStdio(server: Server): Promise<void> {
  await server.connect(new StdioServerTransport());
  await new Promise<void>((resolve) => {
    server.onclose = resolve;
  });
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v as object).sort()) o[k] = sortKeys((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}


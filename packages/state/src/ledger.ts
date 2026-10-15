// The fact ledger: an append-only log of events about what an agent believes, in a JSONL file, SQLite, or Postgres.
// Bitemporal. Valid time is when a fact was true in the world; transaction time is when the ledger learned of it.
// Nothing is ever edited in place. Correcting a belief is a new event, so "what did the agent believe at T" is always answerable.
import { randomUUID } from "node:crypto";
import { createHash, createHmac } from "node:crypto";
import { openStore, type EventStore } from "./storage.ts";
import type { RemovalOutcome } from "./stores.ts";

/** Where a write came from. A receipt id means the write went through a receipts producer and can be verified there. */
export interface Source {
  receiptId: string | null;
}

/**
 * How far the write can be trusted.
 *  - claimed:  it came from somewhere that only says who it is. Quarantined: not returned by default until confirmed.
 *  - attested: it came through the receipts gateway, so the actor is the agent named in a human-signed grant and the
 *              receipt exists. The value is still what the agent said.
 *  - verified: attested, and the value equals what the gateway itself fetched from the source system for this call.
 *              The actor and the value are both vouched for by something other than the agent.
 */
export type FactProvenance = "claimed" | "attested" | "verified";
const RANK: Record<FactProvenance, number> = { claimed: 0, attested: 1, verified: 2 };

export interface Fact {
  factId: string;
  subject: string;
  predicate: string;
  value: unknown;
  /** Which shared space the fact lives in: a person, a team, an org. ACLs attach here later. */
  space: string;
  /** Who wrote it: a user id, an agent id, a tool name. */
  actor: string;
  source: Source;
  provenance: FactProvenance;
  /** present once the value has been erased: the value field is null and this is the digest of what it was, or null when none was kept */
  forgotten?: { valueDigest: string | null; digestKind: DigestKind; at: string };
  /** ids of this fact in the retrieval stores it was written through to, by store name; absent when there are none */
  external?: Record<string, string>;
  /** ISO timestamps. validTo is null while the fact is believed to still hold. */
  validFrom: string;
  validTo: string | null;
  confidence: number | null;
}

/** An assert creates a fact version. If it supersedes an earlier fact, that fact's validity ends where this one begins. */
export interface AssertEvent {
  eventId: string;
  kind: "assert";
  txTime: string;
  fact: Fact;
  supersedes: string | null;
}

/** A retract says the fact should never have been believed. It is the undo. The record stays; queries before txTime still see it. */
export interface RetractEvent {
  eventId: string;
  kind: "retract";
  txTime: string;
  factId: string;
  actor: string;
  reason: string;
  source: Source;
}

/** A confirm lifts a claimed fact to attested. Only an attested party can confirm; the event records who and which receipt. */
export interface ConfirmEvent {
  eventId: string;
  kind: "confirm";
  txTime: string;
  factId: string;
  actor: string;
  source: Source;
}

/**
 * How a forgotten value's digest was made. sha256 is guessable for short values by anyone holding the file;
 * hmac-sha256 needs the ledger's forget key, kept outside the file; none keeps nothing derived from the value.
 */
export type DigestKind = "sha256" | "hmac-sha256" | "none";

/**
 * A forget is erasure, not correction. The fact's value is removed from the ledger file itself and replaced by its
 * digest, so the ledger can still prove which value it held without holding it. The fact stops being believed.
 */
export interface ForgetEvent {
  eventId: string;
  kind: "forget";
  txTime: string;
  factId: string;
  actor: string;
  reason: string;
  source: Source;
  /** digest of the canonical JSON of the erased value, per digestKind; null when none was kept */
  valueDigest: string | null;
  digestKind: DigestKind;
}

/** A legal hold: while it stands, the fact cannot be forgotten, by request or by retention sweep. Release lifts it. */
export interface HoldEvent {
  eventId: string;
  kind: "hold" | "release";
  txTime: string;
  factId: string;
  actor: string;
  reason: string;
  source: Source;
}

/**
 * A repair records the removal of a store entry that the ledger has no fact for: the stores were written, then the
 * ledger append failed. The factId is the id in the entry's custody metadata, which no assert carries.
 */
export interface RepairEvent {
  eventId: string;
  kind: "repair";
  txTime: string;
  factId: string;
  actor: string;
  reason: string;
  source: Source;
  /** the store the entry was in, and the store's id for it */
  store: string;
  externalId: string;
  /** what the store answered: the same outcomes a retraction or forget reports */
  outcome: RemovalOutcome;
}

export type LedgerEvent = AssertEvent | RetractEvent | ConfirmEvent | ForgetEvent | HoldEvent | RepairEvent;

export interface AssertInput {
  /** the fact's id, when the caller had to know it before the append, as the memory server does for its stores; default a fresh UUID */
  factId?: string;
  subject: string;
  predicate: string;
  value: unknown;
  space: string;
  actor: string;
  source?: Source;
  /** default claimed; the memory server sets attested for writes that came through the gateway */
  provenance?: FactProvenance;
  external?: Record<string, string>;
  validFrom?: string;
  confidence?: number;
  supersedes?: string;
}

export interface ConfirmInput {
  factId: string;
  actor: string;
  source?: Source;
}

export interface ForgetInput {
  factId: string;
  actor: string;
  reason: string;
  source?: Source;
  /** false keeps no digest at all; default true */
  keepDigest?: boolean;
}

export interface HoldInput {
  factId: string;
  actor: string;
  reason: string;
  source?: Source;
}

export type RepairInput = Omit<RepairEvent, "eventId" | "kind" | "txTime" | "source"> & { source?: Source };

export interface SweepInput {
  /** every fact the ledger learned of before this instant is forgotten, unless held or already forgotten */
  before: string;
  space?: string;
  actor: string;
  reason: string;
  source?: Source;
  keepDigest?: boolean;
}

export interface RetractInput {
  factId: string;
  actor: string;
  reason: string;
  source?: Source;
}

export interface AsOf {
  /** Facts whose validity interval contains this instant. Default: now. */
  validAt?: string;
  /** Only events the ledger had recorded by this instant. Default: now. "What did the agent believe on Tuesday" sets both. */
  txAt?: string;
  space?: string;
  subject?: string;
  predicate?: string;
  /** the least provenance to return: "attested" leaves out quarantined facts, "verified" leaves out everything the agent only asserted; default "all" */
  include?: "attested" | "verified" | "all";
}

export class Ledger {
  private readonly store: EventStore;
  private readonly now: () => Date;
  private readonly forgetKey: Buffer | null;

  /**
   * `location` is a path (JSONL by default, SQLite when it ends in .sqlite or .db) or a postgres:// URL; or pass a
   * store. The ledger holds no events itself: every question is a query to the store, so a shared store means a
   * shared ledger. forgetKey: a secret kept outside the store; with it, forgotten values leave an HMAC rather than a
   * plain hash.
   */
  constructor(location: string | EventStore, opts: { now?: () => Date; forgetKey?: string | Buffer } = {}) {
    this.store = typeof location === "string" ? openStore(location) : location;
    this.now = opts.now ?? (() => new Date());
    this.forgetKey = opts.forgetKey ? Buffer.from(opts.forgetKey) : null;
  }

  /** Where the events live, for reports. */
  get location(): string {
    return this.store.location;
  }

  /** Every event in order, for export. */
  export(): Promise<LedgerEvent[]> {
    return this.store.events();
  }

  close(): Promise<void> {
    return this.store.close();
  }

  count(): Promise<number> {
    return this.store.count();
  }

  /** Every space with at least one fact. */
  spaces(): Promise<string[]> {
    return this.store.spaces();
  }

  /** The checks assert makes, without appending. For callers that must do something irreversible before the append. */
  async validateAssert(input: AssertInput): Promise<void> {
    const validFrom = input.validFrom ?? this.now().toISOString();
    if (input.supersedes !== undefined) {
      const prior = await this.factById(input.supersedes);
      if (!prior) throw new Error(`cannot supersede unknown fact ${input.supersedes}`);
      if (prior.fact.validTo !== null) throw new Error(`fact ${input.supersedes} is already superseded`);
      if (await this.retractedAt(input.supersedes)) throw new Error(`fact ${input.supersedes} is retracted`);
      if (validFrom < prior.fact.validFrom) throw new Error(`replacement cannot start before the fact it supersedes`);
    }
  }

  async assert(input: AssertInput): Promise<AssertEvent> {
    await this.validateAssert(input);
    const txTime = this.now().toISOString();
    const validFrom = input.validFrom ?? txTime;
    const event: AssertEvent = {
      eventId: randomUUID(),
      kind: "assert",
      txTime,
      fact: {
        factId: input.factId ?? randomUUID(),
        subject: input.subject,
        predicate: input.predicate,
        value: input.value,
        space: input.space,
        actor: input.actor,
        source: input.source ?? { receiptId: null },
        provenance: input.provenance ?? "claimed",
        ...(input.external && Object.keys(input.external).length > 0 ? { external: input.external } : {}),
        validFrom,
        validTo: null,
        confidence: input.confidence ?? null,
      },
      supersedes: input.supersedes ?? null,
    };
    await this.store.append(event);
    return event;
  }

  async retract(input: RetractInput): Promise<RetractEvent> {
    if (!(await this.factById(input.factId))) throw new Error(`cannot retract unknown fact ${input.factId}`);
    if (await this.retractedAt(input.factId)) throw new Error(`fact ${input.factId} is already retracted`);
    const event: RetractEvent = {
      eventId: randomUUID(),
      kind: "retract",
      txTime: this.now().toISOString(),
      factId: input.factId,
      actor: input.actor,
      reason: input.reason,
      source: input.source ?? { receiptId: null },
    };
    await this.store.append(event);
    return event;
  }

  async confirm(input: ConfirmInput): Promise<ConfirmEvent> {
    const prior = await this.factById(input.factId);
    if (!prior) throw new Error(`cannot confirm unknown fact ${input.factId}`);
    if (await this.retractedAt(input.factId)) throw new Error(`fact ${input.factId} is retracted`);
    if (prior.fact.provenance !== "claimed" || (await this.confirmedAt(input.factId))) throw new Error(`fact ${input.factId} is already attested`);
    const event: ConfirmEvent = { eventId: randomUUID(), kind: "confirm", txTime: this.now().toISOString(), factId: input.factId, actor: input.actor, source: input.source ?? { receiptId: null } };
    await this.store.append(event);
    return event;
  }

  /** Whether a legal hold currently stands on the fact. */
  async held(factId: string): Promise<boolean> {
    let held = false;
    for (const e of await this.store.eventsFor(factId)) if ((e.kind === "hold" || e.kind === "release") && e.factId === factId) held = e.kind === "hold";
    return held;
  }

  async hold(input: HoldInput): Promise<HoldEvent> {
    const prior = await this.factById(input.factId);
    if (!prior) throw new Error(`cannot hold unknown fact ${input.factId}`);
    if (prior.fact.forgotten) throw new Error(`fact ${input.factId} is already forgotten`);
    if (await this.held(input.factId)) throw new Error(`fact ${input.factId} is already on hold`);
    const event: HoldEvent = { eventId: randomUUID(), kind: "hold", txTime: this.now().toISOString(), factId: input.factId, actor: input.actor, reason: input.reason, source: input.source ?? { receiptId: null } };
    await this.store.append(event);
    return event;
  }

  async release(input: HoldInput): Promise<HoldEvent> {
    if (!(await this.held(input.factId))) throw new Error(`fact ${input.factId} is not on hold`);
    const event: HoldEvent = { eventId: randomUUID(), kind: "release", txTime: this.now().toISOString(), factId: input.factId, actor: input.actor, reason: input.reason, source: input.source ?? { receiptId: null } };
    await this.store.append(event);
    return event;
  }

  /** Records the removal of a store entry with no fact in the ledger. Refuses a fact id that the ledger knows. */
  async repair(input: RepairInput): Promise<RepairEvent> {
    if (await this.factById(input.factId)) throw new Error(`fact ${input.factId} is in the ledger; repair removes only entries the ledger has no fact for`);
    const event: RepairEvent = { eventId: randomUUID(), kind: "repair", txTime: this.now().toISOString(), factId: input.factId, actor: input.actor, reason: input.reason, source: input.source ?? { receiptId: null }, store: input.store, externalId: input.externalId, outcome: input.outcome };
    await this.store.append(event);
    return event;
  }

  /** The facts the ledger learned of before an instant, in one space or all, that have not been forgotten: what a retention sweep decides about. */
  async learnedBefore(before: string, space?: string): Promise<Fact[]> {
    const events = await this.store.eventsAbout({ txBefore: before, ...(space === undefined ? {} : { space }) });
    return events.filter((e): e is AssertEvent => e.kind === "assert" && e.txTime < before && (space === undefined || e.fact.space === space) && !e.fact.forgotten).map((e) => ({ ...e.fact }));
  }

  /** Retention: forgets every fact the ledger learned of before the cutoff, in one space or all, skipping held and already-forgotten facts. Returns what it forgot and what it skipped. */
  async sweep(input: SweepInput): Promise<{ forgotten: ForgetEvent[]; held: string[] }> {
    const forgotten: ForgetEvent[] = [];
    const held: string[] = [];
    for (const f of await this.learnedBefore(input.before, input.space)) {
      if (await this.held(f.factId)) {
        held.push(f.factId);
        continue;
      }
      forgotten.push(await this.forget({ factId: f.factId, actor: input.actor, reason: input.reason, ...(input.source ? { source: input.source } : {}), ...(input.keepDigest === undefined ? {} : { keepDigest: input.keepDigest }), compact: false }));
    }
    if (forgotten.length > 0) await this.store.compact();
    return { forgotten, held };
  }

  /**
   * Erases a fact's value from the store itself, keeping its digest, and stops believing it. The store rewrites the
   * event in place, which is the one thing an append-only ledger must do for a deletion demand. Everything else about
   * the fact stays: who wrote it, when, from which receipt, and now who erased it and why. With compact false the
   * store's reclaim step is left to the caller, for a batch of forgets followed by one compact().
   */
  async forget(input: ForgetInput & { compact?: boolean }): Promise<ForgetEvent> {
    const prior = await this.factById(input.factId);
    if (!prior) throw new Error(`cannot forget unknown fact ${input.factId}`);
    if (prior.fact.forgotten) throw new Error(`fact ${input.factId} is already forgotten`);
    if (await this.held(input.factId)) throw new Error(`fact ${input.factId} is on legal hold; release it first`);
    const txTime = this.now().toISOString();
    const text = canonical(prior.fact.value);
    const digestKind: DigestKind = input.keepDigest === false ? "none" : this.forgetKey ? "hmac-sha256" : "sha256";
    const valueDigest = digestKind === "none" ? null : digestKind === "hmac-sha256" ? createHmac("sha256", this.forgetKey!).update(text).digest("hex") : createHash("sha256").update(text).digest("hex");
    for (const e of await this.store.eventsFor(input.factId)) {
      if (e.kind === "assert" && e.fact.factId === input.factId) {
        await this.store.replaceAssert({ ...e, fact: { ...e.fact, value: null, forgotten: { valueDigest, digestKind, at: txTime } } });
      }
    }
    const event: ForgetEvent = { eventId: randomUUID(), kind: "forget", txTime, factId: input.factId, actor: input.actor, reason: input.reason, source: input.source ?? { receiptId: null }, valueDigest, digestKind };
    await this.store.append(event);
    if (input.compact !== false) await this.store.compact();
    return event;
  }

  /** Reclaims whatever the store may still hold of erased values; forget and sweep do this themselves unless told not to. */
  compact(): Promise<void> {
    return this.store.compact();
  }

  /** The facts believed at a moment. Valid time answers "was it true then"; transaction time answers "did the ledger know it then". */
  async asOf(q: AsOf = {}): Promise<Fact[]> {
    const validAt = q.validAt ?? this.now().toISOString();
    const txAt = q.txAt ?? this.now().toISOString();
    const known = await this.store.eventsAbout({ txAtMost: txAt, ...(q.space === undefined ? {} : { space: q.space }), ...(q.subject === undefined ? {} : { subject: q.subject }), ...(q.predicate === undefined ? {} : { predicate: q.predicate }) });
    const retracted = new Set(known.filter((e): e is RetractEvent | ForgetEvent => e.kind === "retract" || e.kind === "forget").map((e) => e.factId));
    const confirmed = new Set(known.filter((e): e is ConfirmEvent => e.kind === "confirm").map((e) => e.factId));
    const facts = new Map<string, Fact>();
    for (const e of known) {
      if (e.kind !== "assert") continue;
      facts.set(e.fact.factId, { ...e.fact, provenance: confirmed.has(e.fact.factId) ? "attested" : e.fact.provenance });
      if (e.supersedes && facts.has(e.supersedes) && !retracted.has(e.fact.factId)) {
        facts.get(e.supersedes)!.validTo = e.fact.validFrom;
      }
    }
    return [...facts.values()].filter(
      (f) =>
        !retracted.has(f.factId) &&
        f.validFrom <= validAt &&
        (f.validTo === null || validAt < f.validTo) &&
        (q.space === undefined || f.space === q.space) &&
        (q.subject === undefined || f.subject === q.subject) &&
        (q.predicate === undefined || f.predicate === q.predicate) &&
        (q.include === undefined || q.include === "all" || RANK[f.provenance] >= RANK[q.include]),
    );
  }

  /** One fact by id, whatever its state, with supersession applied; undefined when the ledger never held it. */
  async get(factId: string): Promise<Fact | undefined> {
    return (await this.factById(factId))?.fact;
  }

  /** Every fact ever asserted, with supersession applied and retracted ones included, for audits that must see everything. */
  async facts(): Promise<Fact[]> {
    const events = await this.store.events();
    const retracted = new Set(events.filter((e): e is RetractEvent | ForgetEvent => e.kind === "retract" || e.kind === "forget").map((e) => e.factId));
    const out = new Map<string, Fact>();
    for (const e of events) {
      if (e.kind !== "assert") continue;
      out.set(e.fact.factId, { ...e.fact });
      if (e.supersedes && out.has(e.supersedes) && !retracted.has(e.fact.factId)) out.get(e.supersedes)!.validTo = e.fact.validFrom;
    }
    return [...out.values()];
  }

  /** Every event that touched a fact, oldest first: its assert, the assert that superseded it, its confirmation, its retraction. */
  history(factId: string): Promise<LedgerEvent[]> {
    return this.store.eventsFor(factId);
  }

  private async confirmedAt(factId: string): Promise<boolean> {
    return (await this.store.eventsFor(factId)).some((e) => e.kind === "confirm" && e.factId === factId);
  }

  private async factById(factId: string): Promise<AssertEvent | undefined> {
    let found: AssertEvent | undefined;
    for (const e of await this.store.eventsFor(factId)) {
      if (e.kind === "assert" && e.fact.factId === factId) found = { ...e, fact: { ...e.fact } };
      else if (e.kind === "assert" && e.supersedes === factId && found && !(await this.retractedAt(e.fact.factId))) found.fact.validTo = e.fact.validFrom;
    }
    return found;
  }

  private async retractedAt(factId: string): Promise<boolean> {
    return (await this.store.eventsFor(factId)).some((e) => (e.kind === "retract" || e.kind === "forget") && e.factId === factId);
  }
}

/** Canonical JSON: sorted keys, no whitespace, undefined dropped. The same encoding the receipts package uses. */
function canonical(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object") {
      const o: Record<string, unknown> = {};
      for (const k of Object.keys(v as object).sort()) {
        const x = (v as Record<string, unknown>)[k];
        if (x !== undefined) o[k] = sort(x);
      }
      return o;
    }
    return v;
  };
  return JSON.stringify(sort(value));
}


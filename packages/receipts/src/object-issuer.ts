// An issuer that keeps receipts in an object store (Cloudflare R2, or anything with put, get, list, and delete) instead
// of a directory: the same signing, capture, and log rules as the file issuer (issue.ts), for a producer with no disk.
// The layout mirrors the receipts directory: `<prefix><id>.json` for a bundle, `<prefix><id>.authorization.json` for
// an authorization, `<prefix>salts/<id>.json` for the salts behind withheld values, `<prefix>outbox/<id>.json` for a
// signed receipt whose log append is pending. The salts are the owner's alone: the store must not be readable by
// anyone a receipt's withheld values are kept from.
import { effectiveRule, getAt, privateView, type CaptureConfig, type CaptureContext, type PrivateView } from "./capture.ts";
import { canonicalize, dsseSign, dsseVerify, type Envelope, type KeyPair } from "./crypto.ts";
import type { Issuer } from "./issue.ts";
import type { LogAppend, LogSink } from "./log-http.ts";
import { buildAuthorizationStatement, buildStatement, RECEIPT_TYPE, type AuthorizationBundle, type AuthorizationPredicate, type ReceiptBundle, type ReceiptPredicate } from "./receipt.ts";
import { ReceiptPending, type FlushResult } from "./receipt-pending.ts";

/** What the issuer needs of an object store. A put must be whole or absent: R2's is. */
export interface ObjectStore {
  put(key: string, text: string): Promise<void>;
  /** the object's text, or null when there is none */
  get(key: string): Promise<string | null>;
  /** every key under the prefix */
  list(prefix: string): Promise<string[]>;
  delete(key: string): Promise<void>;
}

/** a receipt id as the door mints it; anything else never becomes part of a key */
const RECEIPT_ID = /^[A-Za-z0-9-]{1,64}$/;

export interface ObjectIssuerOptions {
  capture?: { rules?: CaptureConfig | undefined; key?: Buffer | undefined } | undefined;
  /** prepended to every key, so that one bucket can hold several doors' receipts. Default "" */
  prefix?: string | undefined;
}

/**
 * Signs, logs, and stores receipts in `store`. As with the file issuer, a receipt reaches the store only after the log
 * has taken it; with `deferLog`, a refused append keeps the signed receipt in the outbox and throws `ReceiptPending`,
 * and `flushOutbox` appends it later. There is no lock across processes: two flushes at once (two Worker isolates) can
 * each append one outbox entry, which puts the receipt in the log twice, under two leaves. Either inclusion proves it.
 * `pending` counts the outbox entries this issuer has seen, since a count of the store would need a listing.
 */
export function createObjectIssuer(key: KeyPair, store: ObjectStore, sink: LogSink, opts: ObjectIssuerOptions = {}): Issuer {
  const prefix = opts.prefix ?? "";
  const bundleKey = (id: string) => `${prefix}${id}.json`;
  const outboxKey = (id: string) => `${prefix}outbox/${id}.json`;
  const idOk = (id: string) => {
    if (!RECEIPT_ID.test(id)) throw new Error(`receipt id ${JSON.stringify(id)} is not a valid id`);
    return id;
  };
  const view = <P extends AuthorizationPredicate>(predicate: P, ctx?: CaptureContext, prior?: PrivateView<AuthorizationPredicate>) => privateView(predicate, effectiveRule(opts.capture?.rules, predicate.tool.name, ctx?.unknownTool), opts.capture?.key, ctx, prior);
  // as in the file issuer: the authorization's view, until its receipt is issued, so that both carry the same commitments
  const committed = new Map<string, { view: PrivateView<AuthorizationPredicate>; at: number }>();
  const COMMITTED_FOR_MS = 60 * 60 * 1000;
  const COMMITTED_AT_MOST = 10_000;
  let outboxSeen = 0;
  const keepSalts = async (v: PrivateView<AuthorizationPredicate>) => {
    const salts = Object.fromEntries((v.predicate.capture?.withheld ?? []).filter((w) => (getAt(v.predicate, w) as { $custody?: string } | undefined)?.$custody === "withheld").map((w) => [JSON.stringify(w), v.salts[JSON.stringify(w)]!]));
    if (!Object.keys(salts).length) return;
    await store.put(`${prefix}salts/${idOk(v.predicate.receiptId)}.json`, JSON.stringify({ receiptId: v.predicate.receiptId, salts }, null, 2));
  };
  const bundleOf = (envelope: Envelope, entry: LogAppend): ReceiptBundle => ({ envelope, treeHead: entry.treeHead, inclusion: entry.inclusion });

  return {
    keyid: key.keyid,
    log: sink,
    async issue(predicate, ctx, retainPrepared, issueOpts) {
      if (retainPrepared) throw new Error("the object issuer does not retain prepared receipts");
      const id = idOk(predicate.receiptId);
      const pv = view(predicate, ctx, committed.get(id)?.view);
      const envelope = dsseSign(RECEIPT_TYPE, buildStatement(pv.predicate), key);
      let entry: LogAppend;
      try {
        entry = await sink.append(canonicalize(envelope));
      } catch (e) {
        if (!issueOpts?.deferLog) throw e;
        try {
          await keepSalts(pv);
          await store.put(outboxKey(id), JSON.stringify({ envelope }));
        } catch (w) {
          throw new Error(`${e instanceof Error ? e.message : String(e)}; the receipt could not be kept in the outbox either: ${w instanceof Error ? w.message : String(w)}`, { cause: e });
        }
        committed.delete(id);
        outboxSeen++;
        throw new ReceiptPending(id, e);
      }
      committed.delete(id);
      await keepSalts(pv);
      const bundle = bundleOf(envelope, entry);
      await store.put(bundleKey(id), JSON.stringify(bundle, null, 2));
      return bundle;
    },
    async authorize(predicate, ctx) {
      const id = idOk(predicate.receiptId);
      const pv = view(predicate, ctx);
      const envelope = dsseSign(RECEIPT_TYPE, buildAuthorizationStatement(pv.predicate), key);
      const entry = await sink.append(canonicalize(envelope));
      const now = Date.now();
      for (const [k, c] of committed) {
        if (now - c.at <= COMMITTED_FOR_MS) break;
        committed.delete(k);
      }
      committed.set(id, { view: pv, at: now });
      if (committed.size > COMMITTED_AT_MOST) committed.delete(committed.keys().next().value!);
      await keepSalts(pv);
      const bundle: AuthorizationBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
      // stored before the call goes on: if nothing follows, this is the evidence that it was authorized and sent
      await store.put(`${prefix}${id}.authorization.json`, JSON.stringify(bundle, null, 2));
      return bundle;
    },
    pending: () => outboxSeen,
    async flushOutbox(): Promise<FlushResult> {
      const keys = (await store.list(`${prefix}outbox/`)).filter((k) => k.endsWith(".json"));
      let sent = 0;
      let setAside = 0;
      let foreign = 0;
      const errors: string[] = [];
      for (const k of keys) {
        const id = k.slice(`${prefix}outbox/`.length, -".json".length);
        try {
          if (!RECEIPT_ID.test(id)) { setAside++; continue; }
          // a bundle already there: the append and the write happened, and only the removal did not
          if (await store.get(bundleKey(id))) { await store.delete(k); sent++; continue; }
          const text = await store.get(k);
          if (text === null) continue;
          let record: { envelope?: Envelope; appended?: LogAppend };
          try { record = JSON.parse(text) as typeof record; } catch { await store.put(`${k}.bad`, text); await store.delete(k); setAside++; continue; }
          const envelope = record.envelope;
          if (typeof envelope?.payload !== "string" || !Array.isArray(envelope.signatures) || envelope.signatures.length === 0) { await store.put(`${k}.bad`, text); await store.delete(k); setAside++; continue; }
          if (!envelope.signatures.some((s) => s?.keyid === key.keyid)) { foreign++; continue; }
          const checked = dsseVerify(envelope, [key]);
          const statement = (checked.ok ? checked.payload : undefined) as { predicate: ReceiptPredicate } | undefined;
          if (!statement || envelope.payloadType !== RECEIPT_TYPE || statement.predicate?.receiptId !== id) { await store.put(`${k}.bad`, text); await store.delete(k); setAside++; continue; }
          let entry = record.appended;
          if (!entry) {
            try {
              entry = await sink.append(canonicalize(envelope));
            } catch (e) {
              errors.push(e instanceof Error ? e.message : String(e));
              break;
            }
            // until the bundle is written, the answer is the only proof that the log has the leaf
            await store.put(k, JSON.stringify({ envelope, appended: entry }));
          }
          await store.put(bundleKey(id), JSON.stringify(bundleOf(envelope, entry), null, 2));
          await store.delete(k);
          sent++;
        } catch (e) {
          errors.push(`outbox entry ${k}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      const remaining = (await store.list(`${prefix}outbox/`)).filter((k) => k.endsWith(".json")).length;
      outboxSeen = remaining;
      return { sent, pending: remaining, setAside, foreign, ...(errors.length ? { error: errors.length === 1 ? errors[0]! : `${errors[0]} (and ${errors.length - 1} more)` } : {}) };
    },
  };
}

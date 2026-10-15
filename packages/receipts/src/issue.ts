// Signing, logging and writing a receipt. Shared by every producer: the gateway and the SDK.
import { mkdirSync, writeFileSync } from "node:fs";
import { SALTS_DIR, saltsFileFor } from "./retention.ts";
import { join } from "node:path";
import { getAt, privateView, ruleFor, type CaptureConfig, type CaptureContext, type PrivateView } from "./capture.ts";
import { canonicalize, dsseSign, type KeyPair } from "./crypto.ts";
import { fileLog, type LogSink } from "./log-sink.ts";
import type { ReceiptExporter } from "./otel.ts";
import { buildAuthorizationStatement, buildStatement, RECEIPT_TYPE, type AuthorizationBundle, type AuthorizationPredicate, type ReceiptBundle, type ReceiptPredicate } from "./receipt.ts";

export interface Issuer {
  keyid: string;
  log: LogSink;
  /**
   * Applies the tool's capture rule to the whole predicate, signs the statement, appends it to the log, writes the
   * bundle. Rejects if the log refuses the leaf; no bundle is written then. The predicate is the call in full; what
   * is signed, written, and exported is the view.
   */
  issue(predicate: ReceiptPredicate, ctx?: CaptureContext): Promise<ReceiptBundle>;
  /** The same for an authorization, signed and committed before a consequential call is forwarded. Rejects if the log refuses; the caller must then not forward. */
  authorize(predicate: AuthorizationPredicate, ctx?: CaptureContext): Promise<AuthorizationBundle>;
}

export interface IssuerOptions {
  /** told about every receipt after it is written; an exporter's failure never reaches the caller */
  exporter?: ReceiptExporter | undefined;
  /** private evidence: the capture rules by tool, and the key that encrypts (`captureKeyEnv`), applied here to every statement before it is signed */
  capture?: { rules?: CaptureConfig | undefined; key?: Buffer | undefined } | undefined;
}

/** `log` is a sink, or a file path for the local log with tree heads signed by the issuer's key. */
export function createIssuer(key: KeyPair, receiptsDir: string, log: string | LogSink, opts: IssuerOptions = {}): Issuer {
  const sink = typeof log === "string" ? fileLog(log, key) : log;
  mkdirSync(receiptsDir, { recursive: true });
  const view = <P extends AuthorizationPredicate>(predicate: P, ctx?: CaptureContext, prior?: PrivateView<AuthorizationPredicate>) => privateView(predicate, ruleFor(opts.capture?.rules, predicate.tool.name), opts.capture?.key, ctx, prior);
  /**
   * The view committed in an authorization, by receipt id, until its receipt is issued: the receipt carries the same
   * commitments and salts for the parts they share. Set once the log has taken the authorization, released when the
   * receipt is issued, and bounded: a call that never reaches its receipt does not keep its view for ever.
   */
  const committed = new Map<string, PrivateView<AuthorizationPredicate>>();
  const COMMITTED_AT_MOST = 10_000;
  /**
   * The salts behind a statement's digest-only commitments, kept beside the receipts and never in them:
   * `receipts/salts/<id>.json`, the owner's alone. They are what makes a disclosure possible for a value withheld
   * without its value, and what a reviewer must not be handed, since with them a guess can be confirmed. An encrypted
   * commitment carries its salt inside the ciphertext, so that salt is not written: the key alone recovers it.
   */
  const keepSalts = (v: PrivateView<AuthorizationPredicate>) => {
    const salts = Object.fromEntries((v.predicate.capture?.withheld ?? []).filter((w) => (getAt(v.predicate, w) as { $custody?: string } | undefined)?.$custody === "withheld").map((w) => [JSON.stringify(w), v.salts[JSON.stringify(w)]!]));
    if (!Object.keys(salts).length) return;
    mkdirSync(join(receiptsDir, SALTS_DIR), { recursive: true, mode: 0o700 });
    writeFileSync(saltsFileFor(receiptsDir, v.predicate.receiptId), JSON.stringify({ receiptId: v.predicate.receiptId, salts }, null, 2), { mode: 0o600 });
  };
  return {
    keyid: key.keyid,
    log: sink,
    async issue(predicate, ctx) {
      const prior = committed.get(predicate.receiptId);
      committed.delete(predicate.receiptId);
      const pv = view(predicate, ctx, prior);
      const v = pv.predicate;
      keepSalts(pv);
      const envelope = dsseSign(RECEIPT_TYPE, buildStatement(v), key);
      const entry = await sink.append(canonicalize(envelope));
      const bundle: ReceiptBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
      writeFileSync(join(receiptsDir, `${predicate.receiptId}.json`), JSON.stringify(bundle, null, 2));
      // After the evidence, not before, and awaited so a process that exits right after issuing still exports. The
      // exporter sees the view, never the full call.
      if (opts.exporter) await opts.exporter.exported(v, bundle).catch(() => {});
      return bundle;
    },
    async authorize(predicate, ctx) {
      const pv = view(predicate, ctx);
      const v = pv.predicate;
      const envelope = dsseSign(RECEIPT_TYPE, buildAuthorizationStatement(v), key);
      const entry = await sink.append(canonicalize(envelope));
      // committed: the receipt that follows shares this view; nothing is kept for an authorization the log refused
      committed.set(predicate.receiptId, pv);
      if (committed.size > COMMITTED_AT_MOST) committed.delete(committed.keys().next().value!);
      keepSalts(pv);
      const bundle: AuthorizationBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
      // On disk in its own right: if the process dies between forwarding and the receipt, this is the evidence that the call was authorized and sent.
      writeFileSync(join(receiptsDir, `${predicate.receiptId}.authorization.json`), JSON.stringify(bundle, null, 2));
      return bundle;
    },
  };
}

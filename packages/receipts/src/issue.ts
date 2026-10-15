// Signing, logging and writing a receipt. Shared by every producer: the gateway and the SDK.
import { mkdirSync, writeFileSync } from "node:fs";
import { SALTS_DIR } from "./retention.ts";
import { join } from "node:path";
import { privateView, ruleFor, under, type CaptureConfig, type CaptureContext, type CaptureNote } from "./capture.ts";
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
  const view = <P extends AuthorizationPredicate>(predicate: P, ctx?: CaptureContext) => privateView(predicate, ruleFor(opts.capture?.rules, predicate.tool.name), opts.capture?.key, ctx);
  /** The view committed in an authorization, by receipt id: the receipt that follows carries the same commitments and salts for the parts they share. */
  const committed = new Map<string, { request: AuthorizationPredicate["request"]; facts: AuthorizationPredicate["facts"]; policy: AuthorizationPredicate["policy"]; note: CaptureNote | undefined; salts: Record<string, string> }>();
  /**
   * The salts behind a statement's commitments, kept beside the receipts and never in them: `receipts/salts/<id>.json`.
   * They are what makes a disclosure possible for a value withheld without its value, and what a reviewer must not
   * be handed, since with them a guess can be confirmed. Written at authorization and again, complete, at issue.
   */
  const keepSalts = (receiptId: string, salts: Record<string, string>) => {
    if (!Object.keys(salts).length) return;
    mkdirSync(join(receiptsDir, SALTS_DIR), { recursive: true });
    writeFileSync(join(receiptsDir, SALTS_DIR, `${receiptId}.json`), JSON.stringify({ receiptId, salts }, null, 2));
  };
  return {
    keyid: key.keyid,
    log: sink,
    async issue(predicate, ctx) {
      let { predicate: v, salts } = view(predicate, ctx);
      const prior = committed.get(predicate.receiptId);
      if (prior) {
        committed.delete(predicate.receiptId);
        const shared = (w: string[]) => under(w, ["request"]) || under(w, ["facts"]) || under(w, ["policy"]);
        const rest = (v.capture?.withheld ?? []).filter((w) => !shared(w));
        const mode = prior.note?.mode ?? v.capture?.mode;
        const withheld = [...(prior.note?.withheld ?? []), ...rest];
        v = { ...v, request: prior.request, facts: prior.facts, policy: prior.policy, ...(withheld.length && mode ? { capture: { mode, withheld } } : {}) };
        if (!withheld.length) delete (v as { capture?: unknown }).capture;
        salts = { ...Object.fromEntries(Object.entries(salts).filter(([k]) => !shared(JSON.parse(k) as string[]))), ...prior.salts };
      }
      keepSalts(predicate.receiptId, salts);
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
      const { predicate: v, salts } = view(predicate, ctx);
      committed.set(predicate.receiptId, { request: v.request, facts: v.facts, policy: v.policy, note: v.capture, salts });
      keepSalts(predicate.receiptId, salts);
      const envelope = dsseSign(RECEIPT_TYPE, buildAuthorizationStatement(v), key);
      const entry = await sink.append(canonicalize(envelope));
      const bundle: AuthorizationBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
      // On disk in its own right: if the process dies between forwarding and the receipt, this is the evidence that the call was authorized and sent.
      writeFileSync(join(receiptsDir, `${predicate.receiptId}.authorization.json`), JSON.stringify(bundle, null, 2));
      return bundle;
    },
  };
}

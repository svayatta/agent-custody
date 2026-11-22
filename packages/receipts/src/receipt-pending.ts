// What an issuer reports when a receipt's log append is pending, apart from the file issuer so that any issuer (a
// Worker's included) and the door core can share it.

/** What one `flushOutbox` did. `foreign` entries are signed by another key and stay in the outbox. */
export interface FlushResult {
  sent: number;
  pending: number;
  setAside: number;
  foreign: number;
  error?: string;
}

/**
 * Thrown by `issue` with `deferLog` when the log did not take the receipt. The signed receipt is kept in the outbox and
 * no bundle is written yet: `flushOutbox` appends it later and then writes the bundle.
 */
export class ReceiptPending extends Error {
  readonly receiptId: string;
  constructor(receiptId: string, cause: unknown) {
    super(`receipt ${receiptId} is kept in the outbox; its log append is pending: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    this.name = "ReceiptPending";
    this.receiptId = receiptId;
  }
}

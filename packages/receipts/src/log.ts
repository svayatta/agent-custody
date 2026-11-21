// Append-only Merkle log with RFC 6962 / RFC 9162 hashing and inclusion proofs.
// Leaves are stored as JSONL so anyone holding the file can recompute the root.
import { appendFileSync, closeSync, fstatSync, mkdirSync, openSync, readSync, statSync, truncateSync, writeSync, type Stats } from "node:fs";
import { dirname } from "node:path";
import { withLock } from "./lock.ts";
import { leafHash, SubtreeCache, type InclusionProof } from "./merkle.ts";

export * from "./merkle.ts";

const LOCK_STALE_MS = 60_000;
const LOG_LOCK_WAIT_MS = 20_000;

/** Each hook of a coding agent is its own process, so appends overlap: one writer at a time holds `<file>.lock`. */
export function logLocked<T>(file: string, fn: () => T): T {
  return withLock(`${file}.lock`, { staleMs: LOCK_STALE_MS, waitMs: LOG_LOCK_WAIT_MS }, fn);
}

/** The append descriptor of a log that was dropped without being closed is closed when the log is collected. */
interface Appender { fd: number | null; dev: number; ino: number }
const appenders = new FinalizationRegistry<Appender>((out) => {
  if (out.fd !== null) try { closeSync(out.fd); } catch { /* already closed */ }
});

export class MerkleLog {
  private readonly hashes: Buffer[] = [];
  private tree = new SubtreeCache(this.hashes);
  private readonly file: string;
  private bytes = 0;
  private inode: number | bigint = -1;
  private readonly out: Appender = { fd: null, dev: 0, ino: 0 };

  constructor(file: string) {
    this.file = file;
    mkdirSync(dirname(file), { recursive: true });
    this.catchUp();
    appenders.register(this, this.out);
  }

  /**
   * Reads the leaves that another handle or process appended since the last read. A file that was replaced or cut
   * short is read again from the start. Bytes after the last newline are not read: a writer may be in the middle of its
   * write, or may have died in it.
   */
  private catchUp(): Stats | null {
    let st: Stats | null;
    try { st = statSync(this.file); } catch { st = null; }
    if (!st || st.ino !== this.inode || st.size < this.bytes) {
      this.hashes.length = 0;
      this.tree = new SubtreeCache(this.hashes);
      this.bytes = 0;
    }
    if (!st) return null;
    this.inode = st.ino;
    if (st.size === this.bytes) return st;
    const buf = Buffer.alloc(st.size - this.bytes);
    const fd = openSync(this.file, "r");
    let got = 0;
    try {
      while (got < buf.length) {
        const n = readSync(fd, buf, got, buf.length - got, this.bytes + got);
        if (n === 0) break;
        got += n;
      }
    } finally {
      closeSync(fd);
    }
    got = buf.subarray(0, got).lastIndexOf(0x0a) + 1;
    this.bytes += got;
    for (const line of buf.subarray(0, got).toString("utf8").split("\n")) {
      if (!line.trim()) continue;
      const parsed = JSON.parse(line) as string | { pruned?: string; hash?: string };
      // A pruned leaf keeps only its hash, and a leaf appended by hash never had content here: the tree, its
      // roots, and every proof are the same either way.
      this.hashes.push(typeof parsed === "string" ? leafHash(parsed) : Buffer.from((parsed.pruned ?? parsed.hash)!, "hex"));
    }
    return st;
  }

  /**
   * Under the lock: a last line with no newline is the remains of a writer that died in the middle of its write. No
   * leaf was acknowledged for it. The bytes go to `<file>.torn`, so no data is lost, and the file ends after the last whole line.
   */
  private cutTornTail(): void {
    let size: number;
    try { size = statSync(this.file).size; } catch { return; }
    if (size <= this.bytes) return;
    const tail = Buffer.alloc(size - this.bytes);
    const fd = openSync(this.file, "r");
    try {
      readSync(fd, tail, 0, tail.length, this.bytes);
    } finally {
      closeSync(fd);
    }
    appendFileSync(`${this.file}.torn`, tail, { mode: 0o600 });
    truncateSync(this.file, this.bytes);
  }

  /** Under the lock: reads what other writers appended, then writes this line, so each leaf gets the next index. */
  private appendLine(line: string, hash: () => Buffer): InclusionProof & { rootHash: string } {
    return logLocked(this.file, () => {
      const st = this.catchUp();
      this.cutTornTail();
      this.write(line, st);
      this.bytes += Buffer.byteLength(line);
      return this.pushHash(hash());
    });
  }

  /**
   * Under the lock: writes the line through one descriptor opened for append, so the file is not opened and closed
   * for every leaf. O_APPEND puts each write at the end, after a torn tail was cut too. The descriptor is reopened when
   * the path names another file than the one it holds (a prune renames a new file into place) or no file. Nothing is
   * fsynced, as before: the line is in the kernel's page cache when the append returns.
   */
  private write(line: string, st: Stats | null): void {
    const out = this.out;
    if (out.fd === null || !st || st.ino !== out.ino || st.dev !== out.dev) {
      this.close();
      const fd = openSync(this.file, "a");
      const now = fstatSync(fd);
      if (st && (now.ino !== st.ino || now.dev !== st.dev)) {
        closeSync(fd);
        throw new Error(`${this.file} was replaced while its lock was held; the leaf was not appended`);
      }
      out.fd = fd;
      out.dev = now.dev;
      out.ino = now.ino;
      this.inode = now.ino;
    }
    const buf = Buffer.from(line);
    try {
      for (let off = 0; off < buf.length; ) off += writeSync(out.fd, buf, off);
    } catch (e) {
      // the bytes written so far are a torn tail, which the next append cuts; that append reopens the file
      this.close();
      throw e;
    }
  }

  /** Closes the append descriptor. The log stays usable: the next append opens the file again. */
  close(): void {
    if (this.out.fd === null) return;
    const fd = this.out.fd;
    this.out.fd = null;
    closeSync(fd);
  }

  get size(): number {
    return this.hashes.length;
  }

  /** Leaf hashes `from` (inclusive) to `to` (exclusive), as hex: what an export carries and what a copy is rebuilt from. */
  leafHashes(from: number, to: number = this.hashes.length): string[] {
    return this.hashes.slice(Math.max(0, from), Math.min(to, this.hashes.length)).map((h) => h.toString("hex"));
  }

  /** Appends a leaf (an opaque string, typically a canonical JSON envelope). Returns its proof against the new root. */
  append(leaf: string): InclusionProof & { rootHash: string } {
    return this.appendLine(JSON.stringify(leaf) + "\n", () => leafHash(leaf));
  }

  /**
   * Appends a leaf by its RFC 6962 leaf hash, sha256(0x00 || leaf), as hex. The log commits to the leaf without ever
   * holding it, which is what a log run for someone else should do: the receipt stays with its issuer.
   */
  appendHash(leafHashHex: string): InclusionProof & { rootHash: string } {
    if (!/^[0-9a-f]{64}$/.test(leafHashHex)) throw new Error("leafHash must be 64 lowercase hex characters");
    return this.appendLine(JSON.stringify({ hash: leafHashHex }) + "\n", () => Buffer.from(leafHashHex, "hex"));
  }

  private pushHash(hash: Buffer): InclusionProof & { rootHash: string } {
    this.hashes.push(hash);
    const treeSize = this.hashes.length;
    return { leafIndex: treeSize - 1, treeSize, hashes: this.tree.path(treeSize - 1, 0, treeSize).map((b) => b.toString("hex")), rootHash: this.tree.mth(0, treeSize).toString("hex") };
  }

  root(size = this.size): string {
    if (size < 0 || size > this.size) throw new Error("size out of range");
    return this.tree.mth(0, size).toString("hex");
  }

  /** Proof that this log at newSize extends its own earlier state at oldSize. */
  consistencyProof(oldSize: number, newSize = this.size): string[] {
    if (oldSize < 0 || oldSize > newSize || newSize > this.size) throw new Error("sizes out of range");
    if (oldSize === 0 || oldSize === newSize) return [];
    return this.tree.subproof(oldSize, 0, newSize, true).map((b) => b.toString("hex"));
  }

  /** Reads a log file and returns the root at the given size, for auditors holding a copy of the log. */
  static rootFromFile(file: string, size: number): string {
    return new MerkleLog(file).root(size);
  }
}

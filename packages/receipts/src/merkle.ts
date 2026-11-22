// RFC 6962 / RFC 9162 Merkle tree hashing and proofs: pure functions, no files. The local log (log.ts) and every
// reader of a log (the HTTP sink, the verifiers) share them.
import { createHash } from "node:crypto";

export interface InclusionProof {
  leafIndex: number;
  treeSize: number;
  hashes: string[]; // hex, leaf-to-root order
}

const h = (...parts: Buffer[]) => {
  const c = createHash("sha256");
  for (const p of parts) c.update(p);
  return c.digest();
};

export function leafHash(data: string): Buffer {
  return h(Buffer.from([0x00]), Buffer.from(data));
}

const nodeHash = (l: Buffer, r: Buffer) => h(Buffer.from([0x01]), l, r);

// Every hash a proof check reads is 32 bytes: a proof hash and a root are each a string of 64 lowercase hex digits, as
// the Python verifier requires. Checked before the loop: with children of other widths, sha256(0x01 || left || right)
// no longer fixes where one child ends and the other begins.
const HASH_HEX = /^[0-9a-f]{64}$/;
const isHash = (x: unknown): x is string => typeof x === "string" && HASH_HEX.test(x);
const EMPTY_ROOT = createHash("sha256").digest("hex");
// Sizes and indices are integers. The loops halve them with Math.floor, so a fraction such as 6.5 can walk a real path.
const isSize = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;

/** n is a power of two. Exact for every safe integer: `(n & (n - 1)) === 0` reads only the low 32 bits of n. */
function isPowerOfTwo(n: number): boolean {
  let k = 1;
  while (k < n) k *= 2;
  return k === n;
}

/** largest power of two strictly less than n (n >= 2) */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Subtree hashes over a growing list of leaves. A subtree over an aligned, complete, power-of-two range never changes
 * once its leaves exist, so those are cached; everything else is recomputed from at most log(n) cached parts. That
 * makes appends, roots, and proofs O(log n) instead of O(n), which is what keeps a long session's receipts cheap.
 */
export class SubtreeCache {
  private readonly perfect = new Map<string, Buffer>();
  private readonly leaves: Buffer[];
  constructor(leaves: Buffer[]) {
    this.leaves = leaves;
  }
  mth(lo: number, hi: number): Buffer {
    const n = hi - lo;
    if (n === 0) return createHash("sha256").digest();
    if (n === 1) return this.leaves[lo]!;
    const aligned = (n & (n - 1)) === 0 && lo % n === 0;
    const key = aligned ? `${lo}:${hi}` : "";
    if (aligned) {
      const hit = this.perfect.get(key);
      if (hit) return hit;
    }
    const k = split(n);
    const h = nodeHash(this.mth(lo, lo + k), this.mth(lo + k, hi));
    if (aligned) this.perfect.set(key, h);
    return h;
  }
  path(m: number, lo: number, hi: number): Buffer[] {
    const n = hi - lo;
    if (n <= 1) return [];
    const k = split(n);
    return m < k ? [...this.path(m, lo, lo + k), this.mth(lo + k, hi)] : [...this.path(m - k, lo + k, hi), this.mth(lo, lo + k)];
  }
  subproof(m: number, lo: number, hi: number, b: boolean): Buffer[] {
    const n = hi - lo;
    if (m === n) return b ? [] : [this.mth(lo, hi)];
    const k = split(n);
    return m <= k ? [...this.subproof(m, lo, lo + k, b), this.mth(lo + k, hi)] : [...this.subproof(m - k, lo + k, hi, false), this.mth(lo, lo + k)];
  }
}

const mth = (leaves: Buffer[], lo: number, hi: number): Buffer => new SubtreeCache(leaves).mth(lo, hi);
const path = (m: number, leaves: Buffer[], lo: number, hi: number): Buffer[] => new SubtreeCache(leaves).path(m, lo, hi);

/** RFC 9162 section 2.1.4.1: SUBPROOF(m, D[n], b). */
const subproof = (m: number, leaves: Buffer[], lo: number, hi: number, b: boolean): Buffer[] => new SubtreeCache(leaves).subproof(m, lo, hi, b);

/** Proof that the tree of size newSize extends the tree of size oldSize. Empty when oldSize is 0 or equal to newSize. */
export function consistencyProof(leafHashes: Buffer[], oldSize: number, newSize = leafHashes.length): string[] {
  if (oldSize < 0 || oldSize > newSize || newSize > leafHashes.length) throw new Error("sizes out of range");
  if (oldSize === 0 || oldSize === newSize) return [];
  return subproof(oldSize, leafHashes, 0, newSize, true).map((b) => b.toString("hex"));
}

/** RFC 9162 section 2.1.4.2. Pure: needs only the two sizes, the two roots, and the proof. */
export function verifyConsistency(oldSize: number, oldRoot: string, newSize: number, newRoot: string, proofHex: string[]): boolean {
  if (!isSize(oldSize) || !isSize(newSize) || oldSize > newSize) return false;
  if (!isHash(oldRoot) || !isHash(newRoot) || !Array.isArray(proofHex) || !proofHex.every(isHash)) return false;
  // the empty tree has one root, sha256 of nothing; any other root at size 0, old or new, is a head no log could have signed
  if (oldSize === 0) return proofHex.length === 0 && oldRoot === EMPTY_ROOT && (newSize > 0 || newRoot === EMPTY_ROOT);
  if (oldSize === newSize) return proofHex.length === 0 && oldRoot === newRoot;
  if (proofHex.length === 0) return false;
  const proof = proofHex.map((x) => Buffer.from(x, "hex"));
  if (isPowerOfTwo(oldSize)) proof.unshift(Buffer.from(oldRoot, "hex"));
  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = proof[0]!;
  let sr = proof[0]!;
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && fr.toString("hex") === oldRoot && sr.toString("hex") === newRoot;
}

export function rootOf(leafHashes: Buffer[], size = leafHashes.length): string {
  return mth(leafHashes, 0, size).toString("hex");
}

export function inclusionProof(leafHashes: Buffer[], leafIndex: number, treeSize = leafHashes.length): InclusionProof {
  if (leafIndex < 0 || leafIndex >= treeSize || treeSize > leafHashes.length) throw new Error("index out of range");
  return { leafIndex, treeSize, hashes: path(leafIndex, leafHashes, 0, treeSize).map((b) => b.toString("hex")) };
}

/** RFC 9162 section 2.1.3.2 verification. Pure function: needs only the leaf hash, proof and claimed root. */
export function verifyInclusion(leaf: Buffer, proof: InclusionProof, rootHex: string): boolean {
  if (!isSize(proof.leafIndex) || !isSize(proof.treeSize)) return false;
  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  if (fn < 0 || sn < 0 || fn > sn) return false;
  if (leaf.length !== 32 || !isHash(rootHex) || !Array.isArray(proof.hashes) || !proof.hashes.every(isHash)) return false;
  let r = leaf;
  for (const hex of proof.hashes) {
    if (sn === 0) return false;
    const p = Buffer.from(hex, "hex");
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.toString("hex") === rootHex;
}

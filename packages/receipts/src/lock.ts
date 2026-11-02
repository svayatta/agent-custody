// One lock file design for the files that many processes write: the outbox and the local receipt log.
import { randomUUID } from "node:crypto";
import { closeSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { ownerAlive, processStamp } from "./operations.ts";

/** A lock file that holds no readable owner is a lock that is being written. After this age it is a leftover. */
const UNREADABLE_STALE_MS = 60_000;
const pause = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

interface LockOwner { token: string; pid: number; start?: string; host: string }

function readOwner(lockFile: string): LockOwner | undefined {
  try {
    const o = JSON.parse(readFileSync(lockFile, "utf8")) as Partial<LockOwner> | null;
    return o && typeof o.token === "string" && typeof o.pid === "number" && typeof o.host === "string" ? (o as LockOwner) : undefined;
  } catch {
    return undefined;
  }
}

/** The owner on this host is gone, or no one has touched the file for `staleMs`. */
function lockIsStale(lockFile: string, staleMs: number): boolean {
  try {
    const age = Date.now() - statSync(lockFile).mtimeMs;
    const owner = readOwner(lockFile);
    if (!owner) return age > UNREADABLE_STALE_MS;
    if (owner.host === hostname() && !ownerAlive({ ownerPid: owner.pid, ...(owner.start ? { ownerStart: owner.start } : {}) })) return true;
    return age > staleMs;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw e;
  }
}

/**
 * Takes the lock with an exclusive create, and returns its release. The release removes the file only when it still
 * holds this call's token, so a holder whose lock was broken never removes the lock of the next holder. Returns
 * undefined when a live holder has the lock. A stale lock is moved away with a rename: of two callers that find it
 * stale, one moves it and the other gets ENOENT and tries again.
 */
export function takeLock(lockFile: string, staleMs: number): (() => void) | undefined {
  const token = randomUUID();
  const body = JSON.stringify({ token, pid: process.pid, start: processStamp(process.pid), host: hostname() });
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const fd = openSync(lockFile, "wx", 0o600);
      try {
        writeFileSync(fd, body);
      } finally {
        closeSync(fd);
      }
      return () => {
        if (readOwner(lockFile)?.token === token) rmSync(lockFile, { force: true });
      };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    if (!lockIsStale(lockFile, staleMs)) return undefined;
    try {
      const gone = `${lockFile}.stale-${randomUUID()}`;
      renameSync(lockFile, gone);
      rmSync(gone, { force: true });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
  }
  return undefined;
}

/** Runs `fn` under the lock. Waits up to `waitMs` for a live holder, then throws. */
export function withLock<T>(lockFile: string, opts: { staleMs: number; waitMs: number }, fn: () => T): T {
  const deadline = Date.now() + opts.waitMs;
  for (;;) {
    const release = takeLock(lockFile, opts.staleMs);
    if (release) {
      try {
        return fn();
      } finally {
        release();
      }
    }
    if (Date.now() > deadline) throw new Error(`${lockFile} is held by another process, so the file is not written. Remove the lock file if no agent-custody process runs.`);
    pause(2 + Math.random() * 8);
  }
}

// Revoked grants: digests of grant envelopes (`grantDigest` in delegation.ts), in a JSON array the operator edits or
// `agent-custody revoke` appends to. The gateway and the door read the same file the same way: re-read whenever it
// changes, so revocation takes effect on the next call or arrival without a restart or a key rotation.
import { existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";

/** Replaces the revocation file by rename, so a reader never sees half a list. */
export function writeRevokedGrants(path: string, digests: string[]): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(digests, null, 2) + "\n");
  renameSync(tmp, path);
}

export interface RevocationList {
  /** re-reads the file if it changed; throws when it exists and cannot be read as a JSON array */
  reload(): void;
  /** true when any of `digests` is revoked, as of the last reload */
  has(digests: string[]): boolean;
  /** reloads, adds a digest, and writes the file back when there is one */
  add(digest: string): void;
  /** reloads and returns every revoked digest */
  list(): string[];
}

/** The revocation list in `path`; with no path, a list held in memory only. A missing file is an empty list. */
export function createRevocationList(path: string | undefined): RevocationList {
  const revoked = new Set<string>();
  let seen = "";
  const reload = () => {
    if (!path) return;
    if (!existsSync(path)) {
      if (seen !== "absent") { revoked.clear(); seen = "absent"; }
      return;
    }
    // inode as well as mtime: `revoke` replaces the file by rename, so two writes in one mtime tick are still seen
    const st = statSync(path);
    const m = `${st.ino}:${st.mtimeMs}:${st.size}`;
    if (m === seen) return;
    const list = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!Array.isArray(list)) throw new Error(`${path}: expected a JSON array of grant digests`);
    revoked.clear();
    for (const d of list) if (typeof d === "string") revoked.add(d);
    seen = m;
  };
  return {
    reload,
    has: (digests) => digests.some((d) => revoked.has(d)),
    add(digest) {
      reload();
      revoked.add(digest);
      if (path) writeRevokedGrants(path, [...revoked]);
    },
    list() {
      reload();
      return [...revoked];
    },
  };
}

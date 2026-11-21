// One lock design for the files that many processes write: the local log, its prune, and the outbox.
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { takeLock, withLock } from "../src/lock.ts";
import { leafHash, MerkleLog, rootOf } from "../src/log.ts";
import { pruneLog } from "../src/retention.ts";

const dir = () => mkdtempSync(join(tmpdir(), "mlock-"));
const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const ownerBody = (o: object) => JSON.stringify({ token: "other", host: hostname(), ...o });
const deadPid = () => {
  const child = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  return Number(child.stdout);
};

describe("the lock", () => {
  it("is held by one caller at a time, and a release removes only the lock of its own call", () => {
    const lock = join(dir(), "x.lock");
    const first = takeLock(lock, 60_000)!;
    expect(takeLock(lock, 60_000)).toBeUndefined();
    first();
    expect(existsSync(lock)).toBe(false);

    const stalled = takeLock(lock, 60_000)!;
    writeFileSync(lock, ownerBody({ pid: deadPid(), token: "gone" }));
    const next = takeLock(lock, 60_000)!;
    expect(next).toBeTypeOf("function");
    stalled();
    expect(existsSync(lock)).toBe(true);
    next();
    expect(existsSync(lock)).toBe(false);
  });

  it("breaks the lock of a process on this host that is gone, and never the lock of a live one", () => {
    const lock = join(dir(), "x.lock");
    writeFileSync(lock, ownerBody({ pid: deadPid() }));
    expect(takeLock(lock, 60_000)).toBeTypeOf("function");

    writeFileSync(lock, ownerBody({ pid: process.pid }));
    expect(takeLock(lock, 60_000)).toBeUndefined();
    const old = new Date(Date.now() - 120_000);
    utimesSync(lock, old, old);
    expect(takeLock(lock, 60_000)).toBeUndefined();
  });

  it("loses no acknowledged leaf when many processes append at the same time", async () => {
    const file = join(dir(), "log.jsonl");
    const logModule = join(import.meta.dirname, "..", "src", "log.ts");
    const writer = (w: number) =>
      new Promise<string>((done, fail) => {
        const script = `import { MerkleLog } from ${JSON.stringify(logModule)}; const log = new MerkleLog(${JSON.stringify(file)}); const out = []; for (let k = 0; k < 50; k++) out.push([log.append("w${w}-" + k).leafIndex, "w${w}-" + k]); process.stdout.write(JSON.stringify(out));`;
        const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "pipe", "inherit"] });
        let out = "";
        child.stdout.on("data", (d) => (out += d));
        child.on("exit", (code) => (code === 0 ? done(out) : fail(new Error(`writer ${w} exited ${code}`))));
      });
    const acks = (await Promise.all(Array.from({ length: 20 }, (_, w) => writer(w)))).flatMap((o) => JSON.parse(o) as [number, string][]);
    const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l) as string);
    expect(acks).toHaveLength(1000);
    expect(lines).toHaveLength(1000);
    for (const [index, leaf] of acks) expect(lines[index]).toBe(leaf);
    expect(existsSync(`${file}.torn`)).toBe(false);
  }, 60_000);

  it("does not take the lock file of another host as dead, and leaves a lock file with no owner for a minute", () => {
    const lock = join(dir(), "x.lock");
    writeFileSync(lock, ownerBody({ pid: deadPid(), host: "another-host.example" }));
    expect(takeLock(lock, 60_000)).toBeUndefined();
    writeFileSync(lock, "");
    expect(takeLock(lock, 60_000)).toBeUndefined();
    const old = new Date(Date.now() - 120_000);
    utimesSync(lock, old, old);
    expect(takeLock(lock, 60_000)).toBeTypeOf("function");
  });
});

describe("the local log", () => {
  it("appends at once past the lock of a process that is gone", () => {
    const file = join(dir(), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("x");
    writeFileSync(`${file}.lock`, ownerBody({ pid: deadPid() }));
    expect(log.append("y").leafIndex).toBe(1);
    expect(existsSync(`${file}.lock`)).toBe(false);
  });

  it("cuts a last line with no newline into <file>.torn, and the next append works", () => {
    const file = join(dir(), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("one");
    log.append("two");
    appendFileSync(file, '"thr');
    // a reader sees the two whole leaves and does not parse the partial line
    expect(new MerkleLog(file).size).toBe(2);
    const proof = log.append("three");
    expect(proof.leafIndex).toBe(2);
    expect(readFileSync(`${file}.torn`, "utf8")).toBe('"thr');
    expect(readFileSync(file, "utf8").split("\n")).toEqual([JSON.stringify("one"), JSON.stringify("two"), JSON.stringify("three"), ""]);
    expect(new MerkleLog(file).root()).toBe(rootOf(["one", "two", "three"].map(leafHash)));
    // another handle that never saw the partial line gets the same result
    const other = new MerkleLog(file);
    appendFileSync(file, "42");
    expect(other.append("four").leafIndex).toBe(3);
    expect(readFileSync(`${file}.torn`, "utf8")).toBe('"thr42');
  });

  it("keeps a partial line that is valid JSON out of the log too", () => {
    const file = join(dir(), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("one");
    appendFileSync(file, JSON.stringify("never acknowledged"));
    expect(log.append("two").leafIndex).toBe(1);
    expect(readFileSync(`${file}.torn`, "utf8")).toBe(JSON.stringify("never acknowledged"));
  });
});

// A log keeps one descriptor open for its appends. Each test fails if a leaf goes to a file the path no longer names,
// or lands anywhere but after the last whole line: the leaf would be acknowledged with a proof that no copy of the log backs.
describe("the descriptor a log keeps open for its appends", () => {
  const lines = (file: string) => readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as string);

  it("follows a prune, which renames a new file into place: the next leaf goes into the file the path names", () => {
    const file = join(dir(), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("one");
    log.append("two");
    const before = statSync(file).ino;
    pruneLog(file, "2000-01-01T00:00:00Z");
    expect(statSync(file).ino).not.toBe(before);
    const proof = log.append("three");
    expect(lines(file)).toEqual(["one", "two", "three"]);
    expect([proof.leafIndex, proof.treeSize]).toEqual([2, 3]);
    expect(proof.rootHash).toBe(MerkleLog.rootFromFile(file, 3));
  });

  it("creates the file again when it was removed, and starts the tree again from it", () => {
    const file = join(dir(), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("one");
    rmSync(file);
    const proof = log.append("two");
    expect(lines(file)).toEqual(["two"]);
    expect(proof.rootHash).toBe(rootOf([leafHash("two")]));
    expect(log.append("three").rootHash).toBe(MerkleLog.rootFromFile(file, 2));
  });

  it("writes after the last whole line when another handle appended and a writer died mid-line since its own last write", () => {
    const file = join(dir(), "log.jsonl");
    const a = new MerkleLog(file);
    const b = new MerkleLog(file);
    a.append("one");
    b.append("two");
    appendFileSync(file, '"thr');
    expect(a.append("three").leafIndex).toBe(2);
    expect(readFileSync(`${file}.torn`, "utf8")).toBe('"thr');
    expect(lines(file)).toEqual(["one", "two", "three"]);
    expect(b.append("four").rootHash).toBe(rootOf(["one", "two", "three", "four"].map(leafHash)));
  });

  it("opens the file again after close, so a closed log is still a log", () => {
    const file = join(dir(), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("one");
    log.close();
    log.close();
    expect(log.append("two").leafIndex).toBe(1);
    expect(lines(file)).toEqual(["one", "two"]);
  });
});

describe("prune", () => {
  it("waits for the log lock, so a leaf that is appended during the prune is not lost", async () => {
    const d = dir();
    const file = join(d, "log.jsonl");
    new MerkleLog(file).append("one");
    const release = takeLock(`${file}.lock`, 60_000)!;
    const inode = statSync(file).ino;
    const child = spawn(process.execPath, [cli, "prune", "--log", file, "--before", "2000-01-01T00:00:00Z"], { stdio: "ignore" });
    const done = new Promise<number | null>((resolve) => child.on("close", resolve));
    // the prune rewrites the file through a rename: the inode changes only if it ran without the lock
    const until = Date.now() + 3000;
    while (Date.now() < until && statSync(file).ino === inode) await new Promise((r) => setTimeout(r, 50));
    expect(statSync(file).ino).toBe(inode);
    appendFileSync(file, JSON.stringify("two") + "\n");
    release();
    expect(await done).toBe(0);
    expect(readFileSync(file, "utf8").trim().split("\n")).toEqual([JSON.stringify("one"), JSON.stringify("two")]);
  }, 30_000);
});

// Contention, timeouts, and the races between judging a lock stale and breaking it.
describe("lock contention and break races", () => {
  it("withLock waits out waitMs under a live holder, then throws its message; free, it runs the work", () => {
    const lock = join(dir(), "x.lock");
    const release = takeLock(lock, 60_000)!;
    const started = Date.now();
    expect(() => withLock(lock, { staleMs: 60_000, waitMs: 200 }, () => "ran")).toThrow(/is held by another process/);
    expect(Date.now() - started).toBeGreaterThanOrEqual(100);
    release();
    expect(withLock(lock, { staleMs: 60_000, waitMs: 200 }, () => "ran")).toBe("ran");
    expect(existsSync(lock)).toBe(false);
  });

  it("a lock path under a regular file rethrows the filesystem error instead of waiting", () => {
    const d = dir();
    writeFileSync(join(d, "not-a-dir"), "hi");
    const lock = join(d, "not-a-dir", "x.lock");
    expect(() => takeLock(lock, 60_000)).toThrow(/ENOTDIR/);
    expect(() => withLock(lock, { staleMs: 60_000, waitMs: 50 }, () => {})).toThrow(/ENOTDIR/);
  });

  it("a held .break makes the caller back off, and the lock and the breaker both survive", () => {
    const lock = join(dir(), "x.lock");
    writeFileSync(lock, ownerBody({ pid: deadPid() }));
    writeFileSync(`${lock}.break`, "held by another breaker");
    expect(takeLock(lock, 60_000)).toBeUndefined();
    expect(readFileSync(lock, "utf8")).toContain('"other"');
    expect(existsSync(`${lock}.break`)).toBe(true);
  });

  it("a stale .break is cleared and the stale lock is then broken", () => {
    const lock = join(dir(), "x.lock");
    writeFileSync(lock, ownerBody({ pid: deadPid() }));
    writeFileSync(`${lock}.break`, "leftover breaker");
    const old = new Date(Date.now() - 120_000);
    utimesSync(`${lock}.break`, old, old);
    const release = takeLock(lock, 60_000);
    expect(release).toBeTypeOf("function");
    expect(existsSync(`${lock}.break`)).toBe(false);
    release!();
    expect(existsSync(lock)).toBe(false);
  });

  it("a directory in place of the lock file surfaces an error instead of being silently dropped", () => {
    const d = dir();
    const lock = join(d, "x.lock");
    mkdirSync(lock);
    writeFileSync(join(lock, "kept"), "a lock file is a file, not a directory");
    const old = new Date(Date.now() - 120_000);
    utimesSync(lock, old, old);
    expect(() => takeLock(lock, 60_000)).toThrow(/EISDIR/);
    expect(existsSync(lock)).toBe(false);
    expect(readdirSync(d).some((n) => n.startsWith("x.lock.stale-"))).toBe(true);
    rmSync(join(d, readdirSync(d).find((n) => n.startsWith("x.lock.stale-"))!), { recursive: true, force: true });
  });

  it("a lock swapped between judgement and break survives: the breaker never takes a live lock", async () => {
    const d = dir();
    const lock = join(d, "x.lock");
    // Fifty stale owners and fifty live ones, each a few hundred kilobytes so that judging one takes long
    // enough for the swapper to replace it several times over, and each on its own inode: the breaker must
    // see a different file than the judge saw on every attempt, and must back off every time.
    const pad = "x".repeat(300_000);
    const dead = deadPid();
    for (let i = 0; i < 50; i++) writeFileSync(join(d, `stale-${i}.json`), JSON.stringify({ token: `stale-${i}`, pid: dead, host: hostname(), pad }));
    writeFileSync(join(d, "swap.mjs"), `
      import { linkSync, readdirSync, renameSync, writeFileSync } from "node:fs";
      import { hostname } from "node:os";
      import { join } from "node:path";
      const dir = process.argv[2];
      const lock = process.argv[3];
      const pad = "x".repeat(300_000);
      for (let i = 0; i < 50; i++) writeFileSync(join(dir, "live-" + i + ".json"), JSON.stringify({ token: "live-" + i, pid: process.pid, host: hostname(), pad }));
      const stale = readdirSync(dir).filter((n) => n.startsWith("stale-")).sort();
      const pool = [];
      for (let i = 0; i < 50; i++) { pool.push(stale[i]); pool.push("live-" + i + ".json"); }
      writeFileSync(join(dir, "ready"), "ok");
      let n = 0;
      for (;;) {
        const tmp = join(dir, "flip-" + n + ".tmp");
        try { linkSync(join(dir, pool[n % pool.length]), tmp); renameSync(tmp, lock); } catch {}
        n++;
      }
    `);
    const child = spawn(process.execPath, [join(d, "swap.mjs"), d, lock], { stdio: "ignore" });
    try {
      const until = Date.now() + 10_000;
      while (!existsSync(join(d, "ready")) && Date.now() < until) await new Promise((r) => setTimeout(r, 25));
      expect(existsSync(join(d, "ready"))).toBe(true);
      expect(child.exitCode).toBeNull();
      for (let i = 0; i < 5; i++) expect(takeLock(lock, 60_000)).toBeUndefined();
      expect(child.exitCode).toBeNull();
    } finally {
      child.kill();
      await new Promise((r) => child.on("close", r));
      rmSync(d, { recursive: true, force: true });
    }
  }, 30_000);
});

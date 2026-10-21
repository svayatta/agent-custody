// A container runtime, systemd and Kubernetes stop a service with SIGTERM. A process that is PID 1 in a container
// ignores a signal it has no handler for, so the service is killed after the grace period instead of closing.
// A graceful stop exits with code 0; a process that died of the signal reports the signal.
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { generateKeyPair, writeKeyPair } from "../src/crypto.ts";
import { buildFixture } from "../scripts/fixture.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");

/** starts the CLI, waits for its ready line, sends SIGTERM, and reports how the process ended */
async function stopWithSigterm(args: string[], ready: RegExp): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  const child = spawn(process.execPath, ["--import", "tsx", cli, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  let seen = "";
  const up = new Promise<void>((resolve, reject) => {
    const onData = (d: Buffer) => {
      seen += d;
      if (ready.test(seen)) resolve();
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("close", () => reject(new Error(`exited before it was ready:\n${seen}`)));
  });
  const ended = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.on("close", (code, signal) => resolve({ code, signal })));
  await up;
  child.kill("SIGTERM");
  return ended;
}

describe("a service stopped with SIGTERM", () => {
  it("the log closes and exits with code 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-log-"));
    const key = writeKeyPair(generateKeyPair(), join(dir, "keys"), "log");
    const r = await stopWithSigterm(["log", "--file", join(dir, "log.jsonl"), "--key", key.keyFile, "--port", "0"], /agent-custody log: http/);
    expect(r).toEqual({ code: 0, signal: null });
  });

  it("the shared HTTP gateway closes and exits with code 0", async () => {
    const fx = buildFixture(join(mkdtempSync(join(tmpdir(), "shutdown-gw-")), "fx"));
    const r = await stopWithSigterm(["gateway", "--config", fx.configFile, "--http", "--port", "0"], /one session per grant/);
    expect(r).toEqual({ code: 0, signal: null });
  });
});

describe("a stdio gateway stopped with SIGTERM", () => {
  it("keeps the default behaviour and does not ignore the signal", async () => {
    const fx = buildFixture(join(mkdtempSync(join(tmpdir(), "shutdown-stdio-")), "fx"));
    const child = spawn(process.execPath, ["--import", "tsx", cli, "gateway", "--config", fx.configFile], { stdio: ["pipe", "pipe", "pipe"] });
    const ended = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.on("close", (code, signal) => resolve({ code, signal })));
    await new Promise<void>((resolve, reject) => {
      let seen = "";
      child.stderr.on("data", (d: Buffer) => { seen += d; if (/agent-custody gateway: agent=/.test(seen)) resolve(); });
      child.on("close", () => reject(new Error(`exited before it was ready:\n${seen}`)));
    });
    child.kill("SIGTERM");
    // with no handler the default action ends the process by the signal; a handler that closed it would exit 0
    expect(await ended).toEqual({ code: null, signal: "SIGTERM" });
  });
});

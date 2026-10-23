// A container runtime, systemd and Kubernetes stop a service with SIGTERM. A graceful stop closes the service and exits
// with code 0; a process that died of the signal reports the signal.
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");

/** starts the CLI, waits for its ready line, sends SIGTERM, and reports how the process ended */
async function stopWithSigterm(args: string[], ready: RegExp, env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
  let seen = "";
  const up = new Promise<void>((resolve, reject) => {
    child.stderr.on("data", (d: Buffer) => { seen += d; if (ready.test(seen)) resolve(); });
    child.on("close", () => reject(new Error(`exited before it was ready:\n${seen}`)));
  });
  const ended = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.on("close", (code, signal) => resolve({ code, signal })));
  await up;
  child.kill("SIGTERM");
  return ended;
}

describe("a memory service stopped with SIGTERM", () => {
  it("serve --http closes and exits with code 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-memory-"));
    const r = await stopWithSigterm(["serve", "--ledger", join(dir, "ledger.jsonl"), "--http", "--port", "0", "--token-env", "SHUTDOWN_TEST_TOKEN"], /agent-custody-memory: http/, { SHUTDOWN_TEST_TOKEN: "test-token" });
    expect(r).toEqual({ code: 0, signal: null });
  });

  it("review closes and exits with code 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-review-"));
    const r = await stopWithSigterm(["review", "--receipts", dir, "--port", "0"], /agent-custody-memory review: http/);
    expect(r).toEqual({ code: 0, signal: null });
  });
});

// A container runtime, systemd and Kubernetes stop a service with SIGTERM. A graceful stop closes the service and exits
// with code 0; a process that died of the signal reports the signal.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { connect } from "node:net";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");

type Ended = { code: number | null; signal: NodeJS.Signals | null };

/** starts the CLI and waits for its ready line */
async function start(args: string[], ready: RegExp, env: NodeJS.ProcessEnv = {}): Promise<{ child: ChildProcess; seen: () => string; ended: Promise<Ended> }> {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
  let seen = "";
  const ended = new Promise<Ended>((resolve) => child.on("close", (code, signal) => resolve({ code, signal })));
  await new Promise<void>((resolve, reject) => {
    child.stderr.on("data", (d: Buffer) => { seen += d; if (ready.test(seen)) resolve(); });
    child.on("close", () => reject(new Error(`exited before it was ready:\n${seen}`)));
  });
  return { child, seen: () => seen, ended };
}

/** sends SIGTERM and reports how the process ended; a process that is still running after the bound is killed and reported as "hung" */
async function stopWithSigterm(s: { child: ChildProcess; ended: Promise<Ended> }, boundMs: number): Promise<Ended | "hung"> {
  s.child.kill("SIGTERM");
  let timer: NodeJS.Timeout | undefined;
  const hung = new Promise<"hung">((resolve) => { timer = setTimeout(() => { s.child.kill("SIGKILL"); resolve("hung"); }, boundMs); });
  const r = await Promise.race([s.ended, hung]);
  clearTimeout(timer);
  return r;
}

const serveArgs = (dir: string) => ["serve", "--ledger", join(dir, "ledger.jsonl"), "--http", "--port", "0", "--token-env", "SHUTDOWN_TEST_TOKEN"];
const serveEnv = { SHUTDOWN_TEST_TOKEN: "test-token" };
const urlOf = (seen: string) => /(http:\/\/\S+\/mcp)/.exec(seen)![1];

describe("a memory service stopped with SIGTERM", () => {
  it("serve --http closes and exits with code 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-memory-"));
    const s = await start(serveArgs(dir), /agent-custody-memory: http/, serveEnv);
    expect(await stopWithSigterm(s, 10_000)).toEqual({ code: 0, signal: null });
  });

  it("serve --http exits with code 0 while a gateway client is connected", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-client-"));
    const s = await start(serveArgs(dir), /agent-custody-memory: http/, serveEnv);
    const client = new Client({ name: "agent-custody-gateway", version: "0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(urlOf(s.seen())), { requestInit: { headers: { authorization: "Bearer test-token" } } }));
    expect((await client.listTools()).tools.length).toBeGreaterThan(0);
    expect(await stopWithSigterm(s, 2_000)).toEqual({ code: 0, signal: null });
    await client.close().catch(() => {});
  });

  it("serve --http exits with code 0 after the deadline when a request body never arrives", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-stalled-"));
    const s = await start(serveArgs(dir), /agent-custody-memory: http/, serveEnv);
    const { hostname, port } = new URL(urlOf(s.seen()));
    const socket = connect(Number(port), hostname);
    socket.on("error", () => {});
    socket.write("POST /mcp HTTP/1.1\r\nHost: x\r\nauthorization: Bearer test-token\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: 100\r\n\r\n{");
    await new Promise((r) => setTimeout(r, 200));
    expect(await stopWithSigterm(s, 15_000)).toEqual({ code: 0, signal: null });
    socket.destroy();
  });

  it("review closes and exits with code 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "shutdown-review-"));
    const s = await start(["review", "--receipts", dir, "--port", "0"], /agent-custody-memory review: http/);
    expect(await stopWithSigterm(s, 10_000)).toEqual({ code: 0, signal: null });
  });
});

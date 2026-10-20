// The gateway container's entrypoint (deploy/gateway/gateway-entrypoint.sh), run on the host with a shim for the
// agent-custody command: init writes a starter config the gateway accepts, serve creates the key on first start and
// serves the shared HTTP gateway on all interfaces, an agent without a grant is refused, and SIGTERM closes it.
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { GatewayConfigSchema } from "../src/config.ts";
import { decodeDelegation } from "../src/delegation.ts";

const receipts = join(import.meta.dirname, "..");
const entrypoint = join(receipts, "..", "..", "deploy", "gateway", "gateway-entrypoint.sh");
const freePort = () => new Promise<number>((resolve) => { const s = createServer().listen(0, () => { const p = (s.address() as { port: number }).port; s.close(() => resolve(p)); }); });

let dir: string;
let env: NodeJS.ProcessEnv;
let config: string;
let data: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "gateway-image-"));
  config = join(dir, "config");
  data = join(dir, "data");
  mkdirSync(config);
  mkdirSync(data);
  const bin = join(dir, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "agent-custody"), `#!/bin/sh\nexec "${process.execPath}" --import tsx "${join(receipts, "src", "cli.ts")}" "$@"\n`);
  chmodSync(join(bin, "agent-custody"), 0o755);
  env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, DATA_DIR: data, GATEWAY_CONFIG: join(config, "gateway.json") };
});

const run = (...args: string[]) => spawnSync("sh", [entrypoint, ...args], { cwd: receipts, env, encoding: "utf8", timeout: 30_000 });

describe("the gateway image entrypoint", () => {
  it("serve refuses to start without a config and says how to make one", () => {
    const r = run("serve");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("init");
  });

  it("init writes a config the gateway accepts, an example policy, and a demo grant that names the demo agent", () => {
    const r = run("init");
    expect(r.status, r.stderr).toBe(0);
    const cfg = GatewayConfigSchema.parse(JSON.parse(readFileSync(join(config, "gateway.json"), "utf8")));
    expect(cfg.identity.keyFile).toBe(join(data, "keys", "gateway.key"));
    expect(cfg.receiptsDir).toBe(join(data, "receipts"));
    expect(cfg.precommit).toEqual(["*"]);
    expect(readFileSync(join(config, "policy.cedar"), "utf8")).toContain("example.lookup");
    expect(existsSync(join(config, "keys", "principal.pub"))).toBe(true);
    const grant = decodeDelegation(JSON.parse(readFileSync(join(config, "demo", "grant.json"), "utf8")));
    expect(grant?.agent).toBe("demo-agent");
    expect(grant?.scopes).toEqual(["example.lookup"]);
    expect(r.stderr).toContain("Delete this directory in production");
  });

  it("init does not overwrite a config that exists", () => {
    const r = run("init");
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("already exists");
  });

  it("serve refuses to start on a config the check calls an error, and rejects an unknown GATEWAY_CHECK value", async () => {
    const badDir = join(dir, "bad-config");
    mkdirSync(badDir);
    cpSync(config, badDir, { recursive: true });
    const cfg = JSON.parse(readFileSync(join(badDir, "gateway.json"), "utf8"));
    cfg.precomit = ["example.lookup"];
    writeFileSync(join(badDir, "gateway.json"), JSON.stringify(cfg));
    const bad = { ...env, GATEWAY_CONFIG: join(badDir, "gateway.json"), GATEWAY_PORT: String(await freePort()) };
    const strict = spawnSync("sh", [entrypoint, "serve"], { cwd: receipts, env: bad, encoding: "utf8", timeout: 30_000 });
    expect(strict.status).toBe(1);
    expect(strict.stderr).toContain("precomit");
    expect(strict.stderr).toContain("not starting");
    const off = spawnSync("sh", [entrypoint, "serve"], { cwd: receipts, env: { ...bad, GATEWAY_CHECK: "bogus" }, encoding: "utf8", timeout: 30_000 });
    expect(off.status).toBe(1);
    expect(off.stderr).toContain("GATEWAY_CHECK must be");
  });

  it("serve creates the gateway key, answers /health, refuses a connection with no grant, and exits 0 on SIGTERM", async () => {
    const port = await freePort();
    const child = spawn("sh", [entrypoint, "serve"], { cwd: receipts, env: { ...env, GATEWAY_PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
    let seen = "";
    const up = new Promise<void>((resolve, reject) => {
      const onData = (d: Buffer) => { seen += d; if (/one session per grant/.test(seen)) resolve(); };
      child.stdout.on("data", onData);
      child.stderr.on("data", onData);
      child.on("close", () => reject(new Error(`exited before it was ready:\n${seen}`)));
    });
    const ended = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.on("close", (code, signal) => resolve({ code, signal })));
    await up;
    expect(existsSync(join(data, "keys", "gateway.key"))).toBe(true);
    const health = await fetch(`http://127.0.0.1:${port}/health`);
    expect(health.status).toBe(200);
    expect(((await health.json()) as { ok: boolean }).ok).toBe(true);
    const noGrant = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }) });
    expect(noGrant.status).toBe(403);
    child.kill("SIGTERM");
    expect(await ended).toEqual({ code: 0, signal: null });
  });
});

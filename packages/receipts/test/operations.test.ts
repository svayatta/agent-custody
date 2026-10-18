import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { GatewayConfigSchema, loadConfig } from "../src/config.ts";
import { OperationStore, type OperationReservation } from "../src/operations.ts";
import { buildFixture } from "../scripts/fixture.ts";

const database = () => join(mkdtempSync(join(tmpdir(), "custody-operations-")), "operations.sqlite");
const input = (patch: Partial<OperationReservation> = {}): OperationReservation => ({ id: randomUUID(), issuerKeyid: "issuer", providerDigest: "provider", principal: "principal", agent: "agent", tool: "payments.transfer", argsDigest: "arguments", budget: "daily", currency: "USD", amount: 60, limit: 100, originalReceiptId: randomUUID(), ...patch });

/** Two independent Node processes, held at a barrier after opening their own database connections. */
async function concurrentReservations(file: string, inputs: OperationReservation[]): Promise<{ created?: boolean; error?: string }[]> {
  const module = new URL("../src/operations.ts", import.meta.url).href;
  const children = inputs.map((reservation) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", `
      import { OperationStore } from ${JSON.stringify(module)};
      const store = new OperationStore(process.argv[1]);
      process.send({ ready: true });
      process.on('message', () => {
        try { process.send({ created: store.reserve(JSON.parse(process.argv[2])).created }); }
        catch (error) { process.send({ error: error.message }); }
        finally { store.close(); process.disconnect(); }
      });
    `, file, JSON.stringify(reservation)], { stdio: ["ignore", "pipe", "pipe", "ipc"] });
    let stderr = "";
    child.stderr!.on("data", (chunk) => { stderr += chunk; });
    let ready!: () => void;
    const started = new Promise<void>((resolveStarted) => { ready = resolveStarted; });
    const result = new Promise<{ created?: boolean; error?: string }>((resolveResult, reject) => {
      let answer: { created?: boolean; error?: string } | undefined;
      child.on("message", (message) => {
        if ((message as { ready?: boolean }).ready) ready();
        else answer = message as { created?: boolean; error?: string };
      });
      child.on("error", reject);
      child.on("exit", (code) => answer && code === 0 ? resolveResult(answer) : reject(new Error(`operation writer exited ${code}: ${stderr}`)));
    });
    return { child, started, result };
  });
  try {
    await Promise.all(children.map((child) => Promise.race([child.started, child.result.then(() => {})])));
    for (const { child } of children) child.send("reserve");
    return await Promise.all(children.map((child) => child.result));
  } finally {
    for (const { child } of children) if (child.exitCode === null) child.kill();
  }
}

describe("durable financial operation reservations", () => {
  it("persists a single binding, receipt, result, and reconciliation across restarts", () => {
    const file = database();
    const reservation = input();
    const one = new OperationStore(file);
    const first = one.reserve(reservation);
    expect(first.created).toBe(true);
    expect(first.operation.idempotencyKey).toMatch(/^[0-9a-f]{64}$/);
    one.update(reservation.id, { status: "unknown", original: { signed: "authorization" }, result: { timeout: true } });
    one.close();
    const two = new OperationStore(file);
    try {
      const retry = two.reserve({ ...reservation, originalReceiptId: randomUUID(), period: "2099-12-31" });
      expect(retry.created).toBe(false);
      expect(retry.operation).toMatchObject({ originalReceiptId: reservation.originalReceiptId, status: "unknown", original: { signed: "authorization" }, result: { timeout: true }, idempotencyKey: first.operation.idempotencyKey, period: first.operation.period });
      expect(two.claimReconciliation(reservation.id, { predicate: "first" })).toEqual({ predicate: "first" });
      expect(two.claimReconciliation(reservation.id, { predicate: "conflicting" })).toEqual({ predicate: "first" });
      expect(two.get(reservation.id)?.status).toBe("unknown");
      two.update(reservation.id, { status: "confirmed", reconciliation: { predicate: "first", bundle: "signed" } });
      expect(two.get(reservation.id)?.reconciliation).toEqual({ predicate: "first", bundle: "signed" });
      expect(two.list()).toEqual([two.get(reservation.id)]);
      expect(() => two.update(reservation.id, { status: "failed" })).toThrow(/terminal/);
    } finally { two.close(); }
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(resolve(file, "..")).mode & 0o777).toBe(0o700);
  });

  it("rejects changed arguments, identity, destination, amount, currency, or budget for an existing id", () => {
    const store = new OperationStore(database());
    const reservation = input();
    try {
      store.reserve(reservation);
      for (const field of ["issuerKeyid", "providerDigest", "principal", "agent", "tool", "argsDigest", "budget", "currency"] as const) {
        expect(() => store.reserve({ ...reservation, [field]: "changed" })).toThrow(new RegExp(field));
      }
      expect(() => store.reserve({ ...reservation, amount: 61 })).toThrow(/amount/);
      expect(store.reserve(reservation).created).toBe(false);
    } finally { store.close(); }
  });

  it("shares daily reservations across principals and holds unknown/pending/confirmed until an explicit failed outcome", () => {
    const file = database();
    const one = new OperationStore(file);
    const two = new OperationStore(file);
    const original = input({ period: "2026-10-18" });
    try {
      one.reserve(original);
      for (const status of ["submitted", "unknown", "pending"] as const) {
        one.update(original.id, { status });
        expect(() => two.reserve(input({ principal: "another", amount: 41, period: original.period }))).toThrow(/budget.*exceeded/);
      }
      one.update(original.id, { status: "failed" });
      const paid = two.reserve(input({ amount: 100, period: original.period })).operation;
      two.update(paid.id, { status: "confirmed" });
      expect(() => one.reserve(input({ amount: 1, period: original.period }))).toThrow(/budget.*exceeded/);
      expect(one.reserve(input({ amount: 100, period: "2026-10-19" })).created).toBe(true);
      expect(one.reserve({ ...original, period: "2026-10-19" }).operation.period).toBe("2026-10-18");
      expect(() => one.reserve(input({ currency: "EUR", period: "2026-10-20" }))).toThrow(/currency/);
    } finally { one.close(); two.close(); }
  });

  it("serializes distinct process budget claims and duplicate operation claims", async () => {
    const file = database();
    const init = new OperationStore(file);
    init.close();
    const competing = await concurrentReservations(file, [input(), input({ principal: "another" })]);
    expect(competing.filter((r) => r.created)).toHaveLength(1);
    expect(competing.filter((r) => r.error?.includes("exceeded"))).toHaveLength(1);
    const same = input({ budget: "another" });
    const duplicate = await concurrentReservations(file, [same, same]);
    expect(duplicate.map((r) => r.created).sort()).toEqual([false, true]);
  }, 30_000);

  it("rejects invalid minor units, periods, insecure directories, and symlinked databases", () => {
    const store = new OperationStore(database());
    try {
      for (const amount of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) expect(() => store.reserve(input({ amount }))).toThrow(/positive safe integer/);
      for (const limit of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) expect(() => store.reserve(input({ limit }))).toThrow(/nonnegative safe integer/);
      expect(() => store.reserve(input({ period: "2026-02-30" }))).toThrow(/UTC date/);
      expect(() => store.reserve(input({ id: "../not-an-id" }))).toThrow(/UUID/);
    } finally { store.close(); }
    const dir = mkdtempSync(join(tmpdir(), "custody-operation-permissions-"));
    chmodSync(dir, 0o755);
    expect(() => new OperationStore(join(dir, "operations.sqlite"))).toThrow(/owner-only/);
    chmodSync(dir, 0o700);
    const target = join(dir, "target");
    writeFileSync(target, "untouched");
    symlinkSync(target, join(dir, "operations.sqlite"));
    expect(() => new OperationStore(join(dir, "operations.sqlite"))).toThrow(/regular file/);
    expect(readFileSync(target, "utf8")).toBe("untouched");
  });
});

describe("financial operation configuration", () => {
  const config = () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "custody-operation-config-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.operations = { database: "operations/operations.sqlite", budgets: [{ id: "daily", currency: "USD", limit: 100 }], tools: [{ tool: "payments.transfer", budget: "daily", reconcile: { tool: "payments.lookup", args: { key: "$operation.idempotencyKey" }, statusPath: "status", confirmed: ["succeeded"], failed: ["failed"], pending: ["pending"] } }] };
    return { fx, cfg };
  };

  it("resolves the durable database path and supplies operation field/header defaults", () => {
    const { fx, cfg } = config();
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const parsed = loadConfig(fx.configFile);
    expect(parsed.operations?.database).toBe(join(resolve(fx.configFile, ".."), "operations/operations.sqlite"));
    expect(parsed.operations?.tools[0]).toMatchObject({ amountField: "amount", currencyField: "currency", idempotencyHeader: "Idempotency-Key" });
  });

  it("rejects duplicate budgets/tools, unsafe limits, unknown budgets, side-effecting fact reads, and ambiguous reconciliation statuses", () => {
    const mutations = [
      (c: any) => c.operations.budgets.push(c.operations.budgets[0]),
      (c: any) => c.operations.tools.push(c.operations.tools[0]),
      (c: any) => { c.operations.budgets[0].limit = Number.MAX_SAFE_INTEGER + 1; },
      (c: any) => { c.operations.budgets[0].currency = "usd"; },
      (c: any) => { c.operations.budgets[0].id = "x".repeat(129); },
      (c: any) => { c.operations.tools[0].budget = "missing"; },
      (c: any) => { c.operations.tools[0].reconcile.tool = "payments.transfer"; },
      (c: any) => { c.facts = [{ name: "balance", tool: "payments.transfer", args: {}, forTools: ["anything"] }]; },
      (c: any) => { c.operations.tools[0].reconcile.failed = ["succeeded"]; },
      (c: any) => { c.operations.tools[0].reconcile.args.key = "$args.secret"; },
      (c: any) => { c.operations.tools[0].reconcile.statusPath = "body..status"; },
      (c: any) => { delete c.logFile; c.log = { url: "https://log.example" }; },
    ];
    for (const mutate of mutations) {
      const { cfg } = config();
      mutate(cfg);
      expect(GatewayConfigSchema.safeParse(cfg).success).toBe(false);
    }
  });
});

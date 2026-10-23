// A policy file replaced while the gateway reads it at startup: the bytes it keeps and the metadata it compares later
// must belong to the same file, or the replacement looks unchanged and is never applied. The hook below renames a
// tightened policy into place right after the gateway's first read of the policy, the narrowest window there is.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

const hook = vi.hoisted(() => ({ path: "", fd: -1, fire: undefined as undefined | (() => void) }));

vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const once = () => {
    const fire = hook.fire;
    hook.fire = undefined;
    fire?.();
  };
  return {
    ...fs,
    openSync: ((path: Parameters<typeof fs.openSync>[0], ...rest: unknown[]) => {
      const fd = (fs.openSync as (...a: unknown[]) => number)(path, ...rest);
      if (hook.fire && path === hook.path) hook.fd = fd;
      return fd;
    }) as typeof fs.openSync,
    readFileSync: ((target: Parameters<typeof fs.readFileSync>[0], ...rest: unknown[]) => {
      const out = (fs.readFileSync as (...a: unknown[]) => unknown)(target, ...rest);
      if (hook.fire && (target === hook.path || (typeof target === "number" && target === hook.fd))) once();
      return out;
    }) as typeof fs.readFileSync,
  };
});

const { readFileSync, renameSync, writeFileSync } = await vi.importActual<typeof import("node:fs")>("node:fs");
const { loadConfig } = await import("../src/config.ts");
const { createGateway, RECEIPT_META_KEY } = await import("../src/gateway.ts");
const { policyDigest } = await import("../src/policy.ts");
const { buildFixture, POLICY } = await import("../scripts/fixture.ts");

const TIGHT = POLICY.replace("context.args.amount <= 100000", "context.args.amount <= 1000");

describe("policy reload, startup", () => {
  it("a policy replaced while the gateway reads it at startup is applied from the first call", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-reload-startup-")));
    const path = join(fx.dir, "policy.cedar");
    hook.path = path;
    hook.fire = () => {
      writeFileSync(`${path}.tmp`, TIGHT);
      renameSync(`${path}.tmp`, path);
    };
    const error = console.error;
    console.error = () => {};
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      expect(hook.fire, "the hook never saw the gateway read its policy").toBeUndefined();
      const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000 } });
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as { envelope: { payload: string } };
      const p = JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()).predicate as { policy: { decision: string; policyDigest: string } };
      expect(p.policy.policyDigest).toBe(policyDigest(TIGHT));
      expect(p.policy.decision).toBe("deny");
      expect(r.isError).toBe(true);
    } finally {
      console.error = error;
      await gw.close();
    }
  });
});

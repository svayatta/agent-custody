// The operator's takeover-relevant commands leave an audit entry with the actor cli:<user>@<host>, like the other
// log-admin commands. The CLI runs as a child process on a PGlite directory (test/pg-standin.cjs stands in for `pg`).
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { hostname, tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresTenancy } from "../src/log-store.ts";
import { PortalStore } from "../src/portal.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const standin = join(import.meta.dirname, "pg-standin.cjs");
const SECRET = "oidc-client-secret-for-this-test";
const actor = `cli:${userInfo().username}@${hostname()}`;
let dir: string;

const run = (...args: string[]) =>
  spawnSync(process.execPath, ["--require", standin, cli, "log-admin", "--db-env", "DB_URL", ...args], { encoding: "utf8", timeout: 60_000, env: { ...process.env, DB_URL: "standin", PG_STANDIN_DIR: dir, ACME_OIDC_SECRET: SECRET } });
const audit = async () => {
  const db = new PGlite(dir);
  try {
    return await new PostgresTenancy(db).audit({ tenant: "acme" });
  } finally {
    await db.close();
  }
};

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "log-admin-cli-"));
  const db = new PGlite(dir);
  await new PostgresTenancy(db).addTenant("acme", "acme", "test");
  const portal = new PortalStore(db);
  const ada = await portal.createUser("ada@acme.example", "a-long-enough-password");
  await portal.addMember(ada.id, "acme", "owner");
  await portal.setMfaSecret(ada.id, Buffer.from("a".repeat(20)).toString("hex"));
  await portal.enableMfa(ada.id);
  await db.close();
}, 60_000);
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("log-admin audit entries for single sign-on and MFA", () => {
  it("sso set, user mfa-reset, and sso remove each write an entry with the operator as the actor, and none holds the secret", async () => {
    const set = run("sso", "set", "acme", "--oidc-issuer", "https://login.acme.example", "--oidc-client-id", "portal-client", "--oidc-secret-env", "ACME_OIDC_SECRET", "--domains", "acme.example,corp.acme.example", "--default-role", "reviewer", "--enforce");
    expect([set.status, set.stderr]).toEqual([0, ""]);
    const reset = run("user", "mfa-reset", "Ada@Acme.example");
    expect([reset.status, reset.stderr]).toEqual([0, ""]);
    const remove = run("sso", "remove", "acme");
    expect([remove.status, remove.stderr]).toEqual([0, ""]);

    const entries = (await audit()).filter((e) => e.action !== "tenant.add");
    expect(entries.map((e) => [e.action, e.actor, e.tenantId])).toEqual([["sso.remove", actor, "acme"], ["user.mfa-reset", actor, "acme"], ["sso.set", actor, "acme"]]);
    expect(entries[1]!.detail).toEqual({ email: "ada@acme.example" });
    expect(entries[2]!.detail).toEqual({ protocol: "oidc", issuer: "https://login.acme.example", domains: ["acme.example", "corp.acme.example"], defaultRole: "reviewer", enforced: true });
    expect(JSON.stringify(entries)).not.toContain(SECRET);
  }, 120_000);

  it("a reset for an address with no account fails and writes no entry", async () => {
    const before = (await audit()).length;
    const r = run("user", "mfa-reset", "nobody@acme.example");
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/no portal account/);
    expect((await audit()).length).toBe(before);
  }, 60_000);
});

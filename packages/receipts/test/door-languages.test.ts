// The door middleware for Go, Rails (Rack), Django (and WSGI), and Java (and the Spring filter's client) are clients of
// a door in authz mode. Each example runs against a live door as its own process and must print OK; each receipt it
// names must be a real door receipt that verifies and records the request the client asked about. A missing
// toolchain skips that language, visibly.
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, type DoorFixture } from "../scripts/door-fixture.ts";

const dir = resolve(import.meta.dirname, "..", "examples", "languages", "door");
const has = (probe: string[]) => spawnSync(probe[0]!, probe.slice(1)).status === 0;
const javaOut = mkdtempSync(join(tmpdir(), "door-java-"));

const languages: { name: string; probes: string[][]; cmd: string[]; cwd: string }[] = [
  { name: "go (net/http)", probes: [["go", "version"]], cmd: ["go", "run", "."], cwd: join(dir, "go") },
  { name: "ruby (Rack, as Rails mounts it)", probes: [["ruby", "--version"]], cmd: ["ruby", "main.rb"], cwd: join(dir, "ruby") },
  { name: "python (Django middleware and WSGI)", probes: [["python3", "--version"]], cmd: ["python3", "main.py"], cwd: join(dir, "python") },
  // The Host header is restricted in java.net.http unless the JVM allows it; the client refuses to start without it.
  { name: "java (JDK HttpServer filter; the Spring adapter is a doc snippet, not compiled here)", probes: [["javac", "-version"], ["java", "-version"]], cmd: ["sh", "-c", `javac -d "${javaOut}" *.java && java -Djdk.httpclient.allowRestrictedHeaders=host -cp "${javaOut}" DoorExample`], cwd: join(dir, "java") },
];

const receiptCount = (d: string) => readdirSync(d).filter((f) => /^[0-9a-f-]{36}\.json$/.test(f)).length;
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

describe("door middleware in other languages, against a door in authz mode", () => {
  let fx: DoorFixture;
  let door: ChildProcess;
  let url = "";
  let grant = "";
  // The door runs as its own process: the examples run synchronously and would block a door hosted in this process.
  beforeAll(async () => {
    fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "door-languages-")), "http://unused.invalid", { authz: true, trustProxy: true });
    const config = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
    delete config.origin;
    writeFileSync(fx.configFile, JSON.stringify(config, null, 2));
    // an authz door never sees a body, so the refund rule reads who arrived, not the amount
    writeFileSync(join(fx.dir, "policy.cedar"), `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"refund", resource) when { context.facts.arrival.class == "verified" };
`);
    const envelope = createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    grant = grantHeader(envelope);
    door = spawn(process.execPath, [resolve(import.meta.dirname, "..", "src", "cli.ts"), "door", "--config", fx.configFile, "--port", "0"]);
    url = await new Promise<string>((res, rej) => {
      door.stderr!.on("data", (d) => {
        const m = /agent-custody door: (http:\/\/[^ ]+)/.exec(String(d));
        if (m) res(m[1]!);
      });
      door.on("exit", (code) => rej(new Error(`door exited with ${code}`)));
    });
  });
  afterAll(() => {
    door.kill();
  });

  for (const l of languages) {
    const missing = l.probes.find((p) => !has(p));
    const run = missing ? it.skip : it;
    run(`${l.name}${missing ? ` (skipped: ${missing[0]} not runnable)` : ""}`, () => {
      const before = receiptCount(fx.receiptsDir);
      const r = spawnSync(l.cmd[0]!, l.cmd.slice(1), { cwd: l.cwd, encoding: "utf8", timeout: 240_000, env: { ...process.env, DOOR_URL: url, CUSTODY_GRANT: grant } });
      expect(r.status, `${l.name}\n${r.stdout}\n${r.stderr}`).toBe(0);
      expect(r.stdout.trim().endsWith("OK"), `${l.name} did not end with OK:\n${r.stdout.slice(-400)}`).toBe(true);

      // Fail closed: a door that is down or silent must stop the request, or the app runs ungated whenever the door does not answer.
      expect(r.stdout).toMatch(/^fail-closed unreachable 503$/m);
      expect(r.stdout).toMatch(/^fail-closed timeout 503$/m);

      // The receipt ids are the ones the app received (allowed) or the client got back (denied). Each must be the door's
      // own receipt of this request, so the id an app logs or shows leads to evidence of the decision that let it run.
      // Python names one set for its WSGI middleware and one for its Django middleware.
      const named = [...r.stdout.matchAll(/^receipt (allowed|denied|verified) ([0-9a-f-]{36})$/gm)].map((m) => ({ kind: m[1]!, id: m[2]! }));
      expect([...new Set(named.map((n) => n.kind))].sort()).toEqual(["allowed", "denied", "verified"]);
      const keys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
      const load = (id: string) => JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
      for (const { kind, id } of named) {
        expect(verifyBundle(load(id), keys).ok, id).toBe(true);
        const p = decode(load(id)).predicate;
        if (kind === "allowed") {
          const args = p.request.args as { method: string; path: string; query: Record<string, string>; headers: Record<string, string> };
          const arrival = (p.facts as Record<string, { value: { class: string; remote: string } }>).arrival!.value;
          expect([p.execution.status, p.policy?.decision, args.method, args.path]).toEqual(["withheld", "allow", "GET", "/catalogue/shoes"]);
          // the query and the client's Host reach the door: a route or a Web Bot Auth signature (@authority) is checked on them
          expect(args.query).toEqual({ colour: "red" });
          expect(args.headers.host).toBe("shop.example");
          // and the client's User-Agent, not the HTTP library's: the receipt records what the arrival sent
          expect(args.headers["user-agent"]).toBe("example-browser");
          // the client wrote an X-Forwarded-For; the middleware sets its own, so the arrival's address is not the client's choice
          expect(arrival.remote).not.toBe("198.51.100.66");
        } else if (kind === "denied") {
          // the client's own X-Original-* headers named a public read; the door decided on the real request
          expect([p.execution.status, p.tool.name, (p.request.args as { method: string }).method]).toEqual(["denied", "refund", "POST"]);
        } else {
          expect([p.execution.status, p.tool.name, p.agent.id, p.agent.provenance]).toEqual(["withheld", "refund", "shopping-agent", "attested"]);
          // a POST is in the log before the door's 200, so before the app ran
          expect(existsSync(join(fx.receiptsDir, `${id}.authorization.json`))).toBe(true);
        }
      }

      // no receipt for the down or silent door: nothing was decided
      expect(receiptCount(fx.receiptsDir)).toBe(before + named.length);
    }, 250_000);
  }
});

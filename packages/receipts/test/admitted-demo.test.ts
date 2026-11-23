// Demo 3 is shown to agent-commerce companies and marketplaces, and run by the Friday gate, which stops new work when a
// demo does not run cold. Done means it runs from nothing twice in a row with no hand edits: a second run that depends
// on what the first left behind, or on anything outside the repository, fails here.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const demo = join(import.meta.dirname, "../examples/65-agent-admitted-demo.ts");

describe("Demo 3, agent admitted", () => {
  it("runs cold twice in a row: blocked unidentified, blocked as a known agent not yet listed, then admitted once listed", () => {
    for (const run of [1, 2]) {
      const r = spawnSync(process.execPath, ["--import", "tsx", demo], { encoding: "utf8", timeout: 90_000 });
      expect(r.status, `run ${run}\n${r.stderr}`).toBe(0);
      expect(r.stdout.trim().endsWith("OK"), `run ${run}`).toBe(true);
      expect(r.stdout).toContain("order: 403, claimed, no passport, lists [], deny");
      expect(r.stdout).toContain("order: 403, verified, passport verified, lists [], deny");
      expect(r.stdout).toContain("order: 201, verified, passport verified, lists [partners], allow");
      expect(r.stdout).toContain("orders that reached the API: 1,");
    }
  }, 200_000);
});

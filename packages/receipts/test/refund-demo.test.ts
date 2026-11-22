// Demo 1 is shown to buyers and run by the Friday gate, which stops new work when a demo does not run cold. Done means
// it runs from nothing twice in a row with no hand edits: a second run that depends on what the first left behind, or
// on anything outside the repository, fails here.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const demo = join(import.meta.dirname, "../examples/59-refund-demo.ts");

describe("Demo 1, the refund (API leg)", () => {
  it("runs cold twice in a row, each run paying the passport holder once, sending the unknown agent to a person, and finding the stray refund", () => {
    for (const run of [1, 2]) {
      const r = spawnSync(process.execPath, ["--import", "tsx", demo], { encoding: "utf8", timeout: 90_000 });
      expect(r.status, `run ${run}\n${r.stderr}`).toBe(0);
      expect(r.stdout.trim().endsWith("OK"), `run ${run}`).toBe(true);
      expect(r.stdout).toContain("refund £25: 200, class verified");
      expect(r.stdout).toContain("refund £20: 202, class unknown");
      expect(r.stdout).toContain("in Stripe with no receipt: re_3 (£10)");
    }
  }, 200_000);
});

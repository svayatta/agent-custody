// Each published page has one purpose. A copy of a repository file (the root README with its CI badges and plan, a
// package README with its layout block and a list of sixty finished items) is not a page a visitor should land on, and
// a second landing page in the docs layout splits the product story in two.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const read = (p: string) => readFileSync(resolve(root, p), "utf8");
const config = read("site/.vitepress/config.ts");

describe("pages with one purpose", () => {
  it("the repository's README files are not built as pages; the site has short overview pages at the same paths", () => {
    for (const f of ["README.md", "packages/receipts/README.md", "packages/state/README.md", "packages/python/README.md"]) {
      expect(config).toContain(`"${f}",`); // in srcExclude
      expect(config).not.toContain(`"${f}": "`); // and in no rewrite
    }
    for (const [file, title] of [["site/receipts/index.md", "Receipts"], ["site/state/index.md", "Fact ledger"], ["site/python/index.md", "Python SDK"]] as const) {
      expect(read(file)).toMatch(new RegExp(`^# ${title}\\n`));
      expect(read(file).split("\n").length).toBeLessThan(40);
    }
  });

  it("/advanced is gone: its content is on How it works, and the old address redirects there", () => {
    const stub = read("site/advanced.md");
    expect(stub).toContain('content: "0; url=/how-it-works"');
    expect(stub.split("\n").length).toBeLessThan(25); // a stub: the redirect, its head tags, and one line
    const how = read("site/how-it-works.md");
    for (const section of ["## Product overview film", "## The problem", "## The refund demo", "## How it works", "## Policies"]) expect(how).toContain(section);
    expect(how).not.toContain("## Parts, one by one"); // the components table lives on /guide/pieces only
    expect(read("site/.vitepress/theme/Landing.vue")).not.toContain('href="/advanced"');
  });

  it("the roadmap shows each package's Next list from its README, and the planned designs", () => {
    const roadmap = read("site/roadmap.md");
    for (const [readme, region] of [["packages/receipts/README.md", "receipts-next"], ["packages/state/README.md", "state-next"]] as const) {
      expect(roadmap).toContain(`${readme.replace(/^/, "../")}#${region}`);
      expect(read(readme)).toContain(`<!-- #region ${region} -->`);
      expect(read(readme)).toContain(`<!-- #endregion ${region} -->`);
    }
    expect(roadmap).toContain("/receipts/mandates");
    expect(read("packages/receipts/docs/mandates.md")).toMatch(/^# .*\(planned\)\n/);
  });

  it("no link, relative or absolute, points at an anchor on a package's overview page, which has none", () => {
    // the overview pages replaced the READMEs; a README section is linked on GitHub, where its anchor exists
    const files = ["packages/receipts/src/portal.ts", "packages/receipts/src/log-admin.ts", "site/reference/index.md", "site/guide/pieces.md", "site/use-cases.md", "site/hosted-log.md"];
    for (const f of files) expect(read(f), f).not.toMatch(/(https:\/\/agent-custody\.dev)?\/(receipts|state|python)\/#/);
  });

  it("the redirect stubs are not indexed, and name the page they moved to as canonical", () => {
    for (const [stub, target] of [["site/advanced.md", "/how-it-works"], ["site/early-access.md", "/hosted-log"]] as const) {
      const s = read(stub);
      expect(s).toMatch(/name: robots\n\s+content: noindex/);
      expect(s).toContain(`href: https://agent-custody.dev${target}`);
    }
  });

  it("every page the sidebar or footer names exists as a source file", () => {
    for (const f of ["site/how-it-works.md", "site/roadmap.md", "site/receipts/index.md", "site/state/index.md", "site/python/index.md"]) expect(existsSync(resolve(root, f))).toBe(true);
  });
});

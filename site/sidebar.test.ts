// One docs sidebar, a learning path from first run to reference. A page listed twice, or in no sidebar at all, is a
// page a reader either meets in two places or never finds. A label that is not the page's H1 makes the reader wonder
// whether the link went where it said.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const config = readFileSync(resolve(import.meta.dirname, ".vitepress/config.ts"), "utf8");
const docs = config.slice(config.indexOf('"/": ['), config.indexOf("socialLinks:"));
const groups = [...docs.matchAll(/\{ text: "([^"]+)", items: \[([\s\S]*?)\] \}/g)].map((g) => ({ group: g[1]!, items: [...g[2]!.matchAll(/\{ text: "([^"]+)", link: "([^"]+)" \}/g)].map((m) => ({ text: m[1]!, link: m[2]! })) }));
const entries = groups.flatMap((g) => g.items);

/** The markdown file a site path is built from, the inverse of sitePath() in config.ts. */
function source(link: string): string {
  if (link.startsWith("/receipts/")) return `packages/receipts/docs/${link.slice("/receipts/".length)}.md`;
  if (link === "/state/") return "packages/state/README.md";
  if (link === "/python/") return "packages/python/README.md";
  return `site${link.endsWith("/") ? `${link}index` : link}.md`;
}
const h1 = (file: string) => /^# (.+)$/m.exec(readFileSync(resolve(root, file), "utf8").replace(/^---\n[\s\S]*?\n---\n/, ""))?.[1];

describe("the docs sidebar", () => {
  it("runs from first run to reference, in order", () => {
    expect(groups.map((g) => g.group)).toEqual(["Start", "Concepts", "Set up", "Advanced", "Tutorials", "Reference"]);
    expect(groups[0]!.items[0]).toEqual({ text: "Getting started", link: "/guide/getting-started" });
  });

  it("lists each page once, the reference pages and the six pages that were in no sidebar included", () => {
    const links = entries.map((e) => e.link);
    expect(links.length).toBe(new Set(links).size);
    for (const page of ["/receipts/anchoring", "/receipts/completeness", "/receipts/financial-operations", "/receipts/mandates", "/receipts/performance", "/receipts/scitt", "/reference/", "/reference/cli", "/guide/glossary"]) expect(links).toContain(page);
    // pages the top nav or the footer link, and pages being removed, stay out of it
    for (const page of ["/advanced", "/changelog", "/custody", "/faq", "/pricing", "/verify", "/receipts/"]) expect(links).not.toContain(page);
  });

  it("labels every entry with its page's H1, which is also the page's title", () => {
    for (const e of entries) {
      const file = source(e.link);
      expect(existsSync(resolve(root, file)), `${e.link} -> ${file}`).toBe(true);
      expect(h1(file), e.link).toBe(e.text);
    }
  });
});

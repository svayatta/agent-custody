// The UI/UX audit's page findings (#331 to #337). Each check names the finding it keeps fixed: a page that lost its
// layout, a price stated twice, a verifier that shows a stale verdict, or a shared link with no image.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { SITE_FOOTER } from "../packages/receipts/src/site-links.ts";

const root = resolve(import.meta.dirname, "..");
const read = (p: string) => readFileSync(resolve(root, p), "utf8");
const frontmatter = (p: string) => /^---\n([\s\S]*?)\n---\n/.exec(read(p))?.[1] ?? "";

describe("page layouts (#334)", () => {
  it("legal pages, the verifier, and pricing have no docs sidebar", () => {
    for (const p of ["site/privacy.md", "site/terms.md", "site/contact.md", "site/verify.md", "site/pricing.md"]) expect(frontmatter(p), p).toMatch(/sidebar: false/);
  });
  it("the hosted log is a page of its own with one sign-up button, /early-access redirects to it, and the terms are terms of service", () => {
    const hosted = read("site/hosted-log.md");
    expect(hosted).toMatch(/^---[\s\S]*?\n# Hosted log\n/);
    expect(hosted.match(/class="btn"/g)).toHaveLength(1);
    expect(hosted).not.toContain("<EarlyAccess");
    expect(existsSync(resolve(root, "site/.vitepress/theme/EarlyAccess.vue"))).toBe(false);
    expect(read("site/early-access.md")).toContain('content: "0; url=/hosted-log"');
    expect(read("site/terms.md")).toContain("\n# Terms of service\n");
  });
});

describe("pricing (#332) and one home for each fact (#331)", () => {
  it("pricing leads with three plans, one action each, then a table of the rows that differ", () => {
    const plans = read("site/.vitepress/theme/PricingPlans.vue");
    expect([...plans.matchAll(/action: \{ text: "/g)]).toHaveLength(3);
    const pricing = read("site/pricing.md");
    expect(pricing.indexOf("<PricingPlans />")).toBeLessThan(pricing.indexOf("## Compare the plans"));
    expect(pricing).not.toContain("the same");
    expect(pricing).not.toContain("Why this price");
  });
  it("prices are stated on the pricing page only (the terms, a contract, excepted)", () => {
    for (const p of ["site/hosted-log.md", "site/reference/hosted.md", "README.md", "site/contact.md"]) expect(read(p), p).not.toMatch(/\$50/);
  });
  it("concept and reference pages link to each other, and field tables live in the reference", () => {
    for (const p of ["packages/receipts/docs/door.md", "packages/receipts/docs/egress.md", "packages/receipts/docs/acs.md", "packages/receipts/docs/usage.md"]) expect(read(p), p).toMatch(/^# .+\n\n> How it works and when to use it\. Every field, route, and flag is in \[the reference\]/);
    for (const p of ["site/reference/door.md", "site/reference/egress.md", "site/reference/acs.md", "site/reference/gateway.md"]) expect(read(p), p).toMatch(/^# .+\n\n> Every field, route, and flag\. How it works and when to use it is in \[the guide\]/);
    expect(read("packages/receipts/docs/door.md")).not.toContain("| field | meaning |");
    expect(read("site/reference/index.md")).toContain("| component | package | reference |");
  });
});

describe("tables on phones (#333)", () => {
  it("a docs table only spans the column from tablet width up, so on a phone it scrolls inside itself", () => {
    const css = read("site/.vitepress/theme/custom.css");
    expect(css).toMatch(/@media \(min-width: 768px\) \{ \.vp-doc table \{ display: table; width: 100%; \} \}/);
    expect(css).not.toMatch(/^\.vp-doc table \{ display: table/m);
  });
});

describe("the landing page (#335)", () => {
  it("has a two-sentence lede, the setup as the hero's main action, the flow diagram under the hero, and a social image", () => {
    const landing = read("site/.vitepress/theme/Landing.vue");
    const lede = /<p class="lede">([^<]+)<\/p>/.exec(landing)![1]!;
    expect(lede.split(/(?<=\.)\s/)).toHaveLength(2);
    expect(lede.startsWith("Give your agents real power, without losing control of them.")).toBe(true);
    expect(landing).toMatch(/<div class="ctas">\s*<a class="btn" :href="setupHref">Set up Claude Code<\/a>/);
    expect(landing.indexOf("<Flow />")).toBeGreaterThan(landing.indexOf('<section class="hero">'));
    const config = read("site/.vitepress/config.ts");
    for (const tag of ['property: "og:image"', 'name: "twitter:card", content: "summary_large_image"', 'name: "twitter:image"']) expect(config).toContain(tag);
    const png = readFileSync(resolve(root, "site/public/og.png"));
    expect([png.readUInt32BE(16), png.readUInt32BE(20)]).toEqual([1200, 630]);
  });
});

describe("the verifier (#337)", () => {
  const v = read("site/.vitepress/theme/Verifier.vue");
  it("starts with a file and the issuer key, and puts the rest under Optional inputs", () => {
    expect(v).toContain('type="file"');
    expect(v.indexOf('id="vf-issuer"')).toBeLessThan(v.indexOf("<summary>Optional inputs</summary>"));
    expect(v.indexOf("<summary>Optional inputs</summary>")).toBeLessThan(v.indexOf('id="vf-principal"'));
  });
  it("announces its result, clears it on any edit, and names its samples in plain words", () => {
    expect(v).toContain('role="status" aria-live="polite"');
    expect(v).toMatch(/watch\(\[bundleText, issuerPem[^\]]*\], \(\) => \{\s*if \(busy\.value\) return;\s*result\.value = null;/);
    const names = /filter\(\(c\) => (\[[^\]]+\])/.exec(v)![1]!;
    for (const n of JSON.parse(names) as string[]) expect(v).toContain(`"${n}": "`);
  });
  it("hides the provider secrets and ties every label to its field", () => {
    for (const id of ["vf-stripe", "vf-github"]) expect(v).toMatch(new RegExp(`id="${id}"[^>]*type="password"`));
    for (const id of [...v.matchAll(/<label for="([^"]+)"/g)].map((m) => m[1]!)) expect(v).toContain(`id="${id}"`);
  });
});

describe("trust content (#336)", () => {
  it("one address for everything, and one page for what is not in place yet, linked from the footer", () => {
    const contact = read("site/contact.md");
    expect(new Set(contact.match(/[\w.+-]+@[\w.-]+\.\w+/g))).toEqual(new Set(["partha@charioteerconsulting.com"]));
    expect(read("site/status.md")).toMatch(/\n# Status and limits\n/);
    expect(SITE_FOOTER.find((c) => c.title === "Trust")!.links[0]).toEqual({ text: "Status and limits", link: "/status" });
  });
});

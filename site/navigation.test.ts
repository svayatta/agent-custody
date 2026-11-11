// One top nav and one footer on every page. A visitor who clicks from the landing page into the docs, or from the
// dashboard back to the site, must find the same menu and the same footer, or the site reads as three products.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { SITE_FOOTER, SITE_NAV } from "../packages/receipts/src/site-links.ts";

const read = (p: string) => readFileSync(resolve(import.meta.dirname, p), "utf8");

describe("one nav and one footer", () => {
  it("the nav is the target list from the audit, in order, with Docs highlighted on every docs path", () => {
    expect(SITE_NAV.map((l) => l.text)).toEqual(["Product", "Docs", "Pricing", "Blog", "Verify a receipt"]);
    const docs = new RegExp(SITE_NAV.find((l) => l.text === "Docs")!.activeMatch!);
    for (const path of ["/guide/getting-started", "/receipts/door", "/state/", "/python/", "/reference/gateway", "/receipt/v0.2"]) expect(docs.test(path)).toBe(true);
    expect(docs.test("/pricing")).toBe(false);
  });

  it("the docs pages, the landing page, and the dashboard all read that one list", () => {
    expect(read(".vitepress/config.ts")).toContain("nav: SITE_NAV.map(");
    const landing = read(".vitepress/theme/Landing.vue");
    expect(landing).toContain('v-for="l in SITE_NAV"');
    // the in-page anchors and the second product page are out of the top bar
    expect(landing).not.toMatch(/<nav class="navlinks"[\s\S]*?href="#report"[\s\S]*?<\/nav>/);
    expect(landing).not.toContain('href="/advanced">Advanced</a>');
    expect(read("../packages/receipts/src/portal.ts")).toContain('<span class="links">${DASHBOARD_NAV}</span>');
  });

  it("the footer is one component, mounted on the landing page and under every other page, with four columns", () => {
    expect(SITE_FOOTER.map((c) => c.title)).toEqual(["Product", "Docs", "Trust", "Company"]);
    expect(read(".vitepress/theme/Landing.vue")).toContain("<SiteFooter />");
    const layout = read(".vitepress/theme/Layout.vue");
    expect(layout).toContain("<template #layout-bottom><SiteFooter /></template>");
    expect(layout).toContain("<template #not-found><NotFound /></template>");
    expect(read(".vitepress/config.ts")).not.toMatch(/footer: \{ message:/);
  });

  it("every footer link is a page of the site or an outside URL", () => {
    for (const l of SITE_FOOTER.flatMap((c) => c.links)) expect(l.link).toMatch(/^(\/|https:\/\/)/);
  });
});

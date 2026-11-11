// One name for each thing (site/README.md, guide/glossary.md). A reader who meets "Register" in the nav, "Create an
// account" in the dashboard, and "Sign up" in the docs cannot tell they are the same step. These checks fail when an
// old label comes back into the places a visitor reads first: the nav and sidebar, the landing page, and the dashboard.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { SITE_FOOTER, SITE_NAV } from "../packages/receipts/src/site-links.ts";

const read = (p: string) => readFileSync(resolve(import.meta.dirname, p), "utf8");
const config = read(".vitepress/config.ts");
const landing = read(".vitepress/theme/Landing.vue");
const dashboard = read("../packages/receipts/src/portal.ts");
const glossary = read("guide/glossary.md");

describe("one name for each thing", () => {
  it("the nav, the sidebar, and the landing page use the glossary's labels", () => {
    // the nav and footer labels live in the shared list, the sidebar labels in config.ts
    const labels = [...config.matchAll(/text: "([^"]+)"/g)].map((m) => m[1]!).concat(SITE_NAV.map((l) => l.text), SITE_FOOTER.flatMap((c) => c.links.map((l) => l.text)));
    for (const old of ["Verify", "Verify a receipt in the browser", "Register", "Writing", "All pieces", "What each piece is for", "The gateway console"]) expect(labels).not.toContain(old);
    for (const term of ["Verify a receipt", "Blog", "Components", "Glossary", "Gateway console"]) expect(labels).toContain(term);
    expect(landing).not.toMatch(/>Writing</);
    expect(landing).not.toContain("Verify a receipt in your browser");
  });

  it("the dashboard says Sign up, Sign in, and API key", () => {
    for (const old of ["Create an account", "Create account", "a bearer token your gateway presents", ">Mint key<", ">Copy key<"]) expect(dashboard).not.toContain(old);
    for (const term of ["Sign up instead", ">Create API key<", ">Copy API key<"]) expect(dashboard).toContain(term);
  });

  it("the glossary defines every product name and the terms the docs used before defining them", () => {
    for (const term of ["Components", "Dashboard", "Gateway console", "Hosted log", "Verify a receipt", "API key", "Cedar", "DSSE", "Principal", "Tree head", "Append", "Leaf"]) expect(glossary).toContain(`**${term}**`);
  });
});

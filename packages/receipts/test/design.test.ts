import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CONSOLE_HTML } from "../src/console-page.ts";
import { DESIGN_CSS, SITE_CSS } from "../src/design.ts";

const root = new URL("../../../", import.meta.url);
const read = (path: string) => readFileSync(new URL(path, root), "utf8");

// WCAG 2 relative luminance and contrast ratio of two #rrggbb colours.
const luminance = (hex: string) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
};
const contrast = (a: string, b: string) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
};
const token = (block: string, name: string) => block.match(new RegExp(`--${name}: (#[0-9a-f]{6})`))![1]!;

describe("design tokens", () => {
  it("the site's tokens.css is the generated SITE_CSS", () => {
    // Regenerate with: bun -e 'import { SITE_CSS } from "./packages/receipts/src/design.ts"; await Bun.write("site/.vitepress/theme/tokens.css", SITE_CSS)'
    expect(read("site/.vitepress/theme/tokens.css")).toBe(SITE_CSS);
  });

  it("button text on the accent passes WCAG AA in light and dark, at rest, on hover, and when pressed", () => {
    const light = SITE_CSS.slice(0, SITE_CSS.indexOf(".dark"));
    const dark = SITE_CSS.slice(SITE_CSS.indexOf(".dark"));
    for (const mode of [light, dark]) {
      for (const fill of ["accent", "accent-hover", "accent-active"]) expect(contrast(token(mode, "accent-ink"), token(mode, fill))).toBeGreaterThanOrEqual(4.5);
      for (const text of ["ink", "ink2", "ink3", "accent"]) expect(contrast(token(mode, text), token(mode, "panel"))).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("the host pages in deploy/Caddyfile use the token values and no other colour", () => {
    const caddyfile = read("deploy/Caddyfile");
    const used = [...caddyfile.matchAll(/--([a-z0-9-]+):(#[0-9a-f]{6})/g)];
    expect(used.length).toBeGreaterThan(0);
    for (const [, name, value] of used) expect(DESIGN_CSS, `--${name}`).toContain(`--${name}: ${value}`);
    expect(caddyfile).not.toMatch(/#(?:0f6e63|4fc3b0|1b2430|fafbfc|0e1418|e6ecf0)/);
  });

  it("every app page inlines the shared CSS and keeps no palette or font of its own", () => {
    expect(CONSOLE_HTML).toContain(DESIGN_CSS);
    expect(DESIGN_CSS).not.toMatch(/url\(|@import|@font-face/);
    for (const file of ["packages/receipts/src/portal.ts", "packages/receipts/src/log-admin.ts", "packages/receipts/src/console-page.ts", "packages/state/src/review.ts", "packages/state/src/case-file.ts"]) {
      const source = read(file);
      expect(source, file).toContain("DESIGN_CSS");
      expect(source, file).not.toMatch(/#0f6e63|#4fc3b0|#1b2430|#0e1418|font: [^;]*system-ui/);
    }
  });
});

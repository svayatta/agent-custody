// The design tokens and the shared components of every surface: the site, the portal, the log admin, the gateway
// console, the review page, and the offline case file. The app pages inline DESIGN_CSS, so they make no outside request.
// The site imports site/.vitepress/theme/tokens.css, which a test keeps identical to SITE_CSS.
// "Inter" comes from VitePress on the site; the app pages use it only when the machine has it installed.

const LIGHT = `--bg: #fafaf9; --panel: #ffffff; --soft: #f5f5f4; --line: #e7e5e4; --line-strong: #d6d3d1;
  --ink: #1c1917; --ink2: #57534e; --ink3: #78716c;
  --accent: #b45309; --accent-hover: #92400e; --accent-active: #78350f; --accent-ink: #ffffff; --accent-bg: #fef3c7;
  --ok: #15803d; --ok-bg: #dcfce7; --warn: #a16207; --warn-bg: #fef9c3; --bad: #b91c1c; --bad-bg: #fee2e2;
  --shadow: 0 1px 2px rgb(28 25 23 / .05), 0 18px 40px -18px rgb(28 25 23 / .25);`;
const DARK = `--bg: #0c0a09; --panel: #1c1917; --soft: #292524; --line: #292524; --line-strong: #44403c;
  --ink: #fafaf9; --ink2: #a8a29e; --ink3: #8a847f;
  --accent: #f59e0b; --accent-hover: #fbbf24; --accent-active: #d97706; --accent-ink: #1c1917; --accent-bg: #451a03;
  --ok: #4ade80; --ok-bg: #052e16; --warn: #facc15; --warn-bg: #422006; --bad: #f87171; --bad-bg: #450a0a;
  --shadow: none;`;
const SCALE = `--font: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --text-xs: .75rem; --text-sm: .875rem; --text-md: 1rem; --text-lg: 1.125rem; --text-xl: 1.5rem; --text-2xl: 2rem; --text-3xl: 2.75rem;
  --space-1: .25rem; --space-2: .5rem; --space-3: .75rem; --space-4: 1rem; --space-5: 1.5rem; --space-6: 2rem; --space-7: 3rem; --space-8: 4rem;
  --radius-sm: 8px; --radius-md: 12px; --radius-full: 999px;`;

// The select arrow is two gradients, because the case file allows no image, not even a data URL.
const components = (button: string) => `
:where(h1, h2, h3) { font-family: var(--font); color: var(--ink); letter-spacing: -.015em; line-height: 1.25; }
:where(h1) { font-size: var(--text-xl); font-weight: 700; }
:where(h2) { font-size: var(--text-lg); font-weight: 600; }
:where(h3) { font-size: var(--text-md); font-weight: 600; }
${button} { display: inline-flex; align-items: center; justify-content: center; gap: var(--space-2); min-height: 2.5rem; padding: 0 var(--space-4); border: 1px solid var(--accent); border-radius: var(--radius-sm); background: var(--accent); color: var(--accent-ink); font: 600 var(--text-sm)/1.2 var(--font); text-decoration: none; white-space: nowrap; cursor: pointer; transition: background-color .15s, border-color .15s, color .15s; }
${button}:not(:disabled):hover { background: var(--accent-hover); border-color: var(--accent-hover); color: var(--accent-ink); }
${button}:not(:disabled):active { background: var(--accent-active); border-color: var(--accent-active); }
${button}:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
${button}:disabled { opacity: .5; cursor: not-allowed; }
${button}:is(.quiet, .secondary) { background: transparent; border-color: var(--line-strong); color: var(--ink); }
${button}:is(.quiet, .secondary):not(:disabled):hover { background: var(--soft); border-color: var(--ink3); color: var(--ink); }
${button}:is(.quiet, .secondary):not(:disabled):active { background: var(--line); }
${button}.danger { background: var(--bad); border-color: var(--bad); color: var(--panel); }
${button}.danger:not(:disabled):hover { background: var(--bad); border-color: var(--bad); color: var(--panel); filter: brightness(1.1); }
${button}.icon { width: 2.25rem; min-height: 2.25rem; padding: 0; background: transparent; border-color: var(--line); color: var(--ink2); }
${button}.icon:not(:disabled):hover { background: var(--soft); border-color: var(--line-strong); color: var(--ink); }
${button}.icon svg { width: 18px; height: 18px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
select { appearance: none; min-height: 2.5rem; padding: 0 2.25rem 0 var(--space-3); border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background-color: var(--panel); color: var(--ink); font: var(--text-sm) var(--font); cursor: pointer;
  background-image: linear-gradient(45deg, transparent 50%, var(--ink2) 50%), linear-gradient(135deg, var(--ink2) 50%, transparent 50%);
  background-position: calc(100% - 17px) 50%, calc(100% - 12px) 50%; background-size: 5px 5px; background-repeat: no-repeat; }
select:hover { border-color: var(--ink3); }
select:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
select:disabled { opacity: .5; cursor: not-allowed; }
:where(.card, .panel, dialog) { background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: var(--radius-md); }
:where(dialog) { padding: var(--space-5); box-shadow: var(--shadow); max-width: min(32rem, calc(100vw - 2rem)); }
:where(dialog)::backdrop { background: rgb(12 10 9 / .5); }
`;

const DARK_ON_SYSTEM = `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { ${DARK} } }
:root[data-theme="dark"] { ${DARK} }`;

/** The app pages: the tokens, light and dark (system or data-theme), the base, and the shared components. */
export const DESIGN_CSS = `
:root { color-scheme: light dark; ${SCALE} ${LIGHT} }
${DARK_ON_SYSTEM}
:root[data-theme="light"] { color-scheme: light; } :root[data-theme="dark"] { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: var(--text-sm)/1.5 var(--font); -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-underline-offset: 3px; }
:where(a, button, input, textarea):focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
:where(code, pre, kbd, .mono) { font-family: var(--mono); }
:where(input:not([type="checkbox"], [type="radio"]), textarea) { min-height: 2.5rem; padding: var(--space-2) var(--space-3); border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--panel); color: var(--ink); font: var(--text-sm) var(--font); }
:where(textarea) { font-family: var(--mono); }
${components(":where(.btn, button:not(.link, nav button))")}`;

/** The site: the same tokens and components; VitePress sets the dark class itself. */
export const SITE_CSS = `/* Generated from packages/receipts/src/design.ts. Do not edit; a test compares the two. */
:root { ${SCALE} ${LIGHT} }
.dark { ${DARK} }
${components(".btn")}`;

/** The logo: a receipt with a check mark. The tile takes the accent colour, so the mark follows the theme. */
export const LOGO_MARK = '<svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><rect class="tile" width="64" height="64" rx="14"/><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff"/><path class="ink" d="M25 20h14M25 27h14" stroke-width="2.6" stroke-linecap="round"/><path class="ink" d="M25 37.5l5 4.5 9.5-10" fill="none" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';

const THEME_BUTTON = '<button class="icon" id="themeToggle" type="button" aria-label="Dark mode" aria-pressed="false" title="Dark mode"><svg class="moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg><svg class="sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button>';

/** The header of the review page and the case file: the logo, the name of the page, and the theme toggle. */
export const appHeader = (name: string) => `<header class="apphead"><a class="brand" href="https://agent-custody.dev/">${LOGO_MARK}agent-custody</a><span class="pill">${name}</span>${THEME_BUTTON}</header>`;

export const APP_HEADER_CSS = `
.apphead { display: flex; align-items: center; gap: var(--space-3); padding: var(--space-3) var(--space-4); border-bottom: 1px solid var(--line); background: var(--panel); }
.apphead .brand { display: inline-flex; align-items: center; gap: var(--space-2); color: var(--ink); font-weight: 700; text-decoration: none; }
.apphead .pill { padding: 0 var(--space-2); border-radius: var(--radius-full); background: var(--accent-bg); color: var(--accent); font: 600 var(--text-xs)/1.6 var(--font); }
.apphead #themeToggle { margin-left: auto; }
.mark { width: 28px; height: 28px; display: block; } .mark .tile { fill: var(--accent); } .mark .ink { stroke: var(--accent); }
#themeToggle[aria-pressed="true"] .moon, #themeToggle[aria-pressed="false"] .sun { display: none; }
`;

/** Applies the saved theme and wires the toggle. It uses the storage key of the portal. Put it after the button. */
export const THEME_SCRIPT = `(() => {
  const root = document.documentElement, button = document.getElementById("themeToggle");
  try { const saved = localStorage.getItem("agent-custody-theme"); if (saved === "dark" || saved === "light") root.dataset.theme = saved; } catch {}
  const now = () => root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const label = () => button.setAttribute("aria-pressed", String(now() === "dark"));
  button.onclick = () => { const next = now() === "dark" ? "light" : "dark"; root.dataset.theme = next; try { localStorage.setItem("agent-custody-theme", next); } catch {} label(); };
  label();
})();
`;

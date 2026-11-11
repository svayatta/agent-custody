<script setup lang="ts">
// One footer on every page: the landing page mounts it, and Layout.vue puts it under every docs page. The columns
// come from the shared list in packages/receipts/src/site-links.ts. It is styled with the VitePress variables, which
// Landing.vue also defines, so it looks the same in both places.
import { SITE_FOOTER, SITE_LEGAL_LINKS } from "../../../packages/receipts/src/site-links.ts";
const year = new Date().getUTCFullYear();
</script>

<template>
  <footer class="site-footer">
    <div class="sf-wrap">
      <div class="sf-cols">
        <div class="sf-about">
          <a class="sf-brand" href="/" aria-label="agent-custody home">
            <svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" class="sf-tile" /><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff" /><path d="M25 20h14M25 27h14" class="sf-ink" stroke-width="2.6" stroke-linecap="round" /><path d="M25 37.5l5 4.5 9.5-10" fill="none" class="sf-ink" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" /></svg>
            <span>agent-custody</span>
          </a>
          <p>Proof of what your AI agents did.</p>
        </div>
        <nav v-for="col in SITE_FOOTER" :key="col.title" :aria-label="col.title">
          <h2>{{ col.title }}</h2>
          <ul><li v-for="l in col.links" :key="l.link"><a :href="l.link">{{ l.text }}</a></li></ul>
        </nav>
      </div>
      <div class="sf-legal">
        <span>Apache-2.0 · Charioteer Consulting Ltd, {{ year }}</span>
        <span><template v-for="(l, i) in SITE_LEGAL_LINKS" :key="l.link"><template v-if="i"> · </template><a :href="l.link">{{ l.text }}</a></template></span>
      </div>
    </div>
  </footer>
</template>

<style scoped>
.site-footer { border-top: 1px solid var(--vp-c-divider); padding: 56px 0 40px; font-size: 14px; background: var(--vp-c-bg); color: var(--vp-c-text-1); }
.sf-wrap { max-width: 1200px; margin: 0 auto; padding: 0 32px; }
.sf-cols { display: grid; grid-template-columns: 2fr repeat(4, 1fr); gap: 32px; }
.sf-brand { display: flex; align-items: center; gap: 10px; font-weight: 600; text-decoration: none; color: inherit; }
.sf-brand svg { width: 28px; height: 28px; flex: none; }
.sf-tile { fill: var(--vp-c-brand-1); } .sf-ink { stroke: var(--vp-c-brand-1); }
.sf-about p { color: var(--vp-c-text-2); max-width: 28ch; margin: 12px 0 0; }
.sf-cols h2 { margin: 0 0 12px; padding: 0; border: 0; font-size: 13px; line-height: 1.6; letter-spacing: 0; font-weight: 600; }
.sf-cols ul { list-style: none; padding: 0; margin: 0; display: grid; gap: 8px; }
.sf-cols a, .sf-legal a { text-decoration: none; color: var(--vp-c-text-2); }
.sf-cols a:hover, .sf-legal a:hover { color: var(--vp-c-text-1); }
.sf-cols a:focus-visible, .sf-legal a:focus-visible, .sf-brand:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 2px; border-radius: 4px; }
.sf-legal { margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--vp-c-divider); color: var(--vp-c-text-2); font-size: 13px; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px 24px; }
@media (max-width: 64rem) { .sf-cols { grid-template-columns: repeat(2, 1fr); } .sf-about { grid-column: 1 / -1; } }
@media (max-width: 40rem) { .sf-wrap { padding: 0 16px; } .sf-legal { flex-direction: column; } }
</style>

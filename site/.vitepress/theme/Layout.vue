<script setup lang="ts">
// The home page is the product's front door and not a docs page: `layout: landing` renders Landing.vue alone.
// Every other page is the default theme, with the shared footer under it, Sign in and Get started in its nav bar, and
// the site's own 404. The nav links themselves come from packages/receipts/src/site-links.ts through config.ts.
import DefaultTheme from "vitepress/theme";
import { useData } from "vitepress";
import Landing from "./Landing.vue";
import SiteFooter from "./SiteFooter.vue";
import NotFound from "./NotFound.vue";
import { SIGN_IN, GET_STARTED } from "../../../packages/receipts/src/site-links.ts";
const { frontmatter } = useData();
</script>

<template>
  <Landing v-if="frontmatter.layout === 'landing'" />
  <DefaultTheme.Layout v-else>
    <template #nav-bar-content-after>
      <div class="nav-actions">
        <a class="nav-quiet" :href="SIGN_IN.link">{{ SIGN_IN.text }}</a>
        <a class="nav-primary" :href="GET_STARTED.link">{{ GET_STARTED.text }}</a>
      </div>
    </template>
    <template #nav-screen-content-after>
      <div class="screen-actions">
        <a class="nav-primary" :href="GET_STARTED.link">{{ GET_STARTED.text }}</a>
        <a class="nav-quiet" :href="SIGN_IN.link">{{ SIGN_IN.text }}</a>
      </div>
    </template>
    <template #not-found><NotFound /></template>
    <template #layout-bottom><SiteFooter /></template>
  </DefaultTheme.Layout>
</template>

<style scoped>
.nav-actions { display: flex; align-items: center; gap: 8px; margin-left: 12px; }
.nav-quiet, .nav-primary { display: inline-flex; align-items: center; height: 32px; padding: 0 12px; border-radius: 8px; font-size: 14px; font-weight: 500; text-decoration: none; white-space: nowrap; }
.nav-quiet { color: var(--vp-c-text-1); border: 1px solid var(--vp-c-divider); }
.nav-quiet:hover { border-color: var(--vp-c-text-3); }
.nav-primary { background: var(--vp-button-brand-bg); color: var(--vp-button-brand-text); border: 1px solid var(--vp-button-brand-border); }
.nav-primary:hover { background: var(--vp-button-brand-hover-bg); }
.nav-quiet:focus-visible, .nav-primary:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 2px; }
.screen-actions { display: grid; gap: 8px; margin-top: 24px; }
.screen-actions a { justify-content: center; height: 40px; }
/* on a phone the bar has no room: the actions move into the VitePress menu screen above */
@media (max-width: 767px) { .nav-actions { display: none; } }
</style>

<style>
/* Under a page with a sidebar, the footer starts where the content starts, the way VitePress offsets its content,
   so the fixed sidebar does not cover the footer's first column. */
@media (min-width: 960px) {
  .VPContent.has-sidebar ~ .site-footer { padding-left: var(--vp-sidebar-width); }
}
@media (min-width: 1440px) {
  .VPContent.has-sidebar ~ .site-footer { padding-left: calc((100vw - var(--vp-layout-max-width)) / 2 + var(--vp-sidebar-width)); }
}
</style>

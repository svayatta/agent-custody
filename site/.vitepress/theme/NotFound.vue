<script setup lang="ts">
import { SITE_NAV, GET_STARTED } from "../../../packages/receipts/src/site-links.ts";
</script>

<template>
  <main class="nf">
    <p class="nf-code">404</p>
    <h1>This page is not here</h1>
    <p>It may have moved when the docs were reorganised. Search the docs with <kbd>/</kbd>, or start from one of these.</p>
    <ul>
      <li v-for="l in SITE_NAV" :key="l.link"><a :href="l.link">{{ l.text }}</a></li>
    </ul>
    <a class="nf-primary" :href="GET_STARTED.link">{{ GET_STARTED.text }}</a>
  </main>
</template>

<style scoped>
.nf { max-width: 640px; margin: 0 auto; padding: 96px 24px 64px; }
.nf-code { margin: 0; font-size: 14px; font-weight: 600; color: var(--vp-c-brand-1); }
.nf h1 { margin: 8px 0 12px; font-size: 32px; line-height: 1.2; font-weight: 700; }
.nf p { color: var(--vp-c-text-2); line-height: 1.6; }
.nf kbd { font-family: var(--vp-font-family-mono); font-size: 13px; padding: 1px 6px; border: 1px solid var(--vp-c-divider); border-radius: 4px; }
.nf ul { list-style: none; padding: 0; margin: 24px 0; display: flex; flex-wrap: wrap; gap: 8px 20px; }
.nf ul a { color: var(--vp-c-text-1); text-decoration: underline; text-underline-offset: 3px; }
.nf-primary { display: inline-flex; align-items: center; height: 40px; padding: 0 16px; border-radius: 8px; background: var(--vp-button-brand-bg); color: var(--vp-button-brand-text); font-weight: 600; text-decoration: none; }
.nf-primary:hover { background: var(--vp-button-brand-hover-bg); }
.nf a:focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 2px; }
</style>

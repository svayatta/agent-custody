<script setup lang="ts">
// The three plans, side by side, each with one action. The comparison table under it on pricing.md has the rows that
// differ. Prices are stated here and on pricing.md only (site/README.md).
const SIGN_UP = "https://app.agent-custody.dev/#register";
const plans = [
  {
    name: "Free", price: "$0", per: "", allowance: "10,000 appends a month",
    points: ["Your own tenant and log id on the hosted log", "As many API keys as you need", "Export everything, any time", "Community support on GitHub"],
    action: { text: "Sign up free", href: SIGN_UP, quiet: true },
  },
  {
    name: "Team", price: "$50", per: "a month", allowance: "1,000,000 appends a month",
    points: ["Everything in Free", "Email support, answered within two working days", "Billed monthly by card; cancel from the dashboard", "Upgrade from the Billing page after you sign up"],
    action: { text: "Sign up, then upgrade", href: SIGN_UP, quiet: false },
  },
  {
    name: "Enterprise", price: "By conversation", per: "", allowance: "No allowance",
    points: ["A dedicated log instance, your own signing key, your region", "API keys managed by your own operators", "A named contact and a stated response time", "A signed agreement and a data processing agreement"],
    action: { text: "Contact us", href: "/contact", quiet: true },
  },
];
</script>

<template>
  <div class="plans">
    <section v-for="p in plans" :key="p.name" class="plan" :aria-labelledby="`plan-${p.name}`">
      <h2 :id="`plan-${p.name}`">{{ p.name }}</h2>
      <p class="price"><span class="amount" :class="{ words: !p.price.startsWith('$') }">{{ p.price }}</span><span v-if="p.per" class="per"> {{ p.per }}</span></p>
      <p class="allowance">{{ p.allowance }}</p>
      <ul><li v-for="pt in p.points" :key="pt">{{ pt }}</li></ul>
      <a class="btn" :class="{ quiet: p.action.quiet }" :href="p.action.href">{{ p.action.text }}</a>
    </section>
  </div>
</template>

<style scoped>
.plans { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-4); margin: var(--space-6) 0; }
.plan { display: flex; flex-direction: column; gap: var(--space-2); padding: var(--space-5); border: 1px solid var(--line); border-radius: var(--radius-md); background: var(--panel); }
.vp-doc .plan h2 { margin: 0; padding: 0; border: 0; font-size: var(--text-lg); line-height: 1.3; }
.price { margin: 0; }
.amount { font-size: var(--text-2xl); font-weight: 700; line-height: 1.2; color: var(--ink); }
.amount.words { font-size: var(--text-xl); }
.per { color: var(--ink2); font-size: var(--text-sm); }
.allowance { margin: 0; color: var(--ink2); font-size: var(--text-sm); }
.plan ul { margin: var(--space-2) 0 var(--space-4); padding-left: 1.1rem; font-size: var(--text-sm); color: var(--ink); flex: 1; }
.plan li { margin: var(--space-1) 0; }
.plan .btn { align-self: stretch; }
@media (max-width: 52rem) { .plans { grid-template-columns: 1fr; } }
</style>

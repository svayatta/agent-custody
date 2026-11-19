import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import Layout from "./Layout.vue";
import Verifier from "./Verifier.vue";
import Flow from "./Flow.vue";
import PricingPlans from "./PricingPlans.vue";
import "./tokens.css";
import "./custom.css";

export default {
  extends: DefaultTheme,
  Layout,
  enhanceApp({ app }) {
    app.component("Verifier", Verifier);
    app.component("Flow", Flow);
    app.component("PricingPlans", PricingPlans);
  },
} satisfies Theme;

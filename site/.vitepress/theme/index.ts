import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import Layout from "./Layout.vue";
import Verifier from "./Verifier.vue";
import EarlyAccess from "./EarlyAccess.vue";
import Flow from "./Flow.vue";
import "./tokens.css";
import "./custom.css";

export default {
  extends: DefaultTheme,
  Layout,
  enhanceApp({ app }) {
    app.component("Verifier", Verifier);
    app.component("EarlyAccess", EarlyAccess);
    app.component("Flow", Flow);
  },
} satisfies Theme;

import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";
import { cpSync, existsSync } from "node:fs";
import { dirname, posix, relative, resolve } from "node:path";
import { SITE_NAV } from "../../packages/receipts/src/site-links.ts";

// The site is generated from the repository's own markdown. Nothing here is a second copy of the docs.
const REPO = "https://github.com/svayatta/agent-custody/blob/main/";

/** Repository-relative markdown path to site path, mirroring `rewrites` below; null when the file is not a page. */
function sitePath(repoPath: string): string | null {
  const m = (re: RegExp) => repoPath.match(re);
  let x: RegExpMatchArray | null;
  if (repoPath === "CHANGELOG.md") return "/changelog";
  if (repoPath === "packages/receipts/README.md") return "/receipts/";
  if ((x = m(/^packages\/receipts\/docs\/([^/]+)\.md$/))) return `/receipts/${x[1]}`;
  if (repoPath === "packages/state/README.md") return "/state/";
  if (repoPath === "packages/python/README.md") return "/python/";
  if ((x = m(/^site\/(.+)\.md$/))) return `/${x[1] === "index" ? "" : x[1]}`;
  return null;
}

export default withMermaid(
  defineConfig({
    title: "agent-custody",
    description: "Proof of what your AI agents did. Give your agents real power, without losing control of them.",
    srcDir: "..",
    srcExclude: ["deploy/**", "site/verifier/**", "**/node_modules/**", "**/dist/**", "**/examples-out/**", "**/demo-out/**", "**/.venv/**", "**/target/**", "CLAUDE.md", "CONTRIBUTING.md", "SECURITY.md", "README.md", "packages/receipts/README.md", "packages/state/README.md", "packages/python/README.md", "packages/receipts/examples/**", "packages/state/examples/**", "packages/python/tests/**", "site/README.md"],
    rewrites: {
      "site/index.md": "index.md",
      "site/verify.md": "verify.md",
      "site/advanced.md": "advanced.md",
      "site/how-it-works.md": "how-it-works.md",
      "site/early-access.md": "early-access.md",
      "site/hosted-log.md": "hosted-log.md",
      "site/status.md": "status.md",
      "site/security.md": "security.md",
      "site/pricing.md": "pricing.md",
      "site/privacy.md": "privacy.md",
      "site/terms.md": "terms.md",
      "site/contact.md": "contact.md",
      "site/custody.md": "custody.md",
      "site/faq.md": "faq.md",
      "site/use-cases.md": "use-cases.md",
      "site/blog/:page": "blog/:page",
      "site/reference/:page": "reference/:page",
      "site/guide/:page": "guide/:page",
      "site/receipt/:page": "receipt/:page",
      "CHANGELOG.md": "changelog.md",
      "site/receipts/index.md": "receipts/index.md",
      "packages/receipts/docs/:page": "receipts/:page",
      "site/state/index.md": "state/index.md",
      "site/python/index.md": "python/index.md",
      "site/roadmap.md": "roadmap.md",
    },
    cleanUrls: true,
    head: [
      // ?v= changes when the mark changes, so browsers that cached the old favicon fetch the new one
      ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg?v=2" }],
      ["link", { rel: "icon", type: "image/png", sizes: "32x32", href: "/favicon-32.png?v=2" }],
      ["link", { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon.png?v=2" }],
      ["meta", { name: "theme-color", content: "#b45309" }],
      ["meta", { property: "og:title", content: "agent-custody" }],
      ["meta", { property: "og:description", content: "Proof of what your AI agents did. Give your agents real power, without losing control of them." }],
      ["meta", { property: "og:image", content: "https://agent-custody.dev/og.png" }],
      ["meta", { property: "og:image:width", content: "1200" }],
      ["meta", { property: "og:image:height", content: "630" }],
      ["meta", { property: "og:image:alt", content: "agent-custody: Proof of what your AI agents did. Give your agents real power, without losing control of them." }],
      ["meta", { name: "twitter:card", content: "summary_large_image" }],
      ["meta", { name: "twitter:title", content: "agent-custody" }],
      ["meta", { name: "twitter:description", content: "Proof of what your AI agents did. Give your agents real power, without losing control of them." }],
      ["meta", { name: "twitter:image", content: "https://agent-custody.dev/og.png" }],
    ],
    // The conformance vectors are published as files next to the spec, straight from the receipts package.
    buildEnd(siteConfig) {
      const src = resolve(__dirname, "..", "..", "packages", "receipts", "vectors");
      cpSync(src, resolve(siteConfig.outDir, "vectors"), { recursive: true });
    },
    // Pages live at the repository root, so the public dir must be named explicitly; and the site's dependencies live under site/ (Bun installs are isolated).
    vite: { publicDir: resolve(__dirname, "..", "public"), resolve: { alias: [{ find: /^vue$/, replacement: resolve(__dirname, "..", "node_modules", "vue") }, { find: /^vue\/(.*)$/, replacement: resolve(__dirname, "..", "node_modules", "vue") + "/$1" }] } },
    lastUpdated: false,
    themeConfig: {
      logo: "/logo.svg?v=2",
      // The one nav list, shared with the landing page and the dashboard (packages/receipts/src/site-links.ts).
      nav: SITE_NAV.map((l) => ({ ...l })),
      // One docs sidebar, a learning path from first run to reference, each page listed once. The label of each
      // entry is the page's H1, which is also its title (site/sidebar.test.ts checks both). Pages that the top nav
      // or the footer links (pricing, legal, trust, the changelog) are not in it. The blog has its own.
      sidebar: {
        "/blog/": [
          { text: "Blog", items: [{ text: "Blog", link: "/blog/" }, { text: "Risk-tiered merges, with evidence", link: "/blog/risk-tiered-merges-with-evidence" }, { text: "Logs are claims. Receipts are evidence.", link: "/blog/logs-are-claims" }] },
        ],
        "/": [
          { text: "Start", items: [
            { text: "Getting started", link: "/guide/getting-started" },
            { text: "Incident replay", link: "/guide/incident-replay" },
            { text: "Put the door in front of a site", link: "/receipts/door-quickstart" },
          ] },
          { text: "Concepts", items: [
            { text: "Components", link: "/guide/pieces" },
            { text: "How verification works", link: "/receipts/verification" },
            { text: "Architecture", link: "/guide/architecture" },
            { text: "Threat model", link: "/receipts/threat-model" },
            { text: "What the evidence satisfies", link: "/receipts/compliance" },
            { text: "Glossary", link: "/guide/glossary" },
          ] },
          { text: "Set up", items: [
            { text: "SDK and framework hooks", link: "/receipts/sdk" },
            { text: "Python SDK", link: "/python/" },
            { text: "Running the gateway", link: "/receipts/usage" },
            { text: "Configuring the gateway", link: "/receipts/configuration" },
            { text: "Gateway console", link: "/receipts/console" },
            { text: "Human approvals", link: "/receipts/approvals" },
            { text: "Writing policies", link: "/receipts/policies" },
            { text: "Deployment", link: "/guide/deployment" },
            { text: "Verifying receipts on a pull request", link: "/receipts/github-action" },
          ] },
          { text: "Advanced", items: [
            { text: "Credential custody and egress lockdown", link: "/guide/credential-custody" },
            { text: "The egress witness", link: "/receipts/egress" },
            { text: "Writing egress policies", link: "/guide/egress-policies" },
            { text: "The door", link: "/receipts/door" },
            { text: "Door signals", link: "/receipts/door-signals" },
            { text: "Safe financial operations", link: "/receipts/financial-operations" },
            { text: "Completeness", link: "/receipts/completeness" },
            { text: "Anchoring the log on a chain", link: "/receipts/anchoring" },
            { text: "The ACS Guardian", link: "/receipts/acs" },
            { text: "Fact ledger", link: "/state/" },
            { text: "What a receipt costs", link: "/receipts/performance" },
          ] },
          { text: "Tutorials", items: [
            { text: "Tutorials", link: "/receipts/tutorials" },
            { text: "A real Codex agent, a wrong plan, and recovery", link: "/receipts/codex-recovery" },
          ] },
          { text: "Reference", items: [
            { text: "Reference", link: "/reference/" },
            { text: "The gateway", link: "/reference/gateway" },
            { text: "The door", link: "/reference/door" },
            { text: "The egress witness", link: "/reference/egress" },
            { text: "The ACS Guardian", link: "/reference/acs" },
            { text: "The TypeScript SDK", link: "/reference/sdk-typescript" },
            { text: "The sidecar", link: "/reference/sidecar" },
            { text: "Python", link: "/reference/python" },
            { text: "Claude Code and the Claude Agent SDK", link: "/reference/claude-code" },
            { text: "The log API", link: "/reference/log-api" },
            { text: "Verify, audit, export", link: "/reference/verify" },
            { text: "The hosted log", link: "/reference/hosted" },
            { text: "Memory: the ledger and the memory server", link: "/reference/memory" },
            { text: "Explain, review, packs, blast radius, evals, retention", link: "/reference/state-tools" },
            { text: "Command line", link: "/reference/cli" },
            { text: "Receipt specification, v0.2", link: "/receipt/v0.2" },
            { text: "Conformance vectors", link: "/receipt/vectors" },
            { text: "Aligning with IETF SCITT", link: "/receipts/scitt" },
          ] },
          { text: "Roadmap", items: [
            { text: "Roadmap", link: "/roadmap" },
            { text: "Payment mandates and agent identity (planned)", link: "/receipts/mandates" },
          ] },
        ],
      },
      socialLinks: [{ icon: "github", link: "https://github.com/svayatta/agent-custody" }, { icon: "npm", link: "https://www.npmjs.com/org/agent-custody" }],
      // The footer is SiteFooter.vue, mounted by Layout.vue on every page.
      search: { provider: "local" },
    },
    markdown: {
      config(md) {
        // Links are written for the repository. Here they become site links where the target is a page of the site,
        // and repository links otherwise. Relative markdown links must be mapped through the rewrites by hand,
        // because VitePress resolves them against the source path, not the rewritten one.
        const root = resolve(__dirname, "..", "..");
        const open = md.renderer.rules.link_open ?? ((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options));
        md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
          const href = tokens[idx]!.attrGet("href");
          const file: string | undefined = env?.realPath ?? env?.path; // realPath is the source file when the page was rewritten
          if (href && file && !/^(https?:|mailto:|#|\/)/.test(href)) {
            const [path, hash = ""] = href.split("#");
            // Included fragments keep their source file's links, which are relative to the including file's original
            // location; when the link resolves to nothing next to the including file, try it from the repository root.
            // A link may name the page without its .md, as the reference pages do (`./gateway#grants`); resolve that
            // to the file, or the link becomes a repository URL that does not exist.
            const beside = resolve(dirname(file), path!);
            const candidates = [beside, `${beside}.md`, resolve(root, path!), `${resolve(root, path!)}.md`];
            const abs = candidates.find((c) => existsSync(c)) ?? beside;
            const target = posix.normalize(relative(root, abs).split("\\").join("/"));
            // a package README is an overview page on the site, but its anchors exist only in the README itself
            const page = hash && /(^|\/)README\.md$/.test(target) ? null : sitePath(target);
            if (page) {
              tokens[idx]!.attrSet("href", page + (hash ? `#${hash}` : ""));
            } else {
              tokens[idx]!.attrSet("href", REPO + target + (hash ? `#${hash}` : ""));
              tokens[idx]!.attrSet("target", "_blank");
            }
          }
          return open(tokens, idx, options, env, self);
        };
      },
    },
  }),
);

/**
 * The website's top nav and footer, in one place. The landing page, the docs pages (site/.vitepress), and the
 * dashboard (portal.ts) all read these lists, so a page cannot carry a menu of its own. Links are site paths; the
 * dashboard runs on another host and prefixes them with SITE_URL. Labels follow site/guide/glossary.md.
 */
export const SITE_URL = "https://agent-custody.dev";
export const DASHBOARD_URL = "https://app.agent-custody.dev/";

export interface SiteLink {
  text: string;
  link: string;
  /** a regular expression over the path: the nav item is highlighted on every page it matches */
  activeMatch?: string;
}

export const SITE_NAV: SiteLink[] = [
  { text: "Product", link: "/" },
  { text: "Docs", link: "/guide/getting-started", activeMatch: "^/(guide|receipts|state|python|reference|receipt)/" },
  { text: "Pricing", link: "/pricing" },
  { text: "Blog", link: "/blog/", activeMatch: "^/blog/" },
  { text: "Verify a receipt", link: "/verify" },
];

export const SIGN_IN: SiteLink = { text: "Sign in", link: DASHBOARD_URL };
export const GET_STARTED: SiteLink = { text: "Get started", link: "/guide/getting-started" };

export const SITE_FOOTER: { title: string; links: SiteLink[] }[] = [
  { title: "Product", links: [{ text: "Use cases", link: "/use-cases" }, { text: "Pricing", link: "/pricing" }, { text: "Hosted log", link: "/early-access" }, { text: "Verify a receipt", link: "/verify" }] },
  { title: "Docs", links: [{ text: "Getting started", link: "/guide/getting-started" }, { text: "Incident replay", link: "/guide/incident-replay" }, { text: "Reference", link: "/reference/" }, { text: "Receipt specification", link: "/receipt/v0.2" }, { text: "Glossary", link: "/guide/glossary" }, { text: "Changelog", link: "/changelog" }] },
  { title: "Trust", links: [{ text: "Security", link: "/security" }, { text: "Where data goes", link: "/faq" }, { text: "Threat model", link: "/receipts/threat-model" }, { text: "This repository", link: "/custody" }] },
  { title: "Company", links: [{ text: "Blog", link: "/blog/" }, { text: "Contact", link: "/contact" }, { text: "Privacy", link: "/privacy" }, { text: "Terms", link: "/terms" }] },
];

export const SITE_LEGAL_LINKS: SiteLink[] = [
  { text: "GitHub", link: "https://github.com/svayatta/agent-custody" },
  { text: "npm", link: "https://www.npmjs.com/org/agent-custody" },
  { text: "PyPI", link: "https://pypi.org/project/agent-custody/" },
];

/** A site path as an absolute URL, for pages on another host. External links pass through. */
export const siteUrl = (link: string): string => (/^https?:/.test(link) ? link : SITE_URL + link);

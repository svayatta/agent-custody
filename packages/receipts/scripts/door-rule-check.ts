// Checks the rules of `fingerprint.headers.mismatch` (src/door-signals.ts) against the header model of Apify's
// header-generator (Apache-2.0): https://github.com/apify/fingerprint-suite. Run it with node from packages/receipts:
//
//   node scripts/door-rule-check.ts <header-network/network.json> <headers-order.json>
//
// The model is not labelled traffic: it says which header values were seen with each User-Agent, and not who sent them.
// So the result is a check of the rules and not a rate. The model has a node for `sec-ch-ua` and none for
// `accept-language` or `sec-fetch-*`; for those the check reads only the header order lists. Only the model's HTTP/2
// side is read: a browser uses HTTP/2 over TLS only, which is the case where the door's rule applies.
import { readFileSync } from "node:fs";
import { BROWSER_HEADERS, SEC_CH_UA_SINCE, SEC_FETCH_HEADERS, headerFingerprint, statedClient } from "../src/door-signals.ts";

const [networkFile, orderFile] = process.argv.slice(2);
if (!networkFile || !orderFile) throw new Error("door-rule-check needs <network.json> <headers-order.json>");
const MISSING = "*MISSING_VALUE*";
type Tree = { deeper?: Record<string, Tree>; skip?: Tree } | Record<string, number>;
interface Node { name: string; parentNames: string[]; possibleValues: string[]; conditionalProbabilities: Tree }
const nodes = new Map((JSON.parse(readFileSync(networkFile, "utf8")) as { nodes: Node[] }).nodes.map((n) => [n.name, n]));
const node = (name: string) => {
  const n = nodes.get(name);
  if (!n) throw new Error(`the model has no ${name} node`);
  return n;
};
const down = (t: Tree, key: string): Tree | undefined => (t as { deeper?: Record<string, Tree> }).deeper?.[key];
const skip = (t: Tree): Tree => (t as { skip?: Tree }).skip ?? t;

// each User-Agent with the browser that the model gives it: HTTP/2, then device, system, and browser
const uaNode = node("user-agent");
if (uaNode.parentNames.slice(0, 4).join() !== "*HTTP_VERSION,*DEVICE,*OPERATING_SYSTEM,*BROWSER") throw new Error("the user-agent node has other parents than this script reads");
const browserOf = new Map<string, Set<string>>();
const browserVersions = new Set<string>();
const http2 = down(uaNode.conditionalProbabilities, "_2.0_");
for (const device of Object.values((http2 as { deeper?: Record<string, Tree> })?.deeper ?? {})) {
  for (const [system, bySystem] of Object.entries((device as { deeper?: Record<string, Tree> }).deeper ?? {})) {
    for (const [browser, byBrowser] of Object.entries((bySystem as { deeper?: Record<string, Tree> }).deeper ?? {})) {
      for (const ua of Object.keys(skip(byBrowser))) if (ua !== MISSING) browserVersions.add(browser);
      for (const ua of Object.keys(skip(byBrowser))) if (ua !== MISSING) (browserOf.get(ua) ?? browserOf.set(ua, new Set()).get(ua)!).add(`${browser} ${system}`);
    }
  }
}

const hints = node("sec-ch-ua");
if (hints.parentNames[0] !== "user-agent") throw new Error("the sec-ch-ua node has other parents than this script reads");
const ALL = [...BROWSER_HEADERS, ...SEC_FETCH_HEADERS, "host", "user-agent", "accept"];
type Share = { userAgent: string; shareWithout: number };
const result = {
  browserVersions: 0, userAgents: 0, familyDiffers: [] as string[], expectsClientHints: 0, modelAlwaysHasThem: 0, modelLacksThemCount: 0, modelNeverHasThem: 0, modelLacksThem: [] as Share[],
  doesNotExpect: 0, doesNotExpectButModelAlwaysHasThem: 0,
  // Chromium from the version that sends sec-ch-ua, where the rule does not expect it: the embedded forms
  embeddedExemptCount: 0, embeddedExemptNeverHasThem: 0, embeddedExemptAlwaysHasThem: 0, embeddedExempt: [] as Share[],
};
for (const [ua, browsers] of [...browserOf].sort(([a], [b]) => (a < b ? -1 : 1))) {
  result.userAgents++;
  const stated = statedClient(ua);
  for (const b of browsers) {
    const [name, system] = b.split(" ");
    const family = system === "ios" ? "safari" : name!.startsWith("chrome") || name!.startsWith("edge") ? "chromium" : name!.split("/")[0];
    if (stated.kind !== "browser" || stated.family !== family) result.familyDiffers.push(`${ua} (model: ${b}; door: ${stated.family})`);
  }
  // the share of this User-Agent's requests in the model that have no sec-ch-ua
  const given = down(hints.conditionalProbabilities, ua);
  if (!given) continue;
  const without = (skip(skip(given)) as Record<string, number>)[MISSING] ?? 0;
  // does the rule want sec-ch-ua from this User-Agent? Every other expected header is present
  const expects = headerFingerprint({ at: 0, method: "GET", path: "/", secure: true, userAgent: ua, referer: "absent", secFetch: {}, headers: { names: ALL, ordered: false } }).missing === "sec-ch-ua";
  if (expects) {
    result.expectsClientHints++;
    if (without === 0) result.modelAlwaysHasThem++;
    else result.modelLacksThem.push({ userAgent: ua, shareWithout: Math.round(without * 10_000) / 10_000 });
  } else {
    result.doesNotExpect++;
    if (without === 0) result.doesNotExpectButModelAlwaysHasThem++;
    if (stated.kind === "browser" && stated.family === "chromium" && (stated.version ?? 0) >= SEC_CH_UA_SINCE) result.embeddedExempt.push({ userAgent: ua, shareWithout: Math.round(without * 10_000) / 10_000 });
  }
}
for (const list of [result.modelLacksThem, result.embeddedExempt]) list.sort((a, b) => b.shareWithout - a.shareWithout || (a.userAgent < b.userAgent ? -1 : 1));
result.browserVersions = browserVersions.size;
result.modelLacksThemCount = result.modelLacksThem.length;
result.modelNeverHasThem = result.modelLacksThem.filter((u) => u.shareWithout === 1).length;
result.embeddedExemptCount = result.embeddedExempt.length;
result.embeddedExemptNeverHasThem = result.embeddedExempt.filter((u) => u.shareWithout === 1).length;
result.embeddedExemptAlwaysHasThem = result.embeddedExempt.filter((u) => u.shareWithout === 0).length;
const order = JSON.parse(readFileSync(orderFile, "utf8")) as Record<string, string[]>;
const orderLists = Object.fromEntries(Object.entries(order).map(([family, list]) => [family, [...BROWSER_HEADERS, ...SEC_FETCH_HEADERS, "sec-ch-ua"].filter((h) => !list.includes(h))]));
console.log(JSON.stringify({ ...result, headersAbsentFromOrderList: orderLists }, null, 2));

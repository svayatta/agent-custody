// Aspect: the door's behavioural and fingerprint signals, and a policy that reads a flag as a reason to ask for more. Source: src/door-signals.ts, src/door-core.ts
// Run:    node examples/58-door-behaviour-signals.ts
//
// A site has a contact form. The door stands in front of it with `behaviour` in its config, so each arrival fact also
// carries `fingerprint` and `behaviour`. The door refuses nothing because of a signal. The policy reads four flags, and
// a flagged post to the form must pass the challenge. Here the example plays the operator's proxy: it sets
// X-Forwarded-For, X-Forwarded-Proto, and the TLS fingerprint header on each request. The challenge provider is a
// stand-in, so nothing leaves the machine. The form report is written by hand, as the form protector script writes it.
import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival } from "../src/door.ts";
import { FLAG_SIGNALS, FORM_REPORT_HEADER, flagOf } from "../src/door-signals.ts";
import { policyReasons, reasonOfRule } from "../src/policy.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

const POLICY = `permit(principal, action == Action::"page", resource);
permit(principal, action == Action::"contact", resource);

// Each flag is a reason to ask for the challenge. No flag is a verdict: a flagged arrival that passes the challenge goes on.
@reason("this post follows no page load from its source; pass the challenge")
forbid(principal, action == Action::"contact", resource)
when { context.facts.arrival.behaviour.navigation.directWrite && context.facts.arrival.challenge.outcome != "passed" };

@reason("the User-Agent states a browser, and the request lacks a header that this browser sends; pass the challenge")
forbid(principal, action == Action::"contact", resource)
when { context.facts.arrival.fingerprint.headers.mismatch && context.facts.arrival.challenge.outcome != "passed" };

// tls and form are present only on some arrivals: test for each before a rule reads it
@reason("the User-Agent states a browser, and the TLS fingerprint is not this browser's; pass the challenge")
forbid(principal, action == Action::"contact", resource)
when { context.facts.arrival.fingerprint has tls && context.facts.arrival.fingerprint.tls.mismatch && context.facts.arrival.challenge.outcome != "passed" };

@reason("the form report states a submit with no key press and no pointer press; pass the challenge")
forbid(principal, action == Action::"contact", resource)
when { context.facts.arrival.behaviour has form && context.facts.arrival.behaviour.form.noInput && context.facts.arrival.challenge.outcome != "passed" };
`;

step(1, "a site with a contact form, and the door in front of it with `behaviour` and a challenge");
/** what reached the site: each post, and whether it carried the form report header */
const received: { path: string; formReport: boolean }[] = [];
const site = createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    if (req.method === "POST") received.push({ path: req.url ?? "", formReport: FORM_REPORT_HEADER in req.headers });
    res.writeHead(200, { "content-type": "text/html" });
    res.end(req.method === "POST" ? "<p>Thank you</p>" : '<form method="post" action="/contact"><input name="message"><button>Send</button></form>');
  });
});
await new Promise<void>((r) => site.listen(0, "127.0.0.1", r));
const siteUrl = `http://127.0.0.1:${(site.address() as AddressInfo).port}`;
process.env.EXAMPLE_TURNSTILE_SECRET = "example-secret";
const fx = buildDoorFixture(out("58-door-behaviour-signals"), siteUrl, {
  routes: [{ name: "page", methods: ["GET"], path: "*" }, { name: "contact", methods: ["POST"], path: "/contact" }],
  trustProxy: true,
  behaviour: { tlsHeader: "x-ja4" },
  challenge: { provider: "turnstile", siteKey: "example-site-key", secretEnv: "EXAMPLE_TURNSTILE_SECRET", hostnames: ["shop.example"] },
});
writeFileSync(join(fx.dir, "policy.cedar"), POLICY);
console.log("   policy:\n" + POLICY.trim().split("\n").map((l) => "     " + l).join("\n"));
// the provider's siteverify, stood in: the token "passes" passes for the site's hostname
const provider: typeof fetch = async (input, init) => {
  if (!String(input).startsWith("https://challenges.cloudflare.com/")) return fetch(input, init);
  const token = new URLSearchParams(String(init?.body)).get("response");
  return Response.json(token === "passes" ? { success: true, hostname: "shop.example" } : { success: false, "error-codes": ["invalid-input-response"] });
};
const host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: provider });
const door = await serveDoor(host, { port: 0, log: () => {} });
console.log(`   door: ${door.url} in front of ${siteUrl}`);

interface Answer { status: number; receipt: string; body: { reason?: string; challenge?: unknown } }
/** One request with exactly these headers, in this order, as the operator's proxy passes it to the door. */
const send = (method: string, path: string, address: string, ja4: string, headers: [string, string][], body?: string) => new Promise<Answer>((resolve, reject) => {
  const u = new URL(door.url);
  const all = [["host", "shop.example"], ...headers, ["x-forwarded-for", address], ["x-forwarded-proto", "https"], ["x-ja4", ja4], ...(body !== undefined ? [["content-type", "application/x-www-form-urlencoded"], ["content-length", String(Buffer.byteLength(body))]] : []), ["connection", "close"]];
  const req = httpRequest({ host: u.hostname, port: u.port, method, path, headers: all.flat() }, (res) => {
    let text = "";
    res.on("data", (c: Buffer) => (text += c));
    res.on("end", () => resolve({ status: res.statusCode ?? 0, receipt: String(res.headers[RECEIPT_HEADER]), body: res.statusCode === 403 ? JSON.parse(text) : {} }));
  });
  req.on("error", reject);
  req.end(body);
});
const bundleOf = (id: string) => JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
const predicateOf = (id: string) => (JSON.parse(Buffer.from(bundleOf(id).envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
const arrivalOf = (id: string) => predicateOf(id).facts[ARRIVAL_FACT]!.value as Arrival;
/** The flags of an arrival that are true. A flag whose group is absent (no TLS fingerprint, no form report) is not listed. */
const flagsOf = (a: Arrival) => FLAG_SIGNALS.filter((f) => flagOf({ fingerprint: a.fingerprint!, behaviour: a.behaviour! }, f) === true);
// the door's answer names each rule that refused by its Cedar id (`policy2`); the text of a rule is its @reason in the policy file
const reasons = policyReasons(POLICY);
const show = (label: string, r: Answer) => {
  console.log(`   ${label}: HTTP ${r.status}${r.body.reason ? `, refused by ${r.body.reason.split("; ").sort().join("; ")}` : ""}`);
  for (const id of (r.body.reason ?? "").split("; ").filter(Boolean).sort()) console.log(`     ${id}: ${reasonOfRule(id, reasons)}`);
  if (r.body.challenge) console.log(`     how to pass: ${JSON.stringify(r.body.challenge)}`);
};

// shaped as a JA4, with hashes that are plainly not a real client's
const ja4 = (a: string) => `${a}_000000000000_111111111111`;
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const chrome = (dest: string, mode: string, fetchSite: string): [string, string][] => [
  ["sec-ch-ua", '"Chromium";v="126", "Google Chrome";v="126"'], ["user-agent", CHROME], ["accept", "text/html,application/xhtml+xml"],
  ["sec-fetch-site", fetchSite], ["sec-fetch-mode", mode], ["sec-fetch-dest", dest], ["accept-language", "en-GB,en;q=0.9"],
];
const all: [string, Answer][] = [];
const keep = (label: string, r: Answer) => { all.push([label, r]); show(label, r); return r; };

step(2, "a person in a browser loads the page, fills the form, and sends it: no flag, and no challenge");
const person = "203.0.113.7";
const page = keep("page load", await send("GET", "/", person, ja4("t13d1516h2"), chrome("document", "navigate", "none")));
const filled = keep("form post", await send("POST", "/contact", person, ja4("t13d1516h2"), [...chrome("empty", "cors", "same-origin"), ["referer", "https://shop.example/"], [FORM_REPORT_HEADER, "v=1;ms=41250;k=63;p=4;paste=0;trusted=1"]], "message=Where+is+my+order%3F"));
const a = arrivalOf(filled.receipt);
console.log(`   fingerprint.headers: ${JSON.stringify(a.fingerprint!.headers)}`);
console.log(`   fingerprint.tls:     ${JSON.stringify(a.fingerprint!.tls)}`);
console.log(`   behaviour.navigation: ${JSON.stringify(a.behaviour!.navigation)}`);
console.log(`   behaviour.form:       ${JSON.stringify(a.behaviour!.form)}`);
console.log(`   the site received the form report header: ${received.at(-1)!.formReport}`);

step(3, "a tool posts the form directly, under its own name: one flag, and the door's answer names the rule and says how to pass");
const tool = keep("tool post", await send("POST", "/contact", "198.51.100.20", ja4("t13d3112h2"), [["user-agent", "python-requests/2.32.3"], ["accept", "*/*"]], "message=hello"));

step(4, "a script states a browser, with the headers and the TLS of a tool, and a form report with no input: four flags");
const script = keep("script post", await send("POST", "/contact", "198.51.100.30", ja4("t12d151600"), [["user-agent", CHROME], ["accept", "*/*"], [FORM_REPORT_HEADER, "v=1;ms=0;k=0;p=0;paste=0;trusted=1"]], "message=cheap+pills"));

step(5, "a flag can be wrong: a person whose address changed after the page load, and whose form page is on another host of the site, is flagged too");
const moved = "203.0.113.200";
const wrong = keep("person, new address", await send("POST", "/contact", moved, ja4("t13d1516h2"), [...chrome("empty", "cors", "same-site"), [FORM_REPORT_HEADER, "v=1;ms=38000;k=41;p=3;paste=0;trusted=1"]], "message=Please+call+me"));
const retried = keep("the same person, with a passed challenge", await send("POST", "/contact", moved, ja4("t13d1516h2"), [...chrome("empty", "cors", "same-site"), ["x-agent-custody-challenge", "passes"], [FORM_REPORT_HEADER, "v=1;ms=38000;k=41;p=3;paste=0;trusted=1"]], "message=Please+call+me"));

step(6, "every receipt verifies with the door's public key, and records the flags that the policy read");
let ok = true;
for (const [label, r] of all) {
  const verified = verifyBundle(bundleOf(r.receipt), { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok;
  ok &&= verified;
  const arrival = arrivalOf(r.receipt);
  console.log(`   ${label}: ${predicateOf(r.receipt).execution.status}, challenge ${arrival.challenge?.outcome}, flags [${flagsOf(arrival).join(", ")}], ${verified ? "verified" : "FAILED"}`);
}

await door.close();
await host.close();
site.close();
const flags = (r: Answer) => flagsOf(arrivalOf(r.receipt)).join(" ");
if (!ok || page.status !== 200 || filled.status !== 200 || flags(filled) !== "" || tool.status !== 403 || flags(tool) !== "behaviour.navigation.directWrite" ||
  script.status !== 403 || flags(script) !== "fingerprint.headers.mismatch fingerprint.tls.mismatch behaviour.navigation.directWrite behaviour.form.noInput" ||
  wrong.status !== 403 || flags(wrong) !== "behaviour.navigation.directWrite" || retried.status !== 200 || flags(retried) !== "behaviour.navigation.directWrite" || received.length !== 2 || received.some((r) => r.formReport)) throw new Error("the door's signals did not behave as described");
console.log("\nOK");

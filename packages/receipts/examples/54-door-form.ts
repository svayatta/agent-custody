// Aspect: the form protector, one script tag that puts the door's challenge in front of a plain HTML form. Source: src/door-form.ts, src/door.ts
// Run:    node examples/54-door-form.ts
//
// A static site has a contact form and no backend code to change. The door stands in front of it with a Turnstile
// challenge, and the page adds one line: <script src="/.well-known/agent-custody-door/form.js" defer></script>. In a
// browser the script renders the widget in the form and sends the form with the widget's token in the door's header.
// Here the provider is a stand-in and the browser's request is made by hand, so nothing leaves the machine: a form
// sent without a token is refused and never reaches the site, and one sent with a passing token reaches it with the
// receipt id the door wrote.
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { FORM_SCRIPT_PATH } from "../src/door-form.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival } from "../src/door.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

step(1, "a static site with a contact form, and the door in front of it with a Turnstile challenge on the form's route");
const received: string[] = [];
const site = createServer((req, res) => {
  let body = "";
  req.on("data", (c: Buffer) => (body += c));
  req.on("end", () => {
    if (req.method === "POST") received.push(`${req.url} ${body} receipt=${req.headers[RECEIPT_HEADER]}`);
    res.writeHead(200, { "content-type": "text/html" });
    res.end(req.method === "POST" ? "<p>Thank you</p>" : `<form method="post" action="/contact"><input name="message"><button>Send</button></form>\n<script src="${FORM_SCRIPT_PATH}" defer></script>`);
  });
});
await new Promise<void>((r) => site.listen(0, "127.0.0.1", r));
const siteUrl = `http://127.0.0.1:${(site.address() as AddressInfo).port}`;
process.env.EXAMPLE_TURNSTILE_SECRET = "example-secret";
const fx = buildDoorFixture(out("54-door-form"), siteUrl, {
  routes: [{ name: "page", methods: ["GET"], path: "/" }, { name: "contact", methods: ["POST"], path: "/contact" }],
  challenge: { provider: "turnstile", siteKey: "example-site-key", secretEnv: "EXAMPLE_TURNSTILE_SECRET", hostnames: ["shop.example"] },
});
writeFileSync(join(fx.dir, "policy.cedar"), 'permit(principal, action == Action::"page", resource);\npermit(principal, action == Action::"contact", resource) when { context.facts.arrival.challenge.outcome == "passed" };\n');
console.log("   policy:\n" + readFileSync(join(fx.dir, "policy.cedar"), "utf8").trim().split("\n").map((l) => "     " + l).join("\n"));
// the provider's siteverify, stood in: the token "passes" passes for the site's hostname, anything else fails
const provider: typeof fetch = async (input, init) => {
  if (!String(input).startsWith("https://challenges.cloudflare.com/")) return fetch(input, init);
  const token = new URLSearchParams(String(init?.body)).get("response");
  return Response.json(token === "passes" ? { success: true, hostname: "shop.example" } : { success: false, "error-codes": ["invalid-input-response"] });
};
const host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: provider });
const door = await serveDoor(host, { port: 0, log: () => {} });
console.log(`   door: ${door.url} in front of ${siteUrl}`);

step(2, "the page's one line: the door serves the script, built from its challenge config; the secret is not in it");
const scriptRes = await fetch(`${door.url}${FORM_SCRIPT_PATH}`);
const script = await scriptRes.text();
console.log(`   GET ${FORM_SCRIPT_PATH}: HTTP ${scriptRes.status}, ${scriptRes.headers.get("content-type")}, ${script.length} bytes`);
console.log(`   ${script.split("\n").find((l) => l.includes("const settings"))!.trim()}`);
console.log(`   the secret is in the script: ${script.includes("example-secret")}`);

step(3, "a bot posts the form directly, with no token: refused, and the 403 says how to pass");
const bot = await fetch(`${door.url}/contact`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "message=cheap+pills" });
console.log(`   HTTP ${bot.status}: ${JSON.stringify((await bot.json()).challenge)}`);

step(4, "a person completes the widget, and the script sends the form with the token in the door's header");
const person = await fetch(`${door.url}/contact`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-agent-custody-challenge": "passes" }, body: "message=Where+is+my+order%3F" });
console.log(`   HTTP ${person.status}: ${await person.text()}`);
console.log(`   the site received: ${received.join("; ")}`);

step(5, "both receipts verify with the door's public key, and record what the challenge came to");
const decode = (id: string) => JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
let ok = true;
for (const [who, res] of [["bot", bot], ["person", person]] as const) {
  const bundle = decode(res.headers.get(RECEIPT_HEADER)!);
  const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
  const verified = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile }).ok;
  ok &&= verified;
  console.log(`   ${who}: ${p.execution.status}, challenge ${(p.facts[ARRIVAL_FACT]!.value as Arrival).challenge?.outcome}, ${verified ? "verified" : "FAILED"}`);
}

await door.close();
await host.close();
site.close();
if (!ok || bot.status !== 403 || person.status !== 200 || received.length !== 1 || script.includes("example-secret")) throw new Error("the form protector did not behave as described");
console.log("\nOK");

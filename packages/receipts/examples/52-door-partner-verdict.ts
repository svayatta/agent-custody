// Aspect: a partner detection engine's signed verdict as a fact the door's policy reads and its receipt carries. Source: src/door-partner.ts, src/door.ts
// Run:    node examples/52-door-partner-verdict.ts
//
// A site already pays for bot detection (Cloudflare Bot Management, HUMAN, DataDome). The door asks the engine about
// each arrival on the API, naming the receipt it is writing, and the engine (here a stub, scripts/fake-partner.ts)
// signs its verdict for that receipt and route. The verdict reaches the Cedar policy as `context.facts.partner` and
// lands in the receipt as an attested fact, which a reader holding the engine's public key checks again. A verdict the
// engine signed for another arrival is refused, and so is the arrival when the engine does not answer: a partner
// outage never becomes an allow.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival } from "../src/door.ts";
import { PARTNER_FACT } from "../src/door-partner.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin } from "../scripts/door-fixture.ts";
import { startPartner } from "../scripts/fake-partner.ts";
import { out, step } from "./_out.ts";

step(1, "the engine's signing key, a stub engine, and a door that asks it about every arrival; the catalogue is public, the API is for arrivals it judged human");
const engineKey = generateKeyPair();
const engine = await startPartner(engineKey, { slowMs: 2_000 });
const origin = await startOrigin();
const fx = buildDoorFixture(out("52-door-partner-verdict"), origin.url, {
  partner: { engine: "stub-engine", url: engine.url, keyFile: "keys/engine.pub", routes: ["*"], timeoutMs: 300 },
});
const enginePub = writeKeyPair(engineKey, join(fx.dir, "keys"), "engine").pubFile;
writeFileSync(join(fx.dir, "policy.cedar"), `permit(principal, action == Action::"catalogue", resource);
permit(principal, action == Action::"api", resource) when { context.facts has partner && context.facts.partner.verdict == "human" };
`);
console.log("   partner:", JSON.stringify(JSON.parse(readFileSync(fx.configFile, "utf8")).partner));
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const get = async (label: string, userAgent: string, path = "/api/orders") => {
  const res = await fetch(`${door.url}${path}`, { headers: { "user-agent": userAgent } });
  await res.arrayBuffer();
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
  const p = decode(bundle).predicate;
  const arrival = p.facts[ARRIVAL_FACT]!.value as Arrival;
  const fact = p.facts[PARTNER_FACT];
  console.log(`   ${label}: HTTP ${res.status}, partner ${arrival.partner?.outcome}${arrival.partner?.error ? ` (${arrival.partner.error})` : ""}${fact ? `, fact ${JSON.stringify(fact.value)} ${fact.provenance}` : ", no partner fact"}`);
  return { status: res.status, bundle };
};

step(2, "a browser and a bot: the engine signs each verdict for its arrival, and the policy decides on it");
const human = await get("GET /api/orders, a browser", "Mozilla/5.0 (Macintosh)");
const bot = await get("GET /api/orders, a bot    ", "examplebot/1.0");

step(3, "the receipt verifies with the engine's key as an upstream key; without it, the attested verdict cannot be confirmed");
const keys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [], logFile: fx.logFile };
const withKey = verifyBundle(human.bundle, { ...keys, upstreamKeys: [loadPublicKey(enginePub)] });
const withoutKey = verifyBundle(human.bundle, keys);
console.log(formatReport(withKey).split("\n").filter((l) => l.includes("partner") || l.startsWith("RESULT")).map((l) => "   " + l).join("\n"));
console.log(`   without the engine's key: ${withoutKey.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")}`);

step(4, "the engine replays a verdict it signed for another arrival, on a catalogue read the policy alone would allow: refused, and nothing reaches the origin");
engine.mode = "replay";
const before = origin.seen.length;
const replayed = await get("GET /catalogue/shoes, replayed ", "Mozilla/5.0 (Macintosh)", "/catalogue/shoes");

step(5, "the engine is too slow (300 ms budget): partner.onFailure is deny by default, so the arrival is refused with 503, not allowed");
engine.mode = "slow";
const slow = await get("GET /catalogue/shoes, timed out", "Mozilla/5.0 (Macintosh)", "/catalogue/shoes");
const reached = origin.seen.length - before;

await door.close();
await host.close();
await engine.close();
await origin.close();
if (human.status !== 200 || bot.status !== 403 || !withKey.ok || withoutKey.ok || replayed.status !== 503 || slow.status !== 503 || reached !== 0) throw new Error("the partner verdict did not behave as expected");
console.log("\nOK");

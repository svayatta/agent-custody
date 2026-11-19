// Aspect: the door checks Web Bot Auth signatures against the signer's key directory. Source: src/web-bot-auth.ts, src/door.ts
// Run:    node examples/47-web-bot-auth.ts
//
// A crawler signs each request (RFC 9421, Ed25519, tag web-bot-auth) and names its key directory in Signature-Agent.
// The door fetches https://crawler.example/.well-known/http-message-signatures-directory, finds the key by its
// thumbprint, and checks the signature: the arrival is verified as https://crawler.example, with no grant at all. The
// same signed request again is a replay, and a signature made for another site is refused. A grant presented under the
// crawler's signature is bound to its sender when it names the crawler; under another agent's grant it is wrong-sender.
// The directory here is served by a stub in place of the network; everything else is the door as it runs.
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:http";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { ARRIVAL_FACT, RECEIPT_HEADER, createDoorHost, serveDoor, type Arrival } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, jwkThumbprint, parseDictionary, signatureBase, type SfInnerList } from "../src/web-bot-auth.ts";
import { buildDoorFixture, startOrigin } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

const CRAWLER = "https://crawler.example";
const SITE = "shop.example";

step(1, "the crawler's key, published in its directory; the door is configured to check that agent for shop.example");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const x = publicKey.export({ format: "jwk" }).x!;
const keyid = jwkThumbprint(x);
const directory = JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", x }] });
console.log(`   ${CRAWLER}${DIRECTORY_PATH}: ${directory}`);
console.log(`   keyid (the RFC 7638 thumbprint): ${keyid}`);
const fetched: string[] = [];
const stubbed = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  if (url === `${CRAWLER}${DIRECTORY_PATH}`) {
    fetched.push(url);
    return new Response(directory, { headers: { "content-type": DIRECTORY_MEDIA_TYPE } });
  }
  return fetch(input, init);
}) as typeof fetch;
const origin = await startOrigin();
const fx = buildDoorFixture(out("47-web-bot-auth"), origin.url, { webBotAuth: { agents: [CRAWLER], authorities: [SITE] } });
const host = await createDoorHost(loadDoorConfig(fx.configFile), { fetch: stubbed });
const door = await serveDoor(host, { port: 0, log: () => {} });

let n = 0;
const signed = (authority = SITE) => {
  const created = Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = { "signature-agent": `crawler="${CRAWLER}"` };
  headers["signature-input"] = `sig1=("@authority" "signature-agent";key="crawler");created=${created};expires=${created + 60};keyid="${keyid}";alg="ed25519";nonce="example-${process.pid}-${++n}";tag="web-bot-auth"`;
  const base = signatureBase({ method: "GET", target: "/api/orders", authority, header: (h) => (Object.hasOwn(headers, h) ? [headers[h]!] : undefined) }, parseDictionary(headers["signature-input"]).get("sig1") as SfInnerList);
  headers.signature = `sig1=:${sign(null, Buffer.from(base), privateKey).toString("base64")}:`;
  return headers;
};
// node:http, because fetch will not send a Host of our choosing, and the Host is the authority the signature covers
const get = (headers: Record<string, string>, hostHeader = SITE) => new Promise<{ status: number; arrival: Arrival; bundle: ReceiptBundle; agent: string }>((resolve, reject) => {
  const req = request({ host: "127.0.0.1", port: Number(new URL(door.url).port), path: "/api/orders", headers: { host: hostHeader, ...headers } }, (res) => {
    res.resume();
    res.on("end", () => {
      const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${res.headers[RECEIPT_HEADER]}.json`), "utf8")) as ReceiptBundle;
      const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
      resolve({ status: res.statusCode!, arrival: p.facts[ARRIVAL_FACT]!.value as Arrival, bundle, agent: `${p.agent.id} (${p.agent.provenance})` });
    });
  });
  req.on("error", reject);
  req.end();
});
const show = (label: string, r: Awaited<ReturnType<typeof get>>) => console.log(`   ${label}: HTTP ${r.status}, class ${r.arrival.class}, signature ${r.arrival.signature}, grant ${r.arrival.grant}, agent ${r.agent}${r.arrival.signatureError ? `; ${r.arrival.signatureError}` : ""}${r.arrival.grantError ? `; ${r.arrival.grantError}` : ""}`);

step(2, "the API is for verified arrivals: unsigned, the crawler is unknown and refused");
show("GET /api/orders, unsigned ", await get({}));

step(3, "signed per Web Bot Auth: the door fetches the directory once, checks the signature, and the arrival is verified");
const once = signed();
const ok = await get(once);
show("GET /api/orders, signed   ", ok);
console.log(`   directory fetches: ${fetched.length}`);

step(4, "the same signed request again is a replay; a signature made for another site, sent here, is refused");
show("the same request again    ", await get(once));
show("signed for other.example  ", await get(signed("other.example"), "other.example"));

step(5, "a grant under the crawler's own signature is bound to its sender; another agent's grant under it is wrong-sender");
const grant = (agent: string) => grantHeader(createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent, scopes: ["api"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 300_000).toISOString() }));
const bound = await get({ ...signed(), authorization: `Bearer ${grant(CRAWLER)}` });
show("grant for the crawler     ", bound);
show("grant for shopping-agent  ", await get({ ...signed(), authorization: `Bearer ${grant("shopping-agent")}` }));

step(6, "the receipts verify with the door's and the principal's public keys");
const keys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
const results = [ok, bound].map((r) => verifyBundle(r.bundle, keys));
console.log(`   signed arrival: ${results[0]!.ok ? "verified" : "FAILED"}; bound grant: ${results[1]!.ok ? "verified" : "FAILED"}`);

await door.close();
await host.close();
await origin.close();
if (ok.arrival.class !== "verified" || bound.arrival.grant !== "verified" || fetched.length !== 1 || !results.every((r) => r.ok)) throw new Error("the example did not behave as described");
console.log("\nOK");

// A labelled test set for the door: arrivals built to be one known kind each, decided by the real door core, with no
// network. The origin and the signature agent's directory are stand-ins in memory. The labels are true by construction,
// so the error rates measured on it say what the door's checks do with each kind, not how common each kind is.
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DoorConfigSchema } from "./config.ts";
import { generateKeyPair, type KeyPair } from "./crypto.ts";
import { createDelegation } from "./delegation.ts";
import { createDoorCoreWith, relayToOrigin, type DoorIO, type DoorRequest, type OriginTarget } from "./door-core.ts";
import type { DoorLabel } from "./door-error-rates.ts";
import { grantHeader } from "./grant-header.ts";
import { createIssuer } from "./issue.ts";
import { DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, jwkThumbprint, parseDictionary, signatureBase, type SfInnerList } from "./web-bot-auth.ts";

const SITE = "shop.test";
const AGENT_ORIGIN = "https://crawler.test";
const BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const POLICY = `permit(principal, action == Action::"api", resource) when { context.facts.arrival.class == "verified" };
permit(principal, action == Action::"account", resource) when { context.facts.arrival.class == "verified" };`;

interface Keys {
  principal: KeyPair;
  stranger: KeyPair;
  agent: { privateKey: KeyObject; x: string };
  impostor: KeyObject;
}

/** One kind of arrival: what it really is, and how to build one. `prime` runs first and is not labelled. */
export interface TestKind {
  kind: string;
  automated: boolean;
  genuine: boolean | null;
  describes: string;
  build: (k: Keys, n: number) => { headers: Record<string, string>; prime?: Record<string, string> };
}

const grant = (k: KeyPair, agent: string, scopes: string[], fromMs: number, toMs: number) =>
  grantHeader(createDelegation(k, { version: "0.1", principal: "shop-owner", agent, scopes, issuedAt: new Date(Date.now() + fromMs).toISOString(), expiresAt: new Date(Date.now() + toMs).toISOString() }));

function signed(key: KeyObject, x: string, nonce: string, path: string): Record<string, string> {
  const created = Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = { "signature-agent": `crawler="${AGENT_ORIGIN}"` };
  headers["signature-input"] = `sig1=("@authority" "signature-agent";key="crawler");created=${created};expires=${created + 60};keyid="${jwkThumbprint(x)}";alg="ed25519";nonce="${nonce}";tag="web-bot-auth"`;
  const base = signatureBase({ method: "GET", target: path, authority: SITE, header: (h) => (Object.hasOwn(headers, h) ? [headers[h]!] : undefined) }, parseDictionary(headers["signature-input"]).get("sig1") as SfInnerList);
  headers.signature = `sig1=:${sign(null, Buffer.from(base), key).toString("base64")}:`;
  return headers;
}

const PATH = "/api/orders";

/** The kinds in the published test set, in the order the page lists them. */
export const DOOR_TEST_KINDS: TestKind[] = [
  { kind: "browser", automated: false, genuine: null, describes: "a person's browser: a current Chrome user agent and an HTML accept header, nothing else", build: () => ({ headers: { "user-agent": BROWSER_UA, accept: "text/html" } }) },
  { kind: "script", automated: true, genuine: null, describes: "a program that presents nothing: a curl user agent", build: () => ({ headers: { "user-agent": "curl/8.7.1", accept: "*/*" } }) },
  { kind: "script-as-browser", automated: true, genuine: null, describes: "a program that sends the browser's headers, byte for byte", build: () => ({ headers: { "user-agent": BROWSER_UA, accept: "text/html" } }) },
  { kind: "granted-agent", automated: true, genuine: true, describes: "an agent with a grant from a trusted principal, in its window, for this route", build: (k) => ({ headers: { "x-agent-custody-grant": grant(k.principal, "buyer-bot", ["api"], -1000, 3600_000) } }) },
  { kind: "signed-agent", automated: true, genuine: true, describes: "an agent with a Web Bot Auth signature its listed directory's key verifies, with a fresh nonce", build: (k, n) => ({ headers: signed(k.agent.privateKey, k.agent.x, `signed-${n}`, PATH) }) },
  { kind: "declared-name", automated: true, genuine: false, describes: "a program that names an agent in `x-agent-custody-agent` and presents nothing else", build: () => ({ headers: { "x-agent-custody-agent": "buyer-bot" } }) },
  { kind: "forged-signature", automated: true, genuine: false, describes: "a Web Bot Auth signature in the agent's name and keyid, made with another key", build: (k, n) => ({ headers: signed(k.impostor, k.agent.x, `forged-${n}`, PATH) }) },
  { kind: "replayed-signature", automated: true, genuine: false, describes: "the agent's own valid signature, sent a second time by someone who saw it", build: (k, n) => { const h = signed(k.agent.privateKey, k.agent.x, `replayed-${n}`, PATH); return { headers: h, prime: h }; } },
  { kind: "untrusted-grant", automated: true, genuine: false, describes: "a well-formed grant signed by a principal key the door does not trust", build: (k) => ({ headers: { "x-agent-custody-grant": grant(k.stranger, "buyer-bot", ["api"], -1000, 3600_000) } }) },
  { kind: "expired-grant", automated: true, genuine: false, describes: "a trusted principal's grant whose window ended a minute ago", build: (k) => ({ headers: { "x-agent-custody-grant": grant(k.principal, "buyer-bot", ["api"], -3600_000, -60_000) } }) },
  { kind: "out-of-scope-grant", automated: true, genuine: false, describes: "a trusted principal's grant for another route", build: (k) => ({ headers: { "x-agent-custody-grant": grant(k.principal, "buyer-bot", ["account"], -1000, 3600_000) } }) },
  { kind: "grant-under-other-signature", automated: true, genuine: false, describes: "a valid grant for one agent, sent under another agent's verified signature", build: (k, n) => ({ headers: { ...signed(k.agent.privateKey, k.agent.x, `wrong-sender-${n}`, PATH), "x-agent-custody-grant": grant(k.principal, "buyer-bot", ["api"], -1000, 3600_000) } }) },
];

export interface DoorTestSet {
  receiptsDir: string;
  logFile: string;
  labelsFile: string;
  labels: DoorLabel[];
  /** the door's key; its public half verifies every receipt in the set */
  doorKey: KeyPair;
  /** the trusted principal's key, which signs the granted agents' grants */
  principalKey: KeyPair;
}

/** Builds the test set in `dir`: `perKind` labelled arrivals of each kind, their receipts and log, and `labels.jsonl`. */
export async function buildDoorTestSet(dir: string, opts: { perKind: number; kinds?: TestKind[] }): Promise<DoorTestSet> {
  const receiptsDir = join(dir, "receipts");
  const logFile = join(dir, "log.jsonl");
  mkdirSync(receiptsDir, { recursive: true });
  const doorKey = generateKeyPair();
  const agent = generateKeyPairSync("ed25519");
  const keys: Keys = {
    principal: generateKeyPair(),
    stranger: generateKeyPair(),
    agent: { privateKey: agent.privateKey, x: agent.publicKey.export({ format: "jwk" }).x! },
    impostor: generateKeyPairSync("ed25519").privateKey,
  };
  const directory = JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", x: keys.agent.x }] });
  const cfg = DoorConfigSchema.parse({
    identity: { keyFile: "unread" },
    policyFile: "unread",
    receiptsDir,
    logFile,
    routes: [{ name: "api", path: "/api/*", methods: ["GET"] }, { name: "account", path: "/account/*", methods: ["GET"] }],
    webBotAuth: { agents: [AGENT_ORIGIN], authorities: [SITE] },
  });
  const stand: typeof fetch = async (input) => {
    const u = new URL(input instanceof Request ? input.url : String(input));
    if (u.origin === AGENT_ORIGIN && u.pathname === DIRECTORY_PATH) return new Response(directory, { headers: { "content-type": DIRECTORY_MEDIA_TYPE } });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const io: DoorIO = {
    key: doorKey,
    trustedPrincipalKeys: [keys.principal],
    readPolicy: () => ({ text: POLICY, key: "test-set" }),
    policySource: "the test set's policy",
    revoked: () => null,
    secret: () => undefined,
    issuer: (capture) => createIssuer(doorKey, receiptsDir, logFile, { capture }),
    fetch: stand,
    timers: false,
  };
  const core = createDoorCoreWith(cfg, io, "test-set");
  const target: OriginTarget = { url: new URL("https://origin.test"), headers: {}, timeoutMs: 5000, proto: "https" };
  const send = async (headers: Record<string, string>, remote: string): Promise<string> => {
    const req: DoorRequest = { method: "GET", url: PATH, headers: { host: SITE, ...headers }, socket: { remoteAddress: remote } };
    const d = await core.decide(req, randomUUID(), async () => ({ body: Buffer.alloc(0) }));
    const relayed = await relayToOrigin(core, cfg, d, req, target, stand);
    await core.record(d, relayed.execution);
    return d.receiptId;
  };
  const labels: DoorLabel[] = [];
  try {
    let i = 0;
    for (const t of opts.kinds ?? DOOR_TEST_KINDS) {
      for (let n = 0; n < opts.perKind; n++, i++) {
        const built = t.build(keys, n);
        // a documentation address per arrival, so the rate counter never ties one kind to another
        const remote = `198.51.100.${i % 250}`;
        if (built.prime) await send(built.prime, remote);
        labels.push({ receiptId: await send(built.headers, remote), kind: t.kind, automated: t.automated, genuine: t.genuine, source: "test-set" });
      }
    }
  } finally {
    core.close();
  }
  const labelsFile = join(dir, "labels.jsonl");
  writeFileSync(labelsFile, labels.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return { receiptsDir, logFile, labelsFile, labels, doorKey, principalKey: keys.principal };
}

/** The kinds as a Markdown table: what each arrival is, and what the labels say it is. */
export function formatTestKinds(kinds: TestKind[] = DOOR_TEST_KINDS): string {
  const yes = (b: boolean | null) => (b === null ? "names no agent" : b ? "yes" : "no");
  return ["| kind | what arrives | a program | genuine |", "| --- | --- | --- | --- |", ...kinds.map((k) => `| \`${k.kind}\` | ${k.describes} | ${k.automated ? "yes" : "no"} | ${yes(k.genuine)} |`), ""].join("\n");
}

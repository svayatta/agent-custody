// Generates the conformance vectors in vectors/. Run with `bun run vectors`; commit the result.
// The vectors are a snapshot: keys, receipts, logs, and expected verdicts produced by this implementation, so that a
// verifier written elsewhere can prove it agrees. Regenerate only when the format changes, never to make a test pass.
import { withhold } from "../src/capture.ts";
import { createDelegation, delegateFrom, DELEGATION_TYPE } from "../src/delegation.ts";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, digestOf, dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, sha256Hex, type Envelope, type KeyPair, publicKeyToPem } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY, createGatewayHost } from "../src/gateway.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { consistencyProof, inclusionProof, leafHash, rootOf } from "../src/log.ts";
import { serveLog } from "../src/log-sink.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { verifyBundle, type VerifyOptions } from "../src/verify.ts";
import { buildFixture, buildSdkFixture } from "./fixture.ts";

const out = join(import.meta.dirname, "..", "vectors");
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const bundleFile = (dir: string, id: string) => JSON.parse(readFileSync(join(dir, `${id}.json`), "utf8")) as ReceiptBundle;
const logLines = (file: string) => readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l) as string);

interface Case {
  name: string;
  description: string;
  bundle: ReceiptBundle;
  issuerKeys: string[];
  principalKeys: string[];
  logKeys: string[];
  upstreamKeys?: string[];
  /** shared secrets for provider-native deliveries; test values, published on purpose */
  providerSecrets?: { stripe?: string; github?: string };
  /** the log id the verifier is told to expect on the tree head */
  logId?: string;
  log: string[] | null;
  expected: { ok: boolean; failing: string[] };
}

const keys: Record<string, { publicKeyPem: string; keyid: string }> = {};
const pems: Record<string, string> = {};
function key(name: string, pubFile: string) {
  const pem = readFileSync(pubFile, "utf8");
  pems[name] = pem;
  keys[name] = { publicKeyPem: pem, keyid: loadPublicKey(pubFile).keyid };
}

/** Re-sign a statement whose predicate was edited, with the issuer's key, keeping the original tree head and proof. */
function resigned(bundle: ReceiptBundle, issuer: KeyPair, edit: (st: ReceiptStatement) => void): ReceiptBundle {
  const st = decode(bundle);
  edit(st);
  return { ...bundle, envelope: dsseSign(RECEIPT_TYPE, st, issuer) };
}

const cases: Case[] = [];
function addCase(c: Omit<Case, "expected">, opts?: Partial<VerifyOptions>) {
  const tmp = mkdtempSync(join(tmpdir(), "vectors-"));
  const logFile = c.log ? join(tmp, "log.jsonl") : undefined;
  if (c.log && logFile) writeFileSync(logFile, c.log.map((l) => JSON.stringify(l)).join("\n") + "\n");
  const r = verifyBundle(c.bundle, {
    issuerKeys: c.issuerKeys.map((k) => keyFrom(k)),
    principalKeys: c.principalKeys.map((k) => keyFrom(k)),
    logKeys: c.logKeys.map((k) => keyFrom(k)),
    ...(c.upstreamKeys ? { upstreamKeys: c.upstreamKeys.map((k) => keyFrom(k)) } : {}),
    ...(c.providerSecrets ? { providerSecrets: c.providerSecrets } : {}),
    ...(c.logId ? { logId: c.logId } : {}),
    ...(logFile ? { logFile } : {}),
    ...opts,
  });
  cases.push({ ...c, expected: { ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) } });
}
import { publicKeyFromPem } from "../src/crypto.ts";
const keyFrom = (name: string) => publicKeyFromPem(pems[name]!);

// ---- gateway receipts: executed, denied, and edited-then-resigned variants ----
const gfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-gateway-")));
key("gateway", gfx.gatewayPub);
key("principal", gfx.principalPub);
key("upstream", gfx.upstreamPub);
const gatewayKey = loadPrivateKey(join(gfx.dir, "keys", "gateway.key"));
const gw = await createGateway(loadConfig(gfx.configFile));
const ok = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 }, _meta: { "agent-custody/model": "vector-model" } });
const denied = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000000 } });
await gw.close();
const executed = bundleFile(gfx.receiptsDir, String(ok._meta?.[RECEIPT_META_KEY]));
const deniedBundle = bundleFile(gfx.receiptsDir, String(denied._meta?.[RECEIPT_META_KEY]));
const glog = logLines(gfx.logFile);
const G = { issuerKeys: ["gateway"], principalKeys: ["principal"], logKeys: [] as string[] };

addCase({ name: "gateway-executed", description: "An in-policy refund through the gateway: delegation attested, facts observed, executed. Every check passes with the log.", bundle: executed, ...G, log: glog });

// ---- arguments with special keys: an own property named __proto__ is in the digest, as it was in the call ----
const protoFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-proto-")));
key("proto-gateway", protoFx.gatewayPub);
key("proto-principal", protoFx.principalPub);
const pgwProto = await createGateway(loadConfig(protoFx.configFile));
const protoCall = await pgwProto.handleCall({ name: "stripe.refund", arguments: JSON.parse('{"customer_id":"cust_123","amount":2500,"__proto__":{"polluted":true}}') as Record<string, unknown> });
await pgwProto.close();
addCase({ name: "gateway-executed-proto-key", description: "The call's arguments carry an own property named __proto__. The receipt records it and the args digest covers it (a canonicaliser that loses the key fails the digest check).", bundle: bundleFile(protoFx.receiptsDir, String(protoCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["proto-gateway"], principalKeys: ["proto-principal"], logKeys: [], log: logLines(protoFx.logFile) });

// ---- private evidence: the receipt carries commitments where the capture rule withholds; the digests are over the whole call ----
process.env.VECTORS_CAPTURE_KEY = "9f1c2e3d4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0";
const capFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-capture-")));
key("capture-gateway", capFx.gatewayPub);
key("capture-principal", capFx.principalPub);
key("capture-upstream", capFx.upstreamPub);
{
  const cfg = JSON.parse(readFileSync(capFx.configFile, "utf8"));
  cfg.capture = { "stripe.refund": { args: { mode: "encrypted", clear: ["customer_id", "amount"] }, result: { mode: "digest" }, facts: { mode: "encrypted" } } };
  cfg.captureKeyEnv = "VECTORS_CAPTURE_KEY";
  writeFileSync(capFx.configFile, JSON.stringify(cfg));
}
const capGw = await createGateway(loadConfig(capFx.configFile));
const privateCall = await capGw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000" } });
await capGw.close();
const privateBundle = bundleFile(capFx.receiptsDir, String(privateCall._meta?.[RECEIPT_META_KEY]));
const CAP = { issuerKeys: ["capture-gateway"], principalKeys: ["capture-principal"], logKeys: [] as string[] };
// the arguments private and the result in clear: the result's _meta is withheld, the plain attestation stays
const clrFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-capture-clear-result-")));
key("clear-result-gateway", clrFx.gatewayPub);
key("clear-result-principal", clrFx.principalPub);
key("clear-result-upstream", clrFx.upstreamPub);
{
  const cfg = JSON.parse(readFileSync(clrFx.configFile, "utf8"));
  cfg.capture = { "stripe.refund": { args: { mode: "digest", clear: ["amount"] }, result: { mode: "clear" } } };
  writeFileSync(clrFx.configFile, JSON.stringify(cfg));
}
const clrGw = await createGateway(loadConfig(clrFx.configFile));
const clrCall = await clrGw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000" } });
await clrGw.close();
addCase({ name: "gateway-private-clear-result-upstream-attested", description: "A refund whose arguments are withheld (digest) and whose result the rule leaves in clear. The result's _meta is withheld, as it always is under a private rule, and the upstream's plain attestation stays in clear beside the result. With the upstream key given, `upstream signature (upstream key)` runs and passes in both verifiers: the signature covers the content and isError, never _meta. The expected outcome alone cannot tell a pass from a skip; the wrong-key case beside it shows the check runs.", bundle: bundleFile(clrFx.receiptsDir, String(clrCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["clear-result-gateway"], principalKeys: ["clear-result-principal"], logKeys: [], upstreamKeys: ["clear-result-upstream"], log: logLines(clrFx.logFile) });
addCase({ name: "gateway-private-clear-result-upstream-wrong-key", description: "The same receipt with the principal's key offered as the upstream key. The check runs rather than being skipped for the withheld _meta, so `upstream signature (upstream key)` fails in both verifiers; everything else passes.", bundle: bundleFile(clrFx.receiptsDir, String(clrCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["clear-result-gateway"], principalKeys: ["clear-result-principal"], logKeys: [], upstreamKeys: ["clear-result-principal"], log: logLines(clrFx.logFile) });
addCase({ name: "gateway-executed-private", description: "A refund whose capture rule withholds the note (encrypted), the provider's answer (digest), and the customer record (encrypted): the receipt carries commitments, the digests are over the whole call, and without the key or a disclosure the verifier passes them as committed, not recomputed, and does not check the upstream's signature.", bundle: privateBundle, ...CAP, upstreamKeys: ["capture-upstream"], log: logLines(capFx.logFile) });
// commitment-shaped data without a capture note is ordinary data: the digest covers it and a verifier must not take it for a withheld field
const shapedFx = buildSdkFixture(mkdtempSync(join(tmpdir(), "vectors-shaped-")));
key("shaped-app", shapedFx.appPub);
const shapedSdk = createSdkIssuer(loadSdkConfig(shapedFx.configFile));
const shapedBundle = await shapedSdk.record({ tool: "stripe.refund", args: { customer_id: "cust_123", amount: 100 } }, { status: "executed", result: { content: [{ type: "text", text: "{\"status\":\"succeeded\"}" }], extra: { $custody: "withheld", sha256: "00".repeat(32), salt: "00".repeat(16) } } });
const shapedKey = loadPrivateKey(join(shapedFx.dir, "keys", "app.key"));
addCase({ name: "sdk-malformed-commitment-resigned", description: "An SDK receipt whose request argument is replaced by `{ $custody: \"withheld\" }` with no sha256 and no salt, a capture note naming that path added, the original digest kept, re-signed. A tag without the fields a verifier checks is not a commitment, so the note is not borne out and the args digest check fails in both verifiers.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = { $custody: "withheld" }; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["request", "args", "amount"]] }; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });
addCase({ name: "sdk-array-hash-commitment-resigned", description: "As above, with `sha256` an array holding one well-formed hash instead of a string. A pattern test that coerces its argument would take it for a commitment; both verifiers require a string, and the args digest check fails.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = { $custody: "withheld", sha256: ["00".repeat(32)] }; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["request", "args", "amount"]] }; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });
addCase({ name: "sdk-array-keyid-commitment-resigned", description: "An encrypted-shaped commitment whose `keyid` is an array holding one hex string. Not a commitment in either verifier; the args digest check fails.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = { $custody: "encrypted", alg: "A256GCM", keyid: ["00".repeat(32)], iv: "AAAA", ciphertext: "AAAA", tag: "AAAA", sha256: "00".repeat(32) }; (st.predicate as { capture?: unknown }).capture = { mode: "encrypted", withheld: [["request", "args", "amount"]] }; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });
addCase({ name: "gateway-undeclared-envelope-commitment-resigned", description: "An executed receipt with a clear result whose upstream envelope is replaced by a well-formed commitment, with no capture note naming it, re-signed. The note, not the shape, says what is withheld: with the upstream key given, the signature check fails instead of being skipped.", bundle: resigned(executed, gatewayKey, (st) => { (st.predicate.execution as { upstream: { envelope: unknown } }).upstream.envelope = { $custody: "withheld", sha256: "00".repeat(32) }; }), ...G, upstreamKeys: ["upstream"], log: glog });
// a crafted issuer withholds a structural part, or writes a note no issuer writes: the verifiers refuse the statement outright
const structural = (name: string, description: string, edit: (st: ReceiptStatement) => void) => addCase({ name, description, bundle: resigned(executed, gatewayKey, edit), ...G, upstreamKeys: ["upstream"], log: glog });
structural("resigned-status-withheld", "The executed receipt's execution.status replaced by a well-formed commitment, named in the note, re-signed. A note may not name what a verifier reads to run its checks: the statement fails `structural parts in clear` in both verifiers.", (st) => { const w = withhold("executed"); (st.predicate.execution as { status: unknown }).status = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["execution", "status"]] }; });
structural("resigned-tool-withheld", "The whole `tool` replaced by a commitment and named in the note. Fails `structural parts in clear`.", (st) => { const w = withhold(st.predicate.tool); (st.predicate as { tool: unknown }).tool = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["tool"]] }; });
structural("resigned-delegation-withheld", "The grant replaced by a commitment and named in the note. Fails `structural parts in clear` rather than throwing.", (st) => { const w = withhold(st.predicate.delegation); (st.predicate as { delegation: unknown }).delegation = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["delegation"]] }; });
structural("resigned-note-malformed", "A capture note that is a number. Fails `structural parts in clear` in both verifiers, the same way.", (st) => { (st.predicate as { capture?: unknown }).capture = 5; });
structural("resigned-note-path-twice", "A capture note naming the same path twice. No issuer writes one; fails `structural parts in clear` in both verifiers.", (st) => { (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["request", "args", "customer_id"], ["request", "args", "customer_id"]] }; });
structural("resigned-note-path-proto", "A capture note whose path begins with __proto__. A lookup of that head in an ordinary object would throw; both verifiers fail `structural parts in clear` instead.", (st) => { (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["__proto__", "x"]] }; });
structural("resigned-clear-result-envelope-withheld", "The executed receipt with its result in clear and its upstream envelope replaced by a digest-only commitment named in the note, re-signed. A withheld signature beside a result in clear is not a reason to skip the check: with the upstream key given, `upstream signature (upstream key)` fails in both verifiers.", (st) => { const w = withhold("gone"); (st.predicate.execution as { upstream: { envelope: unknown } }).upstream.envelope = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["execution", "upstream", "envelope"]] }; });
structural("resigned-note-path-string", "A capture note whose path is a string rather than segments. Fails `structural parts in clear` in both verifiers, the same way.", (st) => { (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: ["request.args.customer_id"] }; });
addCase({ name: "gateway-private-short-tag-resigned", description: "The private receipt's encrypted commitment over the arguments with its tag cut to 4 bytes, re-signed with the gateway key. A tag shorter than 16 bytes is not a commitment in either verifier, so the note is not borne out and the args digest check fails.", bundle: resigned(privateBundle, loadPrivateKey(join(capFx.dir, "keys", "gateway.key")), (st) => { (st.predicate.request.args as Record<string, { tag: string }>)["$rest"]!.tag = "AAAAAA=="; }), ...CAP, log: logLines(capFx.logFile) });
addCase({ name: "sdk-custody-shaped-data-resigned", description: "An SDK receipt whose result carries data shaped like a commitment but no capture note, with the result edited and re-signed. The data is ordinary, the digest covers it, and the result digest check fails: a verifier must not skip a digest on the shape of the data.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.execution as { result: { content: { text: string }[] } }).result.content[0]!.text = "{\"status\":\"refunded twice\"}"; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });


// ---- a call refused because the grant had expired: the denial is a true record, issued outside the window ----
const efx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-expired-")), 1200);
key("expired-gateway", efx.gatewayPub);
key("expired-principal", efx.principalPub);
const egw = await createGateway(loadConfig(efx.configFile));
await new Promise((r) => setTimeout(r, 1400));
const expiredCall = await egw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
await egw.close();
addCase({ name: "gateway-denied-expired-grant", description: "The session's grant expired before this call; the gateway denied it and issued the receipt after the window. Denied, so the validity check passes with a note; an executed receipt timestamped outside the window would not.", bundle: bundleFile(efx.receiptsDir, String(expiredCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["expired-gateway"], principalKeys: ["expired-principal"], logKeys: [], log: logLines(efx.logFile) });
addCase({ name: "gateway-denied", description: "An over-limit refund denied by policy. The receipt exists, execution is denied, and every check passes.", bundle: deniedBundle, ...G, log: glog });
addCase({ name: "gateway-executed-upstream-attested", description: "The executed receipt verified with the upstream's key as well: the upstream signed its result for this receipt, so the execution is attested, not only observed.", bundle: executed, ...G, upstreamKeys: ["upstream"], log: glog });
addCase({ name: "gateway-executed-upstream-wrong-key", description: "The same receipt with the principal's key offered as the upstream key. The upstream signature check fails; everything else passes.", bundle: executed, ...G, upstreamKeys: ["principal"], log: glog });
addCase({ name: "gateway-executed-no-log-copy", description: "The same executed receipt verified without a copy of the log: inclusion still proven against the signed tree head, the log-file check simply absent.", bundle: executed, ...G, log: null });
addCase({ name: "wrong-issuer-key", description: "Verified against the principal's key as if it were the issuer's. The signature check fails first and nothing else is decided.", bundle: executed, issuerKeys: ["principal"], principalKeys: ["principal"], logKeys: [], log: glog });
addCase({ name: "tampered-payload", description: "One character of the base64 payload changed. The signature no longer verifies.", bundle: { ...executed, envelope: { ...executed.envelope, payload: executed.envelope.payload.replace(/^(.)/, (c) => (c === "A" ? "B" : "A")) } }, ...G, log: glog });
addCase({ name: "resigned-tool-out-of-scope", description: "Predicate edited to name a tool outside the grant, then re-signed with the real gateway key. The signature passes; the scope check fails; the log no longer contains this leaf.", bundle: resigned(executed, gatewayKey, (st) => { st.predicate.tool.name = "stripe.payout"; st.subject[0]!.name = `tool-call:stripe.payout:${st.predicate.receiptId}`; }), ...G, log: glog });
addCase({ name: "resigned-policy-inconsistent", description: "Predicate edited so the policy says deny while execution says executed, re-signed with the gateway key.", bundle: resigned(executed, gatewayKey, (st) => { st.predicate.policy!.decision = "deny"; }), ...G, log: glog });
addCase({ name: "resigned-args-digest", description: "Request args edited without updating the digest, re-signed with the gateway key.", bundle: resigned(executed, gatewayKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = 1; }), ...G, log: glog });
addCase({ name: "resigned-body-note-without-commitment", description: "The executed receipt's capture note says the provider's delivery body is withheld, the evidence is removed, the result edited, re-signed with the gateway key. A note naming a path the receipt carries no commitment for fails that path's check in both verifiers, and the edited result fails its digest.", bundle: resigned(executed, gatewayKey, (st) => { const ex = st.predicate.execution as { upstream?: unknown; result: { content: { text: string }[] } }; delete ex.upstream; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["execution", "upstream", "rawBody"]] }; ex.result.content[0]!.text = "edited"; }), ...G, log: glog });
addCase({ name: "resigned-result-digest", description: "Execution result edited without updating the result digest, re-signed with the gateway key. The result digest check fails.", bundle: resigned(executed, gatewayKey, (st) => { (st.predicate.execution as { result: unknown }).result = { content: [{ type: "text", text: "edited" }] }; }), ...G, log: glog });
addCase({ name: "inclusion-proof-wrong-index", description: "The inclusion proof's leaf index changed. The tree head still verifies; the proof does not.", bundle: { ...executed, inclusion: { ...executed.inclusion, leafIndex: executed.inclusion.leafIndex + 1 } }, ...G, log: glog });
addCase({ name: "log-copy-from-another-log", description: "Verified against a copy of a different log. Everything passes except the recomputed root.", bundle: executed, ...G, log: ["not-the-same-leaf"] });

// ---- a sub-agent under a delegation chain: principal -> planner -> refunder ----
const dfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-chain-")));
key("gateway-chain", dfx.gatewayPub);
key("principal-chain", dfx.principalPub);
const dgatewayKey = loadPrivateKey(join(dfx.dir, "keys", "gateway.key"));
{
  const principalKey = loadPrivateKey(join(dfx.dir, "keys", "principal.key"));
  const planner = generateKeyPair();
  const t0 = Date.now();
  const parent = createDelegation(principalKey, { version: "0.1", principal: "user_456", agent: "planner", scopes: ["stripe.refund", "customer.lookup"], issuedAt: new Date(t0 - 3600_000).toISOString(), expiresAt: new Date(t0 + 7200_000).toISOString(), agentKey: publicKeyToPem(planner.publicKey) });
  const child = delegateFrom(parent, planner, { agent: "refunder", scopes: ["stripe.refund"] });
  const host = await createGatewayHost(loadConfig(dfx.configFile));
  const session = host.open(child);
  const cok = await session.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
  await host.close();
  const chained = bundleFile(dfx.receiptsDir, String(cok._meta?.[RECEIPT_META_KEY]));
  const dlog = logLines(dfx.logFile);
  const D = { issuerKeys: ["gateway-chain"], principalKeys: ["principal-chain"], logKeys: [] as string[] };
  // the same chain with the child's scope escalated beyond the parent's, signed by the planner's real key
  const escalated = createDelegation(planner, { version: "0.1", principal: "user_456", agent: "refunder", scopes: ["stripe.refund", "stripe.payout"], issuedAt: new Date(t0).toISOString(), expiresAt: new Date(t0 + 3600_000).toISOString(), parent });
  addCase({ name: "gateway-chain-executed", description: "A refund by a sub-agent under a two-link delegation chain: the principal granted the planner, whose key the grant names; the planner delegated the refund to the refunder. The chain verifies to the principal's key, the receipt names the refunder and the principal, and every check passes.", bundle: chained, ...D, log: dlog });
  // #43: a child window that sorts inside the parent's as a string but lies outside it in time. The child's start is
  // written with a +02:00 offset, so its text is "later" than the parent's UTC start while the instant is earlier.
  const childStart = new Date(t0).toISOString().replace("Z", "+02:00"); // = t0 - 2h, written as t0 local
  const offsetWindow = dsseSign(DELEGATION_TYPE, { version: "0.1", principal: "user_456", agent: "refunder", scopes: ["stripe.refund"], issuedAt: childStart, expiresAt: new Date(t0 + 7200_000).toISOString(), parent }, planner);
  addCase({ name: "gateway-chain-offset-window-resigned", description: "The chain's leaf re-issued with a start time written in a +02:00 offset: as text it sorts after the parent's start, as an instant it is an hour before it. Both verifiers must compare instants and refuse the link; the re-signed receipt also loses its inclusion.", bundle: resigned(chained, dgatewayKey, (st) => { st.predicate.delegation = { envelope: offsetWindow, provenance: "attested" }; }), ...D, log: dlog });
  addCase({ name: "gateway-chain-escalated-resigned", description: "The same receipt with the chain's leaf replaced by one giving the refunder a scope the planner never held, signed with the planner's real key, then the receipt re-signed with the gateway key. The chain check fails on that link; the re-signed receipt also loses its inclusion.", bundle: resigned(chained, dgatewayKey, (st) => { st.predicate.delegation = { envelope: escalated, provenance: "attested" }; }), ...D, log: dlog });
}

// ---- observe mode: the decision is recorded, never enforced; the receipt says so and the verifier holds it to that ----
const ofx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-observe-")));
{
  const cfg = JSON.parse(readFileSync(ofx.configFile, "utf8"));
  cfg.mode = "observe";
  writeFileSync(ofx.configFile, JSON.stringify(cfg));
}
key("gateway-observe", ofx.gatewayPub);
key("principal-observe", ofx.principalPub);
const ogatewayKey = loadPrivateKey(join(ofx.dir, "keys", "gateway.key"));
const ogw = await createGateway(loadConfig(ofx.configFile));
const observed = await ogw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000000 } });
await ogw.close();
const observedBundle = bundleFile(ofx.receiptsDir, String(observed._meta?.[RECEIPT_META_KEY]));
const olog = logLines(ofx.logFile);
const O = { issuerKeys: ["gateway-observe"], principalKeys: ["principal-observe"], logKeys: [] as string[] };
addCase({ name: "gateway-observe-denied", description: "The over-limit refund through a gateway in observe mode: the policy says deny, the call was forwarded anyway, and the receipt carries enforced: false. Every check passes; the consistency check names the mode.", bundle: observedBundle, ...O, log: olog });
addCase({ name: "resigned-observe-flag-stripped", description: "The same receipt with enforced: false removed and re-signed with the gateway key: a deny now claims to have been enforced beside an executed call, and the consistency check fails.", bundle: resigned(observedBundle, ogatewayKey, (st) => { delete st.predicate.policy!.enforced; }), ...O, log: olog });

// ---- a consequential tool: the authorization is committed to the log before the call is forwarded ----
const cfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-precommit-")));
{
  const cfg = JSON.parse(readFileSync(cfx.configFile, "utf8"));
  cfg.precommit = ["stripe.refund"];
  writeFileSync(cfx.configFile, JSON.stringify(cfg));
}
key("gateway-3", cfx.gatewayPub);
key("principal-3", cfx.principalPub);
const cgatewayKey = loadPrivateKey(join(cfx.dir, "keys", "gateway.key"));
const cgw = await createGateway(loadConfig(cfx.configFile));
const cok = await cgw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 7500 } });
const cok2 = await cgw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 7600 } });
await cgw.close();
const committed = bundleFile(cfx.receiptsDir, String(cok._meta?.[RECEIPT_META_KEY]));
const committed2 = bundleFile(cfx.receiptsDir, String(cok2._meta?.[RECEIPT_META_KEY]));
const clog = logLines(cfx.logFile);
const C = { issuerKeys: ["gateway-3"], principalKeys: ["principal-3"], logKeys: [] as string[] };
addCase({ name: "gateway-precommit-executed", description: "A consequential refund: the gateway committed a signed authorization to the log before forwarding the call, and the receipt embeds it. The five authorization checks pass, and the authorization leaf precedes the receipt leaf.", bundle: committed, ...C, log: clog });
addCase({ name: "gateway-precommit-spliced", description: "The second refund's receipt carrying the first refund's authorization, re-signed with the gateway key. The authorization verifies as a statement but does not name this call; the re-signed receipt also loses its own inclusion.", bundle: resigned(committed2, cgatewayKey, (st) => { st.predicate.authorization = decode(committed).predicate.authorization; }), ...C, log: clog });
addCase({ name: "gateway-precommit-reordered", description: "The authorization's inclusion proof replaced by the receipt's own, so it claims a leaf after the execution. The proof fails and so does the order check.", bundle: resigned(committed, cgatewayKey, (st) => { st.predicate.authorization = { ...st.predicate.authorization!, inclusion: committed.inclusion, treeHead: committed.treeHead }; }), ...C, log: clog });

// ---- a provider-native delivery: the fake Stripe attaches the webhook it would send, signed with the shared secret ----
const pfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-provider-")));
{
  const cfg = JSON.parse(readFileSync(pfx.configFile, "utf8"));
  cfg.upstream.args = [...cfg.upstream.args.filter((a: string, i: number, all: string[]) => a !== "--key" && all[i - 1] !== "--key"), "--webhook-secret", "whsec_vectors"];
  writeFileSync(pfx.configFile, JSON.stringify(cfg));
}
key("gateway-2", pfx.gatewayPub);
key("principal-2", pfx.principalPub);
const pgw = await createGateway(loadConfig(pfx.configFile));
const pok = await pgw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
await pgw.close();
const withWebhook = bundleFile(pfx.receiptsDir, String(pok._meta?.[RECEIPT_META_KEY]));
const plog = logLines(pfx.logFile);
const P = { issuerKeys: ["gateway-2"], principalKeys: ["principal-2"], logKeys: [] as string[] };
addCase({ name: "gateway-executed-stripe-webhook", description: "The upstream attached the Stripe webhook for the refund, signed with the shared secret whsec_vectors. With that secret given, the delivery verifies and binds to the refund id in the result: attested by shared secret.", bundle: withWebhook, ...P, providerSecrets: { stripe: "whsec_vectors" }, log: plog });
addCase({ name: "resigned-provider-bound-value-missing", description: "The webhook receipt with the result's content replaced (the refund id gone), the result digest recomputed, the metadata copy of the delivery kept, re-signed. The delivery's bound value must appear in what the agent received, never in the delivery's own copy in the metadata: the provider check fails.", bundle: resigned(withWebhook, loadPrivateKey(join(pfx.dir, "keys", "gateway.key")), (st) => { const ex = st.predicate.execution as { result: { content: { text: string }[] }; resultDigest: string }; ex.result.content = [{ text: "{\"refund_id\":\"re_SOMETHING_ELSE\",\"amount\":999999}" }] as never; ex.resultDigest = digestOf(ex.result); }), ...P, providerSecrets: { stripe: "whsec_vectors" }, log: plog });
addCase({ name: "gateway-executed-stripe-webhook-wrong-secret", description: "The same receipt with the wrong secret. The provider check fails; everything else passes.", bundle: withWebhook, ...P, providerSecrets: { stripe: "whsec_other" }, log: plog });
addCase({ name: "gateway-executed-stripe-webhook-no-secret", description: "The same receipt with no secret given. The delivery is carried, not checked; every other check passes.", bundle: withWebhook, ...P, log: plog });

// ---- SDK receipts: self-reported, no delegation ----
const sfx = buildSdkFixture(mkdtempSync(join(tmpdir(), "vectors-sdk-")), undefined, "vectors");
key("app", sfx.appPub);
const sdk = createSdkIssuer(loadSdkConfig(sfx.configFile));
const sdkBundle = await sdk.record({ tool: "stripe.refund", args: { amount: 500 }, session: { id: "sess-1", toolUseId: "call-1" } }, { status: "executed", result: { refund_id: "re_1" } }, sdk.decide({ tool: "stripe.refund", args: { amount: 500 } }));
const sdkDenied = await sdk.record({ tool: "stripe.refund", args: { amount: 500000 } }, { status: "denied", reason: "over limit" }, sdk.decide({ tool: "stripe.refund", args: { amount: 500000 } }));
const slog = logLines(sfx.logFile);
addCase({ name: "sdk-executed", description: "A receipt from the in-process SDK: issuer kind sdk, principal claimed, no delegation, every field claimed. Passes; the report says what it is worth.", bundle: sdkBundle, issuerKeys: ["app"], principalKeys: [], logKeys: [], log: slog });
addCase({ name: "sdk-denied", description: "An SDK denial receipt: the wrapped function was never called.", bundle: sdkDenied, issuerKeys: ["app"], principalKeys: [], logKeys: [], log: slog });

// ---- remote log: tree heads signed by the log's key ----
const rdir = mkdtempSync(join(tmpdir(), "vectors-remote-"));
const logKp = generateKeyPair();
const { writeKeyPair } = await import("../src/crypto.ts");
const logFiles = writeKeyPair(logKp, join(rdir, "log-keys"), "log");
key("log", logFiles.pubFile);
const remote = await serveLog(join(rdir, "server-log.jsonl"), logKp, { port: 0, logId: "vectors-log" });
// hash-only: the log's file holds leaf hashes, never the receipts; the tree heads name the log
const remoteSdk = createSdkIssuer({ agentId: "remote-bot", identity: { keyFile: join(sfx.dir, "keys", "app.key") }, receiptsDir: join(rdir, "receipts"), log: { url: remote.url, hashOnly: true } });
const remoteBundle = await remoteSdk.record({ tool: "crm.lookup", args: { id: "acct:42" } }, { status: "executed", result: { plan: "pro" } });
await remoteSdk.record({ tool: "crm.lookup", args: { id: "acct:43" } }, { status: "executed", result: { plan: "free" } });
const remoteHeadLater = (await (await fetch(new URL("head", remote.url))).json()) as { treeHead: Envelope };
const remoteProof = (await (await fetch(new URL("consistency?old=1&new=2", remote.url))).json()) as { hashes: string[] };
const rlog = logLines(join(rdir, "server-log.jsonl"));
await remote.close();
addCase({ name: "remote-log-with-log-key", description: "Logged to a log run by someone else: the tree head is signed by the log's key. With that key trusted, everything passes and the report names the log key.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: ["log"], log: rlog });
addCase({ name: "remote-log-expected-id", description: "The same receipt with the expected log id given. The tree head names vectors-log, so the check passes; the log file is hash-only and its root still matches.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: ["log"], logId: "vectors-log", log: rlog });
addCase({ name: "remote-log-wrong-id", description: "The same receipt with a different expected log id. Only the log-id check fails.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: ["log"], logId: "another-log", log: rlog });
addCase({ name: "remote-log-without-log-key", description: "The same receipt with only the issuer key trusted. The tree head signature fails; nothing about inclusion can be decided.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: [], log: rlog });

writeFileSync(join(out, "receipts.json"), JSON.stringify({ version: "0.2", generated: new Date().toISOString(), note: "Each case: verify `bundle` with the named keys (see `keys`) and, when `log` is not null, a copy of the log whose lines are these leaves. `expected.failing` lists the check names that must fail; `expected.ok` is true only when it is empty.", keys, cases }, null, 2) + "\n");

// ---- audit: consistency between two signed tree heads ----
const audit = {
  version: "0.2",
  note: "auditExtends(older, newer, proof, keys): both tree heads must verify against a listed key; the proof is the log's consistency proof between their sizes.",
  cases: [
    { name: "remote-log-extends", description: "The tree head from the first remote receipt and the log's later head, with the proof the log served.", older: remoteBundle.treeHead, newer: remoteHeadLater.treeHead, proof: remoteProof.hashes, keys: ["log"], expected: { ok: true, failing: [] } },
    { name: "remote-log-wrong-order", description: "The same heads the wrong way round.", older: remoteHeadLater.treeHead, newer: remoteBundle.treeHead, proof: remoteProof.hashes, keys: ["log"], expected: { ok: false, failing: ["older is not larger than newer"] } },
    { name: "remote-log-wrong-key", description: "Tree heads checked against the app key, which did not sign them.", older: remoteBundle.treeHead, newer: remoteHeadLater.treeHead, proof: remoteProof.hashes, keys: ["app"], expected: { ok: false, failing: ["older tree head signature", "newer tree head signature"] } },
    { name: "remote-log-bad-proof", description: "A proof with a hash removed.", older: remoteBundle.treeHead, newer: remoteHeadLater.treeHead, proof: remoteProof.hashes.slice(1), keys: ["log"], expected: { ok: false, failing: ["newer log extends older log"] } },
  ],
};
writeFileSync(join(out, "audit.json"), JSON.stringify(audit, null, 2) + "\n");

// ---- the log itself: RFC 6962 roots, RFC 9162 inclusion and consistency proofs ----
const leaves = Array.from({ length: 7 }, (_, i) => `leaf-${i}`);
const hashes = leaves.map(leafHash);
const merkle = {
  version: "0.2",
  note: "leafHash = sha256(0x00 || leaf); nodeHash = sha256(0x01 || left || right). Proof hashes are hex, leaf-to-root for inclusion; RFC 9162 order for consistency.",
  leaves,
  leafHashes: hashes.map((h) => h.toString("hex")),
  roots: Array.from({ length: 8 }, (_, n) => rootOf(hashes, n)),
  inclusion: leaves.map((_, i) => ({ leafIndex: i, treeSize: 7, hashes: inclusionProof(hashes, i, 7).hashes, root: rootOf(hashes, 7), expected: true })),
  consistency: [
    ...[[0, 7], [1, 7], [2, 5], [3, 7], [4, 7], [5, 6], [7, 7]].map(([m, n]) => ({ oldSize: m, newSize: n, oldRoot: rootOf(hashes, m!), newRoot: rootOf(hashes, n!), hashes: consistencyProof(hashes, m!, n!), expected: true })),
    { oldSize: 3, newSize: 7, oldRoot: rootOf(hashes, 3), newRoot: rootOf(hashes.map((h, i) => (i === 1 ? leafHash("leaf-1-edited") : h)), 7), hashes: consistencyProof(hashes.map((h, i) => (i === 1 ? leafHash("leaf-1-edited") : h)), 3, 7), expected: false, description: "leaf 1 rewritten after the older head was taken" },
  ],
};
writeFileSync(join(out, "merkle.json"), JSON.stringify(merkle, null, 2) + "\n");

// ---- canonical JSON, digests, keyids, and the DSSE pre-authentication encoding ----
const values: unknown[] = [{ b: 1, a: [3, { z: null, y: "ÿ" }], c: undefined }, "plain", 42, [1, 2, 3], { nested: { deep: { deeper: true } } }, {}];
const kp = generateKeyPair();
const env = dsseSign("application/vnd.example+json", { hello: "world" }, kp);
const canonical = {
  version: "0.2",
  note: "canonical JSON: keys sorted, no whitespace, undefined dropped. digest = hex sha256 of the canonical string. keyid = hex sha256 of the SPKI DER public key. DSSE PAE = 'DSSEv1 ' + len(type) + ' ' + type + ' ' + len(payload) + ' ' + payload, signed with Ed25519.",
  values: values.map((v) => ({ value: v ?? null, canonical: canonicalize(v), digest: digestOf(v) })),
  keyid: { publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }), keyid: kp.keyid },
  dsse: { publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }), envelope: env, payloadJson: canonicalize({ hello: "world" }), paeHex: Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(env.payloadType)} ${env.payloadType} ${Buffer.from(env.payload, "base64").length} `), Buffer.from(env.payload, "base64")]).toString("hex"), paeSha256: sha256Hex(Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(env.payloadType)} ${env.payloadType} ${Buffer.from(env.payload, "base64").length} `), Buffer.from(env.payload, "base64")])), expected: true },
};
writeFileSync(join(out, "canonical.json"), JSON.stringify(canonical, null, 2) + "\n");

console.log(`wrote ${cases.length} receipt cases, ${audit.cases.length} audit cases, merkle and canonical vectors to ${out}`);

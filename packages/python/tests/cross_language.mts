// Builds receipts with the TypeScript issuer's own signing, hashing, and log code, verifies each with the TypeScript
// verifier, and prints both as JSON, so test_verify.py can hold the Python verifier to the same verdicts on inputs
// the published vectors do not cover. Usage: node cross_language.ts <dir>; the log is written to <dir>/log.jsonl.
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOf, dsseCountersign, dsseSign, generateKeyPair, publicKeyToPem, type Envelope, type KeyPair } from "../../receipts/src/crypto.ts";
import { DELEGATION_TYPE } from "../../receipts/src/delegation.ts";
import { createIssuer } from "../../receipts/src/issue.ts";
import { MerkleLog } from "../../receipts/src/log.ts";
import { RECEIPT_TYPE, TREEHEAD_TYPE } from "../../receipts/src/receipt.ts";
import { githubSignature, stripeSignature } from "../../receipts/src/upstream.ts";
import { verifyBundle } from "../../receipts/src/verify.ts";

type Json = any;
const dir = process.argv[2]!;
const vectors = JSON.parse(readFileSync(new URL("../../receipts/vectors/receipts.json", import.meta.url), "utf8"));
const keys: Record<string, KeyPair> = { issuer: generateKeyPair(), principal: generateKeyPair(), human: generateKeyPair(), "second-human": generateKeyPair(), upstream: generateKeyPair(), lead: generateKeyPair(), sub: generateKeyPair() };
const logFile = join(dir, "log.jsonl");
const log = new MerkleLog(logFile);

const decode = (env: Envelope): Json => JSON.parse(Buffer.from(env.payload, "base64").toString("utf8"));
const base = (name: string): Json => decode(structuredClone(vectors.cases.find((c: Json) => c.name === name).bundle.envelope));

function logged(env: Envelope) {
  const { rootHash, ...inclusion } = log.append(canonicalize(env));
  return { treeHead: dsseSign(TREEHEAD_TYPE, { treeSize: inclusion.treeSize, rootHash, timestamp: new Date().toISOString() }, keys.issuer), inclusion };
}

// The vectors' private keys are not published: re-sign every signed part of a vector's predicate with fresh keys.
const approvals = new Map<string, Envelope>();
function rebind(p: Json): void {
  p.issuer.keyid = keys.issuer!.keyid;
  if (p.delegation) {
    p.delegation.envelope = dsseSign(p.delegation.envelope.payloadType, decode(p.delegation.envelope), keys.principal!);
    p.principal.keyid = keys.principal!.keyid;
  }
  if (p.approval?.envelope?.payloadType) {
    const old = canonicalize(p.approval.envelope);
    if (!approvals.has(old)) {
      let env = dsseSign(p.approval.envelope.payloadType, decode(p.approval.envelope), keys.human!);
      if (p.approval.requiredApprovers === 2) env = dsseCountersign(env, keys["second-human"]!);
      approvals.set(old, env);
    }
    p.approval.envelope = approvals.get(old);
    p.approval.approverKeyids = p.approval.envelope.signatures.map((s: Json) => s.keyid);
  }
  if (p.authorization) {
    const st = decode(p.authorization.envelope);
    rebind(st.predicate);
    const envelope = dsseSign(RECEIPT_TYPE, st, keys.issuer!);
    p.authorization = { envelope, ...logged(envelope) };
  }
}

function issue(from: string, edit: (st: Json) => void) {
  const st = base(from);
  rebind(st.predicate);
  edit(st);
  const envelope = dsseSign(RECEIPT_TYPE, st, keys.issuer!);
  return { envelope, ...logged(envelope) };
}

function setArgs(st: Json, args: Json) {
  st.predicate.request.args = args;
  st.predicate.request.argsDigest = st.subject[0].digest.sha256 = digestOf(args);
}

const cases = [
  {
    name: "approval-only-in-precommit",
    description: "The approved two-human refund with the approval removed from the final receipt only; the precommit still carries it. No human key is trusted.",
    bundle: issue("gateway-approved-two-humans", (st) => { delete st.predicate.approval; }),
    trust: { approval: [] as string[], upstream: [] as string[] },
  },
  {
    name: "upstream-evidence-missing",
    description: "An executed refund whose execution.upstream is an empty object, verified with an upstream key: missing evidence is not a declared withholding.",
    bundle: issue("gateway-executed", (st) => { st.predicate.execution.upstream = {}; }),
    trust: { approval: [], upstream: ["upstream"] },
  },
  {
    name: "operation-confirmed-without-evidence",
    description: "An executed refund claiming a confirmed financial operation for itself, with neither a committed authorization nor a provider reconciliation.",
    bundle: issue("gateway-executed", (st) => {
      st.predicate.operation = { id: "d8aa260c-84ec-461a-abdc-65337aece9f2", idempotencyKey: "e".repeat(64), lookupDigest: "5".repeat(64), status: "confirmed", budget: { id: "refunds", currency: "GBP", period: "2026-10-24" }, originalReceiptId: st.predicate.receiptId, provenance: "observed" };
    }),
    trust: { approval: [], upstream: [] },
  },
  {
    name: "upstream-unknown-provider",
    description: "An executed refund whose execution.upstream names a provider no verifier recognises, verified with an upstream key: an unknown provider must not stand in for the upstream's signature.",
    bundle: issue("gateway-executed", (st) => { st.predicate.execution.upstream = { provider: "unknown" }; }),
    trust: { approval: [], upstream: ["upstream"] },
  },
  {
    name: "upstream-malformed-provider",
    description: "A recognised provider name with no delivery body, signature, or bind, verified with an upstream key: a malformed delivery is not a provider attestation.",
    bundle: issue("gateway-executed", (st) => { st.predicate.execution.upstream = { provider: "stripe-webhook" }; }),
    trust: { approval: [], upstream: ["upstream"] },
  },
  {
    name: "provider-secret-for-other-provider",
    description: "A well-formed Stripe delivery verified with only a GitHub secret: the delivery cannot be checked, and that is a failure, not a skip.",
    bundle: issue("gateway-executed-stripe-webhook", () => {}),
    trust: { approval: [], upstream: [], providerSecrets: { github: "not-the-stripe-secret" } },
  },
  {
    name: "numeric-keys",
    description: "Arguments and a result with array-index keys: the producer's canonical JSON puts them first, in numeric order.",
    bundle: issue("sdk-executed", (st) => {
      setArgs(st, { "2": "two", "10": "ten", a: 1, "01": "not an index", "4294967295": "not an index either" });
      const result = { content: [{ type: "text", text: "ok" }], "7": { "100": 1, "20": 2 } };
      st.predicate.execution.result = result;
      st.predicate.execution.resultDigest = digestOf(result);
    }),
    trust: { approval: [], upstream: [] },
  },
  {
    name: "astral-key",
    description: "Arguments whose keys order differently by UTF-16 code unit than by code point.",
    bundle: issue("sdk-executed", (st) => { setArgs(st, { "\u{1F600}": 1, "￿": 2, b: 3 }); }),
    trust: { approval: [], upstream: [] },
  },
];

// Malformed inputs. Each is a vector's statement with one part broken, signed again by the issuer, so only the named
// fault separates it from a receipt that verifies. test_verify.py holds the message the Python verifier gives for each.
type Edit = (st: Json) => void;
const noTrust = { approval: [] as string[], upstream: [] as string[] };
const humans = { approval: ["human", "second-human"], upstream: [] as string[] };
const fault = (name: string, from: string, edit: Edit, trust: Json = noTrust) => ({ name, bundle: issue(from, edit), trust });
const part = (name: string, edit: (p: Json) => void, from = "gateway-executed") => fault(name, from, (st) => edit(st.predicate));

const operation = (p: Json) => ({ id: "d8aa260c-84ec-461a-abdc-65337aece9f2", idempotencyKey: "e".repeat(64), lookupDigest: "5".repeat(64), status: "submitted", budget: { id: "refunds", currency: "GBP", period: "2026-10-24" }, originalReceiptId: p.receiptId, provenance: "observed" });
const withOperation = (name: string, edit: (op: Json) => Json) => part(name, (p) => { p.operation = edit(operation(p)); });

// A human approval whose signed payload is malformed, in the receipt and in the precommit alike.
const approvalPayload = (name: string, edit: (a: Json) => Json) => fault(name, "gateway-approved-two-humans", (st) => {
  const p = st.predicate;
  const envelope = dsseCountersign(dsseSign(p.approval.envelope.payloadType, edit(decode(p.approval.envelope)), keys.human!), keys["second-human"]!);
  p.approval.envelope = envelope;
  const pre = decode(p.authorization.envelope);
  pre.predicate.approval.envelope = envelope;
  const authorization = dsseSign(RECEIPT_TYPE, pre, keys.issuer!);
  p.authorization = { envelope: authorization, ...logged(authorization) };
}, humans);

const grant = (payload: Json, key: KeyPair) => dsseSign(DELEGATION_TYPE, payload, key);
const grantFault = (name: string, build: (g: Json) => Envelope) => part(name, (p) => { p.delegation.envelope = build(decode(p.delegation.envelope)); });
const pem = (name: string) => publicKeyToPem(keys[name]!.publicKey);
const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ type: "spki", format: "pem" }) as string;
// A grant to "lead", who delegates to the receipt's agent. `root` and `leaf` change the two payloads; `signer` signs the leaf.
const chain = (name: string, root: Json, leaf: Json = {}, signer = "lead") => grantFault(name, (g) => grant({ ...g, ...leaf, parent: grant({ ...g, agent: "lead", agentKey: pem("lead"), ...root }, keys.principal!) }, keys[signer]!));

const GITHUB_SECRET = "github-secret-for-tests";
const STRIPE_SECRET = vectors.cases.find((c: Json) => c.name === "gateway-executed-stripe-webhook").providerSecrets.stripe;
const github = (name: string, delivery: (raw: string) => Json, rawBody = JSON.stringify({ action: "closed", issue: { id: "issue_4242" } }), withheld?: string[][]) => fault(name, "gateway-executed", (st) => {
  const e = st.predicate.execution;
  e.result = { content: [{ type: "text", text: "closed issue_4242" }] };
  e.resultDigest = digestOf(e.result);
  e.upstream = { provider: "github-delivery", rawBody, signature: githubSignature(rawBody, GITHUB_SECRET), bind: "issue.id", ...delivery(rawBody) };
  if (withheld) st.predicate.capture = { mode: "digest", withheld };
}, { ...noTrust, providerSecrets: { github: GITHUB_SECRET } });
const stripe = (name: string, edit: (u: Json, p: Json) => void) => fault(name, "gateway-executed-stripe-webhook", (st) => edit(st.predicate.execution.upstream, st.predicate), { ...noTrust, providerSecrets: { stripe: STRIPE_SECRET } });

const faults = [
  fault("predicate-not-an-object", "gateway-executed", (st) => { st.predicate = "none"; }),
  fault("subject-empty", "gateway-executed", (st) => { st.subject = []; }),
  fault("subject-without-digest", "gateway-executed", (st) => { st.subject = [{ name: "tool-call" }]; }),
  fault("wrong-predicate-type", "gateway-executed", (st) => { st.predicateType = "https://example.com/other/v1"; }),
  part("capture-note-without-paths", (p) => { p.capture = { mode: "digest" }; }),
  part("receipt-id-not-a-string", (p) => { p.receiptId = 7; }),
  part("issuer-keyid-not-a-string", (p) => { p.issuer.keyid = 7; }),
  part("issuer-strict-not-a-boolean", (p) => { p.issuer.strict = "yes"; }),
  part("principal-provenance-unknown", (p) => { p.principal.provenance = "guessed"; }),
  part("agent-id-not-a-string", (p) => { p.agent.id = 7; }),
  part("tool-without-name", (p) => { p.tool = {}; }),
  part("delegation-without-envelope", (p) => { p.delegation = {}; }),
  part("request-without-args", (p) => { delete p.request.args; }),
  part("executed-without-result", (p) => { delete p.execution.result; }),
  part("policy-decision-unknown", (p) => { p.policy.decision = "maybe"; }),
  part("policy-enforced-not-a-boolean", (p) => { p.policy.enforced = "no"; }),
  part("policy-errors-not-a-list", (p) => { p.policy.errors = "none"; }),
  part("reconciliation-empty", (p) => { p.reconciliation = {}; }),
  part("facts-absent", (p) => { delete p.facts; }),

  part("operation-not-an-object", (p) => { p.operation = "refund"; }),
  withOperation("operation-id-not-a-uuid", (op) => ({ ...op, id: "first" })),
  withOperation("operation-original-not-a-uuid", (op) => ({ ...op, originalReceiptId: "first" })),
  withOperation("operation-key-not-a-sha256", (op) => ({ ...op, idempotencyKey: "abc" })),
  withOperation("operation-status-unknown", (op) => ({ ...op, status: "done" })),
  withOperation("operation-budget-currency-lowercase", (op) => ({ ...op, budget: { ...op.budget, currency: "gbp" } })),

  part("approval-not-a-record", (p) => { p.approval = "yes"; }, "gateway-approved-two-humans"),
  part("approval-three-approvers", (p) => { p.approval.requiredApprovers = 3; }, "gateway-approved-two-humans"),
  part("approval-keyids-not-a-list", (p) => { p.approval.approverKeyids = "both"; }, "gateway-approved-two-humans"),
  part("approval-consumed-at-not-a-time", (p) => { p.approval.consumedAt = "soon"; }, "gateway-approved-two-humans"),
  part("approval-provenance-claimed", (p) => { p.approval.provenance = "claimed"; }, "gateway-approved-two-humans"),
  part("approval-fields-empty-name", (p) => { p.approval.fields = { amount: "" }; }, "gateway-approved-two-humans"),

  approvalPayload("approval-payload-not-an-object", () => []),
  approvalPayload("approval-payload-version", (a) => ({ ...a, version: "0.2" })),
  approvalPayload("approval-payload-id-not-a-uuid", (a) => ({ ...a, approvalId: "first" })),
  approvalPayload("approval-payload-agent-not-a-string", (a) => ({ ...a, agent: 7 })),
  approvalPayload("approval-payload-args-digest", (a) => ({ ...a, argsDigest: "abc" })),
  approvalPayload("approval-payload-currency-empty", (a) => ({ ...a, currency: "" })),
  approvalPayload("approval-payload-expires-at-issue", (a) => ({ ...a, expiresAt: a.issuedAt })),

  grantFault("grant-version", (g) => grant({ ...g, version: "0.2" }, keys.principal!)),
  grantFault("grant-without-agent", (g) => grant({ ...g, agent: undefined }, keys.principal!)),
  grantFault("grant-scopes-not-a-list", (g) => grant({ ...g, scopes: "all" }, keys.principal!)),
  grantFault("grant-expiry-not-a-time", (g) => grant({ ...g, expiresAt: "tomorrow" }, keys.principal!)),
  grantFault("grant-parent-not-an-envelope", (g) => grant({ ...g, parent: { payloadType: "text/plain", payload: "", signatures: [] } }, keys.principal!)),
  chain("chain-verifies", {}),
  chain("chain-parent-without-key", { agentKey: undefined }),
  chain("chain-parent-key-not-ed25519", { agentKey: p256 }),
  chain("chain-leaf-signed-by-another-key", {}, {}, "sub"),
  chain("chain-leaf-names-another-principal", {}, { principal: "someone-else" }),
  ...[4, 5].map((links) => grantFault(`chain-of-${links}-links`, (g) => {
    // every link but the leaf is held by "lead", who delegates to itself
    let env = grant({ ...g, agent: "lead", agentKey: pem("lead") }, keys.principal!);
    for (let i = 2; i < links; i++) env = grant({ ...g, agent: "lead", agentKey: pem("lead"), parent: env }, keys.lead!);
    return grant({ ...g, parent: env }, keys.lead!);
  })),

  part("authorization-tree-head-untrusted", (p) => { p.authorization.treeHead = dsseSign(TREEHEAD_TYPE, decode(p.authorization.treeHead), keys.human!); }, "gateway-strict"),

  github("github-delivery", () => ({})),
  github("github-delivery-wrong-hmac", (raw) => ({ signature: githubSignature(raw, "another-secret") })),
  github("github-delivery-body-not-json", () => ({}), "closed issue_4242"),
  github("github-delivery-bind-missing", () => ({ bind: "issue.number" })),
  github("github-delivery-body-withheld-undeclared", (raw) => ({ rawBody: { $custody: "withheld", sha256: digestOf(raw) } })),
  github("github-delivery-body-withheld", (raw) => ({ rawBody: { $custody: "withheld", sha256: digestOf(raw) } }), undefined, [["execution", "upstream", "rawBody"]]),
  stripe("stripe-signature-without-timestamp", (u) => { u.signature = u.signature.replace(/^t=\d+,/, ""); }),
  stripe("stripe-timestamp-an-hour-early", (u, p) => { u.signature = stripeSignature(u.rawBody, STRIPE_SECRET, Math.floor(Date.parse(p.timestamp) / 1000) - 3600); }),
];
const noHead = fault("bundle-without-tree-head", "gateway-executed", () => {});
delete (noHead.bundle as Json).treeHead;
faults.push(noHead);

// A financial operation, issued by the real issuer into the same log: the authorization committed before the call,
// the receipt of the call, and the provider read that reconciles it. With `crash` no receipt of the call exists, and
// the reconciliation names the authorization bundle as its original.
const response = (text: string) => ({ content: [{ type: "text", text }], isError: false });
const sign = (st: Json) => { const envelope = dsseSign(RECEIPT_TYPE, st, keys.issuer!); return { envelope, ...logged(envelope) }; };
async function financial(name: string, options: { crash?: boolean; private?: boolean; original?: (bundle: Json) => Json; reconciliation?: Edit; receipt?: Edit } = {}) {
  const issuer = createIssuer(keys.issuer!, join(dir, name), logFile, options.private ? { capture: { rules: { "stripe.refund": { args: { mode: "digest" }, result: { mode: "digest" } } } } } : {});
  const receiptId = randomUUID(), operationId = randomUUID();
  const lookup = { tool: "stripe.refund.get", args: { key: digestOf(operationId) }, statusPath: "refund.status", identityPath: "idempotencyKey", confirmed: ["succeeded"], failed: ["failed", "canceled"] };
  const args = { amount: 700 };
  const op = { id: operationId, idempotencyKey: digestOf(operationId), lookupDigest: digestOf(lookup), status: "submitted", budget: { id: "refunds", currency: "USD", period: "2026-01-01" }, originalReceiptId: receiptId, provenance: "observed" };
  const auth: Json = {
    receiptId, timestamp: "2026-01-01T12:00:00.000Z", issuer: { kind: "gateway", keyid: keys.issuer!.keyid, version: "test" },
    principal: { id: "owner", keyid: keys.principal!.keyid, provenance: "attested" }, agent: { id: "bot", provenance: "attested" },
    delegation: { envelope: grant({ version: "0.1", principal: "owner", agent: "bot", scopes: ["stripe.refund"], issuedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-02T00:00:00.000Z" }, keys.principal!), provenance: "attested" },
    tool: { name: "stripe.refund", provenance: "observed" }, request: { args, argsDigest: digestOf(args), provenance: "claimed" }, facts: {},
    policy: { decision: "allow", reasons: ["refunds"], errors: [], policyDigest: digestOf("policy"), provenance: "observed" }, operation: op,
  };
  const authorization = await issuer.authorize(auth);
  const first = response(JSON.stringify({ refund: { status: "pending" } }));
  const base: Json = { ...auth, session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" }, authorization, operation: { ...op, status: "pending" }, execution: { status: "executed", result: first, resultDigest: digestOf(first), provenance: "observed" } };
  let original: Json = options.crash ? authorization : await issuer.issue(base);
  if (options.receipt) { const st = decode(original.envelope); options.receipt(st); return { name, bundle: sign(st), trust: noTrust }; }
  if (options.original) original = options.original(original);
  const read = response(JSON.stringify({ refund: { status: "succeeded" }, idempotencyKey: op.idempotencyKey }));
  let bundle: Json = await issuer.issue({ ...base, receiptId: randomUUID(), timestamp: "2026-01-03T12:00:00.000Z", authorization: undefined, request: { args: lookup.args, argsDigest: digestOf(lookup.args), provenance: "claimed" }, operation: { ...op, status: "confirmed" }, reconciliation: { original, lookup }, execution: { status: "executed", result: read, resultDigest: digestOf(read), provenance: "observed" } });
  if (options.reconciliation) { const st = decode(bundle.envelope); options.reconciliation(st); bundle = sign(st); }
  return { name, bundle, trust: noTrust };
}
// The original authorization with its statement changed, signed and logged again.
const original = (edit: Edit) => (bundle: Json) => { const st = decode(bundle.envelope); edit(st); return sign(st); };
const result = (r: Json): Edit => (st) => { st.predicate.execution.result = r; st.predicate.execution.resultDigest = digestOf(r); };
const precommit = (edit: (q: Json) => void): Edit => (st) => { const pre = decode(st.predicate.authorization.envelope); edit(pre.predicate); st.predicate.authorization = sign(pre); };

const financials = [
  await financial("reconciliation-over-authorization", { crash: true }),
  await financial("reconciliation-over-authorization-private", { crash: true, private: true }),
  await financial("reconciliation-original-other-predicate-type", { crash: true, original: original((st) => { st.predicateType = "https://example.com/other/v1"; }) }),
  await financial("reconciliation-original-tool-without-name", { crash: true, original: original((st) => { st.predicate.tool = {}; }) }),
  await financial("reconciliation-original-without-delegation", { crash: true, original: original((st) => { delete st.predicate.delegation; }) }),
  await financial("reconciliation-original-operation-pending", { crash: true, original: original((st) => { st.predicate.operation.status = "pending"; }) }),
  await financial("reconciliation-original-without-tree-head", { crash: true, original: ({ treeHead: _, ...rest }) => rest }),
  await financial("reconciliation-result-without-text", { reconciliation: result({ content: [], isError: false }) }),
  await financial("reconciliation-result-not-json", { reconciliation: result(response("succeeded")) }),
  await financial("operation-only-in-precommit", { receipt: (st) => { delete st.predicate.operation; } }),
  await financial("operation-precommit-pending", { receipt: precommit((q) => { q.operation.status = "pending"; }) }),
];

const pub = (name: string) => ({ keyid: keys[name]!.keyid, publicKey: keys[name]!.publicKey });
const out = [...cases, ...faults, ...financials].map((c) => {
  const providerSecrets = (c.trust as { providerSecrets?: Record<string, string> }).providerSecrets;
  // an exception is the reference's verdict too: test_verify.py lists the inputs that the TypeScript verifier throws on
  try {
    const r = verifyBundle(c.bundle as never, { issuerKeys: [pub("issuer")], principalKeys: [pub("principal")], approvalKeys: c.trust.approval.map(pub), upstreamKeys: c.trust.upstream.map(pub), ...(providerSecrets ? { providerSecrets } : {}), logFile });
    return { ...c, tsFailing: r.checks.filter((x) => !x.ok).map((x) => x.name) };
  } catch (e) {
    return { ...c, tsFailing: null, tsThrew: String(e) };
  }
});
console.log(JSON.stringify({ keys: Object.fromEntries(Object.entries(keys).map(([n, k]) => [n, publicKeyToPem(k.publicKey)])), log: logFile, cases: out }));

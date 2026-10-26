// Builds receipts with the TypeScript issuer's own signing, hashing, and log code, verifies each with the TypeScript
// verifier, and prints both as JSON, so test_verify.py can hold the Python verifier to the same verdicts on inputs
// the published vectors do not cover. Usage: node cross_language.ts <dir>; the log is written to <dir>/log.jsonl.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, digestOf, dsseCountersign, dsseSign, generateKeyPair, publicKeyToPem, type Envelope, type KeyPair } from "../../receipts/src/crypto.ts";
import { MerkleLog } from "../../receipts/src/log.ts";
import { RECEIPT_TYPE, TREEHEAD_TYPE } from "../../receipts/src/receipt.ts";
import { verifyBundle } from "../../receipts/src/verify.ts";

type Json = any;
const dir = process.argv[2]!;
const vectors = JSON.parse(readFileSync(new URL("../../receipts/vectors/receipts.json", import.meta.url), "utf8"));
const keys: Record<string, KeyPair> = { issuer: generateKeyPair(), principal: generateKeyPair(), human: generateKeyPair(), "second-human": generateKeyPair(), upstream: generateKeyPair() };
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

const pub = (name: string) => ({ keyid: keys[name]!.keyid, publicKey: keys[name]!.publicKey });
const out = cases.map((c) => {
  const providerSecrets = (c.trust as { providerSecrets?: Record<string, string> }).providerSecrets;
  const r = verifyBundle(c.bundle as never, { issuerKeys: [pub("issuer")], principalKeys: [pub("principal")], approvalKeys: c.trust.approval.map(pub), upstreamKeys: c.trust.upstream.map(pub), ...(providerSecrets ? { providerSecrets } : {}), logFile });
  return { ...c, tsFailing: r.checks.filter((x) => !x.ok).map((x) => x.name) };
});
console.log(JSON.stringify({ keys: Object.fromEntries(Object.entries(keys).map(([n, k]) => [n, publicKeyToPem(k.publicKey)])), log: logFile, cases: out }));

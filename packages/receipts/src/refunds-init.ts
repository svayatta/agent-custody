// `agent-custody init refunds`: a working gateway in front of Stripe refunds in one command, and with `--run`, one
// test-mode refund through it, one refused, and the receipt verified. It is the pilot in a box: what a team needs to see
// an agent's refund decided by their policy, sent with a key the agent never holds, and checked by someone else.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadConfig } from "./config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "./crypto.ts";
import { createDelegation } from "./delegation.ts";
import { createGateway, RECEIPT_META_KEY } from "./gateway.ts";
import { formEncode } from "./rest.ts";
import type { ReceiptBundle, ReceiptStatement } from "./receipt.ts";
import { formatReport, verifyBundle } from "./verify.ts";

export const STRIPE_BEARER_ENV = "AGENT_CUSTODY_STRIPE_BEARER";
export const STRIPE_KEY_ENV = "STRIPE_SECRET_KEY";
const AGENT = "refund-agent";
const PRINCIPAL = "pilot-principal";

export interface InitRefundsOptions {
  dir: string;
  /** the largest refund the policy permits, in minor units */
  limit: number;
  /** ISO 4217, lowercase as Stripe writes it */
  currency: string;
  ttlHours: number;
  /** where Stripe is; a stand-in in tests */
  stripeUrl?: string;
  print?: (line: string) => void;
}

export function refundsPolicy(limit: number, currency: string): string {
  return `// The agent may read a payment, so the gateway can look it up before a refund.
permit(principal, action == Action::"stripe.payment_intent", resource);

// Refunds of at most ${limit} (minor units, ${currency.toUpperCase()}), only against a payment the gateway itself looked up
// as succeeded in this currency, and never more than that payment received. context.facts.payment comes from the
// gateway's own call to Stripe, never from the agent.
@reason("refunds up to the limit, for a payment the gateway saw succeed")
permit(principal, action == Action::"stripe.refund", resource)
when {
  context.args has amount &&
  context.args.amount <= ${limit} &&
  context.facts has payment &&
  context.facts.payment.status == "succeeded" &&
  context.facts.payment.currency == "${currency}" &&
  context.args.amount <= context.facts.payment.amount_received
};
`;
}

/** Writes keys, a grant, the policy, and a gateway config into `dir`. Refuses a directory that already holds a config. */
export function initRefunds(o: InitRefundsOptions): { dir: string; configFile: string } {
  const print = o.print ?? ((l: string) => console.log(l));
  if (!Number.isSafeInteger(o.limit) || o.limit <= 0) throw new Error("--limit is a positive whole number of minor units, e.g. 5000 for 50.00");
  if (!/^[a-z]{3}$/.test(o.currency)) throw new Error("--currency is a three-letter code such as gbp");
  if (!(o.ttlHours > 0)) throw new Error("--ttl-hours must be positive");
  const dir = resolve(o.dir);
  const configFile = join(dir, "gateway.json");
  if (existsSync(configFile)) throw new Error(`${configFile} already exists; remove ${dir} to start again, or run with --run`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  const gateway = writeKeyPair(generateKeyPair(), join(dir, "keys"), "gateway");
  const principalKp = generateKeyPair();
  const principal = writeKeyPair(principalKp, join(dir, "keys"), "principal");
  print(`1. keys: the gateway's (${gateway.pubFile}) and the principal's, who signs the agent's grant`);

  const now = Date.now();
  const grant = createDelegation(principalKp, {
    version: "0.1",
    principal: PRINCIPAL,
    agent: AGENT,
    scopes: ["stripe.payment_intent", "stripe.refund"],
    issuedAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + o.ttlHours * 3600_000).toISOString(),
  });
  writeFileSync(join(dir, "grant.json"), JSON.stringify(grant, null, 2));
  print(`2. grant.json: ${PRINCIPAL} lets ${AGENT} read payments and refund them for ${o.ttlHours} hours`);

  writeFileSync(join(dir, "policy.cedar"), refundsPolicy(o.limit, o.currency));
  print(`3. policy.cedar: refunds up to ${o.limit} ${o.currency.toUpperCase()} minor units, for a payment the gateway saw succeed`);

  const config = {
    identity: { keyFile: "keys/gateway.key" },
    upstream: {
      rest: {
        baseUrl: o.stripeUrl ?? "https://api.stripe.com",
        headerEnv: { authorization: STRIPE_BEARER_ENV },
        tools: [
          { name: "stripe.payment_intent", method: "GET", path: "/v1/payment_intents/{id}", description: "Read a payment", inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } },
          {
            name: "stripe.refund", method: "POST", path: "/v1/refunds", body: "form", description: "Refund a payment, amount in minor units",
            inputSchema: { type: "object", properties: { payment_intent: { type: "string" }, amount: { type: "integer" }, reason: { type: "string" } }, required: ["payment_intent", "amount"] },
          },
        ],
      },
    },
    grantFile: "grant.json",
    trustedPrincipalKeys: ["keys/principal.pub"],
    policyFile: "policy.cedar",
    facts: [{ name: "payment", tool: "stripe.payment_intent", args: { id: "$args.payment_intent" }, forTools: ["stripe.refund"] }],
    precommit: ["stripe.refund"],
    receiptsDir: "receipts",
    logFile: "log.jsonl",
  };
  writeFileSync(configFile, JSON.stringify(config, null, 2));
  print(`4. gateway.json: Stripe as the upstream, the key read from ${STRIPE_BEARER_ENV}, each refund authorized in the log before it is sent`);
  print(`   principal key: ${principal.pubFile}`);
  return { dir, configFile };
}

export interface RunRefundsOptions {
  dir: string;
  /** default process.env; holds STRIPE_SECRET_KEY */
  env?: Record<string, string | undefined>;
  fetch?: typeof fetch;
  print?: (line: string) => void;
}

export interface RunRefundsResult {
  paymentIntent: string;
  refundReceipt: string;
  refused: boolean;
  verified: boolean;
}

/**
 * Makes a test-mode payment, refunds part of it through the gateway, asks for a refund over the limit, and verifies the
 * refund's receipt. Refuses any key that is not a Stripe test-mode key, so it cannot move real money.
 */
export async function runRefunds(o: RunRefundsOptions): Promise<RunRefundsResult> {
  const env = o.env ?? process.env;
  const f = o.fetch ?? fetch;
  const print = o.print ?? ((l: string) => console.log(l));
  const dir = resolve(o.dir);
  const configFile = join(dir, "gateway.json");
  if (!existsSync(configFile)) throw new Error(`${configFile} not found; run init refunds --dir ${o.dir} first`);
  const key = env[STRIPE_KEY_ENV];
  if (!key) throw new Error(`${STRIPE_KEY_ENV} is not set: export a Stripe test-mode secret key (sk_test_...)`);
  if (!/^(sk|rk)_test_/.test(key)) throw new Error(`${STRIPE_KEY_ENV} is not a test-mode key; init refunds --run only runs in Stripe test mode`);

  const cfg = loadConfig(configFile);
  const rest = cfg.upstream && "rest" in cfg.upstream ? cfg.upstream.rest : undefined;
  if (!rest) throw new Error(`${configFile} has no REST upstream; it was not written by init refunds`);
  const limit = Number(/context\.args\.amount <= (\d+)/.exec(readFileSync(cfg.policyFile!, "utf8"))?.[1]);
  const currency = /context\.facts\.payment\.currency == "([a-z]{3})"/.exec(readFileSync(cfg.policyFile!, "utf8"))?.[1];
  if (!Number.isSafeInteger(limit) || !currency) throw new Error(`${cfg.policyFile}: cannot read the limit and currency init refunds wrote`);

  const payment = await stripeForm(f, rest.baseUrl, key, "/v1/payment_intents", {
    amount: limit * 2,
    currency,
    payment_method: "pm_card_visa",
    confirm: true,
    automatic_payment_methods: { enabled: true, allow_redirects: "never" },
  });
  const pi = String(payment.id);
  print(`5. a test payment of ${limit * 2} ${currency.toUpperCase()} minor units, made directly with Stripe: ${pi} (${String(payment.status)})`);

  const previous = process.env[STRIPE_BEARER_ENV];
  process.env[STRIPE_BEARER_ENV] = `Bearer ${key}`;
  const gw = await createGateway(cfg);
  try {
    const ok = await gw.handleCall({ name: "stripe.refund", arguments: { payment_intent: pi, amount: limit } });
    const receiptId = String(ok._meta?.[RECEIPT_META_KEY]);
    const text = (ok.content[0] as { text?: string } | undefined)?.text ?? "";
    print(`6. the agent asks the gateway to refund ${limit}: ${ok.isError ? "not done: " + text : "refunded"}; receipt ${receiptId}`);
    const over = await gw.handleCall({ name: "stripe.refund", arguments: { payment_intent: pi, amount: limit + 1 } });
    print(`7. the agent asks for ${limit + 1}, over the limit: ${over.isError ? "refused by policy, and never sent to Stripe" : "sent"}`);

    const bundle = JSON.parse(readFileSync(join(cfg.receiptsDir, `${receiptId}.json`), "utf8")) as ReceiptBundle;
    const v = verifyBundle(bundle, {
      issuerKeys: [loadPublicKey(cfg.identity.keyFile.replace(/\.key$/, ".pub"))],
      principalKeys: cfg.trustedPrincipalKeys.map(loadPublicKey),
      logFile: cfg.logFile!,
    });
    const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
    print(`8. the receipt, checked with the gateway's and the principal's public keys and the log: ${v.ok ? "VALID" : "INVALID"}`);
    for (const line of formatReport(v).split("\n").filter((l) => /^RESULT|^tool|^execution|^policy|^authorization/.test(l))) print(`   ${line}`);
    if (v.ok && p.execution.status === "executed" && over.isError) {
      print(`\nRun the gateway for an agent: export ${STRIPE_BEARER_ENV}="Bearer $${STRIPE_KEY_ENV}" and agent-custody gateway --config ${configFile}`);
      print(`Anyone can check a receipt: agent-custody verify ${join(cfg.receiptsDir, `${receiptId}.json`)} --issuer-key ${cfg.identity.keyFile.replace(/\.key$/, ".pub")} --principal-key ${cfg.trustedPrincipalKeys[0]} --log ${cfg.logFile}`);
    }
    return { paymentIntent: pi, refundReceipt: receiptId, refused: !!over.isError, verified: v.ok && p.execution.status === "executed" };
  } finally {
    await gw.close();
    if (previous === undefined) delete process.env[STRIPE_BEARER_ENV];
    else process.env[STRIPE_BEARER_ENV] = previous;
  }
}

async function stripeForm(f: typeof fetch, base: string, key: string, path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await f(new URL(path.replace(/^\//, ""), base.endsWith("/") ? base : `${base}/`), {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/x-www-form-urlencoded" },
    body: formEncode(body),
    signal: AbortSignal.timeout(30_000),
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) throw new Error(`Stripe ${path}: HTTP ${res.status} ${JSON.stringify((json.error as { message?: string } | undefined)?.message ?? json)}`);
  return json;
}

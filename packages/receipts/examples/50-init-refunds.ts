// Aspect: the refund pilot in one command. Source: src/refunds-init.ts, src/rest.ts
// Run:    node examples/50-init-refunds.ts
//
// `agent-custody init refunds` writes a gateway in front of Stripe refunds, and `--run` makes one test-mode refund
// through it, has one over the limit refused, and verifies the receipt. Here a stand-in plays Stripe, so the example
// needs no key and no network; with STRIPE_SECRET_KEY=sk_test_... the same two calls run against Stripe test mode.
import { createServer } from "node:http";
import { rmSync } from "node:fs";
import { initRefunds, runRefunds } from "../src/refunds-init.ts";
import { out, step } from "./_out.ts";

step(1, "a stand-in for Stripe's v1 API: form bodies only, payment intents with null fields as Stripe returns them");
const refundsSent: string[] = [];
const intents = new Map<string, Record<string, unknown>>();
const stripe = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const send = (status: number, v: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(v));
    };
    const form = new URLSearchParams(body);
    if (req.method === "POST" && req.url === "/v1/payment_intents") {
      const pi = { id: `pi_${intents.size + 1}`, amount: Number(form.get("amount")), amount_received: Number(form.get("amount")), currency: form.get("currency"), status: "succeeded", customer: null, description: null };
      intents.set(pi.id, pi);
      return send(200, pi);
    }
    const m = /^\/v1\/payment_intents\/([^/?]+)$/.exec(req.url ?? "");
    if (req.method === "GET" && m) return send(200, intents.get(m[1]!));
    if (req.method === "POST" && req.url === "/v1/refunds") {
      refundsSent.push(body);
      return send(200, { id: "re_1", amount: Number(form.get("amount")), payment_intent: form.get("payment_intent"), status: "succeeded" });
    }
    send(404, { error: { message: "Unrecognized request URL" } });
  });
});
await new Promise<void>((r) => stripe.listen(0, "127.0.0.1", r));
const stripeUrl = `http://127.0.0.1:${(stripe.address() as { port: number }).port}`;

step(2, "agent-custody init refunds --dir <dir> --limit 5000 --currency gbp");
const dir = out("50-init-refunds");
rmSync(dir, { recursive: true, force: true });
initRefunds({ dir, limit: 5000, currency: "gbp", ttlHours: 24, stripeUrl, print: (l) => console.log("   " + l) });

step(3, "agent-custody init refunds --dir <dir> --run, with a test-mode key");
const result = await runRefunds({ dir, env: { STRIPE_SECRET_KEY: "sk_test_example" }, print: (l) => console.log("   " + l) });
stripe.close();

step(4, "what reached Stripe: one refund, as a form body; the over-limit request never left the gateway");
console.log("   " + refundsSent.join("\n   "));

if (!result.verified || !result.refused || refundsSent.length !== 1) throw new Error("unexpected state");
console.log("\nOK");

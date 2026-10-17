<script setup lang="ts">
// The refund story. Six steps on the left, one terminal on the right. A step shows the output that
// `bun run demo` printed for it. The lines come from one real run of packages/receipts/scripts/demo.ts.
// Where a step leaves out lines, a line "… N more checks" says how many. No timers, no animation.
// Each step is a button with aria-pressed. Exactly one step is pressed.
import { computed, ref } from "vue";

type Kind = "cmd" | "muted" | "plain" | "head" | "row" | "claimed" | "pass" | "fail" | "ok" | "no" | "exec" | "deny";
type Line = { k: Kind; s: string };
type Step = { title: string; badge: string; tone: "allow" | "deny"; text: string; lines: Line[] };

const l = (k: Kind, s = ""): Line => ({ k, s });
const gap = l("plain");

// The provenance table of one receipt. A row with the word "claimed" gets the yellow word.
const table = (rows: string[]): Line[] => [
  l("head", "field           provenance  value"),
  ...rows.map((s) => l(/\bclaimed\b/.test(s) ? "claimed" : "row", s)),
];

const receiptOk = [
  "principal       attested    user_456",
  "agent           attested    support-agent",
  "model           claimed     claude-fable-5-1",
  "tool            observed    stripe.refund",
];
const policyRows = "policy          observed    deny [] policy ba4e4461ffc4";
const consumed = "consumed        observed    (no facts shown before this call)";

const steps: Step[] = [
  {
    title: "Refund £500",
    badge: "Allowed",
    tone: "allow",
    text: "A verified customer, under the £1,000 limit. The gateway forwards the call.",
    lines: [
      l("muted", "> refund £500 to a verified customer"),
      l("exec", '  EXECUTED {"refund_id":"re_b5db9a9e","customer_id":"cust_123","amount":50000,"status":"succeeded"}'),
      l("muted", "  receipt a8094805-e7d0-48da-bf05-9dcfdfe7a1dd"),
      gap,
      l("pass", "PASS  receipt signature (issuer key)  (keyid 13221dd037cb)"),
      l("pass", "PASS  delegation signature (principal key)  (signed by 0b715318f782)"),
      l("pass", "PASS  policy decision consistent with execution  (allow -> executed)"),
      l("pass", "PASS  log inclusion proof  (leaf 0 of 1, root 4901cb4cdc68)"),
      l("muted", "… 14 more checks"),
      gap,
      l("ok", "RESULT: VERIFIED"),
      gap,
      ...table([
        ...receiptOk,
        'args            claimed     {"amount":50000,"customer_id":"cust_123"}',
        'fact.customer   observed    {"email":"alex@example.com","id":"cust_123","verified":true}',
        "policy          observed    allow [policy1] policy ba4e4461ffc4",
        consumed,
        "execution       observed    executed (carries an upstream signature; pass --upstream-key to check it)",
      ]),
    ],
  },
  {
    title: "Refund £5,000",
    badge: "Denied",
    tone: "deny",
    text: "Over the policy limit. The provider never hears about it.",
    lines: [
      l("muted", "> refund £5,000, over the policy limit"),
      l("deny", "  DENIED   Denied by policy: no permit policy matched (receipt aa3e91c0-97ed-4f15-bfbf-ad73c524709d)"),
      l("muted", "  receipt aa3e91c0-97ed-4f15-bfbf-ad73c524709d"),
      gap,
      l("pass", "PASS  receipt signature (issuer key)  (keyid 13221dd037cb)"),
      l("pass", "PASS  delegation signature (principal key)  (signed by 0b715318f782)"),
      l("pass", "PASS  policy decision consistent with execution  (deny -> denied)"),
      l("pass", "PASS  log inclusion proof  (leaf 1 of 2, root 322f3ee01785)"),
      l("muted", "… 13 more checks"),
      gap,
      l("ok", "RESULT: VERIFIED"),
      gap,
      ...table([
        ...receiptOk,
        'args            claimed     {"amount":500000,"customer_id":"cust_123"}',
        'fact.customer   observed    {"email":"alex@example.com","id":"cust_123","verified":true}',
        policyRows,
        consumed,
        "execution       observed    denied",
      ]),
    ],
  },
  {
    title: "Unverified customer",
    badge: "Denied",
    tone: "deny",
    text: "The gateway looks the customer up itself. The agent's word is not enough.",
    lines: [
      l("muted", "> refund £500 to an unverified customer"),
      l("deny", "  DENIED   Denied by policy: no permit policy matched (receipt 7996a636-53c4-47d3-9ae5-5b79e2605c7e)"),
      l("muted", "  receipt 7996a636-53c4-47d3-9ae5-5b79e2605c7e"),
      gap,
      l("pass", "PASS  receipt signature (issuer key)  (keyid 13221dd037cb)"),
      l("pass", "PASS  delegation signature (principal key)  (signed by 0b715318f782)"),
      l("pass", "PASS  policy decision consistent with execution  (deny -> denied)"),
      l("pass", "PASS  log inclusion proof  (leaf 2 of 3, root 3388f2cb303e)"),
      l("muted", "… 13 more checks"),
      gap,
      l("ok", "RESULT: VERIFIED"),
      gap,
      ...table([
        ...receiptOk,
        'args            claimed     {"amount":50000,"customer_id":"cust_999"}',
        'fact.customer   observed    {"email":"sam@example.com","id":"cust_999","verified":false}',
        policyRows,
        consumed,
        "execution       observed    denied",
      ]),
    ],
  },
  {
    title: "A payout",
    badge: "Denied",
    tone: "deny",
    text: "The tool is outside the grant the person signed.",
    lines: [
      l("muted", "> payout, a tool outside the delegated scope"),
      l("deny", '  DENIED   Denied by policy: tool "stripe.payout" is not in the delegation scopes (receipt 96809a6f-64df-4a8a-b55f-79360966e029)'),
      l("muted", "  receipt 96809a6f-64df-4a8a-b55f-79360966e029"),
      gap,
      l("pass", "PASS  receipt signature (issuer key)  (keyid 13221dd037cb)"),
      l("pass", "PASS  delegation signature (principal key)  (signed by 0b715318f782)"),
      l("pass", "PASS  executed tool within delegated scope  (stripe.payout not in [customer.lookup, stripe.refund])"),
      l("pass", "PASS  policy decision consistent with execution  (deny -> denied)"),
      l("pass", "PASS  log inclusion proof  (leaf 3 of 4, root 53d94b1804f7)"),
      l("muted", "… 12 more checks"),
      gap,
      l("ok", "RESULT: VERIFIED"),
      gap,
      ...table([
        "principal       attested    user_456",
        "agent           attested    support-agent",
        "model           claimed     claude-fable-5-1",
        "tool            observed    stripe.payout",
        'args            claimed     {"amount":100}',
        policyRows,
        consumed,
        "execution       observed    denied",
      ]),
    ],
  },
  {
    title: "The auditor verifies",
    badge: "Verified",
    tone: "allow",
    text: "All four receipts, with public keys and a copy of the log.",
    lines: [
      l("muted", "======== 2. auditor verifies every receipt with public keys and a copy of the log"),
      gap,
      l("ok", "a8094805-e7d0-48da-bf05-9dcfdfe7a1dd  RESULT: VERIFIED"),
      l("ok", "aa3e91c0-97ed-4f15-bfbf-ad73c524709d  RESULT: VERIFIED"),
      l("ok", "7996a636-53c4-47d3-9ae5-5b79e2605c7e  RESULT: VERIFIED"),
      l("ok", "96809a6f-64df-4a8a-b55f-79360966e029  RESULT: VERIFIED"),
    ],
  },
  {
    title: "Someone edits a receipt",
    badge: "Not verified",
    tone: "deny",
    text: "The refund is made to look smaller. The signature check fails.",
    lines: [
      l("muted", "======== 3. someone edits the first receipt to make the refund look smaller"),
      l("fail", "FAIL  receipt signature (issuer key)  (signature by 13221dd037cb did not verify)"),
      gap,
      l("no", "RESULT: NOT VERIFIED"),
    ],
  },
];

const current = ref(0);
const step = computed(() => steps[current.value]);

// Split a line into runs, so the colour applies to the word that carries the meaning.
type Run = { c: string; t: string };
function runs({ k, s }: Line): Run[] {
  const split = (re: RegExp, c: string): Run[] => {
    const m = re.exec(s);
    if (!m) return [{ c: "", t: s }];
    return [{ c: "", t: s.slice(0, m.index) }, { c, t: s.slice(m.index, m.index + m[0].length) }, { c: "", t: s.slice(m.index + m[0].length) }];
  };
  switch (k) {
    case "pass": return split(/^PASS/, "g");
    case "fail": return split(/^FAIL/, "r");
    case "exec": return split(/EXECUTED/, "g");
    case "deny": return split(/DENIED/, "r");
    case "claimed": return split(/\bclaimed\b/, "y");
    case "ok": return split(/RESULT:.*$/, "g");
    case "no": return split(/RESULT:.*$/, "r");
    case "muted": return [{ c: "m", t: s }];
    case "head": case "cmd": return [{ c: "c", t: s }];
    default: return [{ c: "", t: s }];
  }
}
</script>

<template>
  <div class="story">
    <ol class="steps">
      <li v-for="(s, i) in steps" :key="s.title">
        <button type="button" :aria-pressed="i === current" aria-controls="demo-term" :class="{ on: i === current }" @click="current = i">
          <span class="dot" aria-hidden="true">{{ i + 1 }}</span>
          <span class="body">
            <span class="h">{{ s.title }} <span class="badge" :class="s.tone">{{ s.badge }}</span></span>
            <span class="p">{{ s.text }}</span>
          </span>
        </button>
      </li>
    </ol>
    <div class="side">
      <div id="demo-term" class="term" role="region" :aria-label="`Demo output for step ${current + 1}: ${step.title}`">
        <div class="bar" aria-hidden="true"><i></i><i></i><i></i><span>bun run demo · step {{ current + 1 }}</span></div>
        <pre tabindex="0"><template v-for="(ln, i) in step.lines" :key="`${current}-${i}`"><span v-for="(r, j) in runs(ln)" :key="j" :class="r.c">{{ r.t }}</span>{{ "\n" }}</template></pre>
      </div>
      <p class="src">
        Source: <a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/scripts/demo.ts">packages/receipts/scripts/demo.ts</a>.
        Receipt ids change on every run.
      </p>
    </div>
  </div>
</template>

<style scoped>
.story {
  --d-line: var(--line, var(--vp-c-divider));
  --d-line-2: var(--line-2, var(--vp-c-divider));
  --d-ink: var(--ink, var(--vp-c-text-1));
  --d-ink-2: var(--ink-2, var(--vp-c-text-2));
  --d-bg: var(--bg, var(--vp-c-bg));
  --d-bg-2: var(--bg-2, var(--vp-c-bg-soft));
  display: grid;
  grid-template-columns: minmax(0, 420px) minmax(0, 1fr);
  gap: 32px;
  align-items: start;
  font-family: var(--sans, var(--vp-font-family-base));
}

.steps { list-style: none; margin: 0; padding: 0; }
.steps li { position: relative; margin: 0; padding: 0; }
/* The connector joins the centre of one dot to the centre of the next. The dot centre sits 30px from the top of the row. */
.steps li:not(:last-child)::after {
  content: ""; position: absolute; left: 32px; top: 30px; height: 100%; width: 1px;
  transform: translateX(-.5px); background: var(--d-line-2); z-index: 0;
}
.steps button {
  display: grid; grid-template-columns: 32px minmax(0, 1fr); gap: 16px; align-items: start;
  width: 100%; margin: 0; padding: 14px 16px; border: 0; border-radius: 10px;
  background: transparent; color: var(--d-ink); font: inherit; text-align: left; cursor: pointer;
}
.steps button:hover { background: var(--d-bg-2); }
.steps button.on { background: var(--d-bg); box-shadow: 0 0 0 1px var(--d-line); }
.steps button:focus-visible { outline: 2px solid var(--brand, var(--vp-c-brand-1)); outline-offset: 2px; }
.dot {
  position: relative; z-index: 1; width: 32px; height: 32px; border-radius: 50%; display: grid; place-items: center;
  font: 600 13px var(--sans, var(--vp-font-family-base)); background: var(--d-bg); border: 1px solid var(--d-line-2); color: var(--d-ink-2);
}
.on .dot { background: var(--d-ink); border-color: var(--d-ink); color: var(--d-bg); }
.body { display: block; min-width: 0; }
.h { display: flex; flex-wrap: wrap; gap: 6px 10px; align-items: center; margin: 4px 0; font-size: 15px; font-weight: 600; line-height: 1.4; }
.p { display: block; font-size: 14px; line-height: 1.55; color: var(--d-ink-2); }

.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; border-radius: 999px; padding: 3px 10px; }
.badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge.allow { background: var(--allow-soft, #dcfce7); color: var(--allow, #15803d); }
.badge.deny { background: var(--deny-soft, #fee2e2); color: var(--deny, #b91c1c); }

.term { background: var(--term, #1c1917); color: var(--term-ink, #e7e5e4); border-radius: var(--r, 12px); overflow: hidden; }
.bar { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid #292524; font: 12px var(--mono, var(--vp-font-family-mono)); color: #a8a29e; }
.bar i { width: 10px; height: 10px; border-radius: 50%; background: #44403c; display: inline-block; }
.bar span { margin-left: 8px; }
.term pre {
  margin: 0; padding: 20px; min-height: 34rem; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere;
  font: 12.5px/1.7 var(--mono, var(--vp-font-family-mono)); color: inherit; background: transparent;
}
.term pre:focus-visible { outline: 2px solid #fcd34d; outline-offset: -2px; }
.term .c { color: #fff; font-weight: 500; }
.term .m { color: #a8a29e; }
.term .g { color: #86efac; }
.term .r { color: #fca5a5; }
.term .y { color: #fcd34d; }

.src { margin: 12px 0 0; font-size: 13px; line-height: 1.55; color: var(--d-ink-2); }
.src a { color: inherit; text-decoration: underline; text-underline-offset: 2px; word-break: break-word; }
.src a:hover { color: var(--d-ink); }

@media (min-width: 64rem) {
  .side { position: sticky; top: 88px; }
}
@media (max-width: 63.99rem) {
  .story { grid-template-columns: minmax(0, 1fr); }
  /* On a narrow screen a wrapped line breaks the provenance table, so each line keeps its length and scrolls. */
  .term pre { min-height: 0; white-space: pre; overflow-wrap: normal; }
}
</style>

<script setup lang="ts">
// A demo that plays in the page: the gateway starts, one refund is allowed and one denied, the denied one is
// verified. The lines are the shapes the CLI prints today (the check names are the verifier's own); the ids are
// short so it fits. No video file, nothing loaded from anywhere, and with reduced motion it shows the end state.
import { onBeforeUnmount, onMounted, ref } from "vue";

type Line = { t: "cmd" | "out" | "pass" | "ok" | "gap"; s: string };
const script: Line[] = [
  { t: "cmd", s: "agent-custody gateway --config gateway.json" },
  { t: "out", s: "agent-custody gateway: agent=support-agent principal=user_456 scopes=[customer.lookup, stripe.refund]" },
  { t: "gap", s: "" },
  { t: "out", s: "→ stripe.refund {\"customer_id\":\"cust_123\",\"amount\":50000}" },
  { t: "out", s: "  fact customer ← customer.lookup, fetched by the gateway, never by the agent" },
  { t: "out", s: "  policy allow [policy1] · forwarded · receipt 3f9a2c…  logged" },
  { t: "gap", s: "" },
  { t: "out", s: "→ stripe.refund {\"customer_id\":\"cust_123\",\"amount\":5000000}" },
  { t: "out", s: "  policy deny · not forwarded · receipt 47eb52…  logged" },
  { t: "gap", s: "" },
  { t: "cmd", s: "agent-custody verify receipts/47eb52….json --issuer-key gateway.pub --principal-key principal.pub --log log.jsonl" },
  { t: "pass", s: "PASS  receipt payload type" },
  { t: "pass", s: "PASS  receipt signature (issuer key)" },
  { t: "pass", s: "PASS  gateway receipt carries a delegation" },
  { t: "pass", s: "PASS  delegation signature (principal key)" },
  { t: "pass", s: "PASS  delegation valid at receipt time" },
  { t: "pass", s: "PASS  gateway receipt carries a policy decision" },
  { t: "pass", s: "PASS  policy decision consistent with execution" },
  { t: "pass", s: "PASS  request args digest" },
  { t: "pass", s: "PASS  tree head signature" },
  { t: "pass", s: "PASS  log inclusion proof" },
  { t: "pass", s: "PASS  log file root matches tree head" },
  { t: "gap", s: "" },
  { t: "ok", s: "RESULT: VERIFIED" },
  { t: "gap", s: "" },
  { t: "out", s: "field           provenance  value" },
  { t: "out", s: "principal       claimed     user_456" },
  { t: "out", s: "agent           claimed     support-agent" },
  { t: "out", s: "tool            observed    stripe.refund" },
  { t: "out", s: "args            observed    {\"customer_id\":\"cust_123\",\"amount\":5000000}" },
  { t: "out", s: "policy          attested    deny [] policy 0e568d6e…" },
  { t: "out", s: "execution       observed    denied" },
];

const shown = ref<Line[]>([]);
const typing = ref("");
const playing = ref(false);
let timer: ReturnType<typeof setTimeout> | undefined;
let run = 0;
const reduced = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

function stop() { if (timer) clearTimeout(timer); timer = undefined; playing.value = false; }
function showAll() { stop(); shown.value = script.slice(); typing.value = ""; }
function play() {
  stop();
  const mine = ++run;
  shown.value = [];
  typing.value = "";
  playing.value = true;
  let i = 0;
  const step = () => {
    if (mine !== run) return;
    if (i >= script.length) { playing.value = false; return; }
    const line = script[i]!;
    if (line.t === "cmd") {
      let n = 0;
      const type = () => {
        if (mine !== run) return;
        n += 3;
        typing.value = line.s.slice(0, n);
        if (n < line.s.length) timer = setTimeout(type, 18);
        else { timer = setTimeout(() => { typing.value = ""; shown.value.push(line); i++; timer = setTimeout(step, 500); }, 350); }
      };
      type();
      return;
    }
    shown.value.push(line);
    i++;
    timer = setTimeout(step, line.t === "gap" ? 420 : line.t === "pass" ? 110 : 320);
  };
  timer = setTimeout(step, 400);
}
onMounted(() => { if (reduced()) showAll(); else play(); });
onBeforeUnmount(stop);
</script>

<template>
  <figure class="demo">
    <figcaption><span>What it looks like from the shell</span><button type="button" @click="playing ? showAll() : play()">{{ playing ? "Skip to the end" : "Replay" }}</button></figcaption>
    <pre aria-live="polite"><code><template v-for="(l, i) in shown" :key="i"><span :class="l.t">{{ l.t === "cmd" ? "$ " + l.s : l.s }}</span>
</template><span v-if="typing" class="cmd">$ {{ typing }}<span class="cursor">▍</span></span></code></pre>
  </figure>
</template>

<style scoped>
.demo { margin: 0 0 3rem; }
.demo figcaption { display: flex; justify-content: space-between; align-items: center; gap: 1rem; font-size: .86rem; color: var(--vp-c-text-2); margin: 0 0 .6rem; }
.demo button { font: inherit; padding: .25rem .7rem; border: 1px solid var(--vp-c-divider); border-radius: 3px; background: transparent; color: var(--vp-c-text-1); cursor: pointer; }
.demo button:hover { border-color: var(--vp-c-text-2); }
.demo pre { margin: 0; padding: 1rem 1.2rem; min-height: 22rem; background: var(--vp-c-bg-soft); border: 1px solid var(--vp-c-divider); border-radius: 8px; overflow-x: auto; font-family: var(--vp-font-family-mono); font-size: .8rem; line-height: 1.55; color: var(--vp-c-text-1); }
.demo code { font: inherit; background: none; padding: 0; white-space: pre; }
.cmd { color: var(--vp-c-text-1); font-weight: 600; }
.out { color: var(--vp-c-text-2); }
.pass { color: var(--vp-c-success-1); }
.ok { color: var(--vp-c-success-1); font-weight: 700; }
.cursor { animation: blink 1s steps(2) infinite; }
@keyframes blink { to { opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .cursor { animation: none; } }
</style>

<script setup lang="ts">
// The receipt verifier, in the page. Everything runs in the visitor's browser; nothing is uploaded anywhere.
import { computed, onMounted, ref, watch } from "vue";
import vectors from "../../../packages/receipts/vectors/receipts.json";
import { formatReport, publicKeyFromPem, verifyBundle, type Result } from "../../verifier/verify-web.ts";

const bundleText = ref("");
const issuerPem = ref("");
const principalPem = ref("");
const approvalPem = ref("");
const logPem = ref("");
const upstreamPem = ref("");
const stripeSecret = ref("");
const githubSecret = ref("");
const logText = ref("");
const report = ref("");
const result = ref<Result | null>(null);
const error = ref("");
const busy = ref(false);
const supported = typeof globalThis.crypto?.subtle?.importKey === "function";
const optionalOpen = ref(false);
const over = ref(false);

// The samples in plain words; the vector name stays in the link and in the tooltip.
const SAMPLE_LABELS: Record<string, string> = {
  "gateway-executed": "A gateway call that ran",
  "gateway-approved-two-humans": "A call two people approved",
  "gateway-precommit-executed": "A call logged before it ran",
  "gateway-executed-upstream-attested": "A result the tool signed",
  "gateway-executed-stripe-webhook": "A refund Stripe confirmed",
  "gateway-denied": "A call the policy denied",
  "sdk-executed": "A call the agent recorded itself",
  "remote-log-with-log-key": "A receipt in a remote log",
};
const failed = computed(() => (result.value ? result.value.checks.filter((c) => !c.ok).map((c) => c.name) : []));

// A result belongs to the inputs it was computed from: any edit clears it, so an old verdict never sits beside new input.
watch([bundleText, issuerPem, principalPem, approvalPem, logPem, upstreamPem, stripeSecret, githubSecret, logText], () => {
  if (busy.value) return;
  result.value = null;
  report.value = "";
  error.value = "";
});

async function readFile(f: File | undefined) {
  if (!f) return;
  bundleText.value = await f.text();
}
const onPick = (e: Event) => readFile((e.target as HTMLInputElement).files?.[0]);
const onDrop = (e: DragEvent) => { over.value = false; readFile(e.dataTransfer?.files?.[0]); };

const samples = computed(() => (vectors.cases as any[]).filter((c) => ["gateway-executed", "gateway-approved-two-humans", "gateway-precommit-executed", "gateway-executed-upstream-attested", "gateway-executed-stripe-webhook", "gateway-denied", "sdk-executed", "remote-log-with-log-key"].includes(c.name)));

function load(c: any) {
  const pem = (names: string[]) => names.map((n) => (vectors.keys as any)[n].publicKeyPem).join("\n");
  bundleText.value = JSON.stringify(c.bundle, null, 2);
  issuerPem.value = pem(c.issuerKeys);
  principalPem.value = pem(c.principalKeys);
  approvalPem.value = pem(c.approvalKeys ?? []);
  logPem.value = pem(c.logKeys);
  upstreamPem.value = pem(c.upstreamKeys ?? []);
  stripeSecret.value = c.providerSecrets?.stripe ?? "";
  githubSecret.value = c.providerSecrets?.github ?? "";
  logText.value = c.log ? (c.log as string[]).map((l) => JSON.stringify(l)).join("\n") : "";
  optionalOpen.value = [principalPem.value, approvalPem.value, logPem.value, upstreamPem.value, stripeSecret.value, githubSecret.value, logText.value].some((v) => v.trim() !== "");
  report.value = "";
  result.value = null;
  error.value = "";
}

function tamper() {
  try {
    const b = JSON.parse(bundleText.value);
    b.envelope.payload = b.envelope.payload.replace(/^(.)/, (c: string) => (c === "A" ? "B" : "A"));
    bundleText.value = JSON.stringify(b, null, 2);
  } catch (e) {
    error.value = String(e);
  }
}

// /verify?receipt=<id> opens one of this site's own receipts (site/public/custody/) with the agent's key and the log's
// key, then verifies it. Only ids of that shape, only files under /custody/ on this origin: nothing else is fetched.
onMounted(async () => {
  const q = new URLSearchParams(location.search);
  // /verify?sample=<vector name> loads a published conformance vector, keys included, and verifies it
  const name = q.get("sample");
  if (name) {
    const c = (vectors.cases as any[]).find((x) => x.name === name);
    if (c) { load(c); await verify(); }
    return;
  }
  const id = q.get("receipt");
  if (!id || !/^[0-9a-f-]{36}$/.test(id)) return;
  try {
    const get = async (path: string) => { const r = await fetch(path); if (!r.ok) throw new Error(`${path}: ${r.status}`); return r.text(); };
    const [b, issuer, log] = await Promise.all([get(`/custody/${id}.json`), get("/custody/claude-code.pub"), get("/custody/log.pub")]);
    bundleText.value = JSON.stringify(JSON.parse(b), null, 2);
    issuerPem.value = issuer;
    principalPem.value = "";
    approvalPem.value = "";
    logPem.value = log;
    await verify();
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  }
});

async function keys(text: string) {
  const pems = text.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) ?? [];
  return Promise.all(pems.map(publicKeyFromPem));
}

async function verify() {
  busy.value = true;
  error.value = "";
  try {
    const bundle = JSON.parse(bundleText.value);
    const issuerKeys = await keys(issuerPem.value);
    if (issuerKeys.length === 0) throw new Error("at least one issuer public key (SPKI PEM) is required");
    const logLeaves = logText.value.trim() ? logText.value.trim().split("\n").map((l) => JSON.parse(l) as string) : undefined;
    const r = await verifyBundle(bundle, { issuerKeys, principalKeys: await keys(principalPem.value), approvalKeys: await keys(approvalPem.value), logKeys: await keys(logPem.value), upstreamKeys: await keys(upstreamPem.value), ...(stripeSecret.value || githubSecret.value ? { providerSecrets: { ...(stripeSecret.value ? { stripe: stripeSecret.value } : {}), ...(githubSecret.value ? { github: githubSecret.value } : {}) } } : {}), ...(logLeaves ? { logLeaves } : {}) });
    result.value = r;
    report.value = formatReport(r);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
    result.value = null;
    report.value = "";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="verifier">
    <p v-if="!supported" class="warn">This browser's WebCrypto has no Ed25519 support, so the verifier cannot run here. Use the CLI, or a current Chrome, Firefox, or Safari.</p>

    <div class="drop" :class="{ over }" @dragover.prevent="over = true" @dragleave="over = false" @drop.prevent="onDrop">
      <p>Drop a receipt file here (<code>receipts/&lt;id&gt;.json</code>), or <label class="pick" for="vf-file">choose a file</label>.</p>
      <input id="vf-file" class="visually-hidden" type="file" accept=".json,application/json" @change="onPick" />
    </div>
    <label for="vf-bundle">Or paste the receipt JSON</label>
    <textarea id="vf-bundle" v-model="bundleText" rows="8" spellcheck="false" placeholder='{ "envelope": ..., "treeHead": ..., "inclusion": ... }'></textarea>

    <label for="vf-issuer">Issuer public key: the gateway's or the agent's, SPKI PEM, one or more</label>
    <textarea id="vf-issuer" v-model="issuerPem" rows="4" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea>

    <details class="optional" :open="optionalOpen" @toggle="optionalOpen = ($event.target as HTMLDetailsElement).open">
      <summary>Optional inputs</summary>
      <div class="grid">
        <div><label for="vf-principal">Principal public keys, for gateway receipts</label><textarea id="vf-principal" v-model="principalPem" rows="4" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
        <div><label for="vf-approval">Approver public keys, for approved actions</label><textarea id="vf-approval" v-model="approvalPem" rows="4" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
        <div><label for="vf-log">Log public keys, for receipts in a remote log</label><textarea id="vf-log" v-model="logPem" rows="4" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
        <div><label for="vf-upstream">Upstream public keys, when the tool signed its result</label><textarea id="vf-upstream" v-model="upstreamPem" rows="4" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
        <div><label for="vf-stripe">Stripe webhook signing secret, when a Stripe event is attached (stays in your browser)</label><input id="vf-stripe" v-model="stripeSecret" type="password" autocomplete="off" placeholder="whsec_…" /></div>
        <div><label for="vf-github">GitHub webhook secret, when a GitHub delivery is attached (stays in your browser)</label><input id="vf-github" v-model="githubSecret" type="password" autocomplete="off" /></div>
        <div class="wide"><label for="vf-logcopy">A copy of the log (<code>log.jsonl</code>, one JSON string per line)</label><textarea id="vf-logcopy" v-model="logText" rows="4" spellcheck="false" placeholder='"eyJ..."'></textarea></div>
      </div>
    </details>

    <div class="samples">
      <span>Or try a sample:</span>
      <button v-for="c in samples" :key="c.name" type="button" class="chip" :title="c.name" @click="load(c)">{{ SAMPLE_LABELS[c.name] ?? c.name }}</button>
      <button type="button" class="chip tamper" :disabled="!bundleText" @click="tamper">Change one byte of the receipt</button>
    </div>

    <div class="actions">
      <button class="btn" type="button" :disabled="busy || !supported || !bundleText" @click="verify">{{ busy ? "Verifying…" : "Verify" }}</button>
    </div>

    <div class="result-region" role="status" aria-live="polite">
      <div v-if="result" :class="['result-card', result.ok ? 'ok' : 'bad']">
        <p class="verdict">{{ result.ok ? "Verified" : "Not verified" }}</p>
        <p v-if="result.ok">Every check passed: the receipt is signed by the key you gave, and nothing in it changed.</p>
        <p v-else>{{ failed.length }} {{ failed.length === 1 ? "check" : "checks" }} failed: {{ failed.join("; ") }}.</p>
        <p v-if="result.treeHeadSigner" class="signer">The tree head is signed by the {{ result.treeHeadSigner }}.</p>
        <details class="full"><summary>Full report</summary><pre class="report">{{ report }}</pre></details>
      </div>
      <p v-if="error" class="warn">{{ error }}</p>
    </div>
    <p class="note">Runs entirely in your browser: WebCrypto Ed25519 and SHA-256, no upload. The checks, their order, and their names are those of the reference verifier, and this implementation passes every published <a href="/receipt/vectors">conformance vector</a>.</p>
  </div>
</template>

<style scoped>
.verifier { margin: 1rem 0 2rem; }
.drop { border: 1.5px dashed var(--line-strong); border-radius: var(--radius-md); padding: 1.25rem; text-align: center; color: var(--vp-c-text-2); }
.drop.over { border-color: var(--accent); background: var(--accent-bg); }
.drop p { margin: 0; }
.pick { display: inline; margin: 0; font-size: inherit; color: var(--accent); text-decoration: underline; cursor: pointer; }
.pick:focus-within, #vf-file:focus-visible + .pick { outline: 2px solid var(--accent); }
.visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); border: 0; }
.optional { margin-top: 1rem; border: 1px solid var(--line); border-radius: var(--radius-md); padding: 0.5rem 1rem 1rem; }
.optional summary { cursor: pointer; font-weight: 600; padding: 0.25rem 0; }
.grid .wide { grid-column: 1 / -1; }
.samples { margin-top: 1rem; }
.result-card { margin-top: 1rem; padding: 1rem 1.25rem; border-radius: var(--radius-md); border: 1px solid var(--line); background: var(--panel); }
.result-card.ok { border-color: var(--ok); background: var(--ok-bg); }
.result-card.bad { border-color: var(--bad); background: var(--bad-bg); }
.result-card p { margin: 0.25rem 0; }
.result-card .full summary { cursor: pointer; font-size: 0.85rem; margin-top: 0.5rem; }
label { display: block; font-size: 0.85rem; color: var(--vp-c-text-2); margin: 0.75rem 0 0.25rem; }
input, textarea { width: 100%; font: var(--text-xs)/1.4 var(--vp-font-family-mono); padding: 0.5rem; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--vp-c-bg-alt); color: var(--vp-c-text-1); resize: vertical; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 1rem; }
@media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
.samples { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; font-size: 0.85rem; color: var(--vp-c-text-2); }
.chip { font: var(--text-xs) var(--vp-font-family-mono); padding: 0.2rem 0.55rem; border: 1px solid var(--vp-c-divider); border-radius: var(--radius-full); background: var(--vp-c-bg-soft); color: var(--vp-c-text-1); cursor: pointer; }
.chip.tamper { border-color: var(--vp-c-danger-1); color: var(--vp-c-danger-1); }
.chip:disabled { opacity: 0.5; cursor: default; }
.actions { display: flex; align-items: center; gap: 1rem; margin-top: 1rem; }
.verdict { font-weight: 700; font-size: var(--text-lg); }
.result-card.ok .verdict { color: var(--ok); } .result-card.bad .verdict { color: var(--bad); }
.signer { font-size: 0.85rem; color: var(--vp-c-text-2); }
.report { margin-top: 1rem; font-size: var(--text-xs); line-height: 1.45; white-space: pre; overflow-x: auto; }
.warn { color: var(--vp-c-danger-1); }
.note { font-size: 0.85rem; color: var(--vp-c-text-2); }
</style>

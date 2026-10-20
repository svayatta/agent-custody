<script setup lang="ts">
// The receipt verifier, in the page. Everything runs in the visitor's browser; nothing is uploaded anywhere.
import { computed, onMounted, ref } from "vue";
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
    <div class="samples">
      <span>Load a sample from the conformance vectors:</span>
      <button v-for="c in samples" :key="c.name" class="chip" @click="load(c)">{{ c.name }}</button>
      <button class="chip tamper" :disabled="!bundleText" @click="tamper">tamper with the payload</button>
    </div>
    <label>Receipt bundle (the JSON in <code>receipts/&lt;id&gt;.json</code>)</label>
    <textarea v-model="bundleText" rows="10" spellcheck="false" placeholder='{ "envelope": ..., "treeHead": ..., "inclusion": ... }'></textarea>
    <div class="grid">
      <div><label>Issuer public keys (gateway or SDK app, SPKI PEM, one or more)</label><textarea v-model="issuerPem" rows="5" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
      <div><label>Principal public keys (for gateway receipts)</label><textarea v-model="principalPem" rows="5" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
      <div><label>Human approval public keys (for approved actions)</label><textarea v-model="approvalPem" rows="5" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
      <div><label>Log public keys (only for receipts logged to a remote log)</label><textarea v-model="logPem" rows="5" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
      <div><label>Upstream public keys (only when the upstream signed its result)</label><textarea v-model="upstreamPem" rows="5" spellcheck="false" placeholder="-----BEGIN PUBLIC KEY-----"></textarea></div>
      <div><label>Provider secrets (only when the upstream attached a Stripe webhook or GitHub delivery; stays in your browser)</label><input v-model="stripeSecret" placeholder="Stripe webhook signing secret, whsec_…" /><input v-model="githubSecret" placeholder="GitHub webhook secret" style="margin-top:0.3rem" /></div>
      <div><label>A copy of the log, optional (<code>log.jsonl</code>, one JSON string per line)</label><textarea v-model="logText" rows="5" spellcheck="false" placeholder='"eyJ..."'></textarea></div>
    </div>
    <div class="actions">
      <button class="run" :disabled="busy || !supported || !bundleText" @click="verify">{{ busy ? "verifying…" : "Verify" }}</button>
      <span v-if="result" :class="['verdict', result.ok ? 'ok' : 'bad']">{{ result.ok ? "VERIFIED" : "NOT VERIFIED" }}</span>
      <span v-if="result?.treeHeadSigner" class="signer">tree head signed by the {{ result.treeHeadSigner }}</span>
    </div>
    <p v-if="error" class="warn">{{ error }}</p>
    <pre v-if="report" class="report">{{ report }}</pre>
    <p class="note">Runs entirely in your browser: WebCrypto Ed25519 and SHA-256, no upload. The checks, their order, and their names are those of the reference verifier, and this implementation passes every published <a href="/receipt/vectors">conformance vector</a>.</p>
  </div>
</template>

<style scoped>
.verifier { margin: 1rem 0 2rem; }
label { display: block; font-size: 0.85rem; color: var(--vp-c-text-2); margin: 0.75rem 0 0.25rem; }
input, textarea { width: 100%; font: 12px/1.4 var(--vp-font-family-mono); padding: 0.5rem; border: 1px solid var(--vp-c-divider); border-radius: 6px; background: var(--vp-c-bg-alt); color: var(--vp-c-text-1); resize: vertical; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 1rem; }
@media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
.samples { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; font-size: 0.85rem; color: var(--vp-c-text-2); }
.chip { font: 12px var(--vp-font-family-mono); padding: 0.2rem 0.55rem; border: 1px solid var(--vp-c-divider); border-radius: 999px; background: var(--vp-c-bg-soft); color: var(--vp-c-text-1); cursor: pointer; }
.chip.tamper { border-color: var(--vp-c-danger-1); color: var(--vp-c-danger-1); }
.chip:disabled { opacity: 0.5; cursor: default; }
.actions { display: flex; align-items: center; gap: 1rem; margin-top: 1rem; }
.run { padding: 0.5rem 1.2rem; border-radius: 6px; background: var(--vp-c-brand-1); color: white; font-weight: 600; border: 0; cursor: pointer; }
.run:disabled { opacity: 0.5; cursor: default; }
.verdict { font-weight: 700; font-family: var(--vp-font-family-mono); }
.verdict.ok { color: var(--vp-c-green-1); } .verdict.bad { color: var(--vp-c-danger-1); }
.signer { font-size: 0.85rem; color: var(--vp-c-text-2); }
.report { margin-top: 1rem; font-size: 12px; line-height: 1.45; white-space: pre; overflow-x: auto; }
.warn { color: var(--vp-c-danger-1); }
.note { font-size: 0.85rem; color: var(--vp-c-text-2); }
</style>

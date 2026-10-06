<script setup lang="ts">
// The product's front door, outside the docs theme. Laid out along the lines of dunetrace.com: a centred hero with
// the three actions and the film under them, then eyebrowed sections (the problem, how it works, denied at runtime,
// not a trace, quick start, where to go). The receipt card is the gateway-denied conformance vector decoded at
// build time; every byte verifies against the published keys, the identities are the fixture's.
import { useData } from "vitepress";
import vectors from "../../../packages/receipts/vectors/receipts.json";
import Flow from "./Flow.vue";
import Demo from "./Demo.vue";

const { isDark } = useData();
const sample = "gateway-denied";
const bundle = (vectors.cases as any[]).find((c) => c.name === sample).bundle;
const decode = (b64: string) => JSON.parse(typeof Buffer !== "undefined" ? Buffer.from(b64, "base64").toString("utf8") : atob(b64));
const receipt = decode(bundle.envelope.payload).predicate;
const head = decode(bundle.treeHead.payload);
const short = (h: string) => h.slice(0, 12) + "…";
const pounds = (pence: number) => "£" + (pence / 100).toLocaleString("en-GB", { minimumFractionDigits: 2 });
const customer = receipt.facts.customer;
const year = new Date().getUTCFullYear();

const steps = [
  { n: "01", t: "Authorize", d: "A person signs a grant: which agent, which tools, for how long. The gateway trusts that key and nothing else." },
  { n: "02", t: "Gate", d: "Every call goes through the gateway. It fetches the facts itself, evaluates the policy, and forwards or denies before the tool hears anything." },
  { n: "03", t: "Record", d: "One signed receipt per call, allowed or denied: who authorized it, what the agent asked, what the gateway checked, what happened." },
  { n: "04", t: "Log", d: "The receipt's hash goes to a Merkle log whose signed heads are published on a second host. The operator cannot rewrite it unnoticed." },
  { n: "05", t: "Verify", d: "Anyone with the public keys checks a receipt, in the shell or in the browser, offline. No account, no access to the agent." },
];
</script>

<template>
  <div class="landing">
    <header class="bar">
      <a class="brand" href="/" aria-label="agent-custody home">
        <svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" class="tile" /><path d="M19 11H45V45L41.75 48 38.5 45 35.25 48 32 45 28.75 48 25.5 45 22.25 48 19 45Z" fill="#fff" /><path d="M25 20h14M25 27h14" class="ink" stroke-width="2.6" stroke-linecap="round" /><path d="M25 37.5l5 4.5 9.5-10" fill="none" class="ink" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" /></svg>
        <span>agent-custody</span>
      </a>
      <nav class="links" aria-label="Site">
        <a href="#problem">Problem</a><a href="#how">How it works</a><a href="#quickstart">Quick start</a><a href="/pricing">Pricing</a><a href="/faq">FAQ</a><a href="/blog/">Writing</a><a href="/guide/getting-started">Docs</a>
      </nav>
      <div class="acts">
        <button class="theme" type="button" :aria-label="isDark ? 'Switch to light mode' : 'Switch to dark mode'" @click="isDark = !isDark">{{ isDark ? "Light" : "Dark" }}</button>
        <a class="signin" href="https://app.agent-custody.dev/">Sign in</a>
      </div>
    </header>

    <main>
      <section class="hero">
        <h1>Proof of what your AI agents did.</h1>
        <p class="sub">agent-custody records it, denies what was never authorized, and proves it to anyone.</p>
        <p class="lede">A gateway between an agent and its tools. Every call is checked against a grant a person signed and a policy, then forwarded or denied, and a signed receipt is issued either way. The receipt's hash lands in a log nobody in the chain can rewrite. For every agent framework, in any language.</p>
        <p class="actions">
          <a class="btn primary" href="https://app.agent-custody.dev/#register">Register for a free account</a>
          <a class="btn" href="https://github.com/svayatta/agent-custody">View GitHub <span aria-hidden="true">↗</span></a>
          <a class="btn quiet" :href="`/verify?sample=${sample}`">Verify a receipt</a>
        </p>
        <figure class="promo">
          <video controls playsinline preload="none" poster="/promo-poster.jpg" width="1920" height="1080" aria-label="A 93-second narrated film. The problem: an AI agent's only record is its own log. The solution: a gateway that checks a signed grant and a policy on every call, issues a signed receipt, and logs it where nobody in the chain can rewrite it. Then a refund agent caught by a prompt injection, the denial receipt, and its verification.">
            <source src="/promo.mp4" type="video/mp4" />
            <track kind="captions" src="/promo.vtt" srclang="en" label="English" />
          </video>
          <figcaption>93 seconds, narrated. What agent-custody is, how it works, and a refund agent caught by a prompt injection. The receipts in it are real ones from <code>bun run demo</code>, against a stand-in Stripe.</figcaption>
        </figure>
      </section>

      <section id="problem" class="block">
        <h2>Your agents' record is their own word.</h2>
        <p class="intro">When an agent acts wrongly, the only account of it is the log its own process wrote, kept by the team that ran it. Every field is a claim. Nobody outside the team can tell what was authorized from what merely happened.</p>
        <div class="split">
          <div class="cards">
            <div class="card"><p class="tag">Made-up authority</p><p>The agent refunds £50,000. Its log says the customer asked for it. Nobody signed anything that allowed it.</p><p class="looks">Looks like: a closed ticket</p></div>
            <div class="card"><p class="tag">A log that can be edited</p><p>The team that ran the agent holds the log. After the incident, the entry that matters is gone, or different, and nobody can tell.</p><p class="looks">Looks like: a clean audit</p></div>
            <div class="card"><p class="tag">Evidence nobody else can check</p><p>Traces sit in a vendor account. The auditor, the customer, or the regulator gets a screenshot and a promise.</p><p class="looks">Looks like: compliance</p></div>
          </div>
          <figure class="receipt">
            <figcaption>What a gateway receipt looks like instead</figcaption>
            <dl>
              <dt>decision</dt><dd><span class="decision" :data-d="receipt.policy.decision">{{ receipt.execution.status }}</span> <span class="why">{{ receipt.execution.reason }}</span></dd>
              <dt>tool</dt><dd>{{ receipt.tool.name }} <span class="why">{{ receipt.tool.provenance }}</span></dd>
              <dt>asked for</dt><dd>refund {{ pounds(receipt.request.args.amount) }} to {{ receipt.request.args.customer_id }} <span class="why">{{ receipt.request.provenance }}</span></dd>
              <dt>gateway checked</dt><dd>customer {{ customer.value.id }}, verified {{ customer.value.verified }} <span class="why">{{ customer.provenance }}, fetched by the gateway</span></dd>
              <dt>policy</dt><dd>refunds up to £1,000, verified customer · {{ short(receipt.policy.policyDigest) }}</dd>
              <dt>agent</dt><dd>{{ receipt.agent.id }} <span class="why">{{ receipt.agent.provenance }}</span></dd>
              <dt>authorized by</dt><dd>{{ receipt.principal.id }} <span class="why">{{ receipt.principal.provenance }}, a grant they signed</span></dd>
              <dt>log</dt><dd>leaf {{ bundle.inclusion.leafIndex + 1 }} of {{ head.treeSize }} · root {{ short(head.rootHash) }}</dd>
            </dl>
            <p class="open"><a :href="`/verify?sample=${sample}`">Open in the verifier</a><span>From the published conformance vectors. Runs in your browser; nothing is uploaded.</span></p>
          </figure>
        </div>
        <p class="limit">A receipt proves what was signed, observed, and logged, and labels everything else as the agent's own claim. The <a href="/receipts/#what-a-receipt-proves-and-what-it-does-not">proof table</a> says which is which, for whoever has to sign off. Where the data goes, what reaches the log, and how secrets are handled: the <a href="/faq">FAQ</a>.</p>
      </section>

      <section id="how" class="block">
        <h2>Authorize. Gate. Record. Log. Verify.</h2>
        <ol class="numbered">
          <li v-for="s in steps" :key="s.n"><span class="n">{{ s.n }}</span><b>{{ s.t }}</b><p>{{ s.d }}</p></li>
        </ol>
        <Flow />
      </section>

      <section id="enforce" class="block">
        <h2>What a policy can say.</h2>
        <p class="intro">Policies are Cedar, the language AWS wrote for authorization and proved correct. Each rule below is a real one from the examples, evaluated on facts the gateway fetched itself. The policy's digest is in every receipt, so a verifier knows which rules decided.</p>
        <div class="rules">
          <div class="rule"><b>Limits</b><p>A ceiling per call, in minor units. No floats, no rounding.</p><pre>permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 100000 };</pre></div>
          <div class="rule"><b>Facts, not claims</b><p>The gateway looks the customer up itself before deciding. The agent's own arguments are never enough.</p><pre>permit(principal, action == Action::"stripe.refund", resource)
when { context.facts.customer.verified
    && context.args.customer_id == context.facts.customer.id };</pre></div>
          <div class="rule"><b>Allowed targets</b><p>Only these accounts, these hosts, these paths. Anything else is refused before it leaves.</p><pre>permit(principal, action == Action::"payout.send", resource)
when { ["acct_treasury", "acct_payroll"].contains(context.args.to) };</pre></div>
          <div class="rule"><b>Human approval</b><p>A larger change needs a person the gateway can see approved it, in the system of record.</p><pre>permit(principal, action == Action::"pr.merge", resource)
when { context.facts.checks.all_green
    && context.facts.reviews.human_count >= 1 };</pre></div>
          <div class="rule"><b>Boundaries</b><p>Where an agent may write, and what it must say when it does.</p><pre>permit(principal, action == Action::"kb.write", resource)
when { context.args.path like "notes/*"
    && context.args has source };</pre></div>
          <div class="rule"><b>Evidence before effect</b><p>Name a tool as consequential and the authorization is logged before the call is forwarded. If the log refuses, nothing happens.</p><pre>"precommit": ["stripe.refund", "pr.merge", "deploy.promote"]</pre></div>
        </div>
        <p class="intro">Nine more, each executed by the test suite, on <a href="/receipts/policies">writing policies</a>. Run any policy in observe mode first: nothing is blocked, and every receipt records what would have been.</p>
      </section>

      <section id="runtime" class="block">
        <h2>The call never reaches the tool.</h2>
        <p class="intro">A policy is a Cedar file. The gateway evaluates it against what the agent asked and the facts it fetched itself. Consequential calls are logged before they are forwarded, so the evidence exists before the side effect does. A denial is a receipt too.</p>
        <Demo />
      </section>

      <section id="compare" class="block">
        <h2>Not a trace. Not an application log.</h2>
        <div class="wrap"><table>
          <thead><tr><th></th><th>Application log</th><th>Trace<br /><small>OpenTelemetry, LangSmith</small></th><th>Gateway receipt</th></tr></thead>
          <tbody>
            <tr><th>Written by</th><td>the agent's process</td><td>the agent's process</td><td>a gateway the agent talks to, signing with its own key</td></tr>
            <tr><th>Says the call was allowed or denied before the tool ran</th><td>no</td><td>no</td><td>yes, and the denial is a receipt too</td></tr>
            <tr><th>Who authorized it</th><td>not recorded</td><td>not recorded</td><td>the grant a person signed, embedded and verified</td></tr>
            <tr><th>Can a third party show the record was not rewritten</th><td>no</td><td>no</td><td>yes: a Merkle log with heads signed by a key the operator does not hold</td></tr>
            <tr><th>Who can check it</th><td>whoever has the log access</td><td>whoever has the tracing account</td><td>anyone with the public keys, offline</td></tr>
          </tbody>
        </table></div>
        <p class="intro">Traces stay useful. A receipt can be exported to OpenTelemetry or Splunk as one span or event per call, with the receipt id as the trace id, so the evidence and the observability sit side by side.</p>
      </section>

      <section id="for" class="block">
        <h2>Built for the calls that matter.</h2>
        <ul class="uses">
          <li><b>Payments and refunds</b><p>A support agent that can refund, within a limit, for a customer the gateway verified, with the authorization logged before the provider hears anything.</p><a href="/verify?sample=gateway-denied">The receipt on this page</a><a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/17-rest-upstream.ts">Example 17, a REST API as the upstream</a></li>
          <li><b>Agents that write code</b><p>Risk-tiered merges: low merges alone, medium needs a human the gateway can see, high is refused for any agent. The receipts are the change-management evidence SOC 2 and ISO 27001 ask for.</p><a href="/blog/risk-tiered-merges-with-evidence">How it works</a><a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts">Example 24, the merge gate</a></li>
          <li><b>Knowledge bases and runbooks</b><p>A docs agent that may read anything and write only under notes/, citing its source. A runbook edit is refused before it happens.</p><a href="/demo-langchain-kb.mp4">A 22-second film</a><a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts">Example 23, on LangChain</a></li>
          <li><b>Coding agents on your own repository</b><p>Every tool call a Claude Code session makes, as a receipt, hash-logged where the operator cannot rewrite it. This repository runs that way.</p><a href="/custody">This repository, under custody</a><a href="/reference/claude-code">The hook</a></li>
        </ul>
      </section>

      <section id="numbers" class="block">
        <h2>Measured, not promised.</h2>
        <div class="wrap"><table class="nums">
          <tbody>
            <tr><th>A policy decision</th><td>0.10 ms</td><td>Cedar, evaluated in the gateway's process</td></tr>
            <tr><th>A full gateway call</th><td>0.52 ms</td><td>agent to gateway, the fact lookup, the decision, the upstream, the receipt signed and logged, and back; upstream on the same machine</td></tr>
            <tr><th>Verifying a receipt</th><td>0.14 ms</td><td>signature, delegation, digests, inclusion proof</td></tr>
            <tr><th>A receipt</th><td>5.7 KB</td><td>a JSON file: the signed statement, the signed tree head, the inclusion proof; the log receives 32 bytes of it</td></tr>
          </tbody>
        </table></div>
        <p class="intro">Medians on an Apple-silicon laptop under Node 22, from <a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/scripts/bench.ts">the script in the repository</a>, which you can run. Your network adds whatever it adds; the hosted log is on the path only for consequential calls, and a refusal there withholds the call rather than losing the evidence.</p>
      </section>

      <section id="quickstart" class="block">
        <h2>A verified receipt in ten minutes.</h2>
        <div class="split">
          <ol class="numbered tight">
            <li><span class="n">1</span><b>Install and make keys</b><p>Node 22 or later. One key for the gateway, one for the person who signs grants.</p></li>
            <li><span class="n">2</span><b>Sign a grant</b><p>Which agent, which tools, for how long. The gateway trusts the principal's public key.</p></li>
            <li><span class="n">3</span><b>Put the gateway in front of the tools</b><p>It is an MCP server. Point your agent at it instead of at the tools, or use an SDK adapter: Claude Code, Claude Agent SDK, OpenAI Agents SDK, LangChain, Vercel AI, Python.</p></li>
            <li><span class="n">4</span><b>Verify the receipt</b><p>In the shell, or drop it on the browser verifier. Register a tenant on the hosted log and the receipt's hash is somewhere you cannot rewrite.</p></li>
          </ol>
          <div class="terminals">
            <div class="term"><div class="tbar"><span></span><span></span><span></span><em>terminal</em></div><pre># 1. install and make keys
npm install @agent-custody/receipts
npx agent-custody keygen --dir keys --name gateway
npx agent-custody keygen --dir keys --name principal

# 2. sign a grant for the agent
npx agent-custody grant --key keys/principal.key \
  --principal user_456 --agent support-agent \
  --scopes customer.lookup,stripe.refund --out grant.json

# 3. run the gateway in front of the tools
npx agent-custody gateway --config gateway.json

# 4. verify a receipt it issued
npx agent-custody verify receipts/&lt;id&gt;.json \
  --issuer-key keys/gateway.pub --principal-key keys/principal.pub</pre></div>
            <div class="term"><div class="tbar"><span></span><span></span><span></span><em>gateway.json</em></div><pre>{
  "identity": { "keyFile": "keys/gateway.key" },
  "grantFile": "grant.json",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "upstream": { "command": "your-mcp-server" },
  "precommit": ["stripe.refund"],
  "receiptsDir": "receipts",
  "log": { "url": "https://log.agent-custody.dev/t/&lt;tenant&gt;/",
           "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true }
}</pre></div>
          </div>
        </div>
        <p class="intro">The whole path, with every command's output, is <a href="/guide/getting-started">Getting started</a>. Twenty runnable tutorials cover the rest.</p>
      </section>

      <section id="go" class="block">
        <h2>Where to go next</h2>
        <div class="doors">
          <a class="door" href="/guide/getting-started"><b>Try it</b><p>Pick a stack: Claude Code, OpenAI Agents, LangChain, Vercel AI, OpenClaw, DeepSeek Harness, Hermes, Python. Ten minutes to a receipt that verifies in the browser.</p><span class="note">The SDK path records the agent's own word.</span></a>
          <a class="door" href="/receipts/usage"><b>Make it evidence</b><p>The gateway, a signed grant, and a log run by someone else. For calls that move money or touch production.</p><span class="note">Hosted log: free to 10,000 appends a month.</span></a>
          <a class="door" href="/security"><b>For security review</b><p>The questionnaire with every no left as a no, the threat model, the compliance mapping, and the FAQ on where the data goes: what a receipt holds, what reaches the log, how secrets are handled.</p><span class="note">Dated, and honest about the witness.</span></a>
        </div>
        <p class="intro">This repository is developed under custody: every tool call the coding agent makes is a receipt, hash-logged to our tenant on the hosted log. The <a href="/custody">custody page</a> shows the hook, the policy, the keys, and two of those receipts to verify. Everything you run yourself is Apache-2.0.</p>
      </section>
      <section id="writing" class="block">
        <h2>Writing</h2>
        <ul class="posts">
          <li><a href="/blog/risk-tiered-merges-with-evidence">Risk-tiered merges, with evidence</a><p>Agents open more pull requests than humans can read. The standards ask for evidence, not a reader on every change.</p></li>
          <li><a href="/blog/logs-are-claims">Logs are claims. Receipts are evidence.</a><p>The four things a record needs before a stranger can rely on it, and the honest limit of a receipt the agent wrote itself.</p></li>
        </ul>
      </section>
    </main>

    <footer>
      <ul class="flinks"><li><a href="https://github.com/svayatta/agent-custody">GitHub</a></li><li><a href="https://www.npmjs.com/org/agent-custody">npm</a></li><li><a href="https://pypi.org/project/agent-custody/">PyPI</a></li><li><a href="/reference/">Reference</a></li><li><a href="/faq">FAQ</a></li><li><a href="/blog/">Writing</a></li><li><a href="/pricing">Pricing</a></li><li><a href="/security">Security</a></li><li><a href="/privacy">Privacy</a></li><li><a href="/terms">Terms</a></li><li><a href="/contact">Contact</a></li></ul>
      <p>Apache-2.0. Charioteer Consulting Ltd, {{ year }}.</p>
    </footer>
  </div>
</template>

<style scoped>
.landing { --amber: var(--vp-c-brand-1); --mono: var(--vp-font-family-mono); --serif: "Source Serif 4", Georgia, "Times New Roman", serif; --paper: color-mix(in srgb, var(--vp-c-bg) 96%, #b45309); --panel: var(--vp-c-bg); --term: #1b1b1f; min-height: 100vh; background: var(--paper); color: var(--vp-c-text-1); font-family: var(--vp-font-family-base); line-height: 1.55; }
.bar { display: flex; align-items: center; gap: 1.2rem; max-width: 72rem; margin: 0 auto; padding: 1rem 1.25rem; }
.brand { display: inline-flex; align-items: center; gap: .7rem; font-family: var(--serif); font-weight: 600; font-size: 1.35rem; color: var(--vp-c-text-1); text-decoration: none; white-space: nowrap; }
.brand svg { width: 40px; height: 40px; display: block; flex: none; } .tile { fill: var(--amber); } .ink { stroke: var(--amber); }
.bar .links { display: flex; gap: 1.1rem; align-items: center; font-size: .92rem; margin-left: auto; white-space: nowrap; }
.bar .links a { color: var(--vp-c-text-2); text-decoration: none; } .bar .links a:hover { color: var(--vp-c-text-1); }
.bar .acts { display: flex; gap: .7rem; align-items: center; flex: none; }
.bar .theme { font: inherit; font-size: .8rem; color: var(--vp-c-text-2); background: transparent; border: 1px solid var(--vp-c-divider); border-radius: 5px; padding: .15rem .55rem; cursor: pointer; } .bar .theme:hover { color: var(--vp-c-text-1); }
.bar .signin { padding: .4rem .9rem; border-radius: 6px; background: var(--amber); color: #fff !important; font-weight: 600; }
main { max-width: 72rem; margin: 0 auto; padding: 1rem 1.25rem 3rem; }

.hero { text-align: center; padding: 2.5rem 0 1rem; }
h1 { font-family: var(--serif); font-weight: 500; font-size: clamp(2.3rem, 6.5vw, 4rem); line-height: 1.08; letter-spacing: 0; margin: 0 auto .6rem; max-width: 18em; text-wrap: balance; }
.sub { font-family: var(--serif); font-weight: 500; font-size: clamp(1.2rem, 2.6vw, 1.7rem); color: var(--amber); margin: 0 auto 1rem; max-width: 30em; text-wrap: balance; }
.lede { font-size: 1.05rem; line-height: 1.6; color: var(--vp-c-text-2); margin: 0 auto 1.6rem; max-width: 40em; }
.actions { display: flex; gap: .7rem; justify-content: center; flex-wrap: wrap; margin: 0 0 2.2rem; }
.btn { display: inline-block; padding: .7rem 1.25rem; border-radius: 7px; border: 1px solid var(--vp-c-text-1); color: var(--vp-c-text-1); font-weight: 600; text-decoration: none; background: var(--panel); }
.btn.primary { background: var(--amber); border-color: var(--amber); color: #fff; } .btn.primary:hover { filter: brightness(1.08); }
.btn.quiet { border-color: var(--vp-c-divider); font-weight: 500; }
.promo { margin: 0 auto; max-width: 56rem; text-align: left; }
.promo video { display: block; width: 100%; height: auto; border: 1px solid var(--vp-c-divider); border-radius: 10px; background: var(--term); box-shadow: 0 20px 50px -30px rgba(0, 0, 0, .45); }
.promo figcaption { margin-top: .7rem; font-size: .88rem; color: var(--vp-c-text-2); text-align: center; }

.block { padding: 3.5rem 0 1rem; border-top: 1px solid var(--vp-c-divider); margin-top: 2.5rem; }
h2 { font-family: var(--serif); font-weight: 500; font-size: clamp(1.6rem, 3.4vw, 2.3rem); line-height: 1.15; margin: 0 0 .8rem; text-wrap: balance; }
.intro { font-size: 1.02rem; color: var(--vp-c-text-2); max-width: 46em; margin: 0 0 1.6rem; }
.intro a, .limit a, footer a { color: var(--vp-c-text-1); text-decoration: underline; text-underline-offset: .18em; }
.split { display: grid; grid-template-columns: 1fr 1fr; gap: 1.4rem; align-items: start; margin: 0 0 1.4rem; }
.cards { display: grid; gap: .9rem; }
.card { background: var(--panel); border: 1px solid var(--vp-c-divider); border-radius: 8px; padding: 1rem 1.1rem; }
.card p { margin: 0; color: var(--vp-c-text-1); font-size: .95rem; }
.card .tag { font-family: var(--mono); font-size: .72rem; letter-spacing: .1em; text-transform: uppercase; color: var(--amber); margin: 0 0 .4rem; }
.card .looks { margin-top: .55rem; padding-top: .5rem; border-top: 1px solid var(--vp-c-divider); font-size: .82rem; color: var(--vp-c-text-2); }
.receipt { margin: 0; padding: 1rem 1.2rem 1.1rem; border: 1px solid var(--vp-c-divider); border-radius: 8px; background: var(--panel); font-family: var(--mono); font-size: .82rem; }
.receipt figcaption { font-family: var(--vp-font-family-base); font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; color: var(--vp-c-text-2); margin: 0 0 .8rem; }
.receipt dl { display: grid; grid-template-columns: max-content 1fr; gap: .34rem 1rem; margin: 0; }
.receipt dt { color: var(--vp-c-text-2); } .receipt dd { margin: 0; overflow-wrap: anywhere; }
.decision { text-transform: uppercase; font-weight: 700; letter-spacing: .06em; padding: 0 .4rem; border: 1.5px solid currentColor; border-radius: 3px; }
.decision[data-d="deny"] { color: var(--vp-c-danger-1); } .decision[data-d="allow"] { color: var(--vp-c-success-1); }
.why { color: var(--vp-c-text-2); }
.open { display: flex; gap: .8rem; align-items: center; flex-wrap: wrap; margin: .9rem 0 0; font-family: var(--vp-font-family-base); font-size: .86rem; }
.open a { display: inline-block; padding: .4rem .85rem; border: 1px solid var(--vp-c-text-1); border-radius: 6px; color: var(--vp-c-text-1); font-weight: 600; text-decoration: none; }
.open span { color: var(--vp-c-text-2); }
.limit { font-size: .95rem; color: var(--vp-c-text-2); margin: 0; max-width: 46em; }

.numbered { list-style: none; margin: 0 0 2rem; padding: 0; display: grid; grid-template-columns: repeat(5, 1fr); gap: .9rem; }
.numbered li { background: var(--panel); border: 1px solid var(--vp-c-divider); border-radius: 8px; padding: 1rem 1.1rem; display: grid; gap: .3rem; align-content: start; }
.numbered .n { font-family: var(--mono); font-size: .74rem; color: var(--amber); letter-spacing: .08em; }
.numbered b { font-size: 1rem; } .numbered p { margin: 0; font-size: .9rem; color: var(--vp-c-text-2); }
.numbered.tight { grid-template-columns: 1fr; gap: .6rem; margin: 0; } .numbered.tight li { grid-template-columns: 2rem 1fr; grid-template-areas: "n t" "n p"; column-gap: .6rem; } .numbered.tight .n { grid-area: n; font-size: 1rem; } .numbered.tight b { grid-area: t; } .numbered.tight p { grid-area: p; }
.terminals { display: grid; gap: .9rem; min-width: 0; }
.term { background: var(--term); color: #e6ecf0; border-radius: 8px; overflow: hidden; border: 1px solid #2a2a30; }
.tbar { display: flex; align-items: center; gap: .4rem; padding: .5rem .8rem; background: #26262c; } .tbar span { width: 10px; height: 10px; border-radius: 50%; background: #55555e; } .tbar span:first-child { background: #ff5f57; } .tbar span:nth-child(2) { background: #febc2e; } .tbar span:nth-child(3) { background: #28c840; } .tbar em { margin-left: .5rem; font: .74rem var(--mono); color: #9fb0bd; font-style: normal; }
.term pre { margin: 0; padding: .9rem 1rem; font: .8rem/1.55 var(--mono); overflow-x: auto; white-space: pre; }
.wrap { overflow-x: auto; margin: 0 0 1.2rem; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; min-width: 36rem; background: var(--panel); border: 1px solid var(--vp-c-divider); border-radius: 8px; }
th, td { text-align: left; vertical-align: top; padding: .6rem .8rem; border-bottom: 1px solid var(--vp-c-divider); }
thead th { font-family: var(--mono); font-size: .72rem; letter-spacing: .06em; text-transform: uppercase; color: var(--vp-c-text-2); } thead small { text-transform: none; letter-spacing: 0; font-family: var(--vp-font-family-base); font-weight: 400; }
tbody th { font-weight: 600; width: 30%; } td { color: var(--vp-c-text-2); } td:last-child { color: var(--vp-c-text-1); }
.doors { display: grid; grid-template-columns: repeat(3, 1fr); gap: .9rem; margin: 0 0 1.6rem; }
.door { display: flex; flex-direction: column; gap: .5rem; padding: 1rem 1.1rem 1.1rem; border: 1px solid var(--vp-c-divider); border-radius: 8px; color: var(--vp-c-text-1); text-decoration: none; background: var(--panel); }
.door:hover { border-color: var(--vp-c-text-2); }
.door b { font-size: 1.05rem; } .door p { margin: 0; font-size: .9rem; color: var(--vp-c-text-2); flex: 1; }
.door .note { font-family: var(--mono); font-size: .72rem; color: var(--vp-c-text-2); padding-top: .5rem; border-top: 1px solid var(--vp-c-divider); }
footer { max-width: 72rem; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; border-top: 1px solid var(--vp-c-divider); font-size: .85rem; color: var(--vp-c-text-2); }
.rules { display: grid; grid-template-columns: repeat(3, 1fr); gap: .9rem; margin: 0 0 1.2rem; }
.rule { background: var(--panel); border: 1px solid var(--vp-c-divider); border-radius: 8px; padding: 1rem 1.1rem; display: grid; gap: .4rem; align-content: start; min-width: 0; }
.rule b { font-size: 1rem; } .rule p { margin: 0; font-size: .9rem; color: var(--vp-c-text-2); }
.rule pre { margin: .3rem 0 0; padding: .7rem .8rem; background: var(--vp-c-bg-soft); border-radius: 6px; font: .76rem/1.5 var(--mono); overflow-x: auto; white-space: pre; color: var(--vp-c-text-1); }
.uses { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(2, 1fr); gap: .9rem; }
.uses li { background: var(--panel); border: 1px solid var(--vp-c-divider); border-radius: 8px; padding: 1rem 1.1rem; display: grid; gap: .35rem; align-content: start; }
.uses b { font-size: 1rem; } .uses p { margin: 0 0 .3rem; font-size: .9rem; color: var(--vp-c-text-2); }
.uses a { font-size: .88rem; color: var(--vp-c-text-1); text-decoration: underline; text-underline-offset: .18em; }
.nums { min-width: 0; } .nums th { width: 28%; } .nums td:nth-child(2) { white-space: nowrap; font-family: var(--mono); color: var(--vp-c-text-1); font-size: .95rem; }
.posts { list-style: none; margin: 0; padding: 0; display: grid; gap: .9rem; }
.posts li { display: grid; gap: .2rem; padding: .9rem 0; border-top: 1px solid var(--vp-c-divider); }
.posts a { font-family: var(--serif); font-size: 1.2rem; color: var(--vp-c-text-1); text-decoration: none; } .posts a:hover { text-decoration: underline; text-underline-offset: .18em; }
.posts p { margin: 0; font-size: .92rem; color: var(--vp-c-text-2); max-width: 46em; }
.flinks { list-style: none; margin: 0 0 .5rem; padding: 0; display: flex; flex-wrap: wrap; gap: .3rem 1.1rem; }
footer p { margin: 0 0 .3rem; }
@media (max-width: 60rem) { .numbered { grid-template-columns: repeat(2, 1fr); } .split { grid-template-columns: 1fr; } .doors { grid-template-columns: 1fr; } .rules { grid-template-columns: 1fr 1fr; } .uses { grid-template-columns: 1fr; } }
/* On a phone the bar is two rows: the brand with the switch and Sign in, then the section links on a row that scrolls sideways instead of wrapping. */
@media (max-width: 48rem) {
  .bar { flex-wrap: wrap; row-gap: .5rem; }
  .brand { font-size: 1.15rem; } .brand svg { width: 32px; height: 32px; }
  .bar .acts { margin-left: auto; }
  .bar .links { flex: 1 0 100%; margin: 0; order: 3; overflow-x: auto; -webkit-overflow-scrolling: touch; scrollbar-width: none; padding-bottom: .15rem; gap: 1rem; }
  .bar .links::-webkit-scrollbar { display: none; }
}
@media (max-width: 40rem) { .numbered { grid-template-columns: 1fr; } .rules { grid-template-columns: 1fr; } .receipt dl { grid-template-columns: 1fr; gap: .1rem; } .receipt dt { margin-top: .5rem; } .bar .signin { padding: .35rem .75rem; } }
</style>

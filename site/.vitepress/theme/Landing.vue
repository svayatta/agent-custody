<script setup lang="ts">
// The product's front door, outside the docs theme. The visual world is the one the product makes: a record. Ledger
// paper with a cool ground and hairline rules; a grotesque with tabular figures (Archivo) and a receipt face (IBM Plex
// Mono); one accent, the brand amber, spent on the mark and the primary action. The one decorated object on the page
// is the receipt itself, set as a slip with perforated edges and a rubber stamp for the decision. It is the
// gateway-denied conformance vector decoded at build time: every byte verifies against the published keys; the
// identities are the fixture's. Everything else is rules, not boxes.
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
const when = receipt.timestamp.replace("T", " ").slice(0, 19) + " UTC";
const year = new Date().getUTCFullYear();

const steps = [
  { t: "Authorize", d: "A person signs a grant: which agent, which tools, for how long. The gateway trusts that key and nothing else." },
  { t: "Gate", d: "Every call goes through the gateway. It fetches the facts itself, evaluates the policy, and forwards or denies before the tool hears anything." },
  { t: "Record", d: "One signed receipt per call, allowed or denied: who authorized it, what the agent asked, what the gateway checked, what happened." },
  { t: "Log", d: "The receipt's hash goes to a Merkle log whose signed heads are published on a second host. The operator cannot rewrite it unnoticed." },
  { t: "Verify", d: "Anyone with the public keys checks a receipt, in the shell or in the browser, offline. No account, no access to the agent." },
];
const rules = [
  { t: "Limits", d: "A ceiling per call, in minor units. No floats, no rounding.", c: 'permit(principal, action == Action::"stripe.refund", resource)\nwhen { context.args.amount <= 100000 };' },
  { t: "Facts, not claims", d: "The gateway looks the customer up itself before deciding. The agent's own arguments are never enough.", c: 'permit(principal, action == Action::"stripe.refund", resource)\nwhen { context.facts.customer.verified\n    && context.args.customer_id == context.facts.customer.id };' },
  { t: "Allowed targets", d: "Only these accounts, these hosts, these paths. Anything else is refused before it leaves.", c: 'permit(principal, action == Action::"payout.send", resource)\nwhen { ["acct_treasury", "acct_payroll"].contains(context.args.to) };' },
  { t: "Human approval", d: "A larger change needs a person the gateway can see approved it, in the system of record.", c: 'permit(principal, action == Action::"pr.merge", resource)\nwhen { context.facts.checks.all_green\n    && context.facts.reviews.human_count >= 1 };' },
  { t: "Boundaries", d: "Where an agent may write, and what it must say when it does.", c: 'permit(principal, action == Action::"kb.write", resource)\nwhen { context.args.path like "notes/*"\n    && context.args has source };' },
  { t: "Evidence before effect", d: "Name a tool as consequential and the authorization is logged before the call is forwarded. If the log refuses, nothing happens.", c: '"precommit": ["stripe.refund", "pr.merge", "deploy.promote"]' },
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
        <a href="#problem">Problem</a><a href="#how">How it works</a><a href="#enforce">Policies</a><a href="/use-cases">Use cases</a><a href="/pricing">Pricing</a><a href="/faq">FAQ</a><a href="/blog/">Writing</a><a href="/guide/getting-started">Docs</a>
      </nav>
      <div class="acts">
        <button class="theme" type="button" :aria-label="isDark ? 'Switch to light mode' : 'Switch to dark mode'" @click="isDark = !isDark">{{ isDark ? "Light" : "Dark" }}</button>
        <a class="signin" href="https://app.agent-custody.dev/">Sign in</a>
      </div>
    </header>

    <main>
      <section class="hero">
        <div class="say">
          <h1>Proof of what your AI agents did.</h1>
          <p class="lede">A gateway between an agent and its tools. Every call is checked against a grant a person signed and a policy, then forwarded or denied, and a signed receipt is issued either way. The receipt's hash lands in a log nobody in the chain can rewrite. Anyone with the public keys can verify it, offline.</p>
          <p class="actions">
            <a class="btn primary" href="https://app.agent-custody.dev/#register">Create a free account</a>
            <a class="btn" href="https://github.com/svayatta/agent-custody">View the source on GitHub</a>
          </p>
          <p class="fine">Open source, Apache-2.0. The hosted log is free to ten thousand appends a month. Works with Claude Code, the OpenAI Agents SDK, LangChain, OpenClaw, DeepSeek Harness, Hermes, Python, and any MCP host.</p>
        </div>

        <figure class="slip" aria-label="A receipt: a £50,000 refund the policy refused before it reached the payment provider.">
          <div class="stamp" :data-d="receipt.policy.decision" aria-hidden="true">{{ receipt.execution.status }}</div>
          <div class="slip-head">
            <span>agent-custody receipt</span>
            <span>{{ when }}</span>
          </div>
          <dl>
            <dt>tool</dt><dd>{{ receipt.tool.name }}</dd>
            <dt>asked for</dt><dd>refund {{ pounds(receipt.request.args.amount) }} to {{ receipt.request.args.customer_id }}</dd>
            <dt>gateway checked</dt><dd>customer {{ customer.value.id }}, verified {{ customer.value.verified }}</dd>
            <dt>policy</dt><dd>refunds to £1,000 for a verified customer<br /><small>sha256 {{ short(receipt.policy.policyDigest) }}</small></dd>
            <dt>decision</dt><dd>{{ receipt.policy.decision }}, {{ receipt.execution.reason }}</dd>
            <dt>agent</dt><dd>{{ receipt.agent.id }} <small>{{ receipt.agent.provenance }}</small></dd>
            <dt>authorized by</dt><dd>{{ receipt.principal.id }} <small>{{ receipt.principal.provenance }}, a grant they signed</small></dd>
            <dt>log</dt><dd>leaf {{ bundle.inclusion.leafIndex + 1 }} of {{ head.treeSize }}<br /><small>root {{ short(head.rootHash) }}</small></dd>
            <dt>receipt</dt><dd><small>{{ receipt.receiptId }}</small></dd>
          </dl>
          <div class="slip-foot">
            <a :href="`/verify?sample=${sample}`">Verify this receipt</a>
            <span>In your browser, with the published keys. Nothing is uploaded.</span>
          </div>
        </figure>
      </section>

      <figure class="promo">
        <video controls playsinline preload="none" poster="/promo-poster.jpg" width="1920" height="1080" aria-label="A 93-second narrated film. The problem: an AI agent's only record is its own log. The solution: a gateway that checks a signed grant and a policy on every call, issues a signed receipt, and logs it where nobody in the chain can rewrite it. Then a refund agent caught by a prompt injection, the denial receipt, and its verification.">
          <source src="/promo.mp4" type="video/mp4" />
          <track kind="captions" src="/promo.vtt" srclang="en" label="English" />
        </video>
        <figcaption>93 seconds, narrated. What agent-custody is, how it works, and a refund agent caught by a prompt injection. The receipts in it are real ones from <code>bun run demo</code>, against a stand-in Stripe.</figcaption>
      </figure>

      <section id="problem" class="block">
        <h2>Your agents' record is their own word.</h2>
        <p class="intro">When an agent acts wrongly, the only account of it is the log its own process wrote, kept by the team that ran it. Every field is a claim. Nobody outside the team can tell what was authorized from what merely happened.</p>
        <dl class="ledger">
          <div><dt>Made-up authority</dt><dd>The agent refunds £50,000. Its log says the customer asked for it. Nobody signed anything that allowed it. It looks like a closed ticket.</dd></div>
          <div><dt>A log that can be edited</dt><dd>The team that ran the agent holds the log. After the incident, the entry that matters is gone, or different, and nobody can tell. It looks like a clean audit.</dd></div>
          <div><dt>Evidence nobody else can check</dt><dd>Traces sit in a vendor account. The auditor, the customer, or the regulator gets a screenshot and a promise. It looks like compliance.</dd></div>
        </dl>
        <p class="intro">A receipt proves what was signed, observed, and logged, and labels everything else as the agent's own claim. The <a href="/receipts/#what-a-receipt-proves-and-what-it-does-not">proof table</a> says which is which, for whoever has to sign off. Where the data goes, what reaches the log, and how secrets are handled: the <a href="/faq">FAQ</a>.</p>
      </section>

      <section id="how" class="block">
        <h2>Authorize. Gate. Record. Log. Verify.</h2>
        <ol class="steps">
          <li v-for="(s, i) in steps" :key="s.t"><span class="n">{{ i + 1 }}</span><div><b>{{ s.t }}</b><p>{{ s.d }}</p></div></li>
        </ol>
        <Flow />
      </section>

      <section id="enforce" class="block">
        <h2>What a policy can say.</h2>
        <p class="intro">Policies are Cedar, the language AWS wrote for authorization and proved correct. Each rule below is a real one from the examples, evaluated on facts the gateway fetched itself. The policy's digest is in every receipt, so a verifier knows which rules decided.</p>
        <div class="rules">
          <div class="rule" v-for="r in rules" :key="r.t">
            <div class="rule-say"><b>{{ r.t }}</b><p>{{ r.d }}</p></div>
            <pre>{{ r.c }}</pre>
          </div>
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
        <div class="wrap"><table class="cmp">
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
        <p class="intro">Four of them below, each with something to run. Crypto wallets, exchanges and payment providers, e-commerce, and legal technology, each with its policy and what the receipt proves, are on the <a href="/use-cases">use cases page</a>.</p>
        <dl class="ledger uses">
          <div><dt>Payments and refunds</dt><dd><p>A support agent that can refund, within a limit, for a customer the gateway verified, with the authorization logged before the provider hears anything.</p><a :href="`/verify?sample=${sample}`">The receipt on this page</a><a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/17-rest-upstream.ts">Example 17, a REST API as the upstream</a></dd></div>
          <div><dt>Agents that write code</dt><dd><p>Risk-tiered merges: low merges alone, medium needs a human the gateway can see, high is refused for any agent. The receipts are the change-management evidence SOC 2 and ISO 27001 ask for.</p><a href="/blog/risk-tiered-merges-with-evidence">How it works</a><a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts">Example 24, the merge gate</a></dd></div>
          <div><dt>Knowledge bases and runbooks</dt><dd><p>A docs agent that may read anything and write only under notes/, citing its source. A runbook edit is refused before it happens.</p><a href="/demo-langchain-kb.mp4">A 22-second film</a><a href="https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts">Example 23, on LangChain</a></dd></div>
          <div><dt>Coding agents on your own repository</dt><dd><p>Every tool call a Claude Code session makes, as a receipt, hash-logged where the operator cannot rewrite it. This repository runs that way.</p><a href="/custody">This repository, under custody</a><a href="/reference/claude-code">The hook</a></dd></div>
        </dl>
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
          <ol class="steps tight">
            <li><span class="n">1</span><div><b>Install and make keys</b><p>Node 22 or later. One key for the gateway, one for the person who signs grants.</p></div></li>
            <li><span class="n">2</span><div><b>Sign a grant</b><p>Which agent, which tools, for how long. The gateway trusts the principal's public key.</p></div></li>
            <li><span class="n">3</span><div><b>Put the gateway in front of the tools</b><p>It is an MCP server. Point your agent at it instead of at the tools, or use an SDK adapter for your framework.</p></div></li>
            <li><span class="n">4</span><div><b>Verify the receipt</b><p>In the shell, or drop it on the browser verifier. Register a tenant on the hosted log and the receipt's hash is somewhere you cannot rewrite.</p></div></li>
          </ol>
          <div class="terminals">
            <div class="term"><div class="tbar"><em>terminal</em></div><pre># 1. install and make keys
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
            <div class="term"><div class="tbar"><em>gateway.json</em></div><pre>{
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
        <p class="intro">The whole path, with every command's output, is <a href="/guide/getting-started">Getting started</a>. Twenty-four runnable tutorials cover the rest.</p>
      </section>

      <section id="go" class="block">
        <h2>Where to go next</h2>
        <dl class="ledger doors">
          <div><dt><a href="/guide/getting-started">Try it</a></dt><dd>Pick a stack: Claude Code, OpenAI Agents, LangChain, Vercel AI, OpenClaw, DeepSeek Harness, Hermes, Python. Ten minutes to a receipt that verifies in the browser. The SDK path records the agent's own word.</dd></div>
          <div><dt><a href="/receipts/usage">Make it evidence</a></dt><dd>The gateway, a signed grant, and a log run by someone else. For calls that move money or touch production. The hosted log is free to ten thousand appends a month.</dd></div>
          <div><dt><a href="/security">For security review</a></dt><dd>The questionnaire with every no left as a no, the threat model, the compliance mapping, and the FAQ on where the data goes. Dated, and honest about the witness.</dd></div>
        </dl>
        <p class="intro">This repository is developed under custody: every tool call the coding agent makes is a receipt, hash-logged to our tenant on the hosted log. The <a href="/custody">custody page</a> shows the hook, the policy, the keys, and two of those receipts to verify.</p>
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
      <ul class="flinks"><li><a href="https://github.com/svayatta/agent-custody">GitHub</a></li><li><a href="https://www.npmjs.com/org/agent-custody">npm</a></li><li><a href="https://pypi.org/project/agent-custody/">PyPI</a></li><li><a href="/reference/">Reference</a></li><li><a href="/faq">FAQ</a></li><li><a href="/use-cases">Use cases</a></li><li><a href="/blog/">Writing</a></li><li><a href="/pricing">Pricing</a></li><li><a href="/security">Security</a></li><li><a href="/privacy">Privacy</a></li><li><a href="/terms">Terms</a></li><li><a href="/contact">Contact</a></li></ul>
      <p>Apache-2.0. Charioteer Consulting Ltd, {{ year }}.</p>
    </footer>
  </div>
</template>

<style scoped>
/* Tokens. Light: ledger paper, a cool off-white with a faint green bias and green-grey rules; ink with a blue bias.
   Dark: the same relationships on slate. The accent is the brand amber and appears twice: the mark and the primary action.
   The receipt slip has its own paper so it reads as a separate object laid on the page. */
.landing {
  --sans: "Archivo", "Helvetica Neue", Arial, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace;
  --vp-font-family-base: var(--sans); --vp-font-family-mono: var(--mono);
  --ground: #f4f6f2; --rule: #d6ddd3; --rule-strong: #9aa79a; --ink: #141a1f; --ink-2: #566069; --paper: #fffdf7; --paper-ink: #1a1a1a;
  --amber: #b45309; --amber-ink: #ffffff; --deny: #b3261e; --allow: #1f7a4d; --term: #141a1f; --term-ink: #e6ecf0;
  --vp-c-bg: var(--ground); --vp-c-bg-soft: #eaeee7; --vp-c-divider: var(--rule); --vp-c-text-1: var(--ink); --vp-c-text-2: var(--ink-2); --vp-c-text-3: var(--rule-strong);
  min-height: 100vh; background: var(--ground); color: var(--ink); font-family: var(--sans); font-variation-settings: "wdth" 100; line-height: 1.55; font-variant-numeric: tabular-nums;
}
.landing a { color: var(--ink); text-decoration: underline; text-decoration-color: var(--rule-strong); text-underline-offset: .2em; }
.landing a:hover { text-decoration-color: var(--ink); }
.landing :focus-visible { outline: 2px solid var(--amber); outline-offset: 2px; }

/* The bar */
.bar { display: flex; align-items: center; gap: 1.2rem; max-width: 76rem; margin: 0 auto; padding: 1rem 1.5rem; border-bottom: 1px solid var(--rule); }
.landing .brand { display: inline-flex; align-items: center; gap: .6rem; font-weight: 600; font-size: 1.1rem; letter-spacing: -.01em; text-decoration: none; }
.brand svg { width: 30px; height: 30px; display: block; flex: none; } .tile { fill: var(--amber); } .ink { stroke: var(--amber); }
.bar .links { display: flex; gap: 1.1rem; align-items: center; font-size: .92rem; margin-left: auto; white-space: nowrap; }
.bar .links a { color: var(--ink-2); text-decoration: none; } .bar .links a:hover { color: var(--ink); }
.bar .acts { display: flex; gap: .7rem; align-items: center; flex: none; }
.bar .theme { font: inherit; font-size: .8rem; color: var(--ink-2); background: transparent; border: 1px solid var(--rule); border-radius: 3px; padding: .2rem .55rem; cursor: pointer; } .bar .theme:hover { color: var(--ink); border-color: var(--rule-strong); }
.bar .signin { padding: .4rem .85rem; border: 1px solid var(--ink); border-radius: 3px; text-decoration: none; font-weight: 500; font-size: .9rem; }

main { max-width: 76rem; margin: 0 auto; padding: 0 1.5rem 3rem; }

/* The hero: the statement on the left, the receipt on the right. Left-aligned, like a ledger. */
.hero { display: grid; grid-template-columns: 7fr 5fr; gap: 3rem; align-items: start; padding: 3rem 0 2.5rem; }
h1 { font-size: clamp(2.2rem, 5.4vw, 3.6rem); font-weight: 600; font-variation-settings: "wdth" 112; line-height: 1.04; letter-spacing: -.025em; margin: 0 0 1.1rem; max-width: 12em; text-wrap: balance; }
.lede { font-size: 1.12rem; line-height: 1.55; color: var(--ink); margin: 0 0 1.6rem; max-width: 36em; }
.actions { display: flex; gap: .7rem; flex-wrap: wrap; margin: 0 0 1.1rem; }
.landing .btn { display: inline-block; padding: .7rem 1.15rem; border-radius: 3px; border: 1px solid var(--ink); color: var(--ink); font-weight: 500; text-decoration: none; background: transparent; }
.landing .btn.primary { background: var(--amber); border-color: var(--amber); color: var(--amber-ink); } .btn.primary:hover { filter: brightness(1.06); }
.fine { font-size: .86rem; color: var(--ink-2); margin: 0; max-width: 40em; }

/* The slip: the one decorated object. Receipt paper, perforated edges, a stamp for the decision. */
.slip { position: relative; margin: 0; padding: 1.4rem 1.3rem 1.2rem; background: var(--paper); color: var(--paper-ink); font-family: var(--mono); font-size: .8rem; line-height: 1.45; box-shadow: 0 1px 0 var(--rule), 0 18px 30px -24px rgba(0, 0, 0, .35); }
.slip::before, .slip::after { content: ""; position: absolute; left: 0; right: 0; height: 8px; background-size: 16px 8px; background-repeat: repeat-x; }
.slip::before { top: -8px; background-image: linear-gradient(135deg, transparent 50%, var(--paper) 50%), linear-gradient(225deg, transparent 50%, var(--paper) 50%); background-position: 0 0, 8px 0; }
.slip::after { bottom: -8px; background-image: linear-gradient(45deg, transparent 50%, var(--paper) 50%), linear-gradient(-45deg, transparent 50%, var(--paper) 50%); background-position: 0 0, 8px 0; }
.slip-head { display: grid; gap: .1rem; padding-right: 8rem; padding-bottom: .6rem; margin-bottom: .6rem; border-bottom: 1px dashed var(--rule-strong); color: var(--ink-2); }
.slip dl { display: grid; grid-template-columns: max-content 1fr; gap: .32rem 1rem; margin: 0; }
.slip dt { color: var(--ink-2); } .slip dd { margin: 0; overflow-wrap: anywhere; } .slip small { font-size: .9em; color: var(--ink-2); }
.slip-foot { display: grid; gap: .3rem; margin-top: .9rem; padding-top: .7rem; border-top: 1px dashed var(--rule-strong); font-family: var(--sans); font-size: .86rem; }
.slip-foot a { color: var(--paper-ink); font-weight: 500; } .slip-foot span { color: var(--ink-2); }
.stamp { position: absolute; top: 1.3rem; right: 1.2rem; padding: .25rem .6rem; border: 3px double currentColor; border-radius: 4px; font-family: var(--mono); font-weight: 600; font-size: 1.25rem; letter-spacing: .16em; text-transform: uppercase; color: var(--deny); transform: rotate(-11deg); opacity: .85; mix-blend-mode: multiply; animation: stamp 420ms cubic-bezier(.2, .9, .3, 1.2) 1 both; }
.stamp[data-d="allow"] { color: var(--allow); }
@keyframes stamp { from { transform: rotate(-11deg) scale(1.35); opacity: 0; } to { transform: rotate(-11deg) scale(1); opacity: .85; } }
@media (prefers-reduced-motion: reduce) { .stamp { animation: none; } }

.promo { margin: 0 0 1rem; }
.promo video { display: block; width: 100%; height: auto; background: var(--term); border: 1px solid var(--rule); }
.promo figcaption { margin-top: .6rem; font-size: .86rem; color: var(--ink-2); }

/* Sections are entries in a ledger: a double rule, a heading, the entry. */
.block { padding: 2.6rem 0 .6rem; margin-top: 2rem; border-top: 3px double var(--rule-strong); }
h2 { font-size: clamp(1.5rem, 3vw, 2.1rem); font-weight: 600; font-variation-settings: "wdth" 108; line-height: 1.15; letter-spacing: -.02em; margin: 0 0 .8rem; max-width: 22em; text-wrap: balance; }
.intro { font-size: 1rem; color: var(--ink-2); max-width: 46em; margin: 0 0 1.4rem; }

/* Ruled lists in place of cards */
.ledger { margin: 0 0 1.4rem; padding: 0; display: grid; }
.ledger > div { display: grid; grid-template-columns: 16rem 1fr; gap: 1.5rem; padding: .9rem 0; border-top: 1px solid var(--rule); }
.ledger > div:last-child { border-bottom: 1px solid var(--rule); }
.ledger dt { font-weight: 600; } .ledger dd { margin: 0; color: var(--ink-2); max-width: 46em; }
.ledger dd p { margin: 0 0 .35rem; } .ledger dd a { display: inline-block; margin-right: 1.1rem; font-size: .9rem; color: var(--ink); }
.ledger.doors dt a { font-weight: 600; }

.steps { list-style: none; margin: 0 0 2rem; padding: 0; display: grid; grid-template-columns: repeat(5, 1fr); gap: 0; border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule); }
.steps li { display: grid; grid-template-columns: 1.6rem 1fr; gap: .4rem; padding: .9rem .9rem .9rem 0; border-right: 1px solid var(--rule); margin-right: .9rem; }
.steps li:last-child { border-right: 0; margin-right: 0; }
.steps .n { font-family: var(--mono); font-size: .85rem; color: var(--ink-2); padding-top: .15rem; }
.steps b { display: block; margin-bottom: .2rem; } .steps p { margin: 0; font-size: .9rem; color: var(--ink-2); }
.steps.tight { grid-template-columns: 1fr; margin: 0; border: 0; } .steps.tight li { border-right: 0; margin-right: 0; border-top: 1px solid var(--rule); padding: .8rem 0; } .steps.tight li:last-child { border-bottom: 1px solid var(--rule); }

.rules { display: grid; margin: 0 0 1.2rem; border-top: 1px solid var(--rule); }
.rule { display: grid; grid-template-columns: 16rem 1fr; gap: 1.5rem; padding: .9rem 0; border-bottom: 1px solid var(--rule); align-items: start; }
.rule b { display: block; margin-bottom: .2rem; } .rule p { margin: 0; font-size: .9rem; color: var(--ink-2); }
.rule pre { margin: 0; padding: .7rem .9rem; background: var(--paper); color: var(--paper-ink); border-left: 2px solid var(--rule-strong); font: .78rem/1.5 var(--mono); overflow-x: auto; white-space: pre; }

.wrap { overflow-x: auto; margin: 0 0 1.2rem; }
table { border-collapse: collapse; width: 100%; font-size: .92rem; }
th, td { text-align: left; vertical-align: top; padding: .6rem .8rem .6rem 0; border-bottom: 1px solid var(--rule); }
thead th { font-weight: 600; color: var(--ink-2); border-bottom: 1px solid var(--rule-strong); } thead small { font-weight: 400; }
tbody th { font-weight: 600; width: 26%; } td { color: var(--ink-2); } .cmp td:last-child { color: var(--ink); }
.cmp { min-width: 36rem; }
.nums th { width: 22%; } .nums td:nth-child(2) { white-space: nowrap; font-family: var(--mono); color: var(--ink); }

.split { display: grid; grid-template-columns: 1fr 1.3fr; gap: 1.6rem; align-items: start; margin: 0 0 1.4rem; }
.terminals { display: grid; gap: .9rem; min-width: 0; }
.term { background: var(--term); color: var(--term-ink); border: 1px solid var(--rule); }
.tbar { padding: .45rem .9rem; border-bottom: 1px solid #2a333b; } .tbar em { font: .78rem var(--mono); color: #9aa8b3; font-style: normal; }
.term pre { margin: 0; padding: .9rem 1rem; font: .8rem/1.55 var(--mono); overflow-x: auto; white-space: pre; }

.posts { list-style: none; margin: 0; padding: 0; display: grid; }
.posts li { display: grid; gap: .2rem; padding: .9rem 0; border-top: 1px solid var(--rule); } .posts li:last-child { border-bottom: 1px solid var(--rule); }
.posts a { font-weight: 600; font-size: 1.1rem; text-decoration: none; } .posts a:hover { text-decoration: underline; }
.posts p { margin: 0; font-size: .92rem; color: var(--ink-2); max-width: 46em; }

footer { max-width: 76rem; margin: 0 auto; padding: 1.4rem 1.5rem 3rem; border-top: 3px double var(--rule-strong); font-size: .86rem; color: var(--ink-2); }
.flinks { list-style: none; margin: 0 0 .5rem; padding: 0; display: flex; flex-wrap: wrap; gap: .3rem 1.1rem; } .flinks a { color: var(--ink-2); } footer p { margin: 0; }

@media (max-width: 64rem) { .hero { grid-template-columns: 1fr; gap: 2rem; } .steps { grid-template-columns: 1fr 1fr; } .steps li { border-right: 0; margin-right: 0; border-top: 1px solid var(--rule); } .split { grid-template-columns: 1fr; } }
@media (max-width: 48rem) {
  .bar { flex-wrap: wrap; row-gap: .5rem; } .bar .acts { margin-left: auto; }
  .bar .links { flex: 1 0 100%; margin: 0; order: 3; overflow-x: auto; -webkit-overflow-scrolling: touch; scrollbar-width: none; padding-bottom: .15rem; gap: 1rem; } .bar .links::-webkit-scrollbar { display: none; }
  .ledger > div, .rule { grid-template-columns: 1fr; gap: .4rem; } .steps { grid-template-columns: 1fr; }
  .slip dl { grid-template-columns: 1fr; gap: .1rem; } .slip dt { margin-top: .45rem; } .slip-head { padding-right: 7.5rem; } .stamp { top: 1.2rem; right: .8rem; font-size: 1.05rem; }
}
</style>

<style>
/* Dark tokens live outside the scoped block: Vue's scoped compiler collapses `:global(.dark) .landing` to `.dark`, which
   sets the variables on the root where the scoped light values on .landing override them. html.dark .landing outranks
   .landing[data-v]. */
html.dark .landing {
  --ground: #0f1416; --rule: #27313a; --rule-strong: #4d5a66; --ink: #e8edf0; --ink-2: #9aa8b3; --paper: #171d22; --paper-ink: #e8edf0;
  --amber: #f59e0b; --amber-ink: #1a1200; --deny: #ff8a80; --allow: #6fd39a; --term: #0a0e11; --term-ink: #dbe3e8;
  --vp-c-bg: var(--ground); --vp-c-bg-soft: #161c21; --vp-c-divider: var(--rule); --vp-c-text-1: var(--ink); --vp-c-text-2: var(--ink-2); --vp-c-text-3: var(--rule-strong);
}
html.dark .landing .stamp { mix-blend-mode: normal; }
</style>

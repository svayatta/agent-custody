<script setup lang="ts">
// The shape of the system in one picture: who signs what, where the gateway sits, and what a verifier needs.
// The drawing uses the VitePress colour variables, so it works in the docs and on the landing page, in both themes.
// The gateway has a strong stroke. The signed receipt has the brand stroke, because it is the product.
</script>

<template>
  <figure class="flow" aria-label="A principal signs a grant. The agent calls tools through the gateway, which checks the grant and the policy, forwards or denies, and issues a signed receipt. The receipt's hash goes to a Merkle log whose signed heads are published as checkpoints. A verifier checks a receipt with public keys alone.">
    <svg viewBox="0 0 760 330" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5 0 10z" class="ahp" /></marker>
      </defs>
      <!-- row one: principal, agent, gateway, tool -->
      <g class="node"><rect x="20" y="30" width="130" height="54" rx="10" /><text x="85" y="52">Principal</text><text x="85" y="70" class="sub">a person, with a key</text></g>
      <g class="node"><rect x="20" y="150" width="130" height="54" rx="10" /><text x="85" y="172">Agent</text><text x="85" y="190" class="sub">any framework</text></g>
      <g class="node gw"><rect x="250" y="130" width="180" height="94" rx="10" /><text x="340" y="156">Gateway</text><text x="340" y="176" class="sub">checks the grant</text><text x="340" y="192" class="sub">evaluates the policy</text><text x="340" y="208" class="sub">fetches facts itself</text></g>
      <g class="node"><rect x="590" y="150" width="150" height="54" rx="10" /><text x="665" y="172">Tool</text><text x="665" y="190" class="sub">MCP, REST, anything</text></g>
      <!-- grant -->
      <path d="M85 84 V150" class="edge" marker-end="url(#ah)" /><text x="96" y="122" class="lbl start">signs a grant</text>
      <path d="M150 57 H340 V130" class="edge dashed" marker-end="url(#ah)" /><text x="246" y="49" class="lbl">trusted key</text>
      <!-- calls -->
      <path d="M150 177 H250" class="edge" marker-end="url(#ah)" /><text x="200" y="170" class="lbl">tool call</text>
      <path d="M430 177 H590" class="edge" marker-end="url(#ah)" /><text x="510" y="170" class="lbl">only if permitted</text>
      <!-- row two: receipt, log, checkpoints, verifier -->
      <path d="M340 224 V262" class="edge" marker-end="url(#ah)" /><text x="352" y="248" class="lbl start">one per call, allowed or denied</text>
      <g class="node receipt"><rect x="250" y="262" width="180" height="50" rx="10" /><text x="340" y="284">Signed receipt</text><text x="340" y="302" class="sub">who, what, saw, did, depended</text></g>
      <path d="M430 287 H510" class="edge" marker-end="url(#ah)" /><text x="470" y="280" class="lbl">hash</text>
      <g class="node"><rect x="510" y="262" width="110" height="50" rx="10" /><text x="565" y="284">Merkle log</text><text x="565" y="302" class="sub">signed heads</text></g>
      <path d="M620 287 H642" class="edge" marker-end="url(#ah)" />
      <g class="node"><rect x="642" y="262" width="108" height="50" rx="10" /><text x="696" y="284">Checkpoints</text><text x="696" y="302" class="sub">published</text></g>
      <g class="node"><rect x="20" y="262" width="150" height="50" rx="10" /><text x="95" y="284">Verifier</text><text x="95" y="302" class="sub">public keys, nothing else</text></g>
      <path d="M250 287 H170" class="edge" marker-end="url(#ah)" /><text x="210" y="280" class="lbl">reads</text>
    </svg>
    <figcaption>The gateway sits between the agent and its tools. Every call becomes a signed receipt whose hash lands in a tamper-evident log. Anyone with the public keys can verify a receipt, offline.</figcaption>
  </figure>
</template>

<style scoped>
/* On a narrow screen the diagram keeps a readable size and scrolls sideways. */
.flow { margin: 1.5rem 0; overflow-x: auto; }
.flow svg { width: 100%; min-width: 600px; height: auto; display: block; font-family: var(--vp-font-family-base); }
.node rect { fill: var(--vp-c-bg); stroke: var(--vp-c-divider); stroke-width: 1; }
.node text { fill: var(--vp-c-text-1); font-size: 14px; font-weight: 600; text-anchor: middle; }
.node text.sub { fill: var(--vp-c-text-2); font-size: 11px; font-weight: 400; }
.node.gw rect { stroke: var(--vp-c-text-2); }
.node.receipt rect { stroke: var(--vp-c-brand-1); stroke-width: 1.5; }
.edge { fill: none; stroke: var(--vp-c-text-2); stroke-width: 1.2; }
.edge.dashed { stroke-dasharray: 4 4; }
.ahp { fill: var(--vp-c-text-2); }
.lbl { fill: var(--vp-c-text-2); font-size: 11px; text-anchor: middle; }
.lbl.start { text-anchor: start; }
.flow figcaption { margin-top: .8rem; font-size: .9rem; color: var(--vp-c-text-2); line-height: 1.55; }
</style>

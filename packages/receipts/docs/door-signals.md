# Door signals

The door records one fact for every arrival, `arrival`, and gives it to the policy as `context.facts.arrival`. Every field in it is a signal: something the door observed, labelled by how far it was checked. None of them is a verdict. This page says, for each signal, what it establishes, what it does not, and how a policy should read it. The door's guide is [the door](door.md); the contract is the [reference](https://agent-custody.dev/reference/door).

Three labels run through the table:

- **Checked.** The door verified it against a key it trusts or computed it itself. A policy may rely on it.
- **Observed.** The door saw it on the wire. It is true that it was sent; nothing about the sender follows.
- **A claim.** The caller asserted it and the door could not check it. A policy that relies on it relies on the caller.

## The signals

| signal | label | what it means | what it does not mean |
| --- | --- | --- | --- |
| `class: "verified"` | checked | A grant signed by a principal in `trustedPrincipalKeys`, inside its validity window, names this agent and lists this arrival's route among its scopes. Or, with no grant, a Web Bot Auth signature checked against the key its signature agent's directory publishes, and the agent is that origin. The Cedar `principal` is that agent | That the agent is well-behaved, that the principal is who they say they are beyond holding the key, or that the request body is what the principal intended. The grant has no revocation list: it stands until it expires. A grant alone is bearer-grade: `signature` says whether the sender also proved it holds the agent's key |
| `class: "claimed"` | a claim | Something was asserted that the door could not accept: a grant from a key it does not trust, an expired one, one for other routes, one presented under another agent's signature, a declared agent name, or a signature that did not verify or was not checked. `grant`, `grantError`, `signature`, and `signatureError` say which | That the arrival is an agent, or that it is hostile. A misconfigured client, a grant for the wrong route, and an impostor all look the same here |
| `class: "unknown"` | observed | Nothing was presented | That the arrival is a person. A browser, a crawler, and a script that sends no headers are all `unknown`. There is no `human` class, and a policy that admits `unknown` on a route admits everything on that route |
| `grant: "verified"` | checked | As `class: "verified"` | |
| `grant: "out-of-scope"` | checked | The grant verified and is valid, but this route is not among its scopes. `subject` is the agent it names | That the agent may do anything here. The principal did not grant this route |
| `grant: "invalid"` | checked | The grant did not verify against a trusted key, did not decode, or is outside its window. `grantError` says which | Who signed it. A grant from an untrusted principal is `invalid` even when it is genuine |
| `grant: "wrong-sender"` | checked | The grant verified and is in scope, and the request is signed, verifiably, by a signature agent the grant does not name. The arrival is `claimed` | Which of the two is lying. The grant was handed on or taken; the door does not admit it as the agent it names |
| `grant: "absent"` | observed | No grant header | |
| `subject` | checked only when `class` is `verified` | The agent a verified grant names; else the signature agent of a verified signature; else the declared name or the agent a rejected grant named; else `unknown` | For a `claimed` arrival, anything. It is recorded so the receipt shows what was asserted; the Cedar `principal` is `Agent::"unknown"` for it |
| `declared` | a claim | The `x-agent-custody-agent` header, as sent, cut at 200 characters | That the agent is that agent. Anyone can send the header. A permit on a declared name admits whoever types it |
| `signature: "verified"` | checked, against the agent's directory | An RFC 9421 signature tagged `web-bot-auth`, Ed25519, covering `@authority` (one of `authorities`) and the `Signature-Agent` member, made at most `maxAgeSeconds` ago, with a nonce not seen before, verified with the key whose thumbprint is its keyid in the directory the door fetched over https from the `Signature-Agent` origin, an origin listed in `agents`. `signatureAgent` and `signatureKeyid` name the agent and the key. With a grant for the same agent, the grant is bound to its sender | That the body, the method, or the path is what the agent sent, unless the signature covers them (a minimal one covers the authority only), that the origin is a crawler you know or behaves well, or that a second door has not seen the nonce. The directory's own response signatures are not checked |
| `signature: "invalid"` | checked | A signature arrived and one check failed: no `web-bot-auth` tag, a missing parameter, an algorithm other than Ed25519, a component not covered or not supported, an agent not in `agents` or not https, outside the window, another authority, a repeated nonce, a redirect or a bad directory, a key not in it, or a signature that does not verify. `signatureError` says which | That the arrival is hostile. A clock off by more than `clockSkewSeconds` and a forgery both land here |
| `signature: "unavailable"` | observed | The directory did not answer in time or answered a non-200, or the door's nonce memory is full | Anything about the arrival. It is the network's or the door's state, like a challenge's `unavailable`; a policy that wants the agent through during a directory outage needs a grant as well |
| `signature: "unchecked"` | a claim | A `Signature-Input` arrived, and the door has no `webBotAuth` config | That the signature is valid, or who signed |
| `signature: "absent"` | observed | No signature headers | |
| `remote` | observed | The socket's address, or with `trustProxy` the last address in `X-Forwarded-For`, the one your proxy appended | Who the person or program is. One address serves a whole office, a mobile carrier, or a cloud region; one program can use many |
| `challenge.outcome` | checked, against the provider | Only when `challenge` is configured. `passed`: Turnstile or hCaptcha confirmed the token this arrival sent, so the provider judged a person present when the token was made. `failed`: the provider refused the token itself (bad, expired, or already used; `error` carries the codes), the token was issued on a hostname not in `hostnames` or for another action, or it was too long to be a token. `unavailable`: the provider did not answer in time, answered a non-200, a redirect, or something that is not JSON, reported a fault of its own or of the operator's (a wrong or rotated secret, a site key that does not match it), or too many checks were already waiting, which is the provider's or the door's state, not the arrival's. `absent`: no token | That the arrival is a person now, or that the person is who they say: a token is made once and sent by whatever holds it, and the provider's own error rate applies. It does not change `class`. `unavailable` is not `failed`: a policy that treats it as one locks everyone out when the provider is down, and one that treats it as a pass admits everyone; say which, on purpose |
| `rate.burst`, `rate.minute` | checked | Arrivals from the same source in the last 10 and 60 seconds, this one included, whatever the policy decided about them, counted by this door process on a monotonic clock, so a step of the wall clock does not move the windows. `rate.by` says what the source is: `agent`, the verified agent's name, or `remote`, the address | That the source is a program, or that it is abusive. Twenty arrivals a minute is one page load for a site that fans out to its API, and one agent on a job. The count is one process's memory: it starts at one when the door starts, two doors do not share it, and an address shared by many people counts them together. It keeps at most 10,000 sources and forgets the least recently seen first, so a client that sends from many new addresses can make another source's count start again |
| `partner.outcome` | checked, against the engine's key | Only when `partner` is configured and the route is in `partner.routes`. `verified`: the partner engine answered with a verdict whose signature verified under `partner.keyFile` and binds this receipt and route; the verdict is then the `partner` fact (below). `rejected`: the engine answered, and it was not a verdict signed for this arrival: a signature by another key, one for another receipt or route, a verdict of another engine, a malformed verdict, or an envelope carrying more than the attestation (`error` says which). `unavailable`: no answer within `timeoutMs`, an error status, a redirect, or `maxInFlight` questions already waiting | Anything about the arrival when it is not `verified`. Under `onFailure: "deny"` (the default) an arrival without a verified verdict is refused with 503 whatever the policy says; under `"absent"` the policy decides without the `partner` fact |
| `method`, `path`, `route` | observed | What arrived, the path percent-decoded once, and the route it fell under | |

## The partner verdict

A second fact, `partner`, is present only when a partner detection engine (Cloudflare Bot Management, HUMAN, DataDome, behind an adapter that holds an Ed25519 key) signed a verdict for this arrival. The policy reads it as `context.facts.partner`; the receipt records it with provenance `attested` and the engine's signature beside it.

| field | label | what it means | what it does not mean |
| --- | --- | --- | --- |
| `engine` | checked | The engine named in `partner.engine`; the signed verdict must name the same | |
| `verdict` | checked, as the engine's word | What the engine concluded, in its own vocabulary (letters, digits, `_ . : -`, at most 64): the stub says `human` or `bot`. The engine signed it for this receipt and route, so it was not edited or moved from another arrival | That the engine is right. Its error rate is the engine's; the door records whose judgement it was |
| `score` | checked, as the engine's word | An integer, when the engine gives one (Cedar has no floats) | A probability on any shared scale. Each engine's scale is its own |

How the verdict is bound to the arrival: the door posts the engine a question carrying the receipt id it is writing (a fresh UUID per arrival), the route, the method, the path, the address, the class, and the recorded headers (`user-agent`, `content-type`, `accept`, `host`), never the query, the body, the grant, or a cookie. The engine signs `{ receiptId, tool: route, contentDigest }` (the upstream attestation format of `src/upstream.ts`, payload type `application/vnd.agent-custody.upstream+json`), with `contentDigest` the digest of the verdict. The door accepts it only when the signature verifies under `keyFile`, the receipt id and route are this arrival's, and the envelope is exactly that plain attestation. A verifier given the engine's public key with `--upstream-key` runs `fact partner signature (upstream key)` on it; without the key the check fails, since the receipt says the verdict is attested and the reader cannot confirm it.

## Reading them in a policy

The signals are attributes of `context.facts.arrival`. A permit for an agent requires the arrival to be verified, or the permit admits nothing but a header:

```cedar
permit(principal == Agent::"shopping-agent", action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
```

`agent-custody check` warns about a permit that names an agent without that condition.

A route that needs to know the sender holds the agent's key requires the signature beside the grant. A grant under another agent's signature is `wrong-sender`, so this holds only for a grant bound to its sender:

```cedar
permit(principal == Agent::"https://crawler.example", action == Action::"api", resource)
when {
  context.facts.arrival.grant == "verified" &&
  context.facts.arrival.signature == "verified"
};
```

Rate is a reason to slow a route down or to ask for more, not a reason to decide what the arrival is. A forbid on it refuses the arrivals past the limit and receipts each refusal, so the receipts show how often the limit was hit and by what:

```cedar
forbid(principal, action == Action::"refund", resource)
when { context.facts.arrival.rate.minute > 30 };
```

A limit by `remote` reaches everyone behind one address. Put it high enough that a shared address is not refused for one user's pace, or scope it to routes where a person's pace is slow in any case, as a refund form is. For a verified agent the count is by agent name across every address it uses, so a limit on a verified agent is a limit on the agent.

An `unknown` arrival that comes fast is still unknown. The honest policy for a route that should not take bursts from strangers is to refuse them and say why, and to route the agents you want through a grant, which makes them `verified` and counted by name.

A challenge is the way a person gets through a route that refuses `unknown`. The permit names the outcome, not the class, and a second permit lets the agents you trust through without the widget:

```cedar
permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.challenge.outcome == "passed" };

permit(principal == Agent::"shopping-agent", action == Action::"refund", resource)
when { context.facts.arrival.class == "verified" };
```

Decide what `unavailable` means for each route before the provider has its first outage: a forbid on `outcome != "passed"` closes the route then, and the receipts show that the provider, not the arrivals, was the reason.

A partner verdict is read through the `partner` fact, which exists only when the engine's signature verified. Test for it before reading it, so a missing verdict denies rather than errors:

```cedar
permit(principal, action == Action::"api", resource)
when { context.facts has partner && context.facts.partner.verdict == "human" };
```

With `onFailure: "absent"`, the arrival still reaches this rule when the engine is down or its signature is bad, and the rule denies it, because the fact is not there. A rule that does not mention `partner` admits it whatever the engine said, so set `partner.routes` to the routes whose rules read it, or keep the default `onFailure: "deny"`, which refuses the arrival before the policy's answer counts. No setting lets an engine outage become an allow on a route whose rule needs the verdict.

## What is not a signal yet

Nothing in the arrival fact says whether an arrival that presents nothing is a program. A Web Bot Auth signature identifies an agent that chooses to sign; it says nothing about the ones that do not. A partner engine's verdict is that engine's judgement, signed, and carries the engine's own error rate. The door's own behavioural and fingerprint signals are not built; when they are, each will arrive with a measured error rate beside it, and this page will say what it means. Until then a policy has the grant, the signature, the claims, the address, and the pace, and the receipt records which of them it used.

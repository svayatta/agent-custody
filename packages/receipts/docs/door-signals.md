# Door signals

The door records one fact for every arrival, `arrival`, and gives it to the policy as `context.facts.arrival`. Every field in it is a signal: something the door observed, labelled by how far it was checked. None of them is a verdict. This page says, for each signal, what it establishes, what it does not, and how a policy should read it. The door's guide is [the door](door.md); the contract is the [reference](https://agent-custody.dev/reference/door).

Three labels run through the table:

- **Checked.** The door verified it against a key it trusts or computed it itself. A policy may rely on it.
- **Observed.** The door saw it on the wire. It is true that it was sent; nothing about the sender follows.
- **A claim.** The caller asserted it and the door could not check it. A policy that relies on it relies on the caller.

## The signals

| signal | label | what it means | what it does not mean |
| --- | --- | --- | --- |
| `class: "verified"` | checked | A grant signed by a principal in `trustedPrincipalKeys`, inside its validity window, names this agent, lists this arrival's route among its scopes, and is not revoked. Or, with no grant, a Web Bot Auth signature checked against the key its signature agent's directory publishes, and the agent is that origin. The Cedar `principal` is that agent | That the agent is well-behaved, that the principal is who they say they are beyond holding the key, or that the request body is what the principal intended. It stands until it expires unless the door has `revokedGrants` and the grant is listed there. A grant alone is bearer-grade: `signature` says whether the sender also proved it holds the agent's key |
| `class: "claimed"` | a claim | Something was asserted that the door could not accept: a grant from a key it does not trust, an expired one, a revoked one, one for other routes, one presented under another agent's signature, a declared agent name, or a signature that did not verify or was not checked. `grant`, `grantError`, `signature`, and `signatureError` say which | That the arrival is an agent, or that it is hostile. A misconfigured client, a grant for the wrong route, and an impostor all look the same here |
| `class: "unknown"` | observed | Nothing was presented | That the arrival is a person. A browser, a crawler, and a script that sends no headers are all `unknown`. There is no `human` class, and a policy that admits `unknown` on a route admits everything on that route |
| `grant: "verified"` | checked | As `class: "verified"` | |
| `grant: "out-of-scope"` | checked | The grant verified and is valid, but this route is not among its scopes. `subject` is the agent it names | That the agent may do anything here. The principal did not grant this route |
| `grant: "invalid"` | checked | The grant did not verify against a trusted key, did not decode, or is outside its window; or it, or a grant above it in its chain, names its agent by a did:key that does not decode to an Ed25519 key, or that is not the key in its `agentKey`. `grantError` says which | Who signed it. A grant from an untrusted principal is `invalid` even when it is genuine. A did:key grant that is not `invalid` and has no request signature is `verified` without any proof that the sender holds the key: it is bearer-grade like any grant. A request signature by the did:key's own key binds it: see `signature: "verified"` |
| `grant: "revoked"` | checked | The grant verified against a trusted key, and it, or a grant above it in its chain, is in the door's `revokedGrants` file; or that file could not be read, which revokes every grant until it can. `grantError` says which | That the agent misbehaved. The operator withdrew the grant, for whatever reason; the revocation file does not record why |
| `grant: "wrong-sender"` | checked | The grant verified and is in scope, and the request is signed, verifiably, by a signature agent, or by the key of a did:key, that the grant does not name. The arrival is `claimed` | Which of the two is lying. The grant was handed on or taken; the door does not admit it as the agent it names |
| `grant: "absent"` | observed | No grant header | |
| `subject` | checked only when `class` is `verified` | The agent a verified grant names; else the signature agent of a verified signature; else the declared name or the agent a rejected grant named; else `unknown` | For a `claimed` arrival, anything. It is recorded so the receipt shows what was asserted; the Cedar `principal` is `Agent::"unknown"` for it |
| `declared` | a claim | The `x-agent-custody-agent` header, as sent, cut at 200 characters | That the agent is that agent. Anyone can send the header. A permit on a declared name admits whoever types it |
| `signature: "verified"` | checked, against the agent's directory | An RFC 9421 signature tagged `web-bot-auth`, Ed25519, covering `@authority` (one of `authorities`) and the `Signature-Agent` member, made at most `maxAgeSeconds` ago, with a nonce not seen before, verified with the key whose thumbprint is its keyid in the directory the door fetched over https from the `Signature-Agent` origin, an origin listed in `agents`. `signatureAgent` and `signatureKeyid` name the agent and the key. With a grant for the same agent, the grant is bound to its sender. For a did:key agent: the same signature with the did:key as its keyid and no `Signature-Agent`, verified with the key that the did:key names, with no directory, and recorded as `verified` only when a verified grant names that did:key; `signatureAgent` and `signatureKeyid` are then the did:key. In every other case a did:key signature is `invalid` | That the body, the method, or the path is what the agent sent, unless the signature covers them (a minimal one covers the authority only), that the origin is a crawler you know or behaves well, or that a second door has not seen the nonce. The directory's own response signatures are not checked |
| `signature: "invalid"` | checked | A signature arrived and one check failed: no `web-bot-auth` tag, a missing parameter, an algorithm other than Ed25519, a component not covered or not supported, an agent not in `agents` or not https, outside the window, another authority, a repeated nonce, a redirect or a bad directory, a key not in it, or a signature that does not verify. `signatureError` says which | That the arrival is hostile. A clock off by more than `clockSkewSeconds` and a forgery both land here |
| `signature: "unavailable"` | observed | The directory did not answer in time or answered a non-200, or the door's nonce store is full or cannot be reached | Anything about the arrival. It is the network's or the door's state, like a challenge's `unavailable`; a policy that wants the agent through during a directory outage needs a grant as well |
| `signature: "unchecked"` | a claim | A `Signature-Input` arrived, and the door has no `webBotAuth` config | That the signature is valid, or who signed |
| `signature: "absent"` | observed | No signature headers | |
| `remote` | observed | The socket's address, or with `trustProxy` the last address in `X-Forwarded-For`, the one your proxy appended | Who the person or program is. One address serves a whole office, a mobile carrier, or a cloud region; one program can use many |
| `challenge.outcome` | checked, against the provider | Only when `challenge` is configured. `passed`: Turnstile or hCaptcha confirmed the token this arrival sent, so the provider judged a person present when the token was made. `failed`: the provider refused the token itself (bad, expired, or already used; `error` carries the codes), the token was issued on a hostname not in `hostnames` or for another action, or it was too long to be a token. `unavailable`: the provider did not answer in time, answered a non-200, a redirect, or something that is not JSON, reported a fault of its own or of the operator's (a wrong or rotated secret, a site key that does not match it), or too many checks were already waiting, which is the provider's or the door's state, not the arrival's. `absent`: no token | That the arrival is a person now, or that the person is who they say: a token is made once and sent by whatever holds it, and the provider's own error rate applies. It does not change `class`. `unavailable` is not `failed`: a policy that treats it as one locks everyone out when the provider is down, and one that treats it as a pass admits everyone; say which, on purpose |
| `rate.burst`, `rate.minute` | checked | Arrivals from the same source in the last 10 and 60 seconds, this one included, whatever the policy decided about them, counted by this door process on a monotonic clock, so a step of the wall clock does not move the windows. `rate.by` says what the source is: `agent`, the verified agent's name, or `remote`, the address | That the source is a program, or that it is abusive. Twenty arrivals a minute is one page load for a site that fans out to its API, and one agent on a job. The count is one process's memory: it starts at one when the door starts, two doors do not share it, and an address shared by many people counts them together. It keeps at most 10,000 sources and forgets the least recently seen first, so a client that sends from many new addresses can make another source's count start again |
| `partner.outcome` | checked, against the engine's key | Only when `partner` is configured and the route is in `partner.routes`. `verified`: the partner engine answered with a verdict whose signature verified under `partner.keyFile` and binds this receipt and route; the verdict is then the `partner` fact (below). `rejected`: the engine answered, and it was not a verdict signed for this arrival: a signature by another key, one for another receipt or route, a verdict of another engine, a malformed verdict, or an envelope carrying more than the attestation (`error` says which). `unavailable`: no answer within `timeoutMs`, an error status, a redirect, or `maxInFlight` questions already waiting | Anything about the arrival when it is not `verified`. Under `onFailure: "deny"` (the default) an arrival without a verified verdict is refused with 503 whatever the policy says; under `"absent"` the policy decides without the `partner` fact |
| `method`, `path`, `route` | observed | What arrived, the path percent-decoded once, and the route it fell under | |

## The behaviour and fingerprint signals

The door adds two fields to the arrival fact when its config has a `behaviour` object: `fingerprint` (what the request and its connection look like) and `behaviour` (how the source acts over time). Without `behaviour` in the config, the arrival fact has neither field, and the door reads no TLS header and no form report. The config is in [the door](door.md#behaviour-and-fingerprint-signals).

Nine of the values are flags: booleans that mark an arrival. A flag is not a verdict. The door never refuses an arrival because of a signal. Only your policy reads the signals, and the receipt records each one that the policy read.

Each flag is wrong for some people and for some programs. The method that measures how often, and the measured rates, are in [door error rates](door-error-rates.md). `agent-custody door measure` replays a labelled set through the same signal functions, and `agent-custody door labels` exports a labelled set from the receipts of your own door. Measure a flag on your own traffic before a rule reads it.

The flags:

| signal | label | what it means | what it does not mean |
| --- | --- | --- | --- |
| `fingerprint.headers.mismatch` | observed, against a claim | The `User-Agent` states a browser, and the request that the door received lacks a header that this browser sends on every request. The rule always reads `accept-language`. When the door knows that the client used https, the rule also reads `sec-fetch-site`, `sec-fetch-mode`, and `sec-fetch-dest` (Chromium from 80, Firefox from 90, Safari from 17) and `sec-ch-ua` (Chromium from 100; not an Android WebView, a WebView browser with `Version/` before `Chrome/`, Electron, a browser that says `like Chrome/`, or an application that names itself before `Chrome/`). On a POST, PUT, PATCH, or DELETE, on any scheme, the rule also reads `origin` (the same versions as `sec-fetch-*`); a browser sends it on every write, with the value `null` when it hides the origin. An OPTIONS request and an upgrade are checked for `accept-language` only. `missing` names the headers | That the client is a program. The flag is true for a person behind a privacy browser, an extension, or a company proxy that removes one of these headers, for a person whose extension changes the `User-Agent`, and for a Chromium browser that sends no client hints. A proxy in front of the door that drops one of these headers makes every browser a mismatch. It does not mean that an arrival without the flag is a browser: a program that sends the headers of a browser has no mismatch, and a program that states its own name is never a mismatch |
| `fingerprint.headers.hintsMismatch` | observed, against a claim | The arrival sent `sec-ch-ua`, the `User-Agent` states a browser, and the two do not state the same browser: the `User-Agent` states Firefox or Safari, which send no `sec-ch-ua`, or the major version of the `Chromium` brand is not the major version in the `User-Agent`. A Chromium that is given another `User-Agent` keeps its own `sec-ch-ua`. The rule reads values, so it also works in authz mode when the proxy forwards `sec-ch-ua` | That the client is a program. The flag is true for a person whose extension changes the `User-Agent` and not the client hints. It does not mean that an arrival without the flag is a browser: a program that copies the `User-Agent` of the Chromium that it runs has no flag, and a program can set the client hints too. The rule reads no brand name: in the recorded capture, headless Chrome sends the brands of Chrome |
| `fingerprint.headers.fetchInvalid` | observed | The `sec-fetch-*` headers have a combination that the Fetch Metadata specification rules out: `sec-fetch-user` without `sec-fetch-mode: navigate`, or `sec-fetch-mode: navigate` with a `sec-fetch-dest` that is not `document`, `iframe`, `frame`, `embed`, `object`, or `fencedframe`. The rules come from the specification, not from data | That an arrival without the flag is a browser: a program that copies a full set of these headers from a browser has no flag. `sec-fetch-site: none` on a write is not in the rule, because a browser extension sends it |
| `fingerprint.tls.mismatch` | observed, against a claim | The `User-Agent` states a browser of a version that offers TLS 1.3 (Chromium from 70, Firefox from 63, Safari from 13), and the JA4 of a TCP ClientHello shows no TLS 1.3 or no ALPN | That the client is a program. A proxy that inspects TLS between the person and the site (a company network, some antivirus products) sends its own ClientHello, so a person behind one can be a mismatch. So can a person whose organisation turns TLS 1.3 off. It does not mean that an arrival without the flag is a browser: the rule reads two properties of the ClientHello, and a program can have both. A QUIC ClientHello is not checked |
| `fingerprint.tls.knownTool` | observed | The JA4 is in the door's table of fingerprints of known tools, `KNOWN_TOOL_JA4` | That the tool is hostile, or that a tool not in the table is absent. The table holds six fingerprints, recorded from one build each of curl, Python, Go, Node, and Bun; another build of the same tool can have another fingerprint. A person behind a proxy that uses the same TLS library has the same fingerprint |
| `behaviour.timing.regular` | checked | The source arrived at a steady pace: at least 5 gaps between its remembered arrivals, a median gap of at least 100 ms, and a difference between the longest gap and the shortest gap of at most 10 % of the median | That the source is a program that you do not want. The flag is true for a page that polls or refreshes on a timer in the browser of a person (a dashboard, a status page), and for the monitoring tool or the health check that you run yourself. It does not mean that an arrival without the flag is a person: a program that varies its pace is not regular, and one more source at the same address breaks the pace |
| `behaviour.navigation.directWrite` | observed | A POST, PUT, PATCH, or DELETE arrived, the source loaded no HTML document through this door in the last 30 minutes, the `Referer` is absent or names another host, the `Origin` is absent or names another host, and the request has no `Sec-Fetch-Site: same-origin` | That the arrival is a program. The flag is true for every API client that loads no page, a verified agent and a webhook included. It is true for a person whose address changed after the page load, who kept the form open for more than 30 minutes, whose page came from a cache in front of the door, or whose page load went to another door process, when the browser also sends no same-origin `Referer`, no same-origin `Origin`, and no `Sec-Fetch-Site: same-origin` (a form page on another host of the site, or a browser that hides the origin on a site that is not https). It does not mean that an arrival without the flag is a person. The `Referer`, the `Origin`, and `Sec-Fetch-Site` are the client's word: a program that sends a GET for the page first, a `Referer` or an `Origin` that names the host, or `Sec-Fetch-Site: same-origin` has no flag. For a program that loads the page first, read `sincePageMs` |
| `behaviour.form.fast` | a claim | The form report states at least 8 key presses, and a fill time of less than 20 ms for each key press | That a program filled the form. A device or a tool that types for a person is fast too: a barcode scanner, a security key, a text expander, a password manager that types. The form report is the word of the client's script: a program can send a report that is not fast |
| `behaviour.form.noInput` | a claim | The form report states a submit with no key press and no pointer press | That a program sent the form. The flag is true for a person whose browser or password manager fills the form and submits it, and for an assistive tool that submits without a key press or a click. A program can send a report that states input |

The fields beside the flags:

| signal | label | what it means | what it does not mean |
| --- | --- | --- | --- |
| `fingerprint.headers.client`, `family`, `version` | a claim | What the `User-Agent` states: `browser` (`chromium`, `firefox`, `safari`), `agent` (an AI agent that names itself; see `vendor` and `purpose` below), `tool` (the name of the tool, or `crawler`), `other`, or `unstated`, and the major version of a browser | What the client is. Any client can send any `User-Agent`. A `User-Agent` with a product name that ends in `bot/`, `crawler/`, or `spider/`, or with a `+http` address, is a `tool` with the family `crawler` |
| `fingerprint.headers.vendor`, `purpose` | a claim | Only for the client `agent`: the vendor (`openai`, `anthropic`, `perplexity`, `google`) and what the vendor says the agent fetches for: `training` (to train a model), `search` (to build a search index), or `user` (one user asked for this page). The table is `AI_AGENTS` in `src/door-signals.ts`; each entry is from the vendor's own page, and the source is beside it. `family` is the product token in lowercase (`gptbot`, `claude-user`) | That the arrival is that agent. Any client can send the name. The door does not check the address against the ranges that a vendor publishes. A signature is the check: [Web Bot Auth](door.md) makes `signature: "verified"`. A token that a vendor documents for another purpose is a `crawler` |
| `fingerprint.headers.hints` | observed | Only when the arrival sent `sec-ch-ua`: `version`, the major version of the `Chromium` brand, when the header has one. The header itself is not recorded | |
| `fingerprint.headers.http` | observed, through Cloudflare | In a Worker only: the HTTP version between the client and Cloudflare (`1.1`, `2`, `3`). A number for your policy, not a flag | That a browser on HTTP/1.1 is a program. A proxy that inspects traffic between the person and the site speaks HTTP/1.1 for the person |
| `fingerprint.network.asn`, `organization` | observed, through Cloudflare | In a Worker only: the number of the autonomous system of the address and the name of its holder, as Cloudflare gives them. A rule can ask for a challenge when the network is a hosting provider | That an arrival from a hosting network is a program. A person behind a VPN, a company gateway, or a private relay comes from such a network. The Node door has no source for this |
| `fingerprint.seen` | checked | How many arrivals in the last 60 seconds had this fingerprint (the JA4 and the header order), from every source, this one included. A client that changes its address and keeps its TLS stack and header order is still one fingerprint. Absent when the arrival has no JA4 and no header order. The count stops at 1,000 | That the arrivals are one client. Every copy of one browser version has the same fingerprint, so a busy site sees a high count for a current browser. A number for your policy, not a flag. One process's memory: at most 10,000 fingerprints |
| `fingerprint.headers.order`, `count` | observed | A hash of the lowercase header names in the order that the door received them, and how many there were, without the door's own headers. No header value is in the hash | The identity of a client. Two clients of the same kind have the same order. A proxy in front of the door can reorder, add, or drop headers, and the door records what it received |
| `fingerprint.tls.ja4` and the fields from it (`protocol`, `version`, `sni`, `ciphers`, `extensions`, `alpn`) | observed, through your proxy or Cloudflare | The JA4 of the ClientHello, as your proxy wrote it in `behaviour.tlsHeader` or as Cloudflare gives it to a Worker. `malformed` is true when a value arrived that is not a JA4; the door then reads nothing from it | The identity of a client: every copy of one browser version has the same JA4. The door does not see the handshake. When the proxy does not overwrite the header, the value is the client's own |
| `fingerprint.tls.negotiated`, `cipher`, `extensionsSha1`, `helloLength` | observed, through Cloudflare | In a Worker only: the negotiated TLS version and cipher, Cloudflare's hash of the extensions, and the length of the ClientHello | |
| `behaviour.timing.gaps`, `medianGapMs`, `minGapMs`, `maxGapMs` | checked | How many gaps the door remembers between the arrivals of this source (at most 16), and their median, their shortest, and their longest in milliseconds. A rule can read the shape: a program that sleeps a random time has gaps inside a band, and a person has long pauses. The source is the name of a verified agent, else the address (for IPv6, its /64) | The pace of one person. One address serves many people |
| `behaviour.navigation.pageLoaded` | observed | The source sent a GET for an HTML document in the last 30 minutes (`Sec-Fetch-Dest: document`, or without that header an `Accept` that names `text/html`) | That a browser showed the page, or that the same person sends this arrival |
| `behaviour.navigation.sincePageMs` | checked | Only when `pageLoaded` is true: the milliseconds from that page load to this arrival. On a write, it is the time that the source took to read and fill the page | That a short time is a program: a browser that restores a filled form sends fast. One address serves many people, so the page load can be another person's |
| `behaviour.navigation.subresources` | checked | Only when `pageLoaded` is true: how many GET requests that are not page loads the source sent after that page load and before this arrival, at most 17. A browser loads the scripts, styles, and images of a page; a program that fetches only the HTML has 0 | Anything when the assets do not go through the door: a site that serves them from a CDN or from another host has 0 for every person. A cached page has 0 too. A number for your policy, not a flag |
| `behaviour.navigation.origin` | observed | As `referer`, for the `Origin` header. `Origin: null`, which a browser sends when it hides the origin, is `cross-origin`. A `Referrer-Policy` does not remove the `Origin` of a write. The `Origin` itself is not recorded | Where the arrival came from. The client writes the `Origin` |
| `behaviour.navigation.referer` | observed | `same-origin` when the host of the `Referer` is the `Host` of the request (with `trustProxy`, the `X-Forwarded-Host`); a default port, `:443` or `:80`, on one side only does not change the result. Else `cross-origin`, or `absent`. The `Referer` itself is not recorded | Where the arrival came from. The client writes the `Referer` |
| `behaviour.navigation.site`, `mode`, `dest` | observed | `sec-fetch-site`, `sec-fetch-mode`, and `sec-fetch-dest` as sent, lowercase; `other` for a value that is not a token | That a browser sent them. A program can send the same values |
| `behaviour.form.report` and its counts (`fillMs`, `keys`, `pointers`, `pasted`, `trusted`, `moves`, `keySpreadMs`, `readyMs`) | a claim | The form protector script counted the events in the form and sent the counts in `X-Agent-Custody-Form`. `moves` is the count of pointer and touch moves over the form: a tool that types through the browser's debugging interface makes none. `keySpreadMs` is the longest gap between two key presses minus the shortest: a tool that types with a fixed delay has a small one. `readyMs` is the time from the start of the script to the first key press, pointer press, click, or paste. `claimed`: the report is well formed. `malformed`: a value arrived that is not exactly a report; the door then reads nothing from it and sets no flag. The script reads no field value and no key | What happened in a browser. Any client can send the header with any counts. The flags catch only a client that runs the script and does not act as a person does |

Limits of these signals:

- **The history is one process's memory.** The timing and navigation signals read what this door process remembers: at most 10,000 sources, 17 arrival times for each source, and 30 minutes. The history starts empty when the door starts, and two door processes do not share it. In a Worker, each isolate has its own. A client that sends from many new addresses can make the door forget another source early.
- **One address is one source.** People behind one address share a history: a page load by one of them is a page load for all, and their arrivals share one pace. A program behind the same address as a person gets that person's page load. The door does not add the `User-Agent` to the key: a client that changes its `User-Agent` would then look new on each arrival.
- **An IPv6 source is its /64.** One device uses many addresses of its /64, so the door keeps one history for the /64. `rate` still counts by the full address. A browser can load the page over IPv6 and send the form over IPv4. The door then sees two sources, and `pageLoaded` is false for that person; a same-origin `Referer`, `Origin`, or `Sec-Fetch-Site` keeps `directWrite` false.
- **The door must know that the client used https.** A browser sends `sec-fetch-*` and `sec-ch-ua` to an https site only. The door knows https from the URL of a Worker request, or from `X-Forwarded-Proto: https` with `trustProxy`. Without that, `fingerprint.headers.mismatch` reads `accept-language` only.
- **Authz mode records no header order.** The proxy selects the headers of a check, so `order` and `count` are absent and `fingerprint.headers.mismatch` is always false. The other signals need the proxy to forward `Referer`, `Origin`, `Accept`, `Sec-Fetch-*`, `Sec-CH-UA`, and `X-Agent-Custody-Form`.
- **A proxy in front of the door changes what the door receives.** It can reorder or drop headers. The order hash is then the proxy's order, and a dropped header is a mismatch for every browser.
- **The TLS fingerprint comes from your proxy or from Cloudflare.** `behaviour.tlsHeader` needs `trustProxy`, and your proxy must overwrite the header on every request. In a Worker the data comes from `request.cf`, and a config with `behaviour.tlsHeader` is refused. `ja4` needs Cloudflare Bot Management on the zone. Without it, `tls` has the Cloudflare fields only and `tls.mismatch` is always false.
- **The form report is a claim.** The script runs in the client's browser, and a program can send the header without the script. The door serves the script only when `challenge` is configured.

## Privacy

The signals are data about the device and the conduct of a person, so your privacy duties apply to them. The door does not decide whether you may collect them. That assessment is yours.

- **The form report runs in the visitor's browser.** With `behaviour` and `challenge` in the config, the form protector script listens for key, pointer, click, paste, and move events on the form. It keeps counts and times only: no field value, no key identity, and no pointer position. It sends them with the form. Reading events on the device of a visitor is in the scope of rules such as Article 5(3) of the ePrivacy Directive (see the EDPB Guidelines 2/2023 on its technical scope). Whether a security purpose covers it on your site is a question for you and your data protection officer.
- **A receipt with `behaviour` holds a device fingerprint beside the address.** `fingerprint` (the JA4, the header order hash, in a Worker the network) and `remote` are in the same arrival fact. Together they can identify a device, so treat such a receipt as personal data.
- **Facts are in clear by default.** The door's default capture rule keeps the arrival fact in clear. A `capture` rule for a route with `"facts": { "mode": "digest" }` or `"encrypted"` keeps the arrival fact out of the readable receipt for that route ([what the receipt records](door.md)). The rule withholds the whole fact, and `door error-rates` and `door labels` then skip those receipts.
- **The labelled export holds no address.** `agent-custody door labels` writes labels and flags only ([door error rates](door-error-rates.md#measure-on-your-own-door)).

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

A route that needs to know the sender holds the agent's key requires the signature beside the grant. A grant under another agent's signature is `wrong-sender`, so this holds only for a grant bound to its sender, by its agent's Web Bot Auth signature or by a signature with the key of its did:key agent:

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

The behaviour and fingerprint signals are reasons to ask for more, never reasons to decide what the arrival is. Each flag is wrong for some people ([door error rates](door-error-rates.md)), so a rule that reads a flag gives the arrival a way through: a challenge for a person, a grant for an agent. The next rule asks an arrival for the challenge when a write follows no page load. A verified agent and an arrival that passed the challenge go on:

```cedar
forbid(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.behaviour.navigation.directWrite &&
  context.facts.arrival.class != "verified" &&
  context.facts.arrival.challenge.outcome != "passed"
};
```

The door answers a refused arrival with 403, the rule's id, and how to pass the challenge. This rule needs `challenge` in the config.

`fingerprint.tls` and `behaviour.form` are present only on some arrivals: `tls` when a TLS fingerprint arrived, `form` when the arrival sent a form report. Test for each with `has` before a rule reads it. A rule that reads an absent field is an error, and the door denies an arrival when a rule errors. So a rule without the test refuses every arrival that has no TLS fingerprint or no form report:

```cedar
forbid(principal, action, resource)
when {
  (context.facts.arrival.fingerprint.headers.mismatch ||
   (context.facts.arrival.fingerprint has tls && context.facts.arrival.fingerprint.tls.mismatch)) &&
  context.facts.arrival.class != "verified" &&
  context.facts.arrival.challenge.outcome != "passed"
};

forbid(principal, action == Action::"contact", resource)
when {
  context.facts.arrival.behaviour has form &&
  (context.facts.arrival.behaviour.form.fast || context.facts.arrival.behaviour.form.noInput) &&
  context.facts.arrival.challenge.outcome != "passed"
};
```

An arrival with no form report passes the second rule. The report is a claim, so do not write a permit that depends on a report that looks like a person: a program can send one.

A steady pace on an API route is a reason to ask the program for a grant. A verified agent is counted by its name, and this rule lets it through:

```cedar
forbid(principal, action == Action::"api", resource)
when {
  context.facts.arrival.behaviour.timing.regular &&
  context.facts.arrival.class != "verified"
};
```

`fingerprint` and `behaviour` exist only when the config has `behaviour`. A policy that must also work on a door without it tests `context.facts.arrival has behaviour` first. Use observe mode to see what a new rule refuses before you enforce it: the receipts record each flag and each decision. Tutorial: [58-door-behaviour-signals.ts](../examples/58-door-behaviour-signals.ts).

A partner verdict is read through the `partner` fact, which exists only when the engine's signature verified. Test for it before reading it, so a missing verdict denies rather than errors:

```cedar
permit(principal, action == Action::"api", resource)
when { context.facts has partner && context.facts.partner.verdict == "human" };
```

With `onFailure: "absent"`, the arrival still reaches this rule when the engine is down or its signature is bad, and the rule denies it, because the fact is not there. A rule that does not mention `partner` admits it whatever the engine said, so set `partner.routes` to the routes whose rules read it, or keep the default `onFailure: "deny"`, which refuses the arrival before the policy's answer counts. No setting lets an engine outage become an allow on a route whose rule needs the verdict.

## What no signal says

Nothing in the arrival fact says whether an arrival that presents nothing is a program or a person. A Web Bot Auth signature identifies an agent that signs; it says nothing about the agents that do not. A partner engine's verdict is the judgement of that engine, signed, with the error rate of that engine. The behaviour and fingerprint signals of the door mark an arrival that does not look or act as its `User-Agent` states. Each flag is wrong for some people and misses some programs, and [door error rates](door-error-rates.md) gives the method and the measured rates. There is no `human` class and no `bot` class. A policy has the grant, the signature, the challenge, the claims, the address, the pace, and the flags, and the receipt records which of them the policy read.

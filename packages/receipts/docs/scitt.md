# Aligning with IETF SCITT

SCITT (Supply Chain Integrity, Transparency, and Trust) is the IETF's standard for transparency services. An issuer signs a statement, a transparency service registers it in an append-only log and returns a signed proof called a receipt, and a relying party checks both offline. That is the shape of agent-custody too. This page maps our receipt and our log onto SCITT: what lines up exactly, what differs, the options for each difference, what an agent-action profile would contain, and the steps that would bring one to the working group. It is step 3 of [issue #185](https://github.com/svayatta/agent-custody/issues/185). Nothing here changes the format yet. [The receipt specification](../../../site/receipt/v0.2.md) and [the log API](../../../site/reference/log-api.md) are what this page compares against.

The documents were read on 26 October 2026, from the IETF datatracker. Three of the drafts that issue #185 names were published as RFCs this summer. Cite the RFCs from now on, not the drafts.

| document | revision and status | what we take from it |
| --- | --- | --- |
| SCITT architecture | [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943), June 2026, Proposed Standard; published from [draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/22/) | the roles, Signed Statements, Registration, Transparent Statements |
| COSE Receipts (the "Merkle tree proofs" draft) | [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942), June 2026, Proposed Standard; published from [draft-ietf-cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/18/) | receipts as COSE_Sign1, the `RFC9162_SHA256` verifiable data structure, inclusion and consistency proofs |
| COSE Hash Envelope | [RFC 9995](https://www.rfc-editor.org/rfc/rfc9995), July 2026, Proposed Standard; published from [draft-ietf-cose-hash-envelope-10](https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/10/) | signing a digest of a statement, so a log can register it without seeing it |
| SCITT Reference APIs (SCRAPI) | [draft-ietf-scitt-scrapi-11](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/), in the RFC Editor queue, expires 28 December 2026 | the HTTP API: register a statement, resolve a receipt, discover keys |
| Fully-specified algorithms for JOSE and COSE | [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), October 2025 | the COSE algorithm `Ed25519` (-19), which replaces the polymorphic `EdDSA` (-8) |
| SCITT charter | [charter-ietf-scitt-01](https://datatracker.ietf.org/doc/charter-ietf-scitt/) | scope: building blocks for software supply chains |

## In short

- **Our inclusion proof is already a SCITT inclusion proof.** We hash with RFC 6962 and prove with RFC 9162, sections 2.1.3 and 2.1.4. RFC 9942 registers exactly that structure as `RFC9162_SHA256` (value 1). The proof `{ leafIndex, treeSize, hashes }` carries the same three values as RFC 9942's `[tree_size, leaf_index, inclusion_path]`, in another order and encoding. The one exception is a tree of one leaf, below.
- **Our signatures and envelopes are not SCITT's.** SCITT requires COSE_Sign1 in CBOR, with an issuer and subject in a protected CWT Claims header. We sign DSSE envelopes over canonical JSON. Ed25519 is not the problem: COSE has it as -19.
- **Our log is not yet a transparency service.** It authenticates the client, but it does not verify the issuer's signature, keep trust anchors, or publish its registration policy in its own log. RFC 9943 requires all three.
- **Recommendation.** Issue each receipt in a second encoding, a COSE_Sign1 hash envelope over the same statement bytes. Teach the hosted log SCRAPI and the mandatory registration checks. Then write the agent-action profile as the rules that sit on top: what goes in the protected header, what a registration policy checks, and how the authorization, receipt, and reconciliation statements relate. Keep DSSE as the primary format until the v1.0 decision in step 1 of issue #185.
- **The field is crowded.** At least five individual drafts already profile SCITT for agent actions, two of them updated in October 2026, and four more extend one of them. The [next steps](#next-steps) start from them rather than from a blank draft.

## The roles

| SCITT (RFC 9943, section 3) | agent-custody | notes |
| --- | --- | --- |
| Issuer | the gateway (`issuer.kind: "gateway"`) or the SDK (`issuer.kind: "sdk"`) | SCITT does not separate an issuer that enforces from one that self-reports. A profile must, because it is the first thing our verifier reads. |
| Signed Statement | the receipt envelope and the authorization statement, both signed by the issuer; also the delegation grant, the human approval, and the upstream attestation, each signed by another party | today the receipt embeds the other envelopes rather than registering them |
| Statement | the in-toto Statement v1 with `predicateType` `https://agent-custody.dev/receipt/v0.2` | RFC 9943, section 6, lists in-toto among the expected payload formats, so the payload can stay as it is |
| Subject (`sub`) | the in-toto subject name, `tool-call:<tool>:<receiptId>` | the authorization statement has the same subject as the receipt that follows it, which is what `sub` is for: grouping statements about one artifact |
| Artifact | one tool call | |
| Transparency Service | the log: a log file, `agent-custody log`, or the hosted log at log.agent-custody.dev | multi-tenant through `/t/<tenant>/`. RFC 9943, section 5.1, suggests one issuer identity per tenant, which our `log` id already is. |
| Receipt | the pair of a signed tree head and an inclusion proof, `treeHead` and `inclusion` in the bundle | one COSE_Sign1 in SCITT; two objects for us. See below. |
| Transparent Statement | the receipt bundle | SCITT puts the receipts in the statement's unprotected header (label 394). We put them beside the envelope. |
| Registration Policy | the tenant's bearer token, the rate limit, the monthly quota, and `hashOnly` | none of this is published as a statement in the log, and none of it is checked against the statement |
| Relying Party, Auditor | `verify`, `audit`, `log-check`, the browser verifier, the witness | |

## The receipt as a Signed Statement

What a COSE encoding of the same receipt would carry, header by header.

| COSE_Sign1 part (RFC 9943, figure 3) | value for an agent-custody receipt | where it comes from today |
| --- | --- | --- |
| tag | 18 (COSE_Sign1) | |
| `alg` (1) | -19, `Ed25519` ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), section 2.2) | Ed25519, implied by the keyid |
| `kid` (4) | the 32 bytes of our keyid, the SHA-256 of the key's SPKI DER | `signatures[0].keyid`, hex |
| CWT Claims (15), `iss` (1) | a URI naming the issuer: the gateway operator's, or the SDK host's | **missing.** We identify issuers by key only. A gateway publishes no identity document. |
| CWT Claims (15), `sub` (2) | the in-toto subject name | `subject[0].name` |
| CWT Claims (15), `iat` (6) | the receipt's `timestamp` as seconds since the epoch | `predicate.timestamp` |
| `typ` (16) | `application/scitt-statement+cose`, registered by RFC 9943, section 10.1 | |
| `payload_hash_alg` (258) | -16, SHA-256 ([RFC 9995](https://www.rfc-editor.org/rfc/rfc9995)) | in a hash envelope only |
| `payload_preimage_content_type` (259) | `application/vnd.in-toto+json` | the DSSE `payloadType` |
| `payload_location` (260) | optional: where the receipt file can be fetched by someone allowed to | |
| issuer kind | `gateway` or `sdk`, in the protected header so that a registration policy can read it | `predicate.issuer.kind`, in the payload. Needs a header label or CWT claim of its own. |
| payload | the SHA-256 of the canonical statement (hash envelope), or the canonical statement itself | the DSSE `payload` |
| unprotected header | empty when registered (RFC 9943, section 6.3); receipts (394) once registered | |

The statement bytes do not change. The same canonical JSON is signed twice, once under the DSSE pre-authentication encoding and once under the COSE `Sig_structure`. A verifier that reads COSE checks the second signature and then runs our checks on the payload. A verifier that reads DSSE does what it does today.

The hash envelope is the variant that matters for us. The hosted log is hash-only, and strict mode requires that: the log sees a leaf hash and never the receipt. With RFC 9995, a transparency service still verifies the issuer's signature, because the signature is over the digest. It learns the headers: `iss`, `sub`, `iat`, and the issuer kind. So **`sub` must not name the tool when the log may not learn it.** A profile should make `sub` the receipt id alone, `urn:uuid:<receiptId>`, and keep the tool name in the payload, where a capture rule governs it. RFC 9942, section 6.2, requires a privacy analysis of every mandatory header.

## The log as a transparency service

What RFC 9943 requires of a transparency service, and where the log stands.

| requirement | RFC 9943 | the log today | to close it |
| --- | --- | --- | --- |
| produce COSE Receipts | 5.1 | signed DSSE tree heads and JSON inclusion proofs | emit a COSE Receipt of inclusion beside them |
| verify the issuer's signature at registration | 5.1.1.1, 6.3 | no: `POST /append` checks the bearer token and nothing in the leaf | verify against the tenant's trust anchors; a hash-only leaf cannot be checked, a hash envelope can |
| keep trust anchors | 5.1.1.1 | no issuer keys are registered with the log | a list of issuer keyids per tenant, managed through the portal |
| publish the registration policy and trust anchors as Signed Statements in the log | 5.1.1.1 | no | log them as the tenant's first leaves, and log every change |
| apply the policy most recently committed | 5.1.1 | policy is configuration | follows from the row above |
| reproducible registration for auditors | 5.1.1.2 | an auditor can rebuild the tree but not re-run a check, because no check is made | follows from the rows above |
| append-only, non-equivocation, replayability | 5.1.3 | RFC 9162 tree, consistency proofs, checkpoints on a second host, the witness, the anchor | already met; the witness and the anchor go beyond what SCITT asks |
| unprotected header emptied before inclusion | 6.3 | the leaf is the whole canonical envelope | define the leaf as the COSE_Sign1 with an empty unprotected header |
| a receipt for every registered statement, on request | 6.3 | inclusion is returned on append; a later proof needs the tenant's token and a client that rebuilds it | `GET /entries/<id>`, SCRAPI section 2.4 |
| register | [SCRAPI](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/) section 2.3, `POST /entries` with `application/cose` | `POST /append` with JSON | add `POST /entries`, returning 201 with the receipt or 202 with a location |
| key discovery | SCRAPI section 2.1, `/.well-known/scitt-keys`, a COSE Key Set | `/.well-known/agent-custody-log.json`, JSON with PEM keys | serve both, from the same keys: OKP keys, curve Ed25519 (6), kid set |
| errors | SCRAPI section 2, Concise Problem Details in CBOR | JSON `{ error }` | on the SCRAPI routes only |

SCITT needs the leaf to be defined, and RFC 9942 does not define it. Its verifier applies the proof "to the bytes of a candidate entry" and leaves the entry to the transparency service. Our leaf is the canonical JSON of the DSSE envelope. A COSE leaf would be the encoded COSE_Sign1 with an empty unprotected header. [draft-gruszka-scitt-statement-identification-02](https://datatracker.ietf.org/doc/draft-gruszka-scitt-statement-identification/02/) collects the open questions about how a statement is identified, and the profile should answer them for agent actions.

## Inclusion proofs and COSE Receipts

The two proofs carry the same values.

| ours | RFC 9942, section 5.2 |
| --- | --- |
| `inclusion.treeSize` | `tree_size` |
| `inclusion.leafIndex` | `leaf_index` |
| `inclusion.hashes`, hex strings | `inclusion_path`, byte strings, same order |
| the leaf hash, `SHA-256(0x00 ‖ leaf)` | the same; RFC 9162 |
| `rootHash` in the tree head payload | the receipt's detached payload, the Merkle tree hash at `tree_size`, recomputed by the verifier |
| the tree head's signature, by the log's key or the issuer's | the receipt's COSE_Sign1 signature |
| `log` in the tree head | the receipt's `iss` |
| `timestamp` in the tree head | a CWT claim in the receipt's protected header, such as `iat` |

Three differences are worth recording.

1. **A tree of one leaf.** RFC 9942's CDDL requires at least one hash in an inclusion path, `inclusion_path: [ + bstr ]`. The first leaf of a log has an empty path, as the bundle example in the specification shows: `{ "leafIndex": 0, "treeSize": 1, "hashes": [] }`. Consistency paths have the same limit, `[ + bstr ]`, and RFC 9162 makes the proof between two equal sizes empty. Our log produces both: the first receipt of every tenant, and the heartbeat checkpoint that re-signs a quiet log at the size it already had. Ask the working group whether `+` was meant to exclude these cases; if not, raise an erratum. Until it is settled, the profile must say what to do: emit no receipt at size one, or relax the CDDL.
2. **Where the signature sits.** Our tree head is signed once per size and serves every receipt under it. A COSE Receipt signs the root together with its protected header. RFC 9943, section 6, requires `iss` and `sub` in that header, and its example receipt repeats the statement's subject. So a COSE Receipt is signed once per subject. The log signs heads on request, so the cost is a signature per append, which it pays already. But a receipt can no longer be checked by matching its tree head to a published checkpoint byte for byte. It has to be checked by root and size.
3. **Order of checks.** RFC 9942 verifies the proof first and the signature second, over the root the proof yields. Our verifier checks the tree head's signature and then recomputes the root from the proof. The result is the same. The vectors should include a bundle that fails in each order.

## Checkpoints, consistency, and witnesses

A checkpoint is a signed tree head at a size. `GET /consistency` returns an unsigned RFC 9162 consistency proof between two sizes. RFC 9942, section 5.3, defines a **Receipt of Consistency**: a COSE_Sign1 whose detached payload is the newer root, with the proof in the unprotected header. A checkpoint together with the proof from the previous checkpoint is that receipt. The log can serve it as a second form of `GET /checkpoints` and lose nothing.

A witness countersigns by adding its signature to the checkpoint's DSSE envelope, which DSSE allows. COSE_Sign1 has one signer. The nearest SCITT construction is a second receipt from a second service, which RFC 9943, section 5, allows. A witness does not register statements, though, so it is not a transparency service. Two options:
- the witness issues its own Receipt of Consistency over the checkpoint it checked, and a verifier that requires the witness requires that receipt;
- the profile defines the countersigned checkpoint as a COSE_Sign (several signers) rather than a COSE_Sign1.

The first needs no new structure. Prefer it.

[draft-mih-scitt-checkpointed-local-log-02](https://datatracker.ietf.org/doc/draft-mih-scitt-checkpointed-local-log/02/) carries a producer's own checkpoints as Signed Statements and registers them with independent transparency services. That fits an SDK that keeps a local log file. It uses a Merkle Mountain Range ([draft-bryce-cose-receipts-mmr-profile-03](https://datatracker.ietf.org/doc/draft-bryce-cose-receipts-mmr-profile/03/)) rather than RFC 9162, so it is a pattern to borrow, not a format to adopt.

## Chain anchoring

SCITT has nothing to say about anchoring. RFC 9943 leaves the security of each data structure to its own specification (section 5.1.3) and allows adjacent services beside a transparency service (section 5.1.4). The anchor is one. It commits checkpoints to an EVM chain as an RFC 9162 tree of checkpoint leaves; [anchoring](anchoring.md) is the guide. [draft-fassbender-scitt-time-anchor-08](https://datatracker.ietf.org/doc/draft-fassbender-scitt-time-anchor/08/), an independent-stream draft, does the same for Bitcoin through OpenTimestamps and also needs no change to SCITT.

Options:
- **nothing**: anchoring stays an adjacent service, described in an informative appendix of the profile;
- **an anchor record as a Signed Statement**, issued by the anchor's key and registered like any other statement, so that a relying party can find the anchor through the log;
- **a new verifiable data structure** in RFC 9942's registry, for "an RFC 9162 tree whose root is in a transaction". This would need a profile of its own and expert review, and it buys nothing that the first option lacks.

Choose the first option now. Consider the second once anyone outside agent-custody asks for it.

## What differs, and the options for each

| difference | an alternative COSE encoding | a profile | nothing | recommendation |
| --- | --- | --- | --- | --- |
| DSSE, not COSE_Sign1 | issue each receipt twice: DSSE as now, plus a COSE_Sign1 hash envelope over the same statement bytes | a profile that admits a DSSE statement as the payload of a COSE_Sign1 (signed twice, nested) or as a "bare" presentation beside the enveloped one, as [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/01/) does | stay DSSE-only and claim alignment with the data structure alone | **encoding.** RFC 9943 accepts only COSE_Sign1 as a Signed Statement, so the DSSE form cannot be registered with another vendor's service. One statement and two signatures is the smallest change. |
| JSON, not CBOR | the statement stays canonical JSON; only the envelope is CBOR | | | nothing to decide: a COSE payload can be any bytes, and the preimage content type names them |
| Ed25519 | `alg` -19 | the profile makes -19 mandatory to implement and rejects -8 | | **encoding**, -19. One key signing under two formats is a reuse that RFC 9943, section 9.4, asks issuers to avoid. The two signed structures cannot be mistaken for each other (DSSE's begins `DSSEv1`, COSE's is a CBOR array that begins `Signature1`), so the profile should argue this in its security considerations rather than require a second key. |
| keyid, not a named issuer | `kid` from our keyid | the profile requires `iss` as a URI and says how the key behind it is found | | **profile.** It needs an issuer key document for gateways like the log's, which we do not have. |
| our tree heads | a COSE Receipt of inclusion beside the DSSE tree head | | | **encoding.** The values are the same, and the size-one case goes to the working group. |
| checkpoints and consistency proofs | Receipts of Consistency | | | **encoding** |
| witness countersignatures | a witness Receipt of Consistency | | keep DSSE countersignatures | **encoding**, and keep DSSE countersignatures alongside |
| chain anchoring | | an informative appendix | | **nothing** normative |
| a log that does not check the issuer | | the profile's registration policy | | **implement** the mandatory checks; it is a requirement of RFC 9943, not an option |
| a hash-only log | the hash envelope | the profile requires the hash envelope for logs the issuer does not run | | **profile** |

## An agent-action profile

What an agent-custody profile of SCITT would contain, section by section.

1. **Scope and roles.** One tool call is one artifact. Issuers are enforcing gateways and self-reporting SDKs. The transparency service is a log the issuer may or may not run. Relying parties are auditors who hold public keys only.
2. **Signed Statements.** COSE_Sign1, tagged. `alg` -19 mandatory to implement. `kid` is the SHA-256 of the SPKI. CWT claims `iss` and `sub`, with `sub` as `urn:uuid:<receiptId>`, and `iat`. `typ`. The issuer kind is a protected header. The payload is a hash envelope over an in-toto Statement v1, or the statement itself where the service may read it.
3. **Statement types**, one `predicateType` each, related by `sub`: the authorization (before the call), the receipt (after it), the reconciliation (the provider's terminal outcome, naming the original), the delegation grant (signed by the principal), the human approval (signed by approvers), and the upstream attestation (signed by the tool). For each, which fields a verifier reads, with their provenance labels: `attested`, `observed`, and `claimed`. The labels are what makes the evidence honest, and no other draft has them in this form.
4. **Registration policy.** Issuer keyids per tenant as trust anchors, published in the log. Required protected headers. An optional strict claim. The rule that a receipt referring to an authorization is refused unless that authorization was registered earlier in the same log. Today our verifier checks the order; with this rule, the service enforces it.
5. **Receipts.** `RFC9162_SHA256`, inclusion mandatory and consistency recommended. How the first leaf of a log is handled. Receipts of Consistency for checkpoints, and for witnesses.
6. **Verification.** The verification steps of the specification, in order, mapped onto COSE verification and payload checks. How a verifier reports a check passed "as committed" when a capture rule withholds a value.
7. **Privacy considerations.** Capture rules and salted commitments. What the headers reveal to the service (RFC 9942, section 6.2). What the tree size reveals: a per-tenant log leaks the tenant's call count (RFC 9942, section 6.1).
8. **Security considerations.** An SDK receipt is self-reported. One key under two formats. What SCITT does not give: completeness. An issuer can leave a call unregistered (RFC 9943, section 9.3); strict mode and provider-side completeness ([issue #178](https://github.com/svayatta/agent-custody/issues/178)) are our answers. The threat model in [threat-model.md](threat-model.md).
9. **Appendices.** Anchoring, informative. Conformance vectors in both encodings. The mapping to DSSE for existing receipts.

## Other agent-action drafts

None of these is a working group document. All are individual submissions, and the charter scopes the group to software supply chains. Whether the group takes on any agent profile is a charter question for the chairs, not one a better draft answers. Each row is from the draft's abstract, and from its text where noted.

| draft | what it records | overlap with ours |
| --- | --- | --- |
| [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/01/), August 2026 | a signed action receipt over canonical JSON, hash-chained, bare or in a COSE_Sign1 | closest in encoding: its text requires `alg` -19 and rejects -8, uses JCS ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)), and defines bare and enveloped forms |
| [draft-mih-scitt-agent-action-capsule-05](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/05/), September 2026, with [selective disclosure](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule-sel-disc/00/), [provenance binding](https://datatracker.ietf.org/doc/draft-rampalli-scitt-capsule-provenance-binding/00/), and two companion drafts | one record per action on every verdict, refusals included; an attempt is distinct from an observed result | our `denied` and `withheld` receipts, `execution.upstream`, and `consumed` |
| [draft-munoz-scitt-permit-profile-01](https://datatracker.ietf.org/doc/draft-munoz-scitt-permit-profile/01/), July 2026 | a pre-execution authorization bound to the canonical request, paired with a closure record | our authorization statement and precommit |
| [draft-emirdag-scitt-ai-agent-execution-01](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/01/), October 2026 | operator as issuer, an independent evidence custodian as service, sequence completeness, redaction receipts, compliance mappings | our roles, and [compliance.md](compliance.md) |
| [draft-thaha-scitt-agent-execution-evidence-00](https://datatracker.ietf.org/doc/draft-thaha-scitt-agent-execution-evidence/00/), October 2026 | agent identity and capabilities bound to a hash-chained record of calls; admission records across operators | the delegation grant, and receipts for agent-to-agent calls |
| [draft-jangra-scitt-digest-evidence-00](https://datatracker.ietf.org/doc/draft-jangra-scitt-digest-evidence/00/), October 2026 | an RFC 9162 log of salted digests only, with completeness chains, selective disclosure, and spot checks | our hash-only log and capture rules |
| [draft-kamimura-scitt-refusal-events-04](https://datatracker.ietf.org/doc/draft-kamimura-scitt-refusal-events/04/), October 2026 | a claim set for AI content refusals | narrower: content refusals, not tool calls |
| [draft-mih-sokolov-scitt-payload-binding-06](https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/06/), October 2026 | declared canonicalization, a derived identifier, and digest references, using RFC 9995 | how our canonical JSON and digests would be declared |

## Next steps

Nothing has been posted to the IETF. Each step below is for the maintainers to decide, and the first four need no one outside the project.

1. **Read the closest drafts in full**: the noa, capsule, and permit drafts first. For each, record what it requires that we cannot meet and what we have that it lacks, in a reply on issue #185. Then decide whether to co-author with one of them or write our own. Our contribution is distinct in three places: provenance labels, an authorization that the service orders before its receipt, and a bridge from DSSE and in-toto. A sixth profile that overlaps the other five on everything else will not be adopted.
2. **Build the COSE encoding in code before writing a draft.** Add a COSE_Sign1 hash envelope beside the DSSE envelope in `src/receipt.ts`, verify it in `src/verify.ts` and the browser verifier, and add vectors in both encodings. Then add `POST /entries`, `GET /entries/<id>`, and `/.well-known/scitt-keys` to the log, with issuer verification against per-tenant trust anchors. A profile that has running code and vectors gets read.
3. **Settle the open points in the v1.0 specification** (step 1 of issue #185): `sub` as the receipt id alone; an `iss` URI and the gateway's identity document; the issuer-kind header; the leaf of a COSE entry; what happens at tree size one.
4. **Interoperate.** Register a receipt with an existing SCITT service that implements SCRAPI, and verify its receipt with our verifier. Verify one of our COSE receipts with someone else's SCITT verifier. Record which implementations were used.
5. **Ask before submitting.** On the scitt@ietf.org list: whether the inclusion-path CDDL in RFC 9942 was meant to exclude a tree of one leaf; and whether the chairs see agent-action profiles inside the charter, and if not, where they would go. The list's archive is public, so a message there is publication. It needs the maintainers' sign-off and wording.
6. **The individual draft.** `draft-<author>-scitt-agent-custody-profile-00` (the name is an assumption), in kramdown-rfc, with the sections above and the vectors as an appendix. The Internet-Draft cutoff for IETF 127 is 2 November 2026. That is too soon for steps 1 to 4. Aim for IETF 128 in Kuala Lumpur, which starts 6 March 2027, and for discussion on the list before then.
7. **The hackathon.** IETF 127's hackathon is on 14 and 15 November 2026 in San Francisco. Its wiki already lists a SCITT time-anchor project. The SCITT session is on Wednesday 18 November, from 16:30 to 17:30 Pacific time. Attending, remotely or in person, is worth it to meet the authors of the drafts above. A project of our own fits IETF 128's hackathon, once step 4 has a result.

## Not done here

This page changes no code and no format. It does not decide between DSSE and COSE for v1.0; that is step 1 of issue #185. It claims no conformance to SCITT, and none should be claimed until step 2 is built and step 4 has been run against an implementation we did not write.

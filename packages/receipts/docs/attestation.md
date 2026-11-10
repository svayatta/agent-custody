# Attested gateway keys

A receipt proves that a gateway key signed it. It does not prove which gateway code held that key. An operator could run a changed gateway that skips logging, or records something other than what the upstream returned, and sign with the same key. An attested key closes part of that gap. The gateway makes its key inside a measured workload, and the platform's evidence ties the key to the image that runs.

This is the first slice of [issue #179](https://github.com/svayatta/agent-custody/issues/179). It is on a branch and has not been released. The [last section](#what-this-slice-proves-and-what-it-does-not) says what it proves and what it does not.

## The chain

```
receipt ──signed by──▶ gateway key ──report data──▶ platform evidence ──measured──▶ image digest ══ release digest
   │                       ▲                                                                            ▲
   └─ issuer.attestation ──┴── attestation statement (logged once per key)                  given by the verifier
```

1. At start, the gateway makes an Ed25519 key in memory. It never writes the key to a file, and there is no key file in the config.
2. The gateway asks an attestation provider for evidence. The key's keyid (sha256 of the public key) goes in as the report data, or as the nonce.
3. The gateway signs an attestation statement with the key itself. The statement holds the public key and the evidence. The gateway appends it to the log once and writes it to `receipts/attestations/<keyid>.json`. Over HTTP the gateway also serves it at `GET /attestation`.
4. Every receipt and authorization that the key signs carries `issuer.attestation`: the sha256 of the canonical attestation envelope.
5. The verifier is given the attestation and a release digest. It trusts the key only through the attestation, and it checks each link of the chain.

### The receipt format

This adds one optional field, `issuer.attestation`, inside `issuer`, which a capture rule always leaves in clear. The predicate type stays `receipt/v0.2`, as every earlier optional field did. Receipts without the field verify as before, and `vectors/receipts.json` is unchanged. The new checks run only when the verifier is given an attestation. Their vectors are in a separate file, `vectors/attestation.json` (`bun run vectors:attestation`). The TypeScript reference and the browser verifier both run them. The Python verifier ignores the field and does not run these checks yet.

## Configuration

Replace `identity.keyFile` with `attestation`. A config with both, or with neither, is refused.

```json
{
  "identity": {},
  "attestation": { "provider": "gcp-confidential-space", "audience": "https://agent-custody.dev/attestation" }
}
```

| provider | runs on | evidence |
| --- | --- | --- |
| `simulated` | anywhere, including Docker on macOS | a statement signed by a **published test key** that says `simulated: true`, with the image digest read from `AGENT_CUSTODY_IMAGE_DIGEST` (`imageDigestEnv` changes the name). Nothing measures that digest. |
| `gcp-confidential-space` | a Confidential Space VM (AMD SEV or Intel TDX) | a Confidential Space **PKI token**: an RS256 JWT from Google's attestation service with an x5c chain to Google's Confidential Space root. Its `eat_nonce` is the keyid, and `submods.container.image_digest` is the image the launcher measured. |

`agent-custody check` reports an attested key as generated in memory, and it warns that simulated evidence proves nothing. `check --connect` tests the upstreams with a scratch key and no attestation. The admin console cannot verify an attested gateway's receipts yet, because it reads the gateway's key file.

A new key is made on every start. Receipts left in the outbox by an earlier run were signed by an earlier key. They stay in the outbox as foreign entries, which is the behaviour for a rotated key. Strict mode has no outbox.

## Verifying

```bash
# a receipt: the attested key replaces --issuer-key
agent-custody verify receipts/<id>.json --principal-key principal.pub \
  --attestation receipts/attestations/<keyid>.json --release-digest sha256:<digest>

# the attestation alone, for example as fetched from the gateway's GET /attestation
agent-custody verify --attestation attestation.json --release-digest sha256:<digest>
```

| flag | meaning |
| --- | --- |
| `--attestation <file>` | the attestation bundle |
| `--release-digest sha256:<hex>` | the image the verifier expects: the digest of a published, cosign-signed build. Required with `--attestation`. |
| `--allow-simulated-attestation` | accept simulated evidence. **For local tests only.** Without it, simulated evidence always fails `attested build`. |
| `--attestation-audience <aud>` | the audience the gateway asked for, when it is not the default |
| `--attestation-root <pem>` | pin another Confidential Space root in place of Google's. Tests use this flag with a test chain. |

The checks, in order:

| check | fails when |
| --- | --- |
| `attestation statement signature (attested key)` | the statement is not signed by the key it names, or was changed after it was signed |
| `attestation log inclusion` | the statement is not under the bundle's signed tree head, signed by a log key or the attested key |
| `attestation evidence` | the evidence does not verify. Simulated: the published test key's signature, and the `simulated` marker. Confidential Space: RS256, a three-certificate chain that ends at a pinned root, each certificate signed by the next, the token issued inside each certificate's validity, `iss`, `aud`, `swname: CONFIDENTIAL_SPACE`, `dbgstat: disabled-since-boot` (a debug image lets the operator in), `hwmodel` AMD SEV, SEV-ES, or Intel TDX, `secboot`, a `STABLE` Confidential Space image, and a container image digest |
| `attestation binds the issuer key` | the evidence's report data or nonce is not this key's keyid |
| `attested build` | the measured image is not the release digest, or the evidence is simulated and the test flag was not given |
| `receipt signed by the attested key` | the receipt was signed by another key, even one the verifier trusts with `--issuer-key` |
| `receipt names the attestation` | `issuer.attestation` is missing or names another attestation |

A Confidential Space token expires after an hour, and the check does not compare it with the current time. It checks the certificates' validity when the token was issued (`iat`). The PKI token carries its own chain, and the root rotates every ten years, so a receipt can still be checked long after the token expired. Google's root is pinned in `src/attestation.ts` and in the browser verifier. Its SHA-1 fingerprint is `B9:51:20:74:2C:24:E3:AA:34:04:2E:1C:3B:A3:AA:D2:8B:21:23:21`, the one Google publishes, and a test checks it.

## Choosing the real provider

Two candidates could produce the first real evidence. The question that decides is how each one binds to the container image digest, because the image digests are what the release workflow signs with cosign.

| | GCP Confidential Space | raw AMD SEV-SNP (Linux configfs-tsm, `/sys/kernel/config/tsm/report`) |
| --- | --- | --- |
| what is measured | Google's hardened launcher boots a measured VM image, pulls the workload container, and records its digest in the vTPM/RTMR. Google's attestation verifier checks the hardware quote and the event log, and issues a token. | the guest's initial memory: firmware, plus kernel, initrd, and command line on a measured direct boot. The container is not in the launch measurement. |
| binding to the image digest | **direct**: `submods.container.image_digest` is a claim in the token | **indirect**: you build your own VM image with the container baked in, or measured through dm-verity and a measured boot chain, and then reproduce that launch measurement from source |
| report data | up to six caller nonces of 10 to 74 bytes (the keyid in hex is 64) | 64 bytes chosen by the caller |
| who you trust | AMD or Intel, plus Google's launcher and attestation service | AMD only, through the ARK → ASK → VCEK chain from AMD's key server |
| offline verification years later | yes, with the PKI token: its x5c chain ends at a root that rotates every ten years | yes: AMD's chain, and the report itself |
| work before the first real receipt | small: a provider that asks a local socket for a token, and a JWT verifier | large: a VM image, measured boot, and reproducing the launch digest before the measurement means anything |

**Chosen: Confidential Space.** It binds directly to the image digest, so the cosign-signed digest a verifier already trusts becomes the value the check compares. It runs on both AMD and Intel. A test can begin in an afternoon. The cost is a larger trusted base: Google's launcher and attestation service. Raw SEV-SNP stays the route to dropping Google from that base, after reproducible builds make the launch measurement worth comparing. Azure confidential containers and AWS Nitro Enclaves come later, behind the same `AttestationProvider` interface.

The gateway asks for the token at `/run/container_launcher/teeserver.sock`, `POST /v1/token`, with `{"audience", "token_type": "PKI", "nonces": [keyid]}`. It asks for a PKI token rather than an OIDC token. An OIDC token is checked against Google's JWKS, which rotates, so an old receipt could no longer be checked. A PKI token carries its own chain to a root that changes once a decade.

## Running it locally (simulated)

```bash
node packages/receipts/examples/45-attested-gateway.ts      # in-process, ends with OK
deploy/gateway/tee/local-simulated.sh                        # the real image, in Docker
```

The script builds the gateway image from your checkout and sets its id as `AGENT_CUSTODY_IMAGE_DIGEST`. It writes a starter config with `attestation: { provider: "simulated" }`, starts the container, and makes one call. Then it verifies on the host:

- The receipt verifies as an attested build with `--allow-simulated-attestation`. The report says SIMULATED.
- It fails `attested build` without that flag, and against another digest.
- A receipt edited after signing fails `receipt signature`.
- An attestation whose evidence was edited fails `attestation statement signature`, and the key is no longer trusted.

It also checks that no key file was written. Locally the image id stands in for a registry digest, and the simulated provider is told that digest. Nothing measures it.

## Running it on a confidential VM

**None of this has run on real hardware yet.** The provider and the token checks are written from Google's published documentation. The tests run against a test chain in the documented shape. The steps below are the first real run. They cost money, so the user starts them.

What to provision:

| | |
| --- | --- |
| cloud | a Google Cloud project with billing on, and the Compute Engine, Confidential Computing, IAM Credentials, and Artifact Registry APIs enabled |
| machine | `n2d-standard-2` (AMD SEV) in a zone that offers it, such as `us-central1-a`. `c3-standard-4` gives Intel TDX instead. |
| image | `confidential-space-images`, family `confidential-space-debug` for the first run, then `confidential-space` (production) |
| identity | a workload service account with `roles/confidentialcomputing.workloadUser` (to get tokens), `roles/logging.logWriter`, and read access to the Artifact Registry repository |
| network | a firewall rule for tcp:8790 from your own IP only |
| approximate cost | an `n2d-standard-2` Confidential VM costs roughly US$0.08 to US$0.10 an hour on demand in us-central1, about US$60 to US$75 a month if left running. Check the Compute Engine and Confidential VM pricing pages. Both stages below fit in an hour, well under US$1 plus a few cents of Artifact Registry storage. Delete the VMs afterwards. |

Steps. Run them on your machine, with this branch checked out.

1. **Build and push the image, with the config baked in.** A Confidential Space VM cannot mount files from the host. The config goes into the image, so the measured digest also covers the config and policy. Write `config/gateway.json` with `"identity": {}` and `"attestation": { "provider": "gcp-confidential-space" }`, a policy, the principal's public key, and absolute `/data/...` paths for what the gateway writes. `deploy/gateway/tee/local-simulated.sh` shows such a config.
   ```bash
   (cd packages/receipts && bun run build && bun pm pack --destination ../../deploy/gateway/pkg)
   cat > deploy/gateway/Dockerfile.tee <<'EOF'
   FROM gateway-base
   COPY config/ /config/
   LABEL "tee.launch_policy.log_redirect"="always"
   CMD ["gateway", "--config", "/config/gateway.json", "--http", "--host", "0.0.0.0", "--port", "8790"]
   EOF
   docker build --platform linux/amd64 -t gateway-base deploy/gateway
   docker build --platform linux/amd64 -f deploy/gateway/Dockerfile.tee -t REGION-docker.pkg.dev/PROJECT/REPO/agent-custody-gateway:tee deploy/gateway
   docker push REGION-docker.pkg.dev/PROJECT/REPO/agent-custody-gateway:tee      # note the sha256 digest it prints
   rm -f deploy/gateway/pkg/*.tgz deploy/gateway/Dockerfile.tee
   ```
2. **The debug image first.** It lets you SSH in, and the verifier must refuse it.
   ```bash
   gcloud compute instances create ac-tee-debug --zone us-central1-a --machine-type n2d-standard-2 \
     --confidential-compute-type SEV --shielded-secure-boot --maintenance-policy MIGRATE \
     --image-project confidential-space-images --image-family confidential-space-debug \
     --service-account WORKLOAD_SA --scopes cloud-platform \
     --metadata tee-image-reference=REGION-docker.pkg.dev/PROJECT/REPO/agent-custody-gateway@sha256:DIGEST,tee-container-log-redirect=true
   curl -s http://EXTERNAL_IP:8790/attestation > attestation-debug.json
   agent-custody verify --attestation attestation-debug.json --release-digest sha256:DIGEST
   ```
   Expected: `FAIL attestation evidence (the token's debug status is enabled: ...)`. The checks run in order, so reaching the debug status means the chain, the signature, the issuer, the audience, and the software name have already passed on real evidence. Decode the token's claims and compare `submods.container.image_digest` with `DIGEST`. An image that is an index for several platforms has a different digest for each platform's manifest, and the verifier must be given the one the token carries. Keep `attestation-debug.json`: it is the first genuine fixture, and a test can assert this exact refusal.
3. **The production image.** Repeat step 2 with `--image-family confidential-space` and the name `ac-tee`. Expected: `RESULT: ATTESTED BUILD, key <keyid>`. Then connect an agent with a grant and make a call. The receipt names this attestation.
4. **Delete both VMs**: `gcloud compute instances delete ac-tee-debug ac-tee --zone us-central1-a`.

For evidence that does not rest on the VM's own file log, give the gateway a remote log (`log.url` with `hashOnly` and `keys`). The attestation leaf then sits in a log the operator does not run.

## What this slice proves, and what it does not

It proves, when `attested build` passes with real evidence:

- The key that signed the receipt was made inside a Confidential Space workload running the image with the given digest, on AMD SEV or Intel TDX, in a production (not debug) image, by the word of Google's attestation service and the hardware vendor.
- The key appears in exactly one logged attestation, and the receipt names that attestation.
- A receipt signed by any other key, a receipt checked against another image, simulated evidence, and evidence changed after the fact all fail.

It does not prove yet:

- **That the result came from the upstream unchanged.** TLS to each upstream does not end inside the enclave yet, and stdio upstreams do not run inside it. The operator controls the network path. Upstream signatures, where an upstream gives them, remain the stronger check.
- **That the image was built from a given source tag.** Release builds are not reproducible yet. The release digest is trusted because the release workflow signed it with cosign, not because anyone rebuilt it from source and compared the result.
- **That strict mode was on.** Strict mode is not forced for an attested key. Use `--require-strict` beside the attestation.
- **Anything in the Python verifier.** It ignores `issuer.attestation` and runs none of these checks.
- **AWS Nitro Enclaves, Azure, or raw SEV-SNP.** Only the Confidential Space provider exists.
- **That receipts can leave a production VM.** A hardened image has no SSH, and the gateway serves its attestation but not its receipts. Getting receipts out of a production VM is not solved yet.
- **Resistance to side channels**, which are in scope for the threat model, or to a compromised Google launcher or attestation service, both of which this provider trusts.
- **Anything at all with the simulated provider.** Its evidence is signed by a key anyone can derive. It exists to test the plumbing on a laptop.

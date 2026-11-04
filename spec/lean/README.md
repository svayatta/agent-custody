# A Lean 4 specification of the verifier

This is a model of the verifier's core in [Lean 4](https://lean-lang.org), with machine-checked proofs. It is not shipped. The TypeScript and Python verifiers stay the ones people run. The model states the acceptance rule precisely. It also checks the conformance vectors as a third implementation, beside those two verifiers.

Tracking issue: #224.

## What is proved

[`AgentCustodySpec/MerkleProofs.lean`](AgentCustodySpec/MerkleProofs.lean) covers the inclusion proofs of RFC 9162. The model in [`Merkle.lean`](AgentCustodySpec/Merkle.lean) follows `packages/receipts/src/log.ts` step for step.

| Theorem | Statement |
| --- | --- |
| `verifyInclusion_complete` | For every leaf of every tree, its audit path verifies against the tree's root. |
| `verifyInclusion_sound` | If the node hash is injective, then any proof that verifies against the root of tree `l`, for leaf `x` at index `i`, satisfies two things: `x` is the leaf at index `i` of `l`, and the proof is exactly that leaf's audit path. |
| `inclusionRoot_eq_down` | The RFC's verification loop, which steers by the bits of the leaf index and of the last index, computes the same root as reading the audit path from the root down along the tree's own splits. This holds for every list of hashes, including ones that are too short, too long, or wrong. |

Each theorem depends only on Lean's three standard axioms: `propext`, `Classical.choice` and `Quot.sound`. To check, run `#print axioms`.

## What is assumed

- **The node hash is injective.** SHA-256 is not injective. So the soundness theorem reads: accepting a wrong leaf, or a proof that is not the audit path, would need a SHA-256 collision, that is, two different inputs to `sha256(0x01 || left || right)` with the same digest.
- **Hashes are parsed bytes.** In `log.ts`, `verifyInclusion` reads proof hashes with `Buffer.from(hex, "hex")`, which skips invalid characters, and compares the root as a lowercase hex string. The model starts from bytes. The vector checker reads hex strictly: lowercase only, and an even number of digits.

## Run it

Install [elan](https://github.com/leanprover/elan), then run this from this directory:

```bash
lake build
```

```bash
lake exe vectors
```

`lake build` checks every proof. `lake exe vectors` runs these checks:
- the FIPS 180-4 SHA-256 examples;
- `packages/receipts/vectors/merkle.json`: the leaf hashes, the root of every prefix, each inclusion verdict, and that `path` produces each vector's proof.

The `lean` workflow runs both, and fails on any `sorry`.

## Still to do

The remaining items of #224:
- consistency proofs;
- the receipt acceptance rule of `verifyBundle`;
- canonical JSON.

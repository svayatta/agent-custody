# Perathos interop vector

Records written by another project's own writer, so that `verify-perathos` is tested against them and not only against our reading of the spec.

`pocketos-replay/` holds three files from the sample evidence pack in [perathos-protocol/perathos](https://github.com/perathos-protocol/perathos), `examples/pocketos_replay/sample-evidence-pack.zip`, at commit `9ec0c3b36d39558fff7aae8652f6c44e7d5396d9` (the zip's SHA-256 is `1815c2f2d4302c44a6e5a1eefd7621579277725f2a1f42ade60e8433c8cd5d56`):

| file | what it is |
| --- | --- |
| `session.jsonl` | the session log, `perathos.receipt/v1`: 8 receipts, 2 signed checkpoints |
| `session.head.json` | the head witness: the last checkpoint's `seq` and `receipt_hash` (it also carries a signature, which the spec does not define and the reader does not check) |
| `verification.json` | the report of Perathos's own verifier on the same log, which `test/perathos.test.ts` compares with ours |

The recorder's key is `d53f11ff38959d472a2e619b346340b44a79866fb8650d96f22ada467f524707`, as `verification.json` names it. The pack's anchors, precondition, manifest, and reports are not copied, because the reader does not read them yet.

Do not edit or regenerate these files. They are copied byte for byte.

The files are Copyright (c) 2026 Tamuka Chagonda and used under the MIT License, whose text is in `LICENSE` beside this file, copied from the same repository.

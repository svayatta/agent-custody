# Door error rates

> How often the door's signals are wrong, for each kind of arrival, and the method beside the numbers. The signals themselves are in [door signals](door-signals.md); the door is in [the door](door.md).

The door does not say whether an arrival is a person. It says what the arrival presented and how far the door could check it: `verified`, `claimed`, or `unknown`. So these numbers answer two narrower questions, one kind of arrival at a time:

- **Does `class` tell a program from a person?** A program should not be `unknown`, and a person should be.
- **Is `verified` given to the genuine agent, and only to it?** A genuine agent is the agent it names, under a permission this door accepts for this route.

What they show: in this test set, no arrival that was not genuine was `verified`, and every genuine agent was. A program that presents nothing is `unknown` every time, like a person. That is not a defect that a better threshold would fix. The door's signals today are credentials, and a program that sends none looks like a browser. Telling those two apart needs behavioural and fingerprint signals, which are not built yet. When they are, their rates will be measured the same way and published here.

## The numbers

Measured with `agent-custody door error-rates --test-set` (200 arrivals of each kind), which anyone can run to get the same counts. The intervals are 95% Wilson score intervals: with 0 errors in 200, the rate could still be as high as 1.9%.

<!-- error-rates:begin -->
**Does `class` tell a program from a person?** An error is a program whose class is `unknown`, or a person whose class is not.

| kind | labels | arrivals | wrong | rate | 95% interval |
| --- | --- | ---: | ---: | ---: | --- |
| `browser` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `script` | test-set | 200 | 200 | 100.0% | 98.1% to 100.0% |
| `script-as-browser` | test-set | 200 | 200 | 100.0% | 98.1% to 100.0% |
| `granted-agent` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `signed-agent` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `declared-name` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `forged-signature` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `replayed-signature` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `untrusted-grant` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `expired-grant` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `out-of-scope-grant` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `grant-under-other-signature` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |

**Is `verified` given to the genuine agent, and only to it?** An error is a genuine agent that is not `verified`, or an arrival that is not genuine and is.

| kind | labels | arrivals | wrong | rate | 95% interval |
| --- | --- | ---: | ---: | ---: | --- |
| `granted-agent` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `signed-agent` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `declared-name` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `forged-signature` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `replayed-signature` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `untrusted-grant` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `expired-grant` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `out-of-scope-grant` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
| `grant-under-other-signature` | test-set | 200 | 0 | 0.0% | 0.0% to 1.9% |
<!-- error-rates:end -->

## Method

### The test set

Each arrival is built to be one known kind, so its label is true by construction. The real door core decides it (`src/door-test-set.ts`), with a Web Bot Auth directory and an origin standing in, in memory. The door writes a receipt for each, and only receipts that verify under the door's key are scored. A test in the repository builds the set again and fails if this page's numbers differ from what the door now does.

<!-- error-rates-kinds:begin -->
| kind | what arrives | a program | genuine |
| --- | --- | --- | --- |
| `browser` | a person's browser: a current Chrome user agent and an HTML accept header, nothing else | no | names no agent |
| `script` | a program that presents nothing: a curl user agent | yes | names no agent |
| `script-as-browser` | a program that sends the browser's headers, byte for byte | yes | names no agent |
| `granted-agent` | an agent with a grant from a trusted principal, in its window, for this route | yes | yes |
| `signed-agent` | an agent with a Web Bot Auth signature its listed directory's key verifies, with a fresh nonce | yes | yes |
| `declared-name` | a program that names an agent in `x-agent-custody-agent` and presents nothing else | yes | no |
| `forged-signature` | a Web Bot Auth signature in the agent's name and keyid, made with another key | yes | no |
| `replayed-signature` | the agent's own valid signature, sent a second time by someone who saw it | yes | no |
| `untrusted-grant` | a well-formed grant signed by a principal key the door does not trust | yes | no |
| `expired-grant` | a trusted principal's grant whose window ended a minute ago | yes | no |
| `out-of-scope-grant` | a trusted principal's grant for another route | yes | no |
| `grant-under-other-signature` | a valid grant for one agent, sent under another agent's verified signature | yes | no |
<!-- error-rates-kinds:end -->

### How the rates are computed

- **One kind, one label source, one row.** A rate is never pooled across kinds. A pooled rate depends on how many of each kind the sample holds, and the mix of a test set is not the mix of any site's traffic. So there is no single accuracy figure, on purpose.
- **Each question is scored only where it applies.** The `verified` question needs to know whether the arrival is genuine, so it skips arrivals that named no agent.
- **95% Wilson score intervals.** They stay inside 0% to 100%, and they give an upper bound when no error was seen, which is the honest reading of a small sample.
- **Receipts that do not verify are skipped and listed.** A label whose receipt was not read, or did not verify, is reported and not scored, so an edited receipt cannot move a rate.

### What it does not measure

- **How common each kind is.** The rates are conditional on the kind. They do not say what share of a site's traffic is scripts.
- **The door's other signals.** A challenge's outcome carries the provider's error rate, and a partner verdict carries the engine's. The rate counters are counts, not judgements. None of them changes `class`.
- **Faults outside the arrival.** A signature agent's directory that does not answer gives `unavailable`, and a signer's clock off by more than `clockSkewSeconds` gives `invalid`. The test set has neither.
- **Real browsers and real agents.** The arrivals are built, not recorded. That is why the labels can be trusted, and also why your own traffic is the better test. The next section says how to score it.

## Measure your own traffic

The same command scores a site's own door receipts against a labels file. It reads the receipts directory, verifies each receipt, and reports the same table:

```sh
agent-custody door error-rates --receipts ./receipts --labels labels.jsonl \
  --issuer-key keys/door.pub --principal-key keys/principal.pub [--log log.jsonl] [--json]
```

A labels file has one JSON object per line, one line per receipt:

```json
{"receiptId":"8a1f…","kind":"crawler-we-run","automated":true,"genuine":true,"source":"operator"}
```

| field | meaning |
| --- | --- |
| `receiptId` | the receipt the label is for; a receipt is labelled once |
| `kind` | what the arrival was, in your own words: lower-case letters, digits, and hyphens, at most 64. Rates are reported per kind |
| `automated` | `true` for a program, `false` for a person at a browser |
| `genuine` | `true` when it is the agent it names, under a permission your door accepts for that route; `false` when it names an agent and is not; `null` when it names none |
| `source` | `operator` for your own knowledge, `test-set` for arrivals you built, `challenge` for labels derived from passed challenges |

Rules that keep the numbers honest:

- **Label from what you know, not from what the door said.** A label copied from `class` scores the door against itself.
- **`--challenge-labels`** adds a label for each unlabelled receipt whose challenge passed: a person, kind `challenge-passed`, source `challenge`. It carries the provider's own error rate, and its rows stay apart from the others.
- **The receipt's arrival fact must be in clear.** The door's default capture keeps facts in clear. A route whose `capture` rule withholds facts cannot be scored, and its receipts are skipped with the reason.
- **`--log` recomputes the log root for each receipt.** It is the stronger check, and it is slow on a large directory, because it reads the log once per receipt. Without it, each receipt's inclusion proof is still checked against the signed tree head it carries.
- **Publish the method beside the numbers.** State the kinds, how they were labelled, the counts, and the intervals, as this page does.

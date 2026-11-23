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

## Behaviour and fingerprint flags

The door's `behaviour` config adds seven flags to the arrival fact ([door signals](door-signals.md)). A flag is a signal, not a verdict: the door refuses nothing because of one, and your policy decides what a flag means. This page says how often each flag is wrong, as far as that is measured, and how the measure is made. The method is public, the tool is in the package, and you can make the same measure on your own door.

Two rates describe a flag:

- The **false-positive rate** is the share of human arrivals that the flag marks. Lower is better.
- The **detection rate** is the share of automated arrivals that the flag marks. Higher is better.

A flag with no labelled data on one side has no rate on that side. The tables say "not measured" and give the reason. No rate on this page is an estimate from memory or from another product.

## Results

Measured on 2026-11-22 (UTC) with the thresholds that the door ships. The source of every number in the tables is [`labelled/results.json`](../labelled/results.json). A test makes the tables again from that file and fails when this page differs. The same test fails when the text of this page states a number that is not a number in a committed file of [`labelled/`](../labelled/).

Read the tables per session first. The arrivals of one session are not independent, so an interval per arrival is narrower than the data supports. Each interval is a 95% Wilson interval, and each bound is printed outward: the low bound is rounded down and the high bound is rounded up. A rate of `<0.1%` is above zero and rounds to 0.0%.

A set is in a table only for the flags that its label is good for. Two cases are left out because the answer is fixed before the measure:

- A mismatch flag compares the request with the browser that the User-Agent states. A client with its own User-Agent (`curl/8.7.1`, `HeadlessChrome`) states no browser, so the flag is false for it by construction. The sets `capture-tools` and `capture-headless-chrome` do not count for the two mismatch flags. A zero for them would not be a measured miss.
- `fingerprint.tls.knownTool` has no measured rate on either side. The table of known tools was filled from the capture. Each tool of the capture is in the table and no browser of the capture is, by construction.

<!-- #region results -->
### False-positive rate per session (lower is better)

| flag | set | sessions | flagged | false-positive rate (lower is better) | 95% interval | what `human` means in this set |
| --- | --- | --- | --- | --- | --- | --- |
| `fingerprint.headers.mismatch` | capture-real-browsers | 3 | 0 | 0.0% | 0.0% to 56.2% | a real browser, which a script started; the label names the client software and not who used it |
| `fingerprint.tls.mismatch` | capture-real-browsers | 2 | 0 | 0.0% | 0.0% to 65.8% | a real browser, which a script started; the label names the client software and not who used it |
| `fingerprint.tls.knownTool` | not measured | | | | | The known-tool table was filled from the capture: no browser of the capture is in the table, by construction, so a rate of zero on the same capture says nothing. No other set has a TLS fingerprint of a real browser |
| `behaviour.timing.regular` | lagopoulos-2018 | 50724 | 9 | <0.1% | 0.0% to 0.1% | ROBOT=0: the dataset's authors did not identify the session as a robot. A robot that hides is on this side, so the rate is biased upward |
| `behaviour.navigation.directWrite` | lagopoulos-2018 | 50724 | 8 | <0.1% | 0.0% to 0.1% | ROBOT=0: the dataset's authors did not identify the session as a robot. A robot that hides is on this side, so the rate is biased upward |
| `behaviour.form.fast` | keyrecs-fixed-text | 198 | 2 | 1.0% | 0.2% to 3.7% | a recruited participant who types the same fixed characters; one arrival is one repetition, and one session is one participant in one sitting |
| `behaviour.form.noInput` | not measured | | | | | No set has a person who sends a form through the form protector script. KeyRecs records key presses only, with no pointer press and no submit |

### Detection rate per session (higher is better)

| flag | set | sessions | flagged | detection rate (higher is better) | 95% interval | what `automated` means in this set |
| --- | --- | --- | --- | --- | --- | --- |
| `fingerprint.headers.mismatch` | capture-headless-chrome-browser-ua | 5 | 0 | 0.0% | 0.0% to 43.5% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `fingerprint.headers.mismatch` | capture-tools-browser-ua | 5 | 5 | 100.0% | 56.5% to 100.0% | an HTTP tool that sends the User-Agent of Chrome, run by the capture script |
| `fingerprint.tls.mismatch` | capture-headless-chrome-browser-ua | 5 | 0 | 0.0% | 0.0% to 43.5% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `fingerprint.tls.mismatch` | capture-tools-browser-ua | 5 | 1 | 20.0% | 3.6% to 62.5% | an HTTP tool that sends the User-Agent of Chrome, run by the capture script |
| `fingerprint.tls.knownTool` | not measured | | | | | The known-tool table was filled from the capture: every tool of the capture is in the table, by construction, so a detection rate on the same capture says nothing. No other set has a TLS fingerprint of a tool |
| `behaviour.timing.regular` | lagopoulos-2018 | 9720 | 72 | 0.7% | 0.5% to 1.0% | ROBOT=1: the dataset's authors identified the session as a robot, in most cases by its User-Agent. A robot that says what it is |
| `behaviour.navigation.directWrite` | capture-headless-chrome | 5 | 0 | 0.0% | 0.0% to 43.5% | headless Chrome with its own User-Agent, driven by the capture script |
| `behaviour.navigation.directWrite` | capture-headless-chrome-browser-ua | 5 | 0 | 0.0% | 0.0% to 43.5% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `behaviour.navigation.directWrite` | capture-tools | 10 | 10 | 100.0% | 72.2% to 100.0% | an HTTP tool with its own User-Agent, run by the capture script |
| `behaviour.navigation.directWrite` | capture-tools-browser-ua | 5 | 5 | 100.0% | 56.5% to 100.0% | an HTTP tool that sends the User-Agent of Chrome, run by the capture script |
| `behaviour.navigation.directWrite` | lagopoulos-2018 | 9720 | 13 | 0.1% | 0.0% to 0.3% | ROBOT=1: the dataset's authors identified the session as a robot, in most cases by its User-Agent. A robot that says what it is |
| `behaviour.form.fast` | capture-headless-chrome | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome with its own User-Agent, driven by the capture script |
| `behaviour.form.fast` | capture-headless-chrome-browser-ua | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `behaviour.form.noInput` | capture-headless-chrome | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome with its own User-Agent, driven by the capture script |
| `behaviour.form.noInput` | capture-headless-chrome-browser-ua | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |

### False-positive rate per arrival (lower is better)

| flag | set | arrivals | flagged | false-positive rate (lower is better) | 95% interval | what `human` means in this set |
| --- | --- | --- | --- | --- | --- | --- |
| `fingerprint.headers.mismatch` | capture-real-browsers | 27 | 0 | 0.0% | 0.0% to 12.5% | a real browser, which a script started; the label names the client software and not who used it |
| `fingerprint.tls.mismatch` | capture-real-browsers | 10 | 0 | 0.0% | 0.0% to 27.8% | a real browser, which a script started; the label names the client software and not who used it |
| `fingerprint.tls.knownTool` | not measured | | | | | The known-tool table was filled from the capture: no browser of the capture is in the table, by construction, so a rate of zero on the same capture says nothing. No other set has a TLS fingerprint of a real browser |
| `behaviour.timing.regular` | lagopoulos-2018 | 3640733 | 25 | <0.1% | 0.0% to 0.1% | ROBOT=0: the dataset's authors did not identify the session as a robot. A robot that hides is on this side, so the rate is biased upward |
| `behaviour.navigation.directWrite` | lagopoulos-2018 | 3640733 | 12 | <0.1% | 0.0% to 0.1% | ROBOT=0: the dataset's authors did not identify the session as a robot. A robot that hides is on this side, so the rate is biased upward |
| `behaviour.form.fast` | keyrecs-fixed-text | 19772 | 96 | 0.5% | 0.3% to 0.6% | a recruited participant who types the same fixed characters; one arrival is one repetition, and one session is one participant in one sitting |
| `behaviour.form.noInput` | not measured | | | | | No set has a person who sends a form through the form protector script. KeyRecs records key presses only, with no pointer press and no submit |

### Detection rate per arrival (higher is better)

| flag | set | arrivals | flagged | detection rate (higher is better) | 95% interval | what `automated` means in this set |
| --- | --- | --- | --- | --- | --- | --- |
| `fingerprint.headers.mismatch` | capture-headless-chrome-browser-ua | 45 | 0 | 0.0% | 0.0% to 7.9% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `fingerprint.headers.mismatch` | capture-tools-browser-ua | 10 | 10 | 100.0% | 72.2% to 100.0% | an HTTP tool that sends the User-Agent of Chrome, run by the capture script |
| `fingerprint.tls.mismatch` | capture-headless-chrome-browser-ua | 45 | 0 | 0.0% | 0.0% to 7.9% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `fingerprint.tls.mismatch` | capture-tools-browser-ua | 10 | 2 | 20.0% | 5.6% to 51.0% | an HTTP tool that sends the User-Agent of Chrome, run by the capture script |
| `fingerprint.tls.knownTool` | not measured | | | | | The known-tool table was filled from the capture: every tool of the capture is in the table, by construction, so a detection rate on the same capture says nothing. No other set has a TLS fingerprint of a tool |
| `behaviour.timing.regular` | lagopoulos-2018 | 409440 | 7778 | 1.9% | 1.8% to 2.0% | ROBOT=1: the dataset's authors identified the session as a robot, in most cases by its User-Agent. A robot that says what it is |
| `behaviour.navigation.directWrite` | capture-headless-chrome | 45 | 0 | 0.0% | 0.0% to 7.9% | headless Chrome with its own User-Agent, driven by the capture script |
| `behaviour.navigation.directWrite` | capture-headless-chrome-browser-ua | 45 | 0 | 0.0% | 0.0% to 7.9% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `behaviour.navigation.directWrite` | capture-tools | 15 | 10 | 66.7% | 41.7% to 84.9% | an HTTP tool with its own User-Agent, run by the capture script |
| `behaviour.navigation.directWrite` | capture-tools-browser-ua | 10 | 5 | 50.0% | 23.6% to 76.4% | an HTTP tool that sends the User-Agent of Chrome, run by the capture script |
| `behaviour.navigation.directWrite` | lagopoulos-2018 | 409440 | 17 | <0.1% | 0.0% to 0.1% | ROBOT=1: the dataset's authors identified the session as a robot, in most cases by its User-Agent. A robot that says what it is |
| `behaviour.form.fast` | capture-headless-chrome | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome with its own User-Agent, driven by the capture script |
| `behaviour.form.fast` | capture-headless-chrome-browser-ua | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
| `behaviour.form.noInput` | capture-headless-chrome | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome with its own User-Agent, driven by the capture script |
| `behaviour.form.noInput` | capture-headless-chrome-browser-ua | 4 | 1 | 25.0% | 4.5% to 70.0% | headless Chrome that sends the User-Agent of Chrome, driven by the capture script |
<!-- #endregion results -->

### What the results say

- `fingerprint.headers.mismatch` marked each tool that sends the User-Agent of Chrome: 5 of 5 sessions. It did not mark headless Chrome that sends the User-Agent of Chrome, because headless Chrome sends the headers of Chrome. It marked no request of Chrome or Safari, but that is 3 sessions on one machine, so the interval is wide.
- `fingerprint.tls.mismatch` marked 1 of the 5 tools that send the User-Agent of Chrome: Python, which sends no ALPN. The other tools offer TLS 1.3 and ALPN, as a browser does, and the flag does not see them.
- `fingerprint.tls.knownTool` is not measured, for the reason above.
- `behaviour.timing.regular` is rare for the sessions that the public log calls human, and it is also rare for the robots in that log. Most robots that say what they are do not arrive at a steady pace, or the one-second times of the log hide that they do.
- `behaviour.navigation.directWrite` is true for every tool in the capture that posts a form, and false for headless Chrome, which loads the page first. In the public log almost every write has a same-origin Referer, from robots also.
- `behaviour.form.fast` marked 2 of 198 sessions of typing by recruited participants. Those sessions hold 96 fast repetitions: 95 from one participant in one sitting, each with 28 to 83 milliseconds from the first key press to the last, and 1 with a time below zero in the file. [`labelled/keyrecs-stats.json`](../labelled/keyrecs-stats.json) lists them. The dataset calls them human, so they count as false positives here.
- `behaviour.form.fast` and `behaviour.form.noInput` each marked one of the four ways in which the capture script fills the form in headless Chrome. A script that sets the field values and submits has no input. A script that sends key events with no pause is fast. A script that inserts the text and clicks the button, and a script that sends key events with a pause between them, get neither flag.

## The method

### The labelled-set format

A labelled set is a JSON Lines file. Each line is one arrival:

```json
{"set":"capture-tools","session":"curl-post","label":"automated","labelSource":"scripted-client","validFor":["fingerprint.headers.mismatch"],"observation":{"at":1250,"method":"POST","path":"/submit","headers":{"names":["host","user-agent","accept"],"ordered":true},"secure":true,"userAgent":"curl/8.7.1","accept":"*/*","referer":"absent","secFetch":{},"tls":{"ja4":"t13d4907h2_0d8feac7bc37_7395dae3b2f3"}}}
```

| field | meaning |
| --- | --- |
| `set` | The name of the labelled set. One file can hold more than one set. |
| `session` | One client over one period. The measure gives each session its own history, as the door gives each source its own. |
| `label` | `human` or `automated`. |
| `labelSource` | How the label was assigned. |
| `validFor` | Optional. The flags that this label is good for. The other flags do not count the record. A label that comes from the User-Agent is not good for a flag that reads the User-Agent. |
| `observation` | What was recorded of the arrival, in the shape that the door's own code reads (`Observation` in `src/door-signals.ts`): the time `at` in milliseconds, the method, the path, the header names in the order received, `secure`, the `userAgent`, `accept`, the relation of the `referer` to the site, the `secFetch` values, the `tls` data, and the `form` report. It holds no cookie, no query, no body, and no address. |
| `flags` | In place of `observation`, for a record that a door exported: the flags that the door computed for the arrival. A flag that did not apply is absent. |

The records of one session are in time order. The tool refuses a file where a session goes back in time, or where a session has two labels.

### The three label sources

1. **Your own door, with your consent.** `agent-custody door labels` reads the receipts of your door. An arrival whose `challenge.outcome` is `passed` is `human` (`challenge-passed`). An arrival whose `class` is `verified` is `automated` (`verified-agent`). Every other arrival has no label and is left out, and so is a verified agent that passed the challenge. No own-door set is in the results above: the door has no installation that agreed to share one yet.
2. **Public datasets.** An adapter script turns a dataset into the format. The label is what the dataset's authors recorded, and the page says what that label means.
3. **A capture.** `scripts/door-capture.ts` runs real clients against a local server and records what they send. The label is the client software that the script started.

### How a rate and its interval are computed

`agent-custody door measure` replays each session in time order through the same functions that the door runs (`createHistoryTracker` and `signalsOf`), with the recorded times. For each flag, each set, and each side it counts:

- **per arrival:** the arrivals that the flag applies to, and those that it marks;
- **per session:** the sessions with one or more arrivals that the flag applies to, and those where it marks one or more.

A flag applies to an arrival when the door computes it from data that the record has:

- `fingerprint.headers.mismatch` applies when the record has the header names.
- `fingerprint.tls.mismatch` and `fingerprint.tls.knownTool` apply when the record has a well-formed JA4.
- `behaviour.form.fast` and `behaviour.form.noInput` apply when the record has a well-formed form report.
- `behaviour.timing.regular` and `behaviour.navigation.directWrite` apply to every arrival. The timing flag needs 5 gaps, so it is false for the first 5 arrivals of a session. The direct-write flag is false for every GET. These arrivals are in the count, so the rate is the share of all arrivals or sessions.

The rate is `flagged / n`. The file keeps the two integers and the rate as an integer per 10,000. The interval is the 95% Wilson score interval, rounded outward to an integer per 10,000: the low bound down, the high bound up. The page prints percentages with one decimal, and it rounds each bound outward again at that decimal, so a printed interval is never narrower than the computed one. A small set gives a wide interval, and the tables show it.

The tool refuses a record that the door could not have made: a method that is not in upper case, or a field of the observation with the wrong type.

### The threshold rule

The thresholds in `src/door-signals.ts` were set before any measure. The results above are for those thresholds, unchanged. `results.json` records every exported constant of that file that a flag reads, and a test fails when the code and the file differ. The rules that read a User-Agent are code and not constants: which product names state a browser, a tool, or a crawler, and which forms are Chromium inside an application. `results.json` does not record them. A change to one of them needs a new measure, and the date of this page then changes.

When a measure shows that a threshold is wrong, the change uses a split. Sessions whose name has a hash with an even first byte tune the threshold. Sessions with an odd first byte give the published rate. The page then states the split. The Lagopoulos adapter has `--half tune` and `--half report` for this. No threshold was tuned for these results, so the tables use all sessions.

Some rules changed after the thresholds were set. None of the changes came from a rate on a labelled set.

From evidence that is not a rate:

- The known-tool table `KNOWN_TOOL_JA4` was empty. It now holds the JA4 values that the tools of the capture sent. For that reason the flag has no measured rate.
- `fingerprint.headers.mismatch` no longer expects `sec-ch-ua` from Chromium inside an application that names itself before `Chrome/` in its User-Agent. See the rule check below.

From a code review, with no labelled data:

- `fingerprint.headers.mismatch` no longer expects `sec-ch-ua` from a User-Agent with `Version/` before `Chrome/` (a WebView browser), or with `like Chrome/`. Not every such browser sends the header. A false flag on a real browser is the costly error, so a doubtful form is not flagged.
- `behaviour.navigation.directWrite` is false when the request has `Sec-Fetch-Site: same-origin`. A browser sends this header to an https site, also when the site's `Referrer-Policy` removes the Referer.
- The Referer is on the same origin when the host is the same with or without its default port.

The Referer and `Sec-Fetch-Site` are the client's word. A program can send them, and the direct-write flag is then false for it. The capture has no tool that does this, so its detection rates are for tools that send neither header.

## The labelled sets

[`labelled/manifest.json`](../labelled/manifest.json) lists each set: its source, licence, file hashes, counts, how the labels were assigned, and the command that makes it.

### The capture

`labelled/capture.jsonl` is committed: 143 arrivals in 29 sessions, recorded on one machine on 2026-11-22. `labelled/capture.meta.json` has the versions of the browsers, the tools, and the system. The file holds five sets:

- `capture-real-browsers`: Chrome and Safari, each started as a person starts it, with a temporary profile for Chrome. The label is `human` with the source `real-browser`. The label names the client software, and not who used it. **A real browser that a program drives sends the same headers and the same ClientHello, so these flags cannot tell it from a person.** The label is good for the two mismatch flags only.
- `capture-tools`: curl, Python urllib, Go net/http, Node fetch, and Bun fetch, each with its own User-Agent. The label is good for the direct-write flag and the form flags.
- `capture-tools-browser-ua`: the same tools with the User-Agent that Chrome sent.
- `capture-headless-chrome`: headless Chrome, driven through its DevTools protocol, with its own User-Agent. Four sessions fill the form through the door's own form protector script, each in another way. The script's challenge widget is replaced by a local stub, so the capture asks no outside service. The label is good for the direct-write flag and the form flags.
- `capture-headless-chrome-browser-ua`: the same sessions with the User-Agent that Chrome sent.

The TLS listener of the capture has a throwaway certificate. It reads the ClientHello before the handshake and computes the JA4 (`scripts/ja4.ts`). `labelled/capture.hellos.json` keeps one ClientHello for each JA4, so that you can compute it again. Each tool gets the certificate as its CA for one process, and Chrome gets its key hash for one temporary profile. No trust store changes.

Three things about the capture are assumptions or joins, and you should know them:

- An observation has `secure: true`, as a door behind a TLS proxy records it. The plain listener is http on `localhost`. A browser treats that as a secure origin. Chrome sent the same header names to the plain listener and to the TLS listener for each of the six kinds of request that the page makes (`chromeHeaderNamesTlsAgainstPlain` in `capture.meta.json`). For Safari this is not checked: Safari stops at the certificate warning.
- The Safari TLS record joins two connections of the same browser: the ClientHello of its https attempt, and the User-Agent of its plain page load. It counts for `fingerprint.tls.mismatch` only.
- The pace of a capture session is the pace of the script. No capture record counts for `behaviour.timing.regular`.

### Lagopoulos and Tsoumakas, web robot detection (public)

The access log of a library search site for March 2018, with a `ROBOT` label for each session ([the Zenodo record](https://zenodo.org/records/3477932), CC-BY-4.0). The adapter writes the counts below to [`labelled/lagopoulos-join.json`](../labelled/lagopoulos-join.json). The raw log has 4,091,155 records. 30,763 of them are timeouts with no request, and the other 4,060,392 are requests.

The ids of the feature file are not the ids of the raw records: 0 of 67,352 match. So the adapter builds the sessions again, as the dataset describes them, and gets 67,561 sessions. Every one of the 67,352 feature rows has a rebuilt session with the same number of requests, duration, bytes, status counts, and method counts. A rebuilt session gets a label when the feature rows with its values agree on the label and are as many as the rebuilt sessions with those values. That labels 60,444 sessions: 50,724 `human` with 3,640,733 arrivals, and 9,720 `automated` with 409,440 arrivals. The other sessions are left out: 6,579 where the rows disagree, 468 where the counts differ, and 70 with no row.

What the label means:

- `ROBOT=1` means that the authors identified a robot, in most cases by its User-Agent. Of the 3,262 User-Agents in the labelled sessions, 12 have sessions with both labels. So `automated` here is a robot that says what it is.
- `ROBOT=0` means "not identified as a robot". It does not mean "a person". A robot that hides is on the human side, so the false-positive rate here is biased upward.
- The label comes from the User-Agent. So a record of this set holds no User-Agent and no header, and it counts for the timing flag and the direct-write flag only.

Limits of the replay:

- The times have a resolution of one second. A steady pace with short gaps can look uneven, and an uneven pace can look steady. Requests in the same second have a gap of zero.
- The door keys its history by address. The dataset's session is the address and the User-Agent, with the address masked.
- The log has no Accept header and no `Sec-Fetch-Site` header, so the replay knows no page load. `behaviour.navigation.directWrite` is then true for every write without a same-origin Referer. A door that sees the page load of the same source flags the same arrivals or fewer.

### KeyRecs (public)

Keystroke timings of 99 recruited participants who type the same 10 characters, in 2 sittings each ([the Zenodo record](https://zenodo.org/records/7886743), CC-BY-4.0): 19,772 repetitions. The adapter writes these counts to [`labelled/keyrecs-stats.json`](../labelled/keyrecs-stats.json). Each repetition becomes one form report with 10 key presses. The fill time is the time from the first key press to the last, which is shorter than the time to the submit that the door's script reports. The set counts for `behaviour.form.fast` on the human side only. It has no pointer press and no submit, so it says nothing about `behaviour.form.noInput`.

### Considered and not used

- **Iliou et al., web bot detection dataset.** Its licence permits non-commercial use only.
- **Aalto University 136M keystrokes dataset.** Its licence permits non-commercial use only.
- **Nanglae et al., form keystroke files.** The files do not say how the data was collected or whether the people agreed, and they hold personal data.

## Checks that are not rates

### The header rule against a header model

Apify's header-generator (Apache-2.0) has a model of the headers that browsers send. Its HTTP/2 side has 339 User-Agents of 155 browser versions. It is not labelled traffic: it does not say who sent a request. `scripts/door-rule-check.ts` reads it as a check of the rule, and [`labelled/rule-check.json`](../labelled/rule-check.json) has the result. Each number here is from that file.

- The header order lists of Chrome, Edge, Firefox, and Safari each contain `accept-language` and the three `sec-fetch-*` headers. The model has no data for these headers per version.
- For `sec-ch-ua` the model has data per User-Agent. The rule expects `sec-ch-ua` from 201 of the 339 User-Agents. For 189 of them, every request in the model has it.
- For the other 12, the model has requests without `sec-ch-ua`: a real request with that User-Agent gets the flag. For 7 of them, no request in the model has it. The file lists the 12 User-Agents. The model cannot say whether a person or a program sent them.
- The rule leaves `sec-ch-ua` out for 4 User-Agents of a current Chromium inside an application that names itself before `Chrome/`, such as `Claude/4.4212.0 Chrome/152.0.7977.167`. No request of these 4 in the model has `sec-ch-ua`. The rule first flagged them, and it was changed for that reason.
- The model has no User-Agent with `Version/` before `Chrome/` or with `like Chrome/`. The rule for those forms has no check here.

### The JA4 implementation

`scripts/ja4.ts` follows FoxIO's JA4 TLS client specification. `test/ja4.test.ts` checks it against FoxIO's values: the example of the specification, and four Chromium rows of FoxIO's `ja4plus-mapping.csv`, each built from the cipher and extension lists. For the clients of the capture, the first two parts of the JA4 of Safari and the cipher hashes of Chrome and Go are the values in the mapping. The third part differs for the Chrome and the Safari of the capture, which send other extensions than the versions in the mapping.

## Limits

- **Set sizes.** Each set of the capture has 10 sessions or fewer. Its intervals are wide, and the tables show them.
- **One machine.** The capture is one Mac, two browsers, and one version of each tool. Other systems, other browser versions, and browsers behind a proxy that inspects TLS are not in it.
- **Weak labels.** `ROBOT=0` is "not identified", and `real-browser` names the software. No set has arrivals that are known to come from a person at a keyboard on a real site.
- **Scripted behaviour.** The capture script decides what an automated session does. The rates of the direct-write flag and the form flags on the capture say which of these scripts a flag marks. They do not say how common each kind of script is.
- **1-second times** in the public log limit the timing flag, as above.
- **The form report, the Referer, and `Sec-Fetch-Site` are claims by the client.** A program can send any report and any header. The form flags catch only a client that runs the script and does not act as a person does.
- **Per-process memory.** The door's history is the memory of one process. Two doors do not share it, and a restart clears it. The replay gives each session one unbroken history. A door with more than one process sees a part of the arrivals of a source in each process. So it flags `behaviour.timing.regular` less often than the replay. It flags `behaviour.navigation.directWrite` more often: a write can reach a process that did not see the page load, and the flag is then true unless the request has a same-origin Referer or `Sec-Fetch-Site: same-origin`.
- **The known-tool table** holds the builds on one machine. Another version of a tool can have another JA4.

## Reproduce the results

The public sets are not in the repository. Download them, check the hashes in the manifest, and run from `packages/receipts`:

```bash
node scripts/door-labels-lagopoulos.ts <public_v2.json> <simple_features.csv> --out lagopoulos.jsonl --stats labelled/lagopoulos-join.json
node scripts/door-labels-keyrecs.ts <fixed-text.csv> --stats labelled/keyrecs-stats.json > keyrecs.jsonl
agent-custody door measure labelled/capture.jsonl keyrecs.jsonl lagopoulos.jsonl
node scripts/door-error-rates.ts results --date <YYYY-MM-DD> labelled/capture.jsonl keyrecs.jsonl lagopoulos.jsonl
node scripts/door-error-rates.ts page
```

The adapters read the downloaded files as data and run nothing from them. The capture is not reproducible to the byte: `node scripts/door-capture.ts --out labelled/capture.jsonl --meta labelled/capture.meta.json` records your machine's clients, which opens Chrome and Safari and closes them again.

## Measure on your own door

```bash
agent-custody door labels --receipts ./receipts --issuer-key keys/door.pub --principal-key keys/principal.pub --out own-door.jsonl
agent-custody door measure own-door.jsonl
```

`door labels` reads the receipts in the directory and verifies each one with the door's public key. It skips a file that does not verify, and it says how many. The receipt of a verified agent verifies only with `--principal-key`, the key of the principal that signed the agent's grant. The command needs a door with `behaviour` in its config, and it gives a label only where the door checked something: a passed challenge, or a verified agent.

What the output holds: for each labelled arrival, the label, the label source, a session number, and the flags. What it does not hold: a path, an address, an agent name, a header, a header value, or a time. The session number counts sources in the order of their first arrival; it is not a hash of the address.

The tool uploads nothing. The file is yours to read. If you want your counts to be part of a later version of this page, send the output of `door measure --json`, which holds counts and no arrival.

Two cautions for an own-door set. A person who was never challenged has no label, so the human side is the people who met a challenge and passed it. A verified agent is an agent that you gave a grant to; an API agent posts without a page load, so `behaviour.navigation.directWrite` is true for it by design.

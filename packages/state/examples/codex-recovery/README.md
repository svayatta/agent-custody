# Codex support recovery demo

A real headless Codex agent handles a support request using incorrect CRM memory. An operator then reviews and approves correction of the resulting beliefs and compensation of a simulated credit.

Follow the [complete setup, command reference, recovery, and verification guide](../../../receipts/docs/codex-recovery.md). The [recorded live run](SAMPLE-RUN.md) shows the observed five Codex calls and 13 verified receipts.

After installing dependencies, building the workspace, and signing in to Codex, run from `packages/state`:

```sh
node examples/codex-recovery/run.ts run
```

The runner prints the case directory and the exact recovery command to review. The offline companion is [10-support-recovery.ts](../10-support-recovery.ts); regular tests do not call a model or the network.

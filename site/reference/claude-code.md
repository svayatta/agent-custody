# Claude Code and the Claude Agent SDK

One hook command records every tool call of a session as a receipt, and can deny a call before it runs. Claude Code invokes it as a command hook with the event on stdin; the Claude Agent SDK calls the same handler in process.

## One command

```bash
npx @agent-custody/receipts init claude-code [--dir <dir>] [--user] [--enforce] [--log-url <url> [--log-id <id>] [--log-token-env NAME] [--log-key <pub>]]
```

The command makes an agent key, writes `sdk.json` with `"mode": "observe"`, writes a starter deny set to `policy.cedar`, and registers the three hooks with absolute paths. It prints each step and ends with the next step.

| option | effect |
| --- | --- |
| `--dir <dir>` | where the key, `sdk.json`, `policy.cedar`, and `receipts/` go. Default: `~/.config/agent-custody` |
| `--user` | write the hooks to `~/.claude/settings.json`. Default: `.claude/settings.local.json` in the current directory, which Claude Code does not commit |
| `--enforce` | leave out `"mode": "observe"`: a denied call is blocked |
| `--log-url <url>` | log the receipts to this URL as hashes (`hashOnly`, `timeoutMs` 3000). Without it, the config has `"logFile": "log.jsonl"` and the receipts stay on the machine |
| `--log-id <id>` | the log id that the tree heads must name |
| `--log-token-env NAME` | the NAME of the environment variable that holds the log token. Default: `AGENT_CUSTODY_LOG_TOKEN`. The token never goes into a flag or a file |
| `--log-key <pub>` | the log's public key file. It is copied to `log.pub` and pinned in `log.keys` |

The starter deny set permits every call and forbids these Bash commands: `git push` with `--force` or `-f`, `rm -rf` on `/` or `~`, `terraform destroy`, and `drop database` or `DROP DATABASE` (the Cedar `like` operator is case-sensitive). Each rule has a `@reason`, which the denial text shows. The file ships in the package as `templates/claude-code.cedar`.

The settings file is merged, not replaced. Every other key and hook stays, a hook that is already there is not added again, and a settings file that is not valid JSON stops the command before it changes anything. The command never overwrites an existing key, `sdk.json`, or `policy.cedar`, so it is safe to run two times. A second run updates the path of a hook of ours. When the path is in the npx cache (`/_npx/`), the command warns that npm can clear the cache; install the package globally and run the command again.

## The report

```bash
agent-custody report --config <sdk.json>
```

The command reads `receiptsDir` of the config and verifies each receipt with the agent's key (and the log keys of the config, when it has a log). It prints `would have denied N calls` and, for each call, the tool, the command or the file path, the `@reason` of the rule when it has one, the rule, and the receipt id. A denial recorded with `enforced: false` is a call that ran. A receipt that does not verify is listed apart with its reason and is not counted. Exit code 1 when any receipt does not verify, otherwise 0. The last line says how to enforce: remove the `"mode": "observe"` line from `sdk.json`.

## Registering the hook

`.claude/settings.json` in the project, or the user's settings:

```json
{ "hooks": {
  "PreToolUse":         [{ "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }],
  "PostToolUse":        [{ "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }],
  "PostToolUseFailure": [{ "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }]
} }
```

`AGENT_CUSTODY_CONFIG` works instead of `--config`. The config is the [SDK config](./sdk-typescript#the-config-file). A wrapper script that exports the log token from a file and then runs the command keeps the token off the command line; the [custody page](https://agent-custody.dev/custody) shows the one this repository uses.

## Input

Claude Code writes the hook event as JSON on stdin. The fields the handler reads:

```json
{ "hook_event_name": "PreToolUse", "session_id": "a1b2…", "tool_use_id": "toolu_01…", "tool_name": "Bash", "tool_input": { "command": "git status --short" } }
```

`PostToolUse` adds `"tool_response": {…}`; `PostToolUseFailure` adds `"error": "…"`. `tool_input` becomes the receipt's `request.args` (a non-object input is recorded as `{ "input": … }`); `session_id` and `tool_use_id` become `session.id` and `session.toolUseId`, `claimed`.

## Output

| event | what the handler does | stdout |
| --- | --- | --- |
| `PreToolUse`, policy denies | issues a **denied** receipt, blocks the call | `{ "continue": true, "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "agent-custody denied this call: terraform destroy deletes infrastructure (rule policy6, receipt 47eb52af-…)" } }` |
| `PreToolUse`, policy allows or none | nothing | `{}`: Claude Code's own permission prompts still apply; the hook never auto-approves |
| `PostToolUse` | issues an **executed** receipt with `tool_response` as the result | `{}` |
| `PostToolUseFailure` | issues a **failed** receipt with the error as the result | `{}` |

The reason text comes from the `@reason("...")` annotation of the rule that denied the call. With several denying rules, the reasons join with `; ` in file order and the line says `rules policy1, policy2`. A rule with no annotation gives its id in place of the reason. A deny that names no rule keeps the plain text, such as `agent-custody: no permit policy matched (receipt …)`. The receipt does not change: it keeps the policy ids and the digest. The issuer parses the annotations once, when it loads the policy, and exposes them as `issuer.ruleReasons`.

Exit code 0 in every case; a receipt that could not be logged is printed on stderr. If the user declines a call at the permission prompt, no `PostToolUse` fires and no receipt is issued for it.

## In process

```ts
import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
import { handleHookEvent, claudeAgentHooks } from "@agent-custody/receipts/sdk/claude";
const issuer = createSdkIssuer(loadSdkConfig("sdk.json"));
const out = await handleHookEvent(issuer, input);      // HookInput → HookOutput, as above
const hooks = claudeAgentHooks(issuer, "Bash|Write|Edit"); // the hooks object the Claude Agent SDK takes
```

Python: `agent_custody.claude_agent_sdk.claude_hook(client)` and `handle_hook_event(client, input_data)`, same input and output, through the sidecar.

## The policy's view

The tool name is the Cedar action, `context.args` is `tool_input`, and there are no facts. A policy that refuses force pushes:

```cedar
permit(principal, action, resource);
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };
```

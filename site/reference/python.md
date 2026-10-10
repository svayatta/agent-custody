# Python

```bash
pip install agent-custody            # the sidecar client and the memory client
pip install "agent-custody[langchain]"  # plus one adapter: langchain, openai-agents, crewai, claude-agent-sdk, adk
```

Python 3.10 or later. The package talks to the [sidecar](./sidecar) for receipts and to the memory server over MCP for beliefs; it holds no key and signs nothing itself.

## `Client`

```python
from agent_custody import Client, PolicyDeniedError, SidecarError, receipt_id_of
client = Client("http://127.0.0.1:8788/", timeout=10.0)
```

| method | request | response |
| --- | --- | --- |
| `client.health()` | `GET /health` | `{"agentId": "…", "keyid": "…", "log": {"kind": "http", "where": "…"}}` |
| `client.decide(tool, args=None, *, model=None, session=None)` | `POST /decide` with `{"tool", "args", "model"?, "session"?}` | the policy decision `{"decision": "allow"\|"deny", "reasons": [...], "errors": [...], "policyDigest": "…"}`, or `None` when the sidecar has no policy |
| `client.record(tool, args, outcome, policy=None, *, model=None, session=None)` | `POST /record` with `{"event", "outcome", "policy"}` | the receipt bundle `{"envelope", "treeHead", "inclusion"}` |
| `client.wrap(tool, fn, *, model=None)` | decide, run `fn(args)`, record | a callable that returns `fn`'s result; raises `PolicyDeniedError(tool, reason, receipt_id)` after recording the denial; records `{"status": "error"}` and re-raises when `fn` raises |

`outcome` is `{"status": "executed"|"failed", "result": …}`, `{"status": "denied", "reason": "…"}`, or `{"status": "error", "error": "…"}`. `session` is `{"id": …, "toolUseId": …}`. `receipt_id_of(bundle)` decodes the statement and returns the receipt id. `SidecarError` is raised for any HTTP failure, with the sidecar's `error` text.

```python
refund = client.wrap("stripe.refund", lambda args: stripe.Refund.create(**args))
try:
    refund({"customer_id": "cust_123", "amount": 2500})
except PolicyDeniedError as e:
    print(e.reason, e.receipt_id)
```

## Adapters

| import | entry point | behaviour |
| --- | --- | --- |
| `agent_custody.langchain` | `ReceiptCallbackHandler(client)` | record-only: `on_tool_start` / `on_tool_end` issue an executed receipt per tool run with the LangChain `tool_call_id` as the session's tool-use id; pass it in `callbacks=[...]` |
| `agent_custody.openai_agents` | `wrap_tools(client, tools)` | enforce: each `FunctionTool`'s `on_invoke_tool` decides, runs, records; a denial is returned as the tool's result text |
| `agent_custody.crewai` | `wrap_tools(client, tools)` | enforce: one `CustodyTool` per tool, same name, description, and schema; `_run` decides, runs, records; a denial is returned as `Denied by policy: … (receipt …)` |
| `agent_custody.claude_agent_sdk` | `claude_hook(client)` | the async hook callable `(input_data, tool_use_id, context) -> dict` for the Claude Agent SDK; `handle_hook_event(client, input_data)` is the same for any host that passes the hook JSON. Same semantics as [Claude Code](./claude-code) |
| `agent_custody.hermes` | `hermes_hooks(client)` → `{"pre_tool_call", "post_tool_call"}` | Hermes Agent plugin hooks: `pre_tool_call(tool_name, args, task_id, **kwargs)` returns `{"action": "block", "message": "agent-custody: … (receipt …)"}` on a policy deny after recording the denial, `None` otherwise; `post_tool_call(tool_name, args, result, task_id, duration_ms, **kwargs)` records the call. `register_hermes(ctx, client)` registers both with `ctx.register_hook`; `register(ctx)` is the plugin entry, reading `sidecar_url` from the plugin's settings |
| `agent_custody.adk` | `adk_callbacks(client)` → `{"before_tool_callback", "after_tool_callback"}` | Google ADK callbacks, for `LlmAgent(..., **adk_callbacks(client))`: `before_tool_callback(tool, args, tool_context)` returns `{"error": "agent-custody: … (receipt …)", "agent-custody/receipt": "…"}` on an enforced policy deny after recording the denial, which skips the tool and shows the model the receipt, `None` otherwise; `after_tool_callback(tool, args, tool_context, tool_response)` records the executed call (the response as JSON when it is JSON, else as text) and returns `None`, skipping the denial dict it recognises. The session is ADK's `invocation_id` and `function_call_id`. Extra `adk` (`google-adk[a2a]`). Delegations over A2A are not tool calls; the gateway's `--a2a` front covers them |

## `MemoryClient`

The memory tools over MCP, against a memory server started with `agent-custody-memory serve --http`. Writes made this way are `claimed` and quarantined until a gateway confirms them; that is the honest position of an SDK-only agent.

```python
from agent_custody.memory import MemoryClient, MemoryError
async with MemoryClient("http://127.0.0.1:8790/mcp", token="…") as memory:
    fact = await memory.write("acct:42", "plan", "pro", space="team:support", actor="py-agent")
    facts = await memory.read(subject="acct:42", include_claimed=True)
```

| method | tool called | response |
| --- | --- | --- |
| `write(subject, predicate, value, *, space, actor=None, supersedes=None, valid_from=None)` | `memory.write` | `{"fact": {...}, "eventId", "txTime", "supersedes"}`; the fact's `provenance` is `claimed` |
| `read(*, subject=None, predicate=None, space=None, valid_at=None, tx_at=None, include_claimed=False, require_verified=False)` | `memory.read` | the list of facts believed at that moment |
| `retract(fact_id, reason, *, actor=None)` | `memory.retract` | `{"eventId", "factId", "txTime", "actor", "reason", "source", "removedFrom", "verification"}` |
| `history(fact_id)` | `memory.history` | the list of events, oldest first |

A refused connection (wrong token) raises `MemoryError("memory server at … refused the connection: HTTP 401")`; a tool error raises `MemoryError` with the server's text. The tool contracts are on the [memory](./memory) page.

# Fact ledger

`@agent-custody/state` is governed memory for AI agents. It is not a vector store: it is a ledger of facts where every write cites the receipt that caused it, carries the time it was true and the time it was recorded, and can be superseded or retracted without losing what the agent believed at any earlier moment. Retrieval stays with the store you already use; this package owns provenance, time, and undo.

```bash
npm install @agent-custody/state
```

- **The memory server** offers the ledger as MCP tools behind the gateway, so each write carries its source receipt and an attested actor ([memory reference](/reference/memory)).
- **Explain, blast radius, and certified forget** trace one action back to what the agent believed, find everything a wrong belief touched, and prove a value was erased ([explain, review, packs](/reference/state-tools)).
- **Write-through** keeps the ledger under Mem0, Zep, Letta, LangGraph, Cognee, or pgvector.

The package's full README is [on GitHub](https://github.com/svayatta/agent-custody/tree/main/packages/state#readme).

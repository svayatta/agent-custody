# Python SDK

`agent-custody` on PyPI records signed receipts for an agent's tool calls from Python. The key, the policy, and the log live in the agent-custody sidecar, a local process from the npm package. This client talks to it over HTTP with the standard library only.

```bash
npm install -g @agent-custody/receipts && agent-custody keygen --dir keys --name app
agent-custody serve --config sdk.json          # loopback, port 8788
pip install agent-custody
```

```python
from agent_custody import Client, PolicyDeniedError

client = Client()                                # http://127.0.0.1:8788/
refund = client.wrap("stripe.refund", lambda args: stripe.refund(**args))
refund({"amount": 5000})                         # decide, run, record; raises PolicyDeniedError on deny
```

It has adapters for LangChain, CrewAI, the OpenAI Agents SDK, the Claude Agent SDK, Hermes, and Google ADK, and a client for the memory server ([Python reference](/reference/python)). Everything it records is the agent's own report (`claimed`); for enforcement the agent cannot skip, put [the gateway](/receipts/usage) in front of the tools.

The package's full README is [on GitHub](https://github.com/svayatta/agent-custody/tree/main/packages/python#readme).

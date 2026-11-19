# Receipts

`@agent-custody/receipts` makes a signed receipt for every tool call an agent makes, and checks it with public keys alone. One receipt format, one verifier, and five components that issue it:

- **The gateway** sits between an agent and its tools. It checks the grant a person signed, decides each call by policy, and receipts it either way ([running the gateway](/receipts/usage)).
- **The door** stands in front of your own site or API and receipts each arrival ([the door](/receipts/door)).
- **The egress witness** receipts the connections that go around the gateway ([the egress witness](/receipts/egress)).
- **The ACS Guardian** answers agents that ask before they act, and receipts each decision ([the ACS Guardian](/receipts/acs)).
- **The SDK** hooks into the agent's own framework, Claude Code included, and labels what it records as the agent's word ([SDK and framework hooks](/receipts/sdk)).

```bash
npm install -g @agent-custody/receipts
agent-custody init claude-code
```

Next: [getting started](/guide/getting-started), [components](/guide/pieces), [how verification works](/receipts/verification), and the [command line](/reference/cli). The package's full README, with its layout and plan, is [on GitHub](https://github.com/svayatta/agent-custody/tree/main/packages/receipts#readme).

# The door for a Shopify store

A small Node server that runs the agent-custody door in front of two agent routes of one Shopify store: `POST /orders` makes a draft order, and `POST /refunds` makes a refund. The guide is [the door as a Shopify app](../../../packages/receipts/docs/door-shopify.md): the policy, the receipts, the install on a development store, and the limits.

| file | what it is |
| --- | --- |
| [server.ts](server.ts) | the two routes, the Shopify Admin GraphQL calls, and the refund keys. It does not import the door, so a test can give it one |
| [start.ts](start.ts) | runs the server with the door from `@agent-custody/receipts` |
| [door.json](door.json), [policy.cedar](policy.cedar), [admission.json](admission.json) | the default config, the admission policy, and the store's admission list |
| [smoke.ts](smoke.ts) | run by hand against a development store. CI does not run it |

```bash
npm install
npx agent-custody keygen --dir data/keys --name door      # and put your registry's public key in keys/registry.pub
SHOPIFY_SHOP=your-store.myshopify.com SHOPIFY_CLIENT_ID=... SHOPIFY_CLIENT_SECRET=... node start.ts
```

`packages/receipts/test/door-shopify.test.ts` tests the server against a stand-in Shopify on loopback. A change here must pass `bun run test`.

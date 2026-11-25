// Runs the Shopify door: `SHOPIFY_SHOP=x.myshopify.com SHOPIFY_ADMIN_TOKEN=... node start.ts`.
// DOOR_CONFIG is the door's config (default: door.json beside this file). The data directory is `data/` beside it.
import { dirname, join, resolve } from "node:path";
import { door } from "@agent-custody/receipts/door";
import { shopifyServer, type ShopifyEnv } from "./server.ts";

const config = resolve(process.env.DOOR_CONFIG ?? join(import.meta.dirname, "door.json"));
const port = Number(process.env.PORT ?? 8790);
shopifyServer(door(config), process.env as ShopifyEnv, join(dirname(config), "data")).listen(port, process.env.HOST ?? "127.0.0.1", () => console.log(`agent-custody Shopify door on port ${port}`));

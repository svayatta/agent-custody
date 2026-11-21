// The door as a Cloudflare Worker. Everything it does is in packages/receipts/src/door-worker.ts; this file is the
// Worker's entry, built by packages/receipts/scripts/build-door-worker.ts (the build command in wrangler.toml).
import { createDoorWorker } from "../../../../packages/receipts/src/door-worker.ts";

export default createDoorWorker();

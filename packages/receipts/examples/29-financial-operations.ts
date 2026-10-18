// One refund, even after a lost response. Budget reservations stay held until a provider read closes them.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { financialFixture } from "../scripts/financial-fixture.ts";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGatewayHost } from "../src/gateway.ts";
import { OPERATION_META_KEY } from "../src/operations.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { out, step } from "./_out.ts";

const fx = await financialFixture(out("29-financial-operations"));
let host = await createGatewayHost(loadConfig(fx.configFile));
const grant = JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8"));
const id = randomUUID(); // Persist before sending; reuse exactly this UUID when a call times out.
const params = { name: "stripe.refund", arguments: { amount: 60, currency: "GBP" }, _meta: { [OPERATION_META_KEY]: id } };
try {
  step(1, "Provider accepts the refund, but its response is dropped");
  fx.api.drop = true;
  const first = await host.open(grant).handleCall(params);
  assert.equal((first._meta?.[OPERATION_META_KEY] as { status: string }).status, "unknown");

  step(2, "Restart and retry the same operation: no second provider request");
  await host.close();
  host = await createGatewayHost(loadConfig(fx.configFile));
  await host.open(grant).handleCall(params);
  assert.equal(fx.api.posts, 1);
  assert.equal(fx.records.size, 1);

  step(3, "The unknown reservation still consumes 60 of the daily 100 minor units");
  const blocked = await host.open(grant).handleCall({ ...params, _meta: { [OPERATION_META_KEY]: randomUUID() } });
  assert.equal(blocked.isError, true);
  assert.equal(fx.api.posts, 1);

  step(4, "Provider confirms settlement; reconciliation links to the original receipt");
  fx.records.values().next().value!.status = "succeeded";
  const receipt = await host.reconcile(id);
  const verified = verifyBundle(receipt, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
  console.log(formatReport(verified));
  assert.equal(verified.ok, true);
  console.log("OK");
} finally { await host.close(); await fx.close(); }

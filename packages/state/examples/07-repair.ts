// Aspect: stores that match the ledger. Source: src/server.ts (memory.repair), src/stores.ts (Store.list)
// Run:    node examples/07-repair.ts        (after `bun run build` at the repository root)
// A write reaches the stores before the ledger. When the ledger append fails, a store keeps an entry that the ledger
// has no fact for. memory.repair finds that entry, removes it once it is older than its cutoff (ten minutes), verifies
// the removal, and records a repair event.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { JsonlStore, Ledger, createMemoryServer, factMetadata, factText, type EventStore, type Store, type StoreEntry } from "../src/index.ts";

const dir = mkdtempSync(join(tmpdir(), "repair-example-"));
const step = (n: number, s: string) => console.log(`\n${n}. ${s}`);
const value = (r: any) => JSON.parse(r.content[0].text);

step(1, "a memory server with one store that can put, remove, verify a removal, and list its entries");
let puts = 0;
const held = new Map<string, { text: string; metadata: Record<string, unknown> }>();
const store: Store = {
  name: "notes",
  async put(fact) {
    // factMetadata stamps storedAt with the time of this write. The first write below fails at the ledger, and repair
    // removes only entries older than ten minutes. This store therefore records a time an hour in the past, which
    // stands in for an orphan from a failed append some time ago. The example does not wait ten minutes.
    const metadata = { ...factMetadata(fact), storedAt: new Date(Date.now() - 3_600_000).toISOString() };
    // The second write succeeds, and its entry gets the real time, so the sweep treats it as young.
    held.set(fact.factId, { text: factText(fact), metadata: ++puts === 1 ? metadata : factMetadata(fact) });
    return fact.factId;
  },
  async delete({ externalId }) {
    held.delete(externalId);
  },
  async verifyDeleted({ externalId }) {
    return !held.has(externalId);
  },
  async list() {
    return [...held].map(([externalId, e]): StoreEntry => ({ externalId, factId: String(e.metadata.factId), text: e.text, storedAt: String(e.metadata.storedAt) }));
  },
};

step(2, "the ledger's event store fails its first append, as a full disk or a lost connection would");
const events = new JsonlStore(join(dir, "ledger.jsonl"));
let appends = 0;
const flaky: EventStore = new Proxy(events, {
  get(target, prop) {
    if (prop === "append") {
      return async (event: Parameters<EventStore["append"]>[0]) => {
        if (appends++ === 0) throw new Error("ledger append failed (simulated)");
        return target.append(event);
      };
    }
    const v = Reflect.get(target, prop, target);
    return typeof v === "function" ? v.bind(target) : v;
  },
});
const ledger = new Ledger(flaky);
const [a, b] = InMemoryTransport.createLinkedPair();
await createMemoryServer(ledger, { stores: [store], verify: { attempts: 1, delayMs: 1 } }).connect(a);
const client = new Client({ name: "repair-example", version: "0" });
await client.connect(b);

step(3, "a write fails at the ledger, after the store took it: the store holds an entry the ledger does not know");
const failed = await client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "support-agent" } });
console.log(`   write isError=${failed.isError}  store entries=${held.size}  ledger facts=${(await ledger.facts()).length}`);

step(4, "a good write follows; its entry has a fact in the ledger, so the repair must leave it alone");
const good = value(await client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "tier", value: "gold", space: "team:support", actor: "support-agent" } }));
console.log(`   store entries=${held.size}  ledger facts=${(await ledger.facts()).length}`);

step(5, "memory.repair removes the orphan, verifies the removal, and records a repair event under the orphan's fact id; the good write's entry stays");
const repair = value(await client.callTool({ name: "memory.repair", arguments: { reason: "ledger append failed" } }));
const orphan = repair.repaired[0];
console.log(`   cutoff=${repair.before}  repaired=${JSON.stringify(repair.repaired.map((r: any) => ({ store: r.store, outcome: r.outcome })))}  unlisted=${repair.unlisted.length}  store entries=${held.size}`);

step(6, "memory.history of the orphan's fact id shows the repair event");
const history = value(await client.callTool({ name: "memory.history", arguments: { factId: orphan.factId } }));
console.log(`   ${history.events.map((e: any) => `${e.kind}/${e.outcome}`).join(", ")}`);

await client.close();
const stillThere = (await ledger.get(good.fact.factId)) !== undefined && held.has(good.fact.factId);
if (!failed.isError || repair.repaired.length !== 1 || orphan.outcome !== "verified" || held.has(orphan.factId) || !stillThere || history.events.length !== 1 || history.events[0].kind !== "repair" || history.events[0].eventId !== orphan.eventId) throw new Error("unexpected");
console.log("\nOK");

// The probe: what an outside monitor runs against a hosted log every few minutes. It does not trust the log's
// answers; it verifies them the way an auditor would, with the log's published keys, and it fails loudly when the
// log is down, its head does not verify, its checkpoints have fallen behind its head, or its witness has stopped
// countersigning. Run it from cron on a machine that is not the log's, or from a scheduled workflow; the exit code
// is the alert.
import { checkAnchorRecord, type AnchorHeartbeat, type AnchorRecord } from "./anchor.ts";
import { dsseVerify, dsseVerifiers, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { verifyConsistency } from "./log.ts";
import { TREEHEAD_TYPE, type TreeHead } from "./receipt.ts";
import { fetchLogKeys } from "./signer.ts";
import { fetchWitnessKeys } from "./witness.ts";

export interface LogCheckOptions {
  logUrl: string;
  checkpointsUrl?: string;
  witnessUrl?: string;
  /** which logs to probe: "default" for the root paths, else tenant names */
  tenants?: string[];
  /** how far a checkpoint may trail the head, in milliseconds, before that is a failure; default fifteen minutes */
  maxLagMs?: number;
  /** how old a checkpoint may be while the head has not moved; default a day, since an idle log is not a broken one */
  maxIdleMs?: number;
  /** where the anchor publishes its records; with it, `anchorAddress` and `anchorRpcUrls` are required */
  anchorUrl?: string;
  /** the anchor's address, pinned from a source other than the anchor's host */
  anchorAddress?: string;
  /** JSON-RPC endpoints of the anchor's chain; with more than one, they must agree */
  anchorRpcUrls?: string[];
  /** the anchor's chain id; default 1, Ethereum mainnet (`resolveAnchorChain` maps a name to its id) */
  anchorChainId?: number;
  /** how long the anchor may go without a run, or stay behind a log that grew; default thirteen hours */
  maxAnchorLagMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface LogCheck {
  tenant: string | null;
  name: string;
  ok: boolean;
  detail?: string;
}

export interface LogCheckResult {
  ok: boolean;
  checks: LogCheck[];
}

const short = (s: string) => s.slice(0, 12);

export async function checkLog(o: LogCheckOptions): Promise<LogCheckResult> {
  const f = o.fetch ?? fetch;
  const now = o.now ?? Date.now;
  const maxLag = o.maxLagMs ?? 15 * 60_000;
  const maxIdle = o.maxIdleMs ?? 24 * 3_600_000;
  const checks: LogCheck[] = [];
  const add = (tenant: string | null, name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { tenant, name, ok } : { tenant, name, ok, detail });
    return ok;
  };
  const base = o.logUrl.endsWith("/") ? o.logUrl : `${o.logUrl}/`;
  const get = async (url: URL): Promise<unknown> => {
    const res = await f(url, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`${res.status} from ${url.pathname}`);
    return res.json();
  };

  const anchorChecks = async (tenant: string, head: TreeHead) => {
    if (!o.anchorAddress || !o.anchorRpcUrls?.length) {
      add(tenant, "anchor verifies on chain", false, "an anchor URL needs the pinned anchor address and at least one JSON-RPC endpoint");
      return;
    }
    const aBase = o.anchorUrl!.endsWith("/") ? o.anchorUrl! : `${o.anchorUrl!}/`;
    const lag = o.maxAnchorLagMs ?? 13 * 3_600_000;
    try {
      const beat = (await get(new URL(`${tenant}/checked.json`, aBase))) as AnchorHeartbeat;
      const ran = now() - Date.parse(beat.at);
      const behind = beat.behindSince ? now() - Date.parse(beat.behindSince) : 0;
      add(tenant, "anchor is running and keeps up", ran <= lag && behind <= lag, beat.behindSince ? `last run ${Math.round(ran / 60_000)} min ago, behind the log for ${Math.round(behind / 60_000)} min` : `last run ${Math.round(ran / 60_000)} min ago`);
    } catch (e) {
      add(tenant, "anchor is running and keeps up", false, e instanceof Error ? e.message : String(e));
    }
    let record: AnchorRecord;
    try {
      record = (await get(new URL(`${tenant}/latest.json`, aBase))) as AnchorRecord;
    } catch (e) {
      add(tenant, "anchor verifies on chain", false, e instanceof Error ? e.message : String(e));
      return;
    }
    const r = await checkAnchorRecord(record, { rpcUrls: o.anchorRpcUrls, address: o.anchorAddress, chainId: o.anchorChainId ?? 1, logKeys: keys, fetch: f });
    if (!add(tenant, "anchor verifies on chain", r.ok, r.ok ? `size ${record.treeSize} in block ${r.blockNumber} at ${r.blockTime}${r.finalized ? ", finalized" : ", not yet finalized"}` : r.error)) return;
    if (record.treeSize > head.treeSize) {
      add(tenant, "head extends the anchored checkpoint", false, `the head at ${head.treeSize} is behind the anchored size ${record.treeSize}: the log was rolled back`);
    } else if (record.treeSize === head.treeSize) {
      add(tenant, "head extends the anchored checkpoint", record.rootHash === head.rootHash, record.rootHash === head.rootHash ? `at the anchored size ${head.treeSize}` : `a different root at the anchored size ${head.treeSize}: history was rewritten`);
    } else {
      try {
        const proof = (await get(new URL(tenant === "default" ? `consistency?old=${record.treeSize}&new=${head.treeSize}` : `t/${tenant}/consistency?old=${record.treeSize}&new=${head.treeSize}`, base))) as { hashes: string[] };
        const ok = verifyConsistency(record.treeSize, record.rootHash, head.treeSize, head.rootHash, proof.hashes);
        add(tenant, "head extends the anchored checkpoint", ok, ok ? `${record.treeSize} -> ${head.treeSize}` : `the head at ${head.treeSize} does not extend the anchored ${record.treeSize}: history was rewritten`);
      } catch (e) {
        add(tenant, "head extends the anchored checkpoint", false, e instanceof Error ? e.message : String(e));
      }
    }
  };

  let keys: PublicKeyRef[] = [];
  try {
    keys = (await fetchLogKeys(base, f)).keys;
    add(null, "key document served", true, `${keys.length} key(s), current ${short(keys[0]!.keyid)}`);
  } catch (e) {
    add(null, "key document served", false, e instanceof Error ? e.message : String(e));
    return { ok: false, checks };
  }
  let witnessKeys: PublicKeyRef[] = [];
  if (o.witnessUrl) {
    try {
      witnessKeys = await fetchWitnessKeys(o.witnessUrl, f);
      add(null, "witness key document served", true, `witness ${short(witnessKeys[0]!.keyid)}`);
    } catch (e) {
      add(null, "witness key document served", false, e instanceof Error ? e.message : String(e));
    }
  }

  for (const tenant of o.tenants ?? ["default"]) {
    const path = (op: string) => new URL(tenant === "default" ? op : `t/${tenant}/${op}`, base);
    let head: TreeHead | null = null;
    try {
      const { treeHead } = (await get(path("head"))) as { treeHead: Envelope };
      const v = dsseVerify(treeHead, keys);
      head = v.ok && treeHead.payloadType === TREEHEAD_TYPE ? (v.payload as TreeHead) : null;
      add(tenant, "head verifies against the published keys", head !== null, head ? `size ${head.treeSize}, signed by ${short(v.ok ? v.keyid : "?")}` : v.ok ? "not a tree head" : v.error);
    } catch (e) {
      add(tenant, "head verifies against the published keys", false, e instanceof Error ? e.message : String(e));
      continue;
    }
    if (!head) continue;
    if (o.anchorUrl) await anchorChecks(tenant, head);
    if (!o.checkpointsUrl) continue;
    const cpBase = o.checkpointsUrl.endsWith("/") ? o.checkpointsUrl : `${o.checkpointsUrl}/`;
    interface Cp {
      treeSize: number;
      rootHash: string;
      signedAt: string;
      envelope: Envelope;
    }
    let cp: Cp | null = null;
    try {
      const fetched = (await get(new URL(`${tenant}/latest.json`, cpBase))) as Cp;
      const v = dsseVerify(fetched.envelope, keys);
      add(tenant, "latest checkpoint verifies", v.ok, v.ok ? `size ${fetched.treeSize} signed ${fetched.signedAt}` : v.error);
      if (v.ok) cp = fetched;
    } catch (e) {
      add(tenant, "latest checkpoint verifies", false, e instanceof Error ? e.message : String(e));
    }
    if (!cp) continue;
    const age = now() - Date.parse(cp.signedAt);
    if (cp.treeSize < head.treeSize) {
      // the head moved on; the publisher must follow within maxLag of the head's own timestamp
      const lag = now() - Date.parse(head.timestamp);
      add(tenant, "checkpoint keeps up with the head", lag <= maxLag, `checkpoint at ${cp.treeSize}, head at ${head.treeSize}, head signed ${Math.round(lag / 1000)}s ago`);
    } else {
      add(tenant, "checkpoint keeps up with the head", cp.treeSize === head.treeSize && age <= maxIdle, cp.treeSize > head.treeSize ? `checkpoint at ${cp.treeSize} is AHEAD of the head at ${head.treeSize}` : `at the head, checkpoint signed ${Math.round(age / 60_000)} min ago`);
    }
    if (cp.treeSize <= head.treeSize) {
      try {
        const proof = (await get(path(`consistency?old=${cp.treeSize}&new=${head.treeSize}`))) as { hashes: string[] };
        add(tenant, "head extends the checkpoint", verifyConsistency(cp.treeSize, cp.rootHash, head.treeSize, head.rootHash, proof.hashes), `${cp.treeSize} -> ${head.treeSize}`);
      } catch (e) {
        add(tenant, "head extends the checkpoint", false, e instanceof Error ? e.message : String(e));
      }
    }
    if (o.witnessUrl && witnessKeys.length > 0) {
      const wBase = o.witnessUrl.endsWith("/") ? o.witnessUrl : `${o.witnessUrl}/`;
      try {
        const w = (await get(new URL(`${tenant}/latest.json`, wBase))) as { treeSize: number; envelope: Envelope };
        const by = dsseVerifiers(w.envelope, witnessKeys);
        add(tenant, "witness has countersigned", by.length > 0, by.length ? `at size ${w.treeSize}` : "latest witnessed checkpoint carries no witness signature");
        add(tenant, "witness keeps up with the checkpoints", w.treeSize >= cp.treeSize || now() - Date.parse(cp.signedAt) <= maxLag, `witness at ${w.treeSize}, checkpoint at ${cp.treeSize}`);
        const alarm = await f(new URL(`${tenant}/ALARM.json`, wBase), { signal: AbortSignal.timeout(10_000) });
        add(tenant, "witness has raised no alarm", alarm.status === 404, alarm.status === 404 ? undefined : `ALARM.json is present (${alarm.status})`);
      } catch (e) {
        add(tenant, "witness has countersigned", false, e instanceof Error ? e.message : String(e));
      }
    }
  }
  return { ok: checks.every((c) => c.ok), checks };
}

export function formatLogCheck(r: LogCheckResult): string {
  const lines = r.checks.map((c) => `${c.ok ? "PASS" : "FAIL"}  ${c.tenant ? `${c.tenant.padEnd(16)} ` : "".padEnd(17)}${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  lines.push("", r.ok ? "RESULT: LOG HEALTHY" : "RESULT: LOG NEEDS ATTENTION");
  return lines.join("\n");
}

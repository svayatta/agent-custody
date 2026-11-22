// A log reached over HTTP, and the sink interface every log satisfies. Kept apart from the local file log and the log
// server so that a producer running outside Node (a Worker) can append to a remote log without loading either.
import { dsseVerify, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { leafHash, verifyInclusion, type InclusionProof } from "./merkle.ts";
import { TREEHEAD_TYPE, type TreeHead } from "./receipt.ts";
import { fetchLogKeys, shownUrl } from "./signer.ts";

export interface LogAppend {
  inclusion: InclusionProof;
  /** signed TreeHead; the signature's keyid says who runs the log */
  treeHead: Envelope;
}

export interface LogSink {
  readonly kind: "file" | "http";
  /** the file path or the URL, for reports */
  readonly where: string;
  append(leaf: string): Promise<LogAppend>;
}

export interface HttpLogOptions {
  /** sent as a bearer token; the log decides what it is worth */
  token?: string;
  /** send only the leaf hash; the log then commits to the receipt without ever holding it. Use it for any log run by someone else. */
  hashOnly?: boolean;
  /** attempts on 429 and 5xx; default 3 */
  retries?: number;
  /** how long one append may take before it counts as unreachable; default 10000. A log that accepts and never answers must not hold a call forever. */
  timeoutMs?: number;
  /** the log's public keys, pinned: the tree head in every append's answer must be signed by one of them. Without them, the key document at the log's /.well-known/agent-custody-log.json is fetched on first use and pinned for the life of the sink. */
  keys?: PublicKeyRef[];
  /** the id the log must write into every tree head; an answer naming another log, or none, is refused */
  logId?: string;
  fetch?: typeof fetch;
}

/**
 * A log reached over HTTP: POST <url>/append with {leaf} or {leafHash}, expecting a LogAppend back. A 429 or a 5xx
 * is retried a few times with backoff, honouring Retry-After; anything else, or the last failure, is the caller's.
 *
 * The answer is not taken on trust. Before it is returned, and so before a pre-committed call is forwarded, the tree
 * head must verify against the log's pinned keys, name the expected log, match the proof's size, and the inclusion
 * proof must place this very leaf under the signed root. A log that answers with anything else has refused the append.
 */
export function httpLog(url: string, opts: HttpLogOptions = {}): LogSink {
  const f = opts.fetch ?? fetch;
  const shown = shownUrl(url);
  const base = url.endsWith("/") ? url : `${url}/`;
  const attempts = opts.retries ?? 3;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  let pinned: Promise<PublicKeyRef[]> | null = opts.keys?.length ? Promise.resolve(opts.keys) : null;
  const keys = () => (pinned ??= fetchLogKeys(base, f).then((r) => r.keys).catch((e) => { pinned = null; throw new Error(`log ${shown}: its keys could not be fetched to check the append, and none are configured: ${e instanceof Error ? e.message : String(e)}`); }));
  const checked = async (entry: LogAppend, leaf: string): Promise<LogAppend> => {
    const th = dsseVerify(entry.treeHead, await keys());
    if (!th.ok || entry.treeHead.payloadType !== TREEHEAD_TYPE) throw new Error(`log ${shown} answered with a tree head that does not verify against its keys${th.ok ? " (wrong payload type)" : `: ${th.error}`}`);
    const head = th.payload as TreeHead;
    if (opts.logId !== undefined && head.log !== opts.logId) throw new Error(`log ${shown} signed a tree head for log "${head.log ?? ""}", not "${opts.logId}"`);
    if (head.treeSize !== entry.inclusion.treeSize) throw new Error(`log ${shown} answered with a tree head of size ${head.treeSize} and a proof for size ${entry.inclusion.treeSize}`);
    if (!verifyInclusion(leafHash(leaf), entry.inclusion, head.rootHash)) throw new Error(`log ${shown} answered with an inclusion proof that does not place this leaf under the signed root`);
    return entry;
  };
  return {
    kind: "http",
    where: url,
    async append(leaf) {
      let last = "";
      for (let i = 0; i < attempts; i++) {
        let res: Response;
        try {
          res = await f(new URL("append", base), {
            method: "POST",
            headers: { "content-type": "application/json", ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}) },
            body: JSON.stringify(opts.hashOnly ? { leafHash: leafHash(leaf).toString("hex") } : { leaf }),
            signal: AbortSignal.timeout(timeoutMs),
          });
        } catch (e) {
          last = `log ${shown} unreachable: ${e instanceof Error ? e.message : String(e)}`;
          if (i + 1 < attempts) await new Promise((r) => setTimeout(r, 200 * 2 ** i));
          continue;
        }
        if (res.ok) {
          const body = (await res.json()) as Partial<LogAppend>;
          if (!body.inclusion || !body.treeHead) throw new Error(`log ${shown} returned a malformed append result`);
          return checked(body as LogAppend, leaf);
        }
        last = `log ${shown} refused the append: ${res.status} ${(await res.text()).slice(0, 200)}`;
        if (res.status !== 429 && res.status < 500) break;
        if (i + 1 < attempts) {
          const after = Number(res.headers.get("retry-after"));
          await new Promise((r) => setTimeout(r, Number.isFinite(after) && after > 0 ? Math.min(after, 5) * 1000 : 200 * 2 ** i));
        }
      }
      throw new Error(last);
    },
  };
}

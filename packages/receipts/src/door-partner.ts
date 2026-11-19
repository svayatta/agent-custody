// A partner detection engine's verdict on one arrival: Cloudflare Bot Management, HUMAN, DataDome, or any engine behind
// an adapter that holds a signing key. The door asks the engine about an arrival, naming the receipt it is writing; the
// engine signs its verdict for that receipt and route in the upstream attestation format (upstream.ts), over the digest
// of the verdict. The verdict reaches the policy only when that signature verifies under the configured key, and lands
// in the receipt as an attested fact that a reader holding the key checks again. A verdict signed for another receipt
// is refused, so one engine answer cannot be replayed onto another arrival.
import type { DoorConfig } from "./config.ts";
import { isPlainEnvelope } from "./capture.ts";
import { digestOf, dsseSign, loadPublicKey, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";
import { checkUpstream, UPSTREAM_TYPE, type UpstreamAttestation } from "./upstream.ts";
import { readCapped } from "./web-bot-auth.ts";

/** the fact a verified verdict is recorded as, and the policy reads as `context.facts.partner` */
export const PARTNER_FACT = "partner";
export const PARTNER_TOOL = "door.partner";

export type PartnerConfig = NonNullable<DoorConfig["partner"]>;

/** What the engine signs: its name, its verdict, and a score when it gives one. An integer, since Cedar has no floats. */
export interface PartnerVerdict {
  engine: string;
  verdict: string;
  score?: number;
}

/**
 * What became of the question, in the arrival fact. `verified`: the verdict's signature verified under the configured
 * key and binds this receipt and route. `rejected`: the engine answered, and the answer was not a verdict signed for this
 * arrival. `unavailable`: no answer in time, an error status, a redirect, or too many questions already waiting.
 */
export interface ArrivalPartner {
  engine: string;
  outcome: "verified" | "rejected" | "unavailable";
  error?: string;
}

/** What the door tells the engine about an arrival. Never the query, the body, the grant, or a cookie. */
export interface PartnerQuestion {
  receiptId: string;
  route: string;
  method: string;
  path: string;
  remote: string;
  class: string;
  /** the request headers a door receipt records: user-agent, content-type, accept, host */
  headers: Record<string, string>;
}

/** The engine's answer: the verdict and its signature. */
export interface PartnerAnswer {
  verdict: PartnerVerdict;
  signature: Envelope;
}

export type PartnerResult = { check: ArrivalPartner; verdict?: undefined } | { check: ArrivalPartner & { outcome: "verified" }; verdict: PartnerVerdict; signature: Envelope };

/** For engines and their adapters: the signature over a verdict for the receipt and route the door named. */
export function signVerdict(verdict: PartnerVerdict, key: KeyPair, receiptId: string, route: string): Envelope {
  const payload: UpstreamAttestation = { receiptId, tool: route, contentDigest: digestOf(verdict) };
  return dsseSign(UPSTREAM_TYPE, payload, key);
}

const VERDICT = /^[A-Za-z0-9_.:-]{1,64}$/;
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** The verdict as the door records it, or why it is not one: exactly engine, verdict, and an optional integer score. */
function verdictOf(v: unknown, engine: string): PartnerVerdict | string {
  if (!isObject(v)) return "the answer carries no verdict object";
  if (Object.keys(v).some((k) => k !== "engine" && k !== "verdict" && k !== "score")) return "the verdict carries fields other than engine, verdict, and score";
  if (v.engine !== engine) return `the verdict does not name engine ${engine}`;
  if (typeof v.verdict !== "string" || !VERDICT.test(v.verdict)) return "the verdict is not a short word (letters, digits, _ . : -, at most 64)";
  if (v.score !== undefined && !Number.isSafeInteger(v.score)) return "the score is not an integer";
  return { engine, verdict: v.verdict, ...(v.score !== undefined ? { score: v.score as number } : {}) };
}

/**
 * Checks an engine's answer for one arrival: a verdict of the configured engine, signed under `key` for this receipt
 * and route, in exactly the plain attestation form (so the receipt can carry the envelope in clear beside the verdict).
 */
export function checkPartnerAnswer(answer: unknown, key: PublicKeyRef, expected: { engine: string; receiptId: string; route: string }): PartnerResult {
  const { engine } = expected;
  const rejected = (error: string): PartnerResult => ({ check: { engine, outcome: "rejected", error } });
  if (!isObject(answer)) return rejected("the answer is not an object with a verdict and a signature");
  const verdict = verdictOf(answer.verdict, engine);
  if (typeof verdict === "string") return rejected(verdict);
  const digest = digestOf(verdict);
  const signature = answer.signature as Envelope;
  const signed = checkUpstream(signature, [key], { receiptId: expected.receiptId, tool: expected.route, contentDigest: digest });
  if (!signed.ok) return rejected(`the verdict's signature does not hold: ${signed.error}`);
  if (!isPlainEnvelope(signature, expected.receiptId, expected.route, digest)) return rejected("the signature envelope carries more than the attestation of this verdict");
  return { check: { engine, outcome: "verified" }, verdict, signature };
}

export interface PartnerEngine {
  /** whether arrivals on this route are asked about */
  applies(route: string): boolean;
  ask(question: PartnerQuestion): Promise<PartnerResult>;
}

/** The engine as the door config names it. Every question carries `AbortSignal.timeout`, follows no redirect, and reads at most `maxResponseBytes`. */
export function createPartnerEngine(cfg: PartnerConfig, f: typeof fetch): PartnerEngine {
  const key = loadPublicKey(cfg.keyFile);
  const all = cfg.routes.includes("*");
  const routes = new Set(cfg.routes);
  const { engine } = cfg;
  const unavailable = (error: string): PartnerResult => ({ check: { engine, outcome: "unavailable", error } });
  let inFlight = 0;
  return {
    applies: (route) => all || routes.has(route),
    async ask(question) {
      // every asked arrival waits on the engine, so the questions at once are bounded; past that, no verdict
      if (inFlight >= cfg.maxInFlight) return unavailable(`${cfg.maxInFlight} questions are already waiting on the engine`);
      inFlight++;
      try {
        let body: Buffer | null;
        try {
          const res = await f(cfg.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(question), redirect: "manual", signal: AbortSignal.timeout(cfg.timeoutMs) });
          if (res.status >= 300 && res.status < 400) return unavailable(`the engine answered a redirect (${res.status}), which the door does not follow`);
          if (!res.ok) return unavailable(`the engine answered ${res.status}`);
          body = await readCapped(res, cfg.maxResponseBytes);
        } catch (e) {
          return unavailable(`the engine did not answer: ${e instanceof Error ? e.message : String(e)}`);
        }
        if (body === null) return { check: { engine, outcome: "rejected", error: `the answer is larger than ${cfg.maxResponseBytes} bytes` } };
        let answer: unknown;
        try {
          answer = JSON.parse(body.toString("utf8"));
        } catch {
          return { check: { engine, outcome: "rejected", error: "the answer is not JSON" } };
        }
        return checkPartnerAnswer(answer, key, { engine, receiptId: question.receiptId, route: question.route });
      } finally {
        inFlight--;
      }
    },
  };
}

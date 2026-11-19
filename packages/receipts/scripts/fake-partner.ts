// A stand-in partner detection engine: what an adapter in front of Cloudflare Bot Management, HUMAN, or DataDome would
// be. It answers the door's question about an arrival with a verdict signed for the receipt the door named, so the door
// passes the verdict to its policy and a verifier holding this key sees the partner fact as attested. Its judgement is
// a toy (a user agent that names a bot is a bot); the signature is the point. `mode` makes it misbehave for the tests:
// `replay` answers every question with the first signed answer it gave, `slow` answers after `slowMs`.
//
// Run: node scripts/fake-partner.ts --key <engine.key> [--port 8790] [--engine stub-engine]
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { loadPrivateKey, type KeyPair } from "../src/crypto.ts";
import { signVerdict, type PartnerAnswer, type PartnerQuestion, type PartnerVerdict } from "../src/door-partner.ts";

export interface PartnerStub {
  url: string;
  /** every question the engine was asked */
  seen: PartnerQuestion[];
  mode: "sign" | "replay" | "slow";
  close(): Promise<void>;
}

/** The toy judgement: a user agent that names a bot, a crawler, or a script is a bot; anything else is human. */
export function judge(engine: string, q: PartnerQuestion): PartnerVerdict {
  return /bot|crawler|spider|curl|python/i.test(q.headers["user-agent"] ?? "") ? { engine, verdict: "bot", score: 95 } : { engine, verdict: "human", score: 3 };
}

export async function startPartner(key: KeyPair, opts: { engine?: string; port?: number; slowMs?: number } = {}): Promise<PartnerStub> {
  const engine = opts.engine ?? "stub-engine";
  const seen: PartnerQuestion[] = [];
  let first: PartnerAnswer | undefined;
  const stub: PartnerStub = { url: "", seen, mode: "sign", close: async () => {} };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      let q: PartnerQuestion;
      try {
        q = JSON.parse(Buffer.concat(chunks).toString("utf8")) as PartnerQuestion;
      } catch {
        res.writeHead(400).end();
        return;
      }
      seen.push(q);
      const verdict = judge(engine, q);
      const answer: PartnerAnswer = stub.mode === "replay" && first ? first : { verdict, signature: signVerdict(verdict, key, q.receiptId, q.route) };
      first ??= answer;
      const send = () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(answer));
      };
      if (stub.mode === "slow") setTimeout(send, opts.slowMs ?? 5_000).unref();
      else send();
    });
  });
  await new Promise<void>((r) => server.listen(opts.port ?? 0, "127.0.0.1", r));
  stub.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/verdict`;
  stub.close = () => {
    server.closeAllConnections();
    return new Promise<void>((r) => server.close(() => r()));
  };
  return stub;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const arg = (name: string) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const keyFile = arg("--key");
  if (!keyFile) {
    console.error("usage: node scripts/fake-partner.ts --key <engine.key> [--port 8790] [--engine stub-engine]");
    process.exit(2);
  }
  const stub = await startPartner(loadPrivateKey(keyFile), { port: Number(arg("--port") ?? 8790), ...(arg("--engine") ? { engine: arg("--engine")! } : {}) });
  console.error(`fake partner engine: ${stub.url}`);
}

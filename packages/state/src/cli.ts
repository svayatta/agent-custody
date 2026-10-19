#!/usr/bin/env node
import { parseArgs } from "node:util";
import { Ledger } from "./ledger.ts";
import { createMemoryServer, serveStdio } from "./server.ts";
import { captureKeyFrom } from "@agent-custody/receipts";

/** the capture key from the environment variable named, for queries over receipts under a capture rule; none when no variable is named */
const keyFromEnv = (name: string | undefined): Buffer | undefined => (name ? captureKeyFrom(process.env[name] ?? (() => { throw new Error(`${name} is not set`); })()) : undefined);
import { blastRadius, formatBlastRadius, loadReceipts } from "./blast.ts";
import { serveMemoryHttp } from "./http.ts";
import { loadPrivateKey, loadPublicKey, verifyBundle } from "@agent-custody/receipts";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { formatReport, runAll, SCENARIOS } from "./evals.ts";
import { ledgerUnderTest, overwriteStoreUnderTest } from "./evals-ledger.ts";
import { loadScenarios, signReport, verifyReport } from "./evals-file.ts";
import { buildPack, formatPack, signPack, verifyPack } from "./pack.ts";
import { buildActionPack, formatExplain, signActionPack, verifyActionPack } from "./explain.ts";
import { serveReview, writeReview } from "./review.ts";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

/** The forget key from an environment variable, when named; a named but unset variable is an error at startup. */
function forgetKeyFrom(envName: string | undefined): { forgetKey?: string } {
  if (!envName) return {};
  const v = process.env[envName];
  if (!v) throw new Error(`forget key: environment variable ${envName} is not set`);
  return { forgetKey: v };
}

/** "org=P365D,team:*=P90D" into retention windows. */
function parseRetention(spec: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of spec.split(",")) {
    const [pattern, duration] = part.split("=").map((x) => x.trim());
    if (!pattern || !duration) throw new Error(`retention: expected space=duration, got "${part}"`);
    out[pattern] = duration;
  }
  return out;
}

const USAGE = `agent-custody-memory <command>

  serve --ledger <ledger.jsonl|ledger.sqlite|postgres://…> [--allow-direct] [--key <memory.key>] [--forget-key-env NAME] [--retention 'org=P365D,team:*=P90D']
                                                   --forget-key-env names a secret kept outside the ledger; forgotten values then leave an HMAC, not a guessable hash.
                                                   the memory server over stdio; run it as the receipts gateway's upstream.
                                                   --key signs every result for its receipt, so executions verify as attested by this server.
                                                   By default it refuses calls that did not come through the gateway.
  serve --ledger <ledger.jsonl> --http [--port 8790] [--host 127.0.0.1] --token-env NAME [--allow-direct --direct-token-env NAME]
                                                   the same server shared over HTTP: several gateways, one ledger. --token-env is the
                                                   gateways' token; direct writers get their own under --direct-token-env and are never
                                                   believed about receipts or agents, whatever their calls carry.
                                                   A postgres:// ledger (needs the pg package; ?table=custody.events names the table)
                                                   is shared by every server pointed at it.
  sweep --via <gateway.json> --reason <text> [--before <ISO instant>] [--space <space>] [--no-digest]
                                                   retention as a receipted call: runs memory.sweep through that gateway, as the principal in its grant.
                                                   Without --before, the memory server's --retention windows decide. Put this on a timer.
  sweep --ledger <ledger.jsonl> --before <ISO instant> [--space <space>] --reason <text> [--actor <id>] [--forget-key-env NAME] [--no-digest]
                                                   retention on the ledger file alone, for ledgers with no gateway or stores in front of them.
  eval [--scenarios <file.json>] [--baseline] [--json] [--sign <key> --out <report.json>]
                                                   runs the memory-mutation scenarios on a fresh ledger; --baseline also scores a naive
                                                   overwrite store; --sign writes a signed report. Exits 1 if the ledger regresses.
  eval --verify <report.json> --key <pub>          checks a signed report and prints its scores
  pack --ledger <ledger> --receipts <dir> --fact <factId> --out <pack.json> --sign <key>
                                                   everything about one fact as one signed artefact: history with receipts, blast radius,
                                                   holds, the forget certificate and what the stores answered. For counsel and auditors.
  pack --verify <pack.json> --key <pub> [--issuer-key <pub>] [--principal-key <pub>]
                                                   checks the pack's signature and every receipt inside it
  explain --receipts <dir> --receipt <receiptId> [--ledger <ledger>] [--issuer-key <pub>] [--principal-key <pub>] [--log-key <pub>] [--json]
                                                   one action, answered: who, who authorized it, what was allowed, what the agent saw, what it did,
                                                   why, the evidence, whether it verifies, what depended on it, what needs reversal.
                                                   With a ledger the last two are answered from the beliefs; without, they say so.
  explain ... --out <action.json> --sign <key>     the same as one signed action pack, every downstream receipt inside
  explain --verify <action.json> --key <pub> [--issuer-key <pub>] [--principal-key <pub>] [--log-key <pub>]
                                                   checks the pack, the receipt inside it, and every downstream receipt
  review --receipts <dir> [--ledger <ledger>] [--issuer-key <pub>] [--principal-key <pub>] [--log-key <pub>] [--log-id <id>] [--port 8791] [--host 127.0.0.1] [--title <text>]
                                                   the explain output as pages, for the reviewer who will not open a terminal: an index of every
                                                   receipt with its verdict, one page per receipt with the ten answers and the verification report.
                                                   Serves on loopback; put it behind your own login if you expose it.
  review ... --out <dir>                           the same as static files, for a case file or a shared drive
  export --ledger <ledger.sqlite|postgres://…> --out <ledger.jsonl>  the auditable JSONL of any ledger, one event per line; also the feed for a warehouse
  blast --ledger <ledger.jsonl> --receipts <dir> --fact <factId> [--capture-key-env NAME] [--json]
                                                   everything that relied on a fact: later calls, derived beliefs, and whether it was retracted
`;

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case "serve": {
      const { values } = parseArgs({ args: rest, options: { ledger: { type: "string" }, "allow-direct": { type: "boolean", default: false }, http: { type: "boolean", default: false }, port: { type: "string", default: "8790" }, host: { type: "string", default: "127.0.0.1" }, "token-env": { type: "string" }, "direct-token-env": { type: "string" }, key: { type: "string" }, "forget-key-env": { type: "string" }, retention: { type: "string" } } });
      if (!values.ledger) throw new Error("serve needs --ledger");
      const ledger = new Ledger(values.ledger, forgetKeyFrom(values["forget-key-env"]));
      // Printed after the startup line, which supervisors and tests read first for the address.
      const digestWarning = values["forget-key-env"] ? "" : "agent-custody-memory: no --forget-key-env; forgotten values leave a plain sha256, which is guessable for short values. Set a forget key, or forget with keepDigest false.";
      const identity = values.key ? loadPrivateKey(values.key) : undefined;
      const retention = values.retention ? parseRetention(values.retention) : undefined;
      const common = { requireGateway: !values["allow-direct"], ...(identity ? { identity } : {}), ...(retention ? { retention } : {}) };
      if (values.http) {
        if (!values["token-env"]) throw new Error("serve --http needs --token-env: the gateways' token is what tells a gateway from any other caller");
        const token = process.env[values["token-env"]];
        if (!token) throw new Error(`serve: environment variable ${values["token-env"]} is not set`);
        const directToken = values["direct-token-env"] ? process.env[values["direct-token-env"]] : undefined;
        if (values["direct-token-env"] && !directToken) throw new Error(`serve: environment variable ${values["direct-token-env"]} is not set`);
        if (values["allow-direct"] && !directToken) throw new Error("serve --http --allow-direct needs --direct-token-env: direct writers present their own token, never the gateways'");
        const running = await serveMemoryHttp(ledger, { port: Number(values.port), host: values.host, ...common, tokens: [token], ...(directToken ? { directTokens: [directToken] } : {}) });
        console.error(`agent-custody-memory: ${running.url} ledger=${values.ledger} events=${await ledger.count()} gateway token required ${values["allow-direct"] ? "direct writers with their own token" : "gateway calls only"}`);
        if (digestWarning) console.error(digestWarning);
        await new Promise<void>((resolve) => process.once("SIGINT", resolve));
        await running.close();
        return 0;
      }
      console.error(`agent-custody-memory: ledger=${values.ledger} events=${await ledger.count()} ${values["allow-direct"] ? "direct calls allowed" : "gateway calls only"}`);
      if (digestWarning) console.error(digestWarning);
      await serveStdio(createMemoryServer(ledger, common));
      return 0;
    }
    case "sweep": {
      const { values } = parseArgs({ args: rest, options: { ledger: { type: "string" }, via: { type: "string" }, before: { type: "string" }, space: { type: "string" }, reason: { type: "string" }, actor: { type: "string", default: "cli" }, "forget-key-env": { type: "string" }, "no-digest": { type: "boolean", default: false } } });
      if (values.via) {
        // Retention as a receipted call: spawn the gateway from its config and call memory.sweep through it, so the
        // sweep runs as the principal named in that gateway's grant and its receipt is the record.
        if (!values.reason) throw new Error("sweep --via needs --reason");
        const gatewayCli = fileURLToPath(import.meta.resolve("@agent-custody/receipts/cli"));
        const client = new Client({ name: "agent-custody-memory-sweep", version: "0" });
        await client.connect(new StdioClientTransport({ command: process.execPath, args: [gatewayCli, "gateway", "--config", values.via], stderr: "inherit" }));
        try {
          const r = await client.callTool({ name: "memory.sweep", arguments: { reason: values.reason, ...(values.before ? { before: new Date(values.before).toISOString() } : {}), ...(values.space ? { space: values.space } : {}), ...(values["no-digest"] ? { keepDigest: false } : {}) } });
          const text = ((r as { content: { type: string; text?: string }[] }).content.find((c) => c.type === "text")?.text) ?? "";
          console.log(text);
          return (r as { isError?: boolean }).isError ? 1 : 0;
        } finally {
          await client.close();
        }
      }
      if (!values.ledger || !values.before || !values.reason) throw new Error("sweep needs --ledger, --before, and --reason, or --via <gateway.json> --reason");
      const sweeper = new Ledger(values.ledger, forgetKeyFrom(values["forget-key-env"]));
      const r = await sweeper.sweep({ before: new Date(values.before).toISOString(), ...(values.space ? { space: values.space } : {}), actor: values.actor, reason: values.reason, ...(values["no-digest"] ? { keepDigest: false } : {}) });
      console.log(`forgot ${r.forgotten.length} fact(s); ${r.held.length} on hold, kept`);
      for (const f of r.forgotten) console.log(`  ${f.factId}  ${f.digestKind}${f.valueDigest ? ` ${f.valueDigest.slice(0, 12)}` : ""}`);
      await sweeper.close();
      return 0;
    }
    case "eval": {
      const { values } = parseArgs({ args: rest, options: { scenarios: { type: "string" }, baseline: { type: "boolean", default: false }, json: { type: "boolean", default: false }, sign: { type: "string" }, out: { type: "string" }, verify: { type: "string" }, key: { type: "string", multiple: true } } });
      if (values.verify) {
        if (!values.key?.length) throw new Error("eval --verify needs --key <pub>");
        const r = verifyReport(JSON.parse(readFileSync(values.verify, "utf8")), values.key.map(loadPublicKey));
        if (!r.ok) {
          console.log(`NOT VERIFIED: ${r.error}`);
          return 1;
        }
        console.log(`VERIFIED  signed by ${r.keyid.slice(0, 12)}  system ${r.predicate.system}  ran ${r.predicate.ranAt}  scenarios ${r.predicate.scenarioNames.length} (digest ${r.predicate.scenariosDigest.slice(0, 12)})`);
        console.log(formatReport(r.predicate.report));
        return 0;
      }
      const scenarios = values.scenarios ? loadScenarios(values.scenarios) : SCENARIOS;
      const ledger = new Ledger(join(mkdtempSync(join(tmpdir(), "agent-custody-eval-")), "ledger.jsonl"));
      const report = await runAll(ledgerUnderTest(ledger), scenarios);
      const baseline = values.baseline ? await runAll(overwriteStoreUnderTest(), scenarios) : null;
      const regressed = report.totals.correctReads < report.totals.reads || report.scenarios.some((s) => s.failures.length > 0);
      if (values.json) console.log(JSON.stringify({ ledger: report, baseline }, null, 2));
      else {
        console.log("The ledger:");
        console.log(formatReport(report));
        if (baseline) {
          console.log("\nA naive overwrite store:");
          console.log(formatReport(baseline));
        }
      }
      if (values.sign) {
        if (!values.out) throw new Error("eval --sign needs --out <report.json>");
        writeFileSync(values.out, JSON.stringify(signReport("agent-custody-ledger", scenarios, report, loadPrivateKey(values.sign)), null, 2));
        console.error(`signed report written to ${values.out}`);
      }
      return regressed ? 1 : 0;
    }
    case "pack": {
      const { values } = parseArgs({ args: rest, options: { "capture-key-env": { type: "string" }, ledger: { type: "string" }, receipts: { type: "string" }, fact: { type: "string" }, out: { type: "string" }, sign: { type: "string" }, verify: { type: "string" }, key: { type: "string", multiple: true }, "issuer-key": { type: "string", multiple: true }, "principal-key": { type: "string", multiple: true }, json: { type: "boolean", default: false } } });
      if (values.verify) {
        if (!values.key?.length) throw new Error("pack --verify needs --key <pub>");
        const r = verifyPack(JSON.parse(readFileSync(values.verify, "utf8")), values.key.map(loadPublicKey), values["issuer-key"]?.length ? { issuerKeys: values["issuer-key"].map(loadPublicKey), principalKeys: (values["principal-key"] ?? []).map(loadPublicKey) } : undefined);
        if (values.json) console.log(JSON.stringify(r, null, 2));
        else {
          for (const c of r.checks) console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
          console.log(`\nRESULT: ${r.ok ? "VERIFIED" : "NOT VERIFIED"}`);
          if (r.pack) console.log("\n" + formatPack(r.pack));
        }
        return r.ok ? 0 : 1;
      }
      if (!values.ledger || !values.receipts || !values.fact || !values.out || !values.sign) throw new Error("pack needs --ledger, --receipts, --fact, --out, and --sign");
      const packLedger = new Ledger(values.ledger);
      const pack = await buildPack(packLedger, values.receipts, values.fact, { captureKey: keyFromEnv(values["capture-key-env"]) });
      await packLedger.close();
      writeFileSync(values.out, JSON.stringify(signPack(pack, loadPrivateKey(values.sign)), null, 2));
      console.log(formatPack(pack));
      console.error(`signed pack written to ${values.out}`);
      return pack.missingReceipts.length ? 1 : 0;
    }
    case "explain": {
      const { values } = parseArgs({ args: rest, options: { "capture-key-env": { type: "string" }, ledger: { type: "string" }, receipts: { type: "string" }, receipt: { type: "string" }, out: { type: "string" }, sign: { type: "string" }, verify: { type: "string" }, key: { type: "string", multiple: true }, "issuer-key": { type: "string", multiple: true }, "principal-key": { type: "string", multiple: true }, "log-key": { type: "string", multiple: true }, json: { type: "boolean", default: false } } });
      const receiptKeys = values["issuer-key"]?.length ? { issuerKeys: values["issuer-key"].map(loadPublicKey), principalKeys: (values["principal-key"] ?? []).map(loadPublicKey), ...(values["log-key"]?.length ? { logKeys: values["log-key"].map(loadPublicKey) } : {}) } : undefined;
      if (values.verify) {
        if (!values.key?.length) throw new Error("explain --verify needs --key <pub>");
        const r = verifyActionPack(JSON.parse(readFileSync(values.verify, "utf8")), values.key.map(loadPublicKey), receiptKeys);
        if (values.json) console.log(JSON.stringify(r, null, 2));
        else {
          for (const c of r.checks) console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
          console.log(`\nRESULT: ${r.ok ? "VERIFIED" : "NOT VERIFIED"}`);
          if (r.pack) console.log("\n" + formatExplain(r.pack, r.receipt, true));
        }
        return r.ok ? 0 : 1;
      }
      if (!values.receipts || !values.receipt) throw new Error("explain needs --receipts and --receipt, or --verify");
      const ledger = values.ledger ? new Ledger(values.ledger) : undefined;
      const pack = await buildActionPack(values.receipts, values.receipt, ledger, { captureKey: keyFromEnv(values["capture-key-env"]) });
      await ledger?.close();
      const verification = receiptKeys ? verifyBundle(pack.receipt, receiptKeys) : null;
      if (values.out) {
        if (!values.sign) throw new Error("explain --out needs --sign <key>");
        writeFileSync(values.out, JSON.stringify(signActionPack(pack, loadPrivateKey(values.sign)), null, 2));
        console.error(`signed action pack written to ${values.out}`);
      }
      if (values.json) console.log(JSON.stringify({ pack, verification }, null, 2));
      else console.log(formatExplain(pack, verification, !!ledger));
      return verification && !verification.ok ? 1 : pack.missingReceipts.length ? 1 : 0;
    }
    case "review": {
      const { values } = parseArgs({ args: rest, options: { receipts: { type: "string" }, ledger: { type: "string" }, "issuer-key": { type: "string", multiple: true }, "principal-key": { type: "string", multiple: true }, "log-key": { type: "string", multiple: true }, "log-id": { type: "string" }, port: { type: "string", default: "8791" }, host: { type: "string", default: "127.0.0.1" }, title: { type: "string" }, out: { type: "string" } } });
      if (!values.receipts) throw new Error("review needs --receipts");
      const keys = values["issuer-key"]?.length ? { issuerKeys: values["issuer-key"].map(loadPublicKey), principalKeys: (values["principal-key"] ?? []).map(loadPublicKey), ...(values["log-key"]?.length ? { logKeys: values["log-key"].map(loadPublicKey) } : {}), ...(values["log-id"] ? { logId: values["log-id"] } : {}) } : undefined;
      const ledger = values.ledger ? new Ledger(values.ledger) : undefined;
      const o = { receiptsDir: values.receipts, ...(ledger ? { ledger } : {}), ...(keys ? { keys } : {}), ...(values.title ? { title: values.title } : {}) };
      if (values.out) {
        const r = await writeReview(o, values.out);
        console.log(`wrote ${r.receipts} receipt page(s) and the index to ${values.out}`);
        await ledger?.close();
        return 0;
      }
      const running = await serveReview(o, { port: Number(values.port), host: values.host });
      console.error(`agent-custody-memory review: ${running.url} receipts=${values.receipts}${ledger ? ` ledger=${values.ledger}` : ""}${keys ? " verifying" : " not verifying (no keys given)"}`);
      await new Promise<void>((resolve) => process.once("SIGINT", resolve));
      await running.close();
      await ledger?.close();
      return 0;
    }
    case "export": {
      const { values } = parseArgs({ args: rest, options: { ledger: { type: "string" }, out: { type: "string" } } });
      if (!values.ledger || !values.out) throw new Error("export needs --ledger and --out");
      const l = new Ledger(values.ledger);
      const events = await l.export();
      writeFileSync(values.out, events.map((e) => JSON.stringify(e)).join("\n") + "\n");
      console.log(`exported ${events.length} event(s) from ${l.location} to ${values.out}`);
      await l.close();
      return 0;
    }
    case "blast": {
      const { values } = parseArgs({ args: rest, options: { ledger: { type: "string" }, receipts: { type: "string" }, fact: { type: "string" }, "capture-key-env": { type: "string" }, json: { type: "boolean", default: false } } });
      if (!values.ledger || !values.receipts || !values.fact) throw new Error("blast needs --ledger, --receipts, and --fact [--capture-key-env NAME]");
      const blastLedger = new Ledger(values.ledger);
      // receipts under a capture rule withhold what the agent had been shown; the key brings it back, else the query says it is incomplete
      const b = await blastRadius(blastLedger, loadReceipts(values.receipts, { captureKey: keyFromEnv(values["capture-key-env"]) }), values.fact);
      await blastLedger.close();
      console.log(values.json ? JSON.stringify(b, null, 2) : formatBlastRadius(b, values.fact));
      return b.fact ? 0 : 1;
    }
    default:
      console.error(USAGE);
      return cmd === undefined || cmd === "--help" || cmd === "-h" ? 0 : 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    console.error(`error: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  },
);

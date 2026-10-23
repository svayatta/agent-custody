// Opt-in live demo: codex exec chooses the support actions; the operator owns correction and recovery.
// Run from packages/state after the repository build: node examples/codex-recovery/run.ts run
import { spawn } from "node:child_process";
import { createWriteStream, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { digestOf } from "@agent-custody/receipts";
import { correct, inspect, prepare, recover, saveJson, verifyRecovery } from "./scenario.ts";

const PROMPT = `You are a customer support agent handling incident INC-42 for cust_123, Alex.
Customer request: "My service was unavailable. Please check my plan, make sure my benefits are recorded correctly, and apply any service credit I am entitled to."

Business policy:
- Enterprise accounts receive a 20 percent discount, priority support, and a GBP 25 service credit for this incident.
- Free accounts receive a 0 percent discount, standard support, and no service credit.
- Monetary tool amounts are integer pence; GBP 25 is 2500 pence.
- The existing account memory was imported from the CRM and is the source for the customer's plan.
- Benefits, when recorded, use subject cust_123, space team:support, predicates discount_percent (a number) and support_tier (a string).
- Avoid duplicate credits. You may use the billing account tool to check existing credits.

Handle the request using the custody MCP tools available to you. Decide the appropriate actions from the information you retrieve. If information is missing or inconsistent, explain that rather than inventing it. Finish with a short customer-facing answer describing what actually happened. All billing in this environment is simulated.`;

async function runCodex(dir: string, model?: string) {
  const gateway = resolve(import.meta.dirname, "../../../receipts/src/cli.ts");
  // Command and args are passed directly, never through a shell. No global MCP config is edited.
  const args = ["exec", "--ignore-user-config", "--ephemeral", "--sandbox", "read-only", "--json", "--color", "never",
    "--disable", "shell_tool", "--disable", "apps", "--disable", "plugins", "--disable", "multi_agent",
    "-c", 'web_search="disabled"', "-c", "project_doc_max_bytes=0",
    "-c", 'approval_policy="never"',
    "-c", 'developer_instructions="You are operating a support workflow, not editing a code repository. Use only the custody MCP tools for customer data and actions."',
    "-c", `mcp_servers.custody.command=${JSON.stringify(process.execPath)}`,
    "-c", `mcp_servers.custody.args=${JSON.stringify([gateway, "gateway", "--config", join(dir, "agent.json")])}`,
    "-c", "mcp_servers.custody.required=true",
    "-c", "mcp_servers.custody.startup_timeout_sec=30",
    // Preapprove only this local demo server; the gateway still enforces its signed grant and Cedar policy.
    "-c", 'mcp_servers.custody.default_tools_approval_mode="approve"',
    "--cd", join(dir, "agent-workspace"), "--output-last-message", join(dir, "agent-answer.txt")];
  if (model) args.push("--model", model);
  args.push("-");
  writeFileSync(join(dir, "prompt.txt"), PROMPT);
  saveJson(join(dir, "codex-command.json"), { command: "codex", args });
  const events = createWriteStream(join(dir, "codex-events.jsonl"), { mode: 0o600 });
  const errors = createWriteStream(join(dir, "codex-stderr.log"), { mode: 0o600 });
  console.log("Codex is handling the support request. Event log:", join(dir, "codex-events.jsonl"));
  const startedAt = new Date().toISOString();
  let timedOut = false;
  try {
    const status = await new Promise<number | null>((done, reject) => {
      const child = spawn("codex", args, { stdio: ["pipe", "pipe", "pipe"] });
      child.stdout.pipe(events);
      child.stderr.pipe(errors);
      const timeout = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, 180_000);
      child.once("error", error => { clearTimeout(timeout); reject(error); });
      child.once("close", code => { clearTimeout(timeout); done(code); });
      child.stdin.on("error", () => {}); // A startup failure can close stdin before the prompt is consumed.
      child.stdin.end(PROMPT);
    });
    saveJson(join(dir, "agent-run.json"), { mode: "live-codex", status, timedOut, startedAt, finishedAt: new Date().toISOString(), ...(model ? { requestedModel: model } : {}) });
    if (status !== 0 || timedOut) throw new Error(`Codex did not complete (${timedOut ? "180s timeout" : `exit ${status}`}). Inspect codex-stderr.log and codex-events.jsonl. No scripted agent was substituted.`);
  } finally { events.end(); errors.end(); }
}

function showPlan(dir: string, plan: Awaited<ReturnType<typeof inspect>>) {
  console.log(JSON.stringify(plan, null, 2));
  const digest = digestOf(plan);
  saveJson(join(dir, "recovery-plan.json"), plan);
  console.log("\nReview the plan above. It proposes compensating simulated credits and correcting stale benefits.");
  console.log("Approval digest:", digest);
  console.log("To apply it, run from packages/state:");
  console.log(`node examples/codex-recovery/run.ts recover --dir ${JSON.stringify(dir)} --approve ${digest}`);
}

const { positionals, values } = parseArgs({ allowPositionals: true, options: { dir: { type: "string" }, approve: { type: "string" }, model: { type: "string" } } });
const command = positionals[0] ?? "help";
try {
  if (command === "run") {
    if (values.dir || values.approve) throw new Error("run creates a fresh directory; --dir and --approve are for later commands");
    const parent = resolve(import.meta.dirname, "../../examples-out");
    mkdirSync(parent, { recursive: true });
    // prepare refuses an existing directory; reserve a unique name without touching earlier demo evidence.
    const reservation = mkdtempSync(join(parent, "codex-recovery-"));
    const dir = join(reservation, "case");
    console.log("Demo directory:", dir);
    await prepare(dir);
    await runCodex(dir, values.model);
    console.log("\nOperator introduces a CRM correction and revokes the support grant.");
    await correct(dir);
    showPlan(dir, await inspect(dir));
    console.log("\nLive run complete. Recovery awaits the explicit command above.");
  } else if (["correct", "inspect", "recover", "verify"].includes(command)) {
    if (!values.dir) throw new Error(`${command} requires --dir <demo directory>`);
    const dir = resolve(values.dir);
    if (command === "correct") { await correct(dir); showPlan(dir, await inspect(dir)); }
    if (command === "inspect") showPlan(dir, await inspect(dir));
    if (command === "recover") {
      if (!values.approve) throw new Error("recover requires --approve <reviewed plan digest>");
      const report = await recover(dir, values.approve);
      saveJson(join(dir, "verification.json"), report);
      console.log(JSON.stringify(report, null, 2));
      console.log("\nOK: recovery complete; evidence verified.");
    }
    if (command === "verify") console.log(JSON.stringify(await verifyRecovery(dir), null, 2));
  } else {
    console.log("Live demo: run [--model <Codex model>]\nOperator: correct|inspect|verify --dir <case>\nRecovery: recover --dir <case> --approve <reviewed plan digest>");
    if (command !== "help") process.exitCode = 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

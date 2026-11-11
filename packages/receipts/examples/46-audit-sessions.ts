// Aspect: what the starter policy would have denied in past Claude Code sessions, read-only. Source: src/session-audit.ts
// Run:    node examples/46-audit-sessions.ts
//
// Before anyone installs a hook, `agent-custody audit-sessions` reads the transcripts Claude Code already keeps
// (~/.claude/projects) and shows the calls the policy would have denied. It writes nothing and sends nothing. Here the
// transcripts are written to examples-out the way Claude Code writes them, and the command reads them with --dir.
// A transcript is the agent host's own account, so the result is a preview; receipts come from `init claude-code`.
import { spawnSync } from "node:child_process";
import { mkdirSync, utimesSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { out, step } from "./_out.ts";

const dir = join(out("46-audit-sessions"), "projects");
const cli = resolve(import.meta.dirname, "..", "src", "cli.ts");
const recent = (hoursAgo: number) => new Date(Date.now() - hoursAgo * 3_600_000).toISOString();
const line = (ts: string, session: string, cwd: string, id: string, name: string, input: unknown) =>
  JSON.stringify({ type: "assistant", timestamp: ts, sessionId: session, cwd, message: { role: "assistant", content: [{ type: "tool_use", id, name, input }] } });

step(1, "Three transcripts: two projects, a subagent's own transcript, a call written twice, and one from a month ago");
mkdirSync(join(dir, "-home-dev-shop", "s-1", "subagents"), { recursive: true });
mkdirSync(join(dir, "-home-dev-platform"), { recursive: true });
writeFileSync(join(dir, "-home-dev-shop", "s-1.jsonl"), [
  line(recent(30), "s-1", "/home/dev/shop", "t1", "Bash", { command: "npm test" }),
  line(recent(29), "s-1", "/home/dev/shop", "t2", "Bash", { command: "git push --force origin main" }),
  line(recent(29), "s-1", "/home/dev/shop", "t2", "Bash", { command: "git push --force origin main" }),
  line(recent(28), "s-1", "/home/dev/shop", "t3", "Edit", { file_path: "/home/dev/shop/src/cart.ts" }),
].join("\n"));
writeFileSync(join(dir, "-home-dev-shop", "s-1", "subagents", "agent-1.jsonl"), line(recent(27), "s-1", "/home/dev/shop", "t4", "Bash", { command: "git push --force-with-lease origin main" }));
writeFileSync(join(dir, "-home-dev-platform", "s-2.jsonl"), line(recent(5), "s-2", "/home/dev/platform", "t5", "Bash", { command: "terraform destroy -auto-approve" }));
const old = join(dir, "-home-dev-platform", "s-old.jsonl");
writeFileSync(old, line(new Date(Date.now() - 30 * 86_400_000).toISOString(), "s-old", "/home/dev/platform", "t6", "Bash", { command: "git push -f" }));
utimesSync(old, new Date(Date.now() - 30 * 86_400_000), new Date(Date.now() - 30 * 86_400_000));
console.log(`   ${dir}`);

step(2, "node src/cli.ts audit-sessions --dir <dir> --since 7d");
const full = spawnSync(process.execPath, [cli, "audit-sessions", "--dir", dir, "--since", "7d"], { encoding: "utf8" });
console.log(full.stdout.split("\n").map((l) => `   ${l}`).join("\n"));
if (full.status !== 0 || !full.stdout.includes("Read 5 tool calls in 2 sessions") || !full.stdout.includes("would have denied 2 calls")) throw new Error("expected 5 calls, 2 denied");
if (full.stdout.includes("git push -f\n")) throw new Error("the month-old transcript is outside the window");

step(3, "--counts: the numbers per rule, with nothing from the transcripts, safe to share");
const counts = spawnSync(process.execPath, [cli, "audit-sessions", "--dir", dir, "--since", "7d", "--counts"], { encoding: "utf8" });
console.log(counts.stdout.split("\n").map((l) => `   ${l}`).join("\n"));
if (/origin main|shop|platform\b|s-1|s-2/.test(counts.stdout.replace(/PREVIEW:.*$/m, ""))) throw new Error("--counts leaked transcript content");

console.log("\nOK");

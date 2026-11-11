// audit-sessions is meant to be run before anyone installs anything: it reads a developer's past Claude Code
// transcripts and shows what the policy would have denied. That only works if it is safe to run on a whim, so it must
// write nothing and send nothing, and the counts it prints must be right: a missed force push or a double-counted call
// would misstate what the hooks would catch. It must also never present a transcript as evidence.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { auditSessions, defaultTranscriptDir, formatSessionAudit, parseSince } from "../src/session-audit.ts";
import { readFileSync } from "node:fs";

const TEMPLATE = readFileSync(resolve(import.meta.dirname, "..", "templates", "claude-code.cedar"), "utf8");
const NOW = new Date("2026-11-11T12:00:00Z");

const call = (ts: string, session: string, cwd: string, tools: { id: string; name: string; input: unknown }[]) =>
  JSON.stringify({ type: "assistant", timestamp: ts, sessionId: session, cwd, message: { role: "assistant", content: [{ type: "text", text: "ok" }, ...tools.map((t) => ({ type: "tool_use", ...t }))] } });

/** two projects, a subagent transcript in a nested folder, noise lines, a repeated call, and one stale transcript */
function fixture(): string {
  const dir = join(mkdtempSync(join(tmpdir(), "audit-")), "projects");
  const a = join(dir, "-home-dev-shop");
  const b = join(dir, "-home-dev-platformx");
  mkdirSync(join(a, "s-1", "subagents"), { recursive: true });
  mkdirSync(b, { recursive: true });
  writeFileSync(join(a, "s-1.jsonl"), [
    JSON.stringify({ type: "user", timestamp: "2026-11-10T09:00:00Z", sessionId: "s-1", message: { role: "user", content: "push it" } }),
    call("2026-11-10T09:00:01Z", "s-1", "/home/dev/shop", [{ id: "t1", name: "Bash", input: { command: "ls -la" } }]),
    call("2026-11-10T09:00:02Z", "s-1", "/home/dev/shop", [{ id: "t2", name: "Bash", input: { command: "git push --force origin main" } }]),
    // the same tool_use written again, as a compacted transcript can: counted once
    call("2026-11-10T09:00:02Z", "s-1", "/home/dev/shop", [{ id: "t2", name: "Bash", input: { command: "git push --force origin main" } }]),
    call("2026-11-10T09:00:03Z", "s-1", "/home/dev/shop", [{ id: "t3", name: "Read", input: { file_path: "/home/dev/shop/README.md" } }]),
    '{"type":"assistant","timestamp":"2026-11-10T09:00:04Z","mess', // a line still being written
  ].join("\n"));
  writeFileSync(join(a, "s-1", "subagents", "agent-1.jsonl"), call("2026-11-10T09:05:00Z", "s-1", "/home/dev/shop", [{ id: "t4", name: "Bash", input: { command: "git push --force-with-lease origin main" } }]));
  writeFileSync(join(b, "s-2.jsonl"), [
    call("2026-11-01T08:00:00Z", "s-2", "/home/dev/platformx", [{ id: "t5", name: "Bash", input: { command: "terraform destroy" } }]), // before the window
    call("2026-11-09T08:00:00Z", "s-2", "/home/dev/platformx", [{ id: "t6", name: "Bash", input: { command: "terraform destroy -auto-approve" } }, { id: "t7", name: "mcp__browser__click", input: { x: 10.5, y: 3 } }]),
  ].join("\n"));
  // a transcript last written a month ago is skipped without being read
  writeFileSync(join(b, "s-old.jsonl"), call("2026-10-01T08:00:00Z", "s-old", "/home/dev/platformx", [{ id: "t8", name: "Bash", input: { command: "git push -f" } }]));
  utimesSync(join(b, "s-old.jsonl"), new Date("2026-10-01T08:00:00Z"), new Date("2026-10-01T08:00:00Z"));
  return dir;
}

describe("auditSessions", () => {
  it("counts each tool call once across projects and subagents, and lists the ones the policy would have denied with the rule and its reason", () => {
    const dir = fixture();
    const a = auditSessions({ dir, policyText: TEMPLATE, policyName: "the template", since: parseSince("7d", NOW) });
    expect(a).toMatchObject({ transcripts: 3, sessions: 2, calls: 6, unreadable: 1 });
    expect(a.denied.map((c) => [c.tool, c.target, c.project])).toEqual([
      ["Bash", "terraform destroy -auto-approve", "platformx"],
      ["Bash", "git push --force origin main", "shop"],
    ]);
    expect(a.denied[1]!.reasons[0]).toContain("force push rewrites shared history");
    expect(a.denied[1]!.rules[0]).toContain('like "*git push --force *"');
    // --force-with-lease is allowed by the template, and the call before the window is not read
    expect(a.denied.some((c) => c.target.includes("with-lease") || c.timestamp.startsWith("2026-11-01"))).toBe(false);
    // a float is a value Cedar cannot hold: listed apart, not counted as a rule's denial
    expect(a.unevaluated.map((u) => u.tool)).toEqual(["mcp__browser__click"]);
  });

  it("counts a call as denied when a rule matched it, even when another rule errored on the same call", () => {
    // a force push matches the first rule; the second rule reads an attribute a Bash call does not have and errors
    const policy = 'permit(principal, action, resource);\n@reason("no force push")\nforbid(principal, action == Action::"Bash", resource) when { context.args.command like "*git push --force*" };\n@reason("no charges")\nforbid(principal, action, resource) when { context.args.amount > 0 };\n';
    const dir = join(mkdtempSync(join(tmpdir(), "audit-err-")), "projects");
    mkdirSync(join(dir, "-p"), { recursive: true });
    writeFileSync(join(dir, "-p", "s.jsonl"), [
      call("2026-11-10T09:00:00Z", "s", "/p", [{ id: "a", name: "Bash", input: { command: "git push --force origin main" } }]),
      call("2026-11-10T09:00:01Z", "s", "/p", [{ id: "b", name: "Bash", input: { command: "ls" } }]),
    ].join("\n"));
    const a = auditSessions({ dir, policyText: policy, policyName: "p" });
    expect(a.denied.map((c) => [c.target, c.reasons])).toEqual([["git push --force origin main", ["no force push"]]]);
    // the call no rule matched, where the second rule errored, is the one listed apart
    expect(a.unevaluated.map((u) => u.target)).toEqual(["ls"]);
    expect(formatSessionAudit(a, { counts: true })).toMatch(/^\s+1\s+policy\d+\s+no force push$/m);
  });

  it("refuses a policy that does not parse, instead of reporting that it denied nothing", () => {
    // a parse error denies every call, which would read as "this policy catches nothing in my work"
    const broken = 'permit(principal, action, resource)\nforbid(principal, action == Action::"Bash", resource);\n';
    expect(() => auditSessions({ dir: fixture(), policyText: broken, policyName: "draft.cedar" })).toThrow(/draft\.cedar does not parse:/);
  });

  it("labels a call that no permit matched under a default-deny policy, rather than printing an empty rule", () => {
    const readsOnly = 'permit(principal, action == Action::"Read", resource);\n';
    const a = auditSessions({ dir: fixture(), policyText: readsOnly, policyName: "reads-only.cedar", since: parseSince("7d", NOW) });
    expect(a.denied.length).toBeGreaterThan(0);
    expect(a.denied.every((c) => c.policyIds.length === 0)).toBe(true);
    expect(formatSessionAudit(a)).toContain("rule:    no permit matched (default deny)");
    expect(formatSessionAudit(a, { counts: true })).toMatch(new RegExp(`^\\s+${a.denied.length}\\s+no permit matched \\(default deny\\)$`, "m"));
  });

  it("names the policy by its file name in --counts, so the shared output carries no home path", () => {
    const a = auditSessions({ dir: fixture(), policyText: TEMPLATE, policyName: "/home/dev/policies/team.cedar", since: parseSince("7d", NOW) });
    expect(formatSessionAudit(a, { counts: true })).toContain("Policy: team.cedar.");
    expect(formatSessionAudit(a, { counts: true })).not.toContain("/home/dev");
    expect(formatSessionAudit(a)).toContain("Policy: /home/dev/policies/team.cedar.");
  });

  it("reads every transcript with --since all, including the stale one", () => {
    const a = auditSessions({ dir: fixture(), policyText: TEMPLATE, policyName: "the template" });
    expect(a).toMatchObject({ transcripts: 4, calls: 8 });
    expect(a.denied.map((c) => c.target)).toEqual(["git push -f", "terraform destroy", "terraform destroy -auto-approve", "git push --force origin main"]);
  });

  it("says it is a preview, not evidence, and --counts leaves out every command, path, session, and project", () => {
    const a = auditSessions({ dir: fixture(), policyText: TEMPLATE, policyName: "the template", since: parseSince("7d", NOW) });
    const full = formatSessionAudit(a);
    expect(full).toContain("The policy would have denied 2 calls:");
    expect(full).toContain("Bash: git push --force origin main");
    expect(full).toContain("PREVIEW: these are the agent host's own transcripts, not receipts");
    expect(full).toContain("The hook denies a call like this");
    const counts = formatSessionAudit(a, { counts: true });
    // only what came from the transcripts is private; the rule's @reason comes from the policy and stays
    for (const secret of ["origin main", "-auto-approve", "shop", "platformx", "s-1", "s-2", "README", "/home/dev", "mcp__browser"]) expect(counts).not.toContain(secret);
    expect(counts).toMatch(/^\s+1\s+policy\d+\s+force push rewrites shared history/m);
    expect(counts).toContain("PREVIEW:");
  });

  it("reads --since as a span or a date, and refuses anything else", () => {
    expect(parseSince("7d", NOW).toISOString()).toBe("2026-11-04T12:00:00.000Z");
    expect(parseSince("24h", NOW).toISOString()).toBe("2026-11-10T12:00:00.000Z");
    expect(parseSince("30m", NOW).toISOString()).toBe("2026-11-11T11:30:00.000Z");
    expect(parseSince("2026-11-01", NOW).toISOString()).toBe("2026-11-01T00:00:00.000Z");
    expect(() => parseSince("last week", NOW)).toThrow(/--since takes 7d, 24h, 30m, or a date/);
  });

  it("is importable from the package root, as the reference documents", async () => {
    const pkg = await import("../src/index.ts");
    for (const name of ["auditSessions", "formatSessionAudit", "parseSince", "defaultTranscriptDir"]) expect(typeof (pkg as Record<string, unknown>)[name]).toBe("function");
  });

  it("finds Claude Code's transcripts where Claude Code keeps them, and says so when there are none", () => {
    expect(defaultTranscriptDir({ CLAUDE_CONFIG_DIR: "/cfg" })).toBe("/cfg/projects");
    expect(defaultTranscriptDir({})).toMatch(/\.claude\/projects$/);
    expect(() => auditSessions({ dir: "/nonexistent/projects", policyText: TEMPLATE, policyName: "x" })).toThrow(/no Claude Code transcripts at \/nonexistent\/projects/);
  });
});

describe("agent-custody audit-sessions", () => {
  const cli = resolve(import.meta.dirname, "..", "src", "cli.ts");
  const snapshot = (d: string): string[] => readdirSync(d, { recursive: true, withFileTypes: true }).map((e) => `${join(e.parentPath, e.name)}:${e.isFile() ? statSync(join(e.parentPath, e.name)).mtimeMs : "d"}`).sort();

  it("writes nothing and opens no connection: a preload makes every write, fetch, and socket throw, and the run still succeeds", () => {
    const dir = fixture();
    const home = resolve(dir, "..");
    const guard = join(mkdtempSync(join(tmpdir(), "guard-")), "guard.mjs");
    writeFileSync(guard, `
      import fs from "node:fs"; import net from "node:net";
      const no = (what) => () => { throw new Error("audit-sessions must not " + what); };
      for (const f of ["writeFileSync", "appendFileSync", "mkdirSync", "rmSync", "renameSync", "copyFileSync", "openSync"]) {
        const real = fs[f];
        fs[f] = f === "openSync" ? (p, flags, ...r) => (flags && flags !== "r" ? no("open a file for writing")() : real(p, flags, ...r)) : no(f);
      }
      globalThis.fetch = no("fetch");
      net.Socket.prototype.connect = no("open a socket");
    `);
    const before = snapshot(home);
    const r = spawnSync(process.execPath, ["--import", guard, cli, "audit-sessions", "--dir", dir, "--since", "all"], { encoding: "utf8", env: { ...process.env, HOME: home } });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("The policy would have denied 4 calls:");
    expect(r.stdout).toContain("Policy: the init claude-code template.");
    expect(snapshot(home)).toEqual(before);
  });

  it("gives --json, honours --policy, and refuses a Rego policy", () => {
    const dir = fixture();
    const pol = join(resolve(dir, ".."), "deny-read.cedar");
    writeFileSync(pol, 'permit(principal, action, resource);\n@reason("no reads")\nforbid(principal, action == Action::"Read", resource);\n');
    const r = spawnSync(process.execPath, [cli, "audit-sessions", "--dir", dir, "--since", "all", "--policy", pol, "--json"], { encoding: "utf8" });
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout) as { denied: { tool: string; reasons: string[] }[]; policy: string };
    expect(j.policy).toBe(pol);
    expect(j.denied.map((c) => [c.tool, c.reasons[0]])).toEqual([["Read", "no reads"]]);
    writeFileSync(join(resolve(dir, ".."), "broken.cedar"), "permit(principal, action, resource)\n");
    const broken = spawnSync(process.execPath, [cli, "audit-sessions", "--dir", dir, "--since", "all", "--policy", join(resolve(dir, ".."), "broken.cedar"), "--counts"], { encoding: "utf8" });
    expect(broken.status).toBe(1);
    expect(broken.stderr).toContain("broken.cedar does not parse");
    expect(broken.stdout).toBe("");
    const rego = spawnSync(process.execPath, [cli, "audit-sessions", "--dir", dir, "--policy", "p.rego"], { encoding: "utf8" });
    expect(rego.status).not.toBe(0);
    expect(rego.stderr).toContain("audit-sessions reads a Cedar policy");
  });
});

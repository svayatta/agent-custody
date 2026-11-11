/**
 * `agent-custody audit-sessions`: which of a developer's past Claude Code tool calls a Cedar policy would have denied,
 * read from the session transcripts Claude Code keeps on the machine. It installs nothing, writes nothing, and makes no
 * network request, so it can run before anyone decides to install the hooks.
 *
 * A transcript is the agent host's own account and anyone with the files can edit it: the result is a preview of what
 * the policy would catch, not evidence. Receipts come from the hooks that `init claude-code` installs.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { ruleTexts, targetOf } from "./deny-report.ts";
import { evaluate, policyDigest, policyParseErrors, policyReasons, policyRules } from "./policy.ts";

export interface AuditedCall {
  session: string;
  /** the last part of the working directory the session ran in */
  project: string;
  timestamp: string;
  tool: string;
  target: string;
  policyIds: string[];
  reasons: string[];
  rules: string[];
}

export interface SessionAudit {
  dir: string;
  since: string | null;
  policy: string;
  policyDigest: string;
  transcripts: number;
  sessions: number;
  calls: number;
  denied: AuditedCall[];
  /** calls that no forbid matched but on which a rule errored (a value Cedar cannot hold, an attribute the call lacks); the hook denies these, and they are listed apart because no rule decided them. A call a forbid matched is in `denied` even when another rule errored on it */
  unevaluated: { tool: string; target: string; errors: string[] }[];
  /** lines that were not JSON; a transcript being written can end in a partial line */
  unreadable: number;
}

export interface SessionAuditOptions {
  /** the directory of Claude Code's per-project transcripts */
  dir: string;
  policyText: string;
  /** shown in the result; the policy file's path, or "the init claude-code template" */
  policyName: string;
  since?: Date;
}

/** Claude Code's transcripts: `$CLAUDE_CONFIG_DIR/projects` when that is set, else `~/.claude/projects`. */
export function defaultTranscriptDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.CLAUDE_CONFIG_DIR ? join(env.CLAUDE_CONFIG_DIR, "projects") : join(homedir(), ".claude", "projects");
}

/** `7d`, `24h`, `30m`, or a date or date-time that Date can read. */
export function parseSince(text: string, now = new Date()): Date {
  const rel = /^(\d+)([dhm])$/.exec(text.trim());
  if (rel) return new Date(now.getTime() - Number(rel[1]) * { d: 86_400_000, h: 3_600_000, m: 60_000 }[rel[2] as "d" | "h" | "m"]);
  const t = Date.parse(text);
  if (Number.isNaN(t)) throw new Error(`--since takes 7d, 24h, 30m, or a date; got "${text}"`);
  return new Date(t);
}

function transcriptsUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && e.name.endsWith(".jsonl")) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

export function auditSessions(o: SessionAuditOptions): SessionAudit {
  if (!existsSync(o.dir)) throw new Error(`no Claude Code transcripts at ${o.dir}; give another directory with --dir`);
  // a policy that does not parse denies every call with the parse error, which would read as "it catches nothing"
  const parseErrors = policyParseErrors(o.policyText);
  if (parseErrors.length) throw new Error(`${o.policyName} does not parse: ${parseErrors.join("; ")}`);
  const rules = policyRules(o.policyText);
  const reasons = policyReasons(o.policyText);
  const since = o.since?.getTime();
  const result: SessionAudit = { dir: o.dir, since: o.since?.toISOString() ?? null, policy: o.policyName, policyDigest: policyDigest(o.policyText), transcripts: 0, sessions: 0, calls: 0, denied: [], unevaluated: [], unreadable: 0 };
  const sessions = new Set<string>();
  const seen = new Set<string>();
  for (const file of transcriptsUnder(o.dir)) {
    // a transcript last written before the window holds nothing inside it
    if (since !== undefined && statSync(file).mtimeMs < since) continue;
    result.transcripts++;
    for (const line of readFileSync(file, "utf8").split("\n")) {
      if (!line.trim()) continue;
      let entry: Record<string, unknown>;
      try {
        entry = JSON.parse(line) as Record<string, unknown>;
      } catch {
        result.unreadable++;
        continue;
      }
      if (entry.type !== "assistant") continue;
      const timestamp = typeof entry.timestamp === "string" ? entry.timestamp : "";
      if (since !== undefined && !(Date.parse(timestamp) >= since)) continue;
      const content = (entry.message as { content?: unknown } | undefined)?.content;
      if (!Array.isArray(content)) continue;
      for (const c of content as Record<string, unknown>[]) {
        if (c?.type !== "tool_use" || typeof c.name !== "string") continue;
        const id = typeof c.id === "string" ? c.id : `${file}:${timestamp}:${c.name}`;
        if (seen.has(id)) continue;
        seen.add(id);
        const session = typeof entry.sessionId === "string" ? entry.sessionId : basename(file, ".jsonl");
        sessions.add(session);
        result.calls++;
        const args = c.input && typeof c.input === "object" ? (c.input as Record<string, unknown>) : {};
        const d = evaluate(o.policyText, { agentId: "claude-code", tool: c.name, context: { args, facts: {} } });
        // A rule error turns the decision into deny but keeps Cedar's own reasons, which for an allowed call are permits.
        // So a call is a rule's denial when a forbid matched it, whatever else errored, and unevaluated otherwise.
        const forbids = d.reasons.filter((id) => ruleTexts([id], rules, reasons).rules[0]?.startsWith("forbid"));
        if (d.errors.length && !forbids.length) {
          result.unevaluated.push({ tool: c.name, target: targetOf(args), errors: d.errors });
          continue;
        }
        if (d.decision !== "deny") continue;
        const ids = d.errors.length ? forbids : d.reasons;
        result.denied.push({ session, project: typeof entry.cwd === "string" ? basename(entry.cwd) : "", timestamp, tool: c.name, target: targetOf(args), policyIds: ids, ...ruleTexts(ids, rules, reasons) });
      }
    }
  }
  result.sessions = sessions.size;
  result.denied.sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  return result;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
const clip = (s: string, n = 160) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const NO_PERMIT = "no permit matched (default deny)";
const PREVIEW = "PREVIEW: these are the agent host's own transcripts, not receipts. Nothing here is signed or logged, and a transcript can be edited. For a receipt of each call, signed and logged, run: agent-custody init claude-code";

/** The audit as text. `counts` leaves out every command, path, session, and project, so the output can be shared. */
export function formatSessionAudit(a: SessionAudit, opts: { counts?: boolean } = {}): string {
  const window = a.since ? ` since ${a.since}` : "";
  // --counts is the output people share: the policy's file name, not the path to it
  const policy = opts.counts && a.policy.includes("/") ? basename(a.policy) : a.policy;
  const lines = [`Read ${plural(a.calls, "tool call")} in ${plural(a.sessions, "session")}${window}.`, `Policy: ${policy}.`, ""];
  lines.push(`The policy would have denied ${plural(a.denied.length, "call")}${a.denied.length ? ":" : "."}`);
  if (opts.counts) {
    const byRule = new Map<string, { n: number; reason: string }>();
    for (const c of a.denied) {
      const key = c.policyIds.join(", ");
      const r = byRule.get(key) ?? { n: 0, reason: c.reasons.join("; ") };
      r.n++;
      byRule.set(key, r);
    }
    for (const [ids, r] of [...byRule].sort((x, y) => y[1].n - x[1].n)) lines.push(`  ${String(r.n).padStart(4)}  ${ids || NO_PERMIT}${r.reason ? `  ${r.reason}` : ""}`);
  } else {
    for (const c of a.denied) {
      lines.push("", `  ${c.tool}: ${clip(c.target)}`);
      if (c.reasons.length) lines.push(`    reason:  ${c.reasons.join("; ")}`);
      lines.push(`    rule:    ${!c.policyIds.length ? NO_PERMIT : c.rules.length ? `${clip(c.rules.join(" | "))} [${c.policyIds.join(", ")}]` : c.policyIds.join(", ")}`);
      lines.push(`    when:    ${c.timestamp}  session ${c.session.slice(0, 8)}${c.project ? `  in ${c.project}` : ""}`);
    }
  }
  if (a.unevaluated.length) {
    lines.push("", `${plural(a.unevaluated.length, "more call")} matched no forbid rule, but a rule errored on ${a.unevaluated.length === 1 ? "it" : "them"}, for example on a value Cedar cannot hold (a float) or an attribute the call does not have. The hook denies a call like this; no rule decided it, so it is listed apart:`);
    if (!opts.counts) for (const u of a.unevaluated) lines.push(`  ${u.tool}: ${clip(u.target, 80)}  (${clip(u.errors[0] ?? "", 80)})`);
  }
  if (a.unreadable) lines.push(`${plural(a.unreadable, "transcript line")} could not be read.`);
  lines.push("", PREVIEW);
  return lines.join("\n");
}

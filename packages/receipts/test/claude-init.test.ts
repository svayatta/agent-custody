// `init claude-code` and `report`. Every test uses a temporary home and a temporary working directory, and never the
// real ~/.config/agent-custody or ~/.claude. The directory name holds spaces, so the quoting of the hook command is tested too.
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { buildSdkFixture } from "../scripts/fixture.ts";
import { initClaudeCode, type ClaudeInitOptions } from "../src/claude-init.ts";
import { loadSdkConfig } from "../src/config.ts";
import { denyReport } from "../src/deny-report.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { handleHookEvent } from "../src/sdk/claude.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"];
const root = mkdtempSync(join(tmpdir(), "claude init "));
afterAll(() => rmSync(root, { recursive: true, force: true }));

let home: string;
let cwd: string;
let n = 0;
beforeEach(() => {
  const base = join(root, String(n++));
  home = join(base, "home");
  cwd = join(base, "project");
  mkdirSync(home, { recursive: true });
  mkdirSync(cwd, { recursive: true });
});

const init = (o: Partial<ClaudeInitOptions> = {}) => {
  const lines: string[] = [];
  const result = initClaudeCode({ cliPath: cli, home, cwd, print: (l) => lines.push(l), ...o });
  return { ...result, text: lines.join("\n") };
};
const cliInit = (...args: string[]) => spawnSync(process.execPath, [cli, "init", "claude-code", ...args], { cwd, encoding: "utf8", env: { ...process.env, HOME: home }, timeout: 30_000 });
const readJson = (file: string) => JSON.parse(readFileSync(file, "utf8"));
const settingsFile = () => join(cwd, ".claude", "settings.local.json");
const commandsOf = (settings: any, event: string): string[] => settings.hooks[event].flatMap((e: any) => e.hooks.map((h: any) => h.command));

/** What Claude Code does for one call in observe mode: the hook runs at PreToolUse and again at PostToolUse. */
async function runCalls(configFile: string, commands: string[]) {
  const issuer = createSdkIssuer(loadSdkConfig(configFile));
  for (const command of commands) {
    const input = { session_id: "s1", tool_name: "Bash", tool_input: { command } };
    expect(await handleHookEvent(issuer, { hook_event_name: "PreToolUse", ...input })).toEqual({});
    await handleHookEvent(issuer, { hook_event_name: "PostToolUse", ...input, tool_response: { stdout: "" } });
  }
}

describe("init claude-code", () => {
  it("makes the key, an observe-mode config that loads, the starter policy, and the three hooks, and touches nothing in the real home", () => {
    const realHome = process.env.HOME;
    const r = init();
    const dir = join(home, ".config", "agent-custody");
    expect(r.dir).toBe(dir);
    expect(statSync(join(dir, "keys", "claude-code.key")).mode & 0o077).toBe(0);
    expect(existsSync(join(dir, "keys", "claude-code.pub"))).toBe(true);
    expect(readFileSync(join(dir, "policy.cedar"), "utf8")).toContain("terraform destroy");
    expect(readJson(join(dir, "sdk.json"))).toMatchObject({ agentId: "claude-code", framework: "claude-code", mode: "observe", receiptsDir: "receipts", logFile: "log.jsonl", identity: { keyFile: "keys/claude-code.key" } });
    expect(loadSdkConfig(join(dir, "sdk.json")).log).toBeUndefined();
    expect(existsSync(join(dir, "receipts"))).toBe(true);
    const settings = readJson(settingsFile());
    for (const event of EVENTS) {
      expect(settings.hooks[event]).toEqual([{ matcher: "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*", hooks: [{ type: "command", command: r.hookCommand }] }]);
    }
    expect(r.hookCommand).toContain(process.execPath);
    expect(r.hookCommand).toContain(`${cli} hook --config '${join(dir, "sdk.json")}'`);
    expect(r.text).toMatch(/Next:[\s\S]*Start a Claude Code session[\s\S]*report --config/);
    expect(process.env.HOME).toBe(realHome);
  });

  it("runs from the command line with HOME set, and the hook command it wrote runs in a shell", () => {
    const run = cliInit();
    expect(run.status, run.stderr).toBe(0);
    const settings = readJson(settingsFile());
    const hook = spawnSync(commandsOf(settings, "PreToolUse")[0]!, { shell: true, input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "git push --force" } }), encoding: "utf8", timeout: 30_000 });
    expect(hook.status, hook.stderr).toBe(0);
    expect(hook.stdout.trim()).toBe("{}");
  });

  it("merges into an existing settings file: other keys and other hooks stay", () => {
    mkdirSync(join(cwd, ".claude"));
    const other = { matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] };
    writeFileSync(settingsFile(), JSON.stringify({ permissions: { allow: ["Bash(ls)"] }, hooks: { PreToolUse: [other], Stop: [{ hooks: [{ type: "command", command: "echo stop" }] }] } }));
    const r = init();
    const settings = readJson(settingsFile());
    expect(settings.permissions).toEqual({ allow: ["Bash(ls)"] });
    expect(settings.hooks.Stop).toEqual([{ hooks: [{ type: "command", command: "echo stop" }] }]);
    expect(settings.hooks.PreToolUse[0]).toEqual(other);
    expect(commandsOf(settings, "PreToolUse")).toEqual(["echo mine", r.hookCommand]);
    expect(commandsOf(settings, "PostToolUse")).toEqual([r.hookCommand]);
  });

  it("run two times: no second hook, and the key, the config, and the policy keep their bytes", () => {
    const first = init();
    const dir = first.dir;
    const files = ["keys/claude-code.key", "keys/claude-code.pub", "sdk.json", "policy.cedar"].map((f) => join(dir, f));
    writeFileSync(join(dir, "policy.cedar"), `${readFileSync(join(dir, "policy.cedar"), "utf8")}// my own edit\n`);
    const before = files.map((f) => readFileSync(f, "utf8"));
    const settingsBefore = readFileSync(settingsFile(), "utf8");
    const second = init();
    expect(files.map((f) => readFileSync(f, "utf8"))).toEqual(before);
    expect(readFileSync(settingsFile(), "utf8")).toBe(settingsBefore);
    for (const event of EVENTS) expect(commandsOf(readJson(settingsFile()), event)).toEqual([second.hookCommand]);
    expect(second.text).toContain("found already registered");
  });

  it("a hook of ours with an old path is updated in place, and the npx cache gets a warning", () => {
    init({ cliPath: join(home, ".npm", "_npx", "abc", "node_modules", "@agent-custody", "receipts", "dist", "cli.js") });
    const stale = init({ cliPath: join(home, ".npm", "_npx", "abc", "node_modules", "@agent-custody", "receipts", "dist", "cli.js") });
    expect(stale.text).toMatch(/npx cache[\s\S]*install the package globally/i);
    const fresh = init({ cliPath: join(home, "global", "dist", "cli.js") });
    expect(fresh.text).not.toContain("npx cache");
    for (const event of EVENTS) expect(commandsOf(readJson(settingsFile()), event)).toEqual([fresh.hookCommand]);
    expect(fresh.text).toContain("updated PreToolUse");
  });

  it("refuses a settings file that is not valid JSON, and changes nothing", () => {
    mkdirSync(join(cwd, ".claude"));
    writeFileSync(settingsFile(), '{ "hooks": { oops');
    const run = cliInit();
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("not valid JSON");
    expect(readFileSync(settingsFile(), "utf8")).toBe('{ "hooks": { oops');
    expect(existsSync(join(home, ".config"))).toBe(false);
  });

  it("--user writes the hooks to ~/.claude/settings.json, and --enforce leaves out the observe mode", () => {
    const r = init({ user: true, enforce: true });
    expect(r.settingsFile).toBe(join(home, ".claude", "settings.json"));
    expect(commandsOf(readJson(r.settingsFile), "PostToolUse")).toEqual([r.hookCommand]);
    expect(existsSync(settingsFile())).toBe(false);
    expect(readJson(r.configFile).mode).toBeUndefined();
  });

  it("--log-url adds a log block with the token variable name, and takes no token value", () => {
    const logKey = join(root, "log.pub");
    copyFileSync(buildSdkFixture(join(root, "fx"), undefined, "t").appPub, logKey);
    const r = init({ logUrl: "https://log.example.com/t/me/", logId: "me", logTokenEnv: "MY_LOG_TOKEN", logKey });
    const config = readJson(r.configFile);
    expect(config.log).toEqual({ url: "https://log.example.com/t/me/", tokenEnv: "MY_LOG_TOKEN", hashOnly: true, keys: ["log.pub"], logId: "me", timeoutMs: 3000 });
    expect(config.logFile).toBeUndefined();
    expect(loadSdkConfig(r.configFile).log?.keys).toEqual([join(r.dir, "log.pub")]);
    expect(() => init({ dir: join(home, "other"), logUrl: "https://log.example.com/", logTokenEnv: "sk_live_abc123" })).toThrow(/NAME of an environment variable/);
    expect(existsSync(join(home, "other"))).toBe(false);
  });
});

describe("the starter policy", () => {
  it("denies the destructive commands, in both cases of drop database, and allows ordinary work", () => {
    const { configFile } = init();
    const issuer = createSdkIssuer(loadSdkConfig(configFile));
    const decide = (command: string) => issuer.decide({ tool: "Bash", args: { command } })!.decision;
    for (const bad of ["git push --force origin main", "git push -f origin main", "git push origin main -f", "rm -rf /", "rm -rf / --no-preserve-root", "rm -rf /*", "rm -rf ~", "rm -rf ~/", "rm -rf ~/*", "terraform destroy -auto-approve", "psql -c 'drop database prod'", "psql -c 'DROP DATABASE prod'"]) {
      expect(decide(bad), bad).toBe("deny");
    }
    for (const fine of ["ls -la", "git push origin main", "rm -rf node_modules", "rm -rf /tmp/build", "rm -rf ~/projects/app/dist", "terraform plan"]) {
      expect(decide(fine), fine).toBe("allow");
    }
  });
});

describe("report", () => {
  it("counts the calls that observe mode let through and the policy would have denied, with the tool, the command, the rule, and the receipt id", async () => {
    const { configFile } = init();
    await runCalls(configFile, ["ls", "git push --force origin main", "terraform destroy"]);
    const report = denyReport(configFile);
    expect(report).toMatchObject({ observe: true, verified: 3, denied: [], unverified: [] });
    expect(report.wouldDeny.map((c) => [c.tool, c.target])).toEqual([["Bash", "git push --force origin main"], ["Bash", "terraform destroy"]]);
    expect(report.wouldDeny[0]!.rules[0]).toContain("git push*--force");
    const ids = readdirSync(join(home, ".config", "agent-custody", "receipts")).map((f) => f.replace(".json", ""));
    expect(ids).toContain(report.wouldDeny[0]!.receiptId);
    const run = spawnSync(process.execPath, [cli, "report", "--config", configFile], { encoding: "utf8", timeout: 30_000 });
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("would have denied 2 calls");
    expect(run.stdout).toContain(report.wouldDeny[1]!.receiptId);
    expect(run.stdout).toContain('remove the "mode": "observe" line');
  });

  it("counts a receipt that does not verify apart, and exits 1", async () => {
    const { configFile, dir } = init();
    await runCalls(configFile, ["git push --force origin main"]);
    const stranger = buildSdkFixture(join(root, "stranger"), undefined, "t");
    const strangerIssuer = createSdkIssuer(loadSdkConfig(stranger.configFile));
    await strangerIssuer.record({ tool: "Bash", args: { command: "terraform destroy" } }, { status: "executed", result: null }, strangerIssuer.decide({ tool: "Bash", args: { command: "terraform destroy" } }));
    const foreign = readdirSync(stranger.receiptsDir).find((f) => f.endsWith(".json"))!;
    copyFileSync(join(stranger.receiptsDir, foreign), join(dir, "receipts", foreign));
    writeFileSync(join(dir, "receipts", "broken.json"), "{ not json");
    const report = denyReport(configFile);
    expect(report.wouldDeny).toHaveLength(1);
    expect(report.unverified.map((u) => u.file).sort()).toEqual([foreign, "broken.json"].sort());
    const run = spawnSync(process.execPath, [cli, "report", "--config", configFile], { encoding: "utf8", timeout: 30_000 });
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("would have denied 1 call");
    expect(run.stdout).toContain("2 receipts did not verify");
  });
});

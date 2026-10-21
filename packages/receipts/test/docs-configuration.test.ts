// docs/configuration.md: the example gateway config must parse as a gateway config, every Cedar block must parse, and the
// policy of the worked example must do what the prose says for each of the two agents.
import { readFileSync } from "node:fs";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { describe, expect, it } from "vitest";
import { GatewayConfigSchema } from "../src/config.ts";
import { evaluate } from "../src/policy.ts";

const doc = readFileSync(new URL("../docs/configuration.md", import.meta.url), "utf8");
const fragments = [...doc.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => m[1]!);
// the full config starts with a brace; the others are single keys shown in the prose
const json = fragments.filter((b) => b.trimStart().startsWith("{"));
const cedarBlocks = [...doc.matchAll(/```cedar\n([\s\S]*?)```/g)].map((m) => m[1]!);

const req = (agentId: string, tool: string, args: Record<string, unknown>, facts: Record<string, unknown> = {}) => ({
  agentId,
  tool,
  context: { args, facts, grant: { principal: "acme-support", scopes: [tool] } },
});
// the gateway hands the policy the value each lookup returned
const verified = { customer: { verified: true } };

describe("docs/configuration.md", () => {
  it("has one full gateway config and one policy, so the examples below are the ones the prose means", () => {
    expect(json.length).toBe(1);
    expect(fragments.length).toBeGreaterThan(1);
    expect(cedarBlocks.length).toBe(1);
  });

  it("the example config is a valid gateway config with four kinds of upstream, a fact, and a pinned remote log", () => {
    const cfg = GatewayConfigSchema.parse(JSON.parse(json[0]!));
    const kinds = (cfg.upstreams ?? []).map((u) => ("rest" in u ? "rest" : "a2a" in u ? "a2a" : "command" in u ? "stdio" : "http"));
    expect(kinds.sort()).toEqual(["a2a", "http", "rest", "stdio"]);
    expect(cfg.facts[0]?.forTools).toEqual(["billing.refund"]);
    expect(cfg.log?.keys?.length).toBeGreaterThan(0);
    expect(cfg.precommit).toContain("billing.refund");
  });

  it("every tool name the config mentions is one the REST and A2A upstreams define, or the prose says the server defines", () => {
    const cfg = GatewayConfigSchema.parse(JSON.parse(json[0]!));
    const rest = (cfg.upstreams ?? []).flatMap((u) => ("rest" in u ? u.rest.tools.map((t) => t.name) : []));
    expect(rest).toEqual(expect.arrayContaining(["customer.lookup", "billing.refund"]));
    expect(cfg.facts[0]?.tool).toBe("customer.lookup");
    expect(new Set(rest).size).toBe(rest.length);
  });

  it("the policy parses", () => {
    expect(cedar.checkParsePolicySet({ staticPolicies: cedarBlocks[0]! }).type).toBe("success");
  });

  it("the support agent may refund up to the cap for a verified customer, and not beyond it, unverified, or without the fact", () => {
    const p = cedarBlocks[0]!;
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: 100000 }, verified)).decision).toBe("allow");
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: 100001 }, verified)).decision).toBe("deny");
    // a refund of nothing or less than nothing would otherwise pass the upper bound
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: 0 }, verified)).decision).toBe("deny");
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: -1 }, verified)).decision).toBe("deny");
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: 1 }, verified)).decision).toBe("allow");
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: 500 }, { customer: { verified: false } })).decision).toBe("deny");
    expect(evaluate(p, req("support-agent", "billing.refund", { amount: 500 })).decision).toBe("deny");
  });

  it("the report agent may read and may not refund or delegate, even with every fact in place", () => {
    const p = cedarBlocks[0]!;
    expect(evaluate(p, req("report-agent", "customer.lookup", {})).decision).toBe("allow");
    expect(evaluate(p, req("report-agent", "kb.search", {})).decision).toBe("allow");
    expect(evaluate(p, req("report-agent", "billing.refund", { amount: 1 }, verified)).decision).toBe("deny");
    expect(evaluate(p, req("report-agent", "docs.send", { text: "x" })).decision).toBe("deny");
    expect(evaluate(p, req("support-agent", "docs.send", { text: "x" })).decision).toBe("allow");
  });
});

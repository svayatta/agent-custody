// Aspect: completeness from the provider's side, for GitHub. Source: src/completeness.ts
// Run:    node examples/53-completeness-github.ts
//
// An agent merges pull requests through a wrapped tool, and each merge gets a signed receipt. Someone with a GitHub
// token of their own pushes to the same branch, and no receipt exists for that push. An auditor with a read-only token
// lists the repository's activity over a window and matches each entry to a verified receipt by the commit the branch
// moved to. Here the list comes from a stand-in that answers the way GitHub's activity API does.
import { checkCompleteness, formatCompleteness, githubSource } from "../src/completeness.ts";
import { loadSdkConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { buildSdkFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildSdkFixture(out("53-completeness-github"), `permit(principal, action == Action::"github.merge_pull_request", resource);`, "example");
const since = Date.now() - 60_000;
const timestamp = new Date().toISOString();

step(1, "an agent merges two pull requests through a wrapped tool; each merge gets a signed receipt that carries the merge commit");
const issuer = createSdkIssuer(loadSdkConfig(fx.configFile));
const merged = ["1f".repeat(20), "2e".repeat(20)];
const merge = issuer.wrap("github.merge_pull_request", async (a: { pull_number: number }) => ({ content: [{ type: "text", text: JSON.stringify({ sha: merged[a.pull_number - 1], merged: true }) }] }));
for (const pull_number of [1, 2]) {
  await merge({ pull_number });
  console.log(`   pull request ${pull_number} merged as ${merged[pull_number - 1]!.slice(0, 12)}`);
}

step(2, "someone with a GitHub token of their own pushes straight to main; the agent's tool never sees it");
const direct = "3d".repeat(20);
const activity = [
  { activity_type: "push", ref: "refs/heads/main", after: direct, timestamp },
  ...merged.map((after) => ({ activity_type: "pr_merge", ref: "refs/heads/main", after, timestamp })),
];
const TOKEN = "github_pat_auditor_read_only";
const standIn = (async (_url: string | URL | Request, init?: RequestInit) => {
  if ((init?.headers as Record<string, string>).authorization !== `Bearer ${TOKEN}`) return new Response("unauthorised", { status: 401 });
  return Response.json(activity);
}) as typeof fetch;

step(3, "the auditor lists the repository's merges and pushes for the window and matches each to a verified receipt");
const check = (object: "merges" | "pushes") =>
  checkCompleteness({
    receiptsDir: fx.receiptsDir,
    verify: { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile },
    source: githubSource({ token: TOKEN, repo: "acme/shop", object, fetch: standIn }),
    tools: object === "merges" ? ["github.merge_pull_request"] : ["github.push_files"],
    sinceMs: since,
    untilMs: Date.now() + 60_000,
    idPath: "sha",
  });
const merges = await check("merges");
const pushes = await check("pushes");
for (const report of [merges, pushes]) console.log(formatCompleteness(report).replace(/^/gm, "   "), "\n");

const ok = merges.complete && merges.matched.length === 2 && pushes.providerOnly.length === 1 && pushes.providerOnly[0]!.providerId === direct && !pushes.complete;
if (!ok) throw new Error("unexpected result");
console.log("OK");

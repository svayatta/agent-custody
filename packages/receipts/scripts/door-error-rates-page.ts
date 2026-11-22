// Writes the measured blocks of docs/door-error-rates.md from a fresh test set: `node scripts/door-error-rates-page.ts`.
// test/door-error-rates.test.ts fails when the page and the door disagree.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { doorErrorRates, formatErrorRates, readDoorArrivals } from "../src/door-error-rates.ts";
import { buildDoorTestSet, formatTestKinds } from "../src/door-test-set.ts";

export const PAGE = join(import.meta.dirname, "../docs/door-error-rates.md");
export const PER_KIND = 200;

export async function measuredBlocks(perKind = PER_KIND): Promise<Record<"error-rates" | "error-rates-kinds", string>> {
  const dir = mkdtempSync(join(tmpdir(), "door-error-rates-page-"));
  try {
    const set = await buildDoorTestSet(dir, { perKind });
    const read = readDoorArrivals(set.receiptsDir, { issuerKeys: [set.doorKey], principalKeys: [set.principalKey] });
    if (read.skipped.length) throw new Error(`test set receipts did not verify: ${read.skipped.map((s) => s.reason).join("; ")}`);
    return { "error-rates": formatErrorRates(doorErrorRates(read.arrivals, set.labels).rows), "error-rates-kinds": formatTestKinds() };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function block(text: string, name: string): string {
  const m = new RegExp(`<!-- ${name}:begin -->\\n([\\s\\S]*?)<!-- ${name}:end -->`).exec(text);
  if (!m) throw new Error(`no ${name} block in the page`);
  return m[1]!;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let text = readFileSync(PAGE, "utf8");
  for (const [name, content] of Object.entries(await measuredBlocks())) text = text.replace(block(text, name), content);
  writeFileSync(PAGE, text);
  console.log(`wrote ${PAGE}`);
}

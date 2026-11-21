// Builds the door Worker for workerd: one ES module, and the Cedar WebAssembly beside it as a module the Worker imports.
// Workers do not compile WebAssembly from bytes at run time, so Cedar's `web` build is initialised from that import in
// place of the `nodejs` build policy.ts loads. `wrangler deploy` runs this as its build command (deploy/door/cloudflare-
// worker/wrangler.toml), and the tests build with it too, so what is tested is what deploys.
//   node scripts/build-door-worker.ts <outDir>
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build, type Plugin } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
export const WORKER_ENTRY = resolve(here, "../../../deploy/door/cloudflare-worker/src/index.ts");
const WASM = "cedar_wasm_bg.wasm";

export async function buildDoorWorker(outDir: string, entry = WORKER_ENTRY): Promise<{ script: string; wasm: string; bytes: number }> {
  let web: string | undefined;
  const cedarWeb: Plugin = {
    name: "cedar-wasm-web",
    setup(b) {
      b.onResolve({ filter: /^@cedar-policy\/cedar-wasm\/nodejs$/ }, async () => {
        const r = await b.resolve("@cedar-policy/cedar-wasm/web", { kind: "import-statement", resolveDir: here });
        if (r.errors.length) return { errors: r.errors };
        web = r.path;
        return { path: "cedar-wasm-web", namespace: "cedar" };
      });
      b.onLoad({ filter: /.*/, namespace: "cedar" }, () => ({
        contents: `import { initSync } from ${JSON.stringify(web)};\nimport wasm from "./${WASM}";\ninitSync({ module: wasm });\nexport * from ${JSON.stringify(web)};\n`,
        loader: "js",
        resolveDir: dirname(web!),
      }));
    },
  };
  mkdirSync(outDir, { recursive: true });
  const script = join(outDir, "index.js");
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["workerd", "worker", "browser"],
    outfile: script,
    external: ["node:*", `./${WASM}`],
    plugins: [cedarWeb],
    minify: true,
    legalComments: "none",
    metafile: true,
    logLevel: "warning",
  });
  if (!web) throw new Error("the Worker does not load Cedar: nothing imported @cedar-policy/cedar-wasm/nodejs");
  const wasm = join(outDir, WASM);
  copyFileSync(join(dirname(web), WASM), wasm);
  return { script, wasm, bytes: Object.values(result.metafile.outputs).reduce((n, o) => n + o.bytes, 0) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = resolve(process.argv[2] ?? "dist");
  const built = await buildDoorWorker(out);
  console.log(`agent-custody door Worker: ${built.script} (${built.bytes} bytes) and ${built.wasm}`);
}

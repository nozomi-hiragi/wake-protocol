// Bundles the browser entry into dist/app.js (shared by build.ts and serve.ts).
import { build } from "esbuild";

export async function buildBrowser(): Promise<void> {
  await build({
    entryPoints: [new URL("../src/browser/main.ts", import.meta.url).pathname],
    outfile: new URL("../dist/app.js", import.meta.url).pathname,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    sourcemap: false,
    logLevel: "warning",
  });
}


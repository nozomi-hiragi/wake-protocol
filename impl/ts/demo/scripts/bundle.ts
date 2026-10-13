// Bundles the browser entry into dist/ (app.js and approve.js) (shared by build.ts and serve.ts).
import { build } from "esbuild";

export async function buildBrowser(): Promise<void> {
  await build({
    entryPoints: {
      app: new URL("../src/browser/main.ts", import.meta.url).pathname,
      approve: new URL("../src/browser/approve.ts", import.meta.url).pathname,
    },
    outdir: new URL("../dist/", import.meta.url).pathname,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    sourcemap: false,
    logLevel: "warning",
  });
}


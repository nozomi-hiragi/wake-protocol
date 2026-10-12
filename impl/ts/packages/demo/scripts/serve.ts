// Builds the bundle and serves the demo on localhost (WebAuthn needs a secure context).
import { serve } from "@hono/node-server";
import { createDemoApp } from "../src/app.ts";
import { buildBrowser } from "./bundle.ts";

const port = Number(process.env.PORT ?? 8787);
await buildBrowser();
const { app } = createDemoApp({ rpId: "localhost", origin: `http://localhost:${port}` });
// Listen on loopback only: the demo has no rate limits and keeps everything in memory.
serve({ fetch: app.fetch, port, hostname: "localhost" });
console.log(`WAKE demo: http://localhost:${port}/`);

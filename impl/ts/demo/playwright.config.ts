import { defineConfig } from "@playwright/test";

const port = 8797;

export default defineConfig({
  testDir: "test/e2e",
  workers: 1,
  use: { baseURL: `http://localhost:${port}` },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: {
    command: "node --conditions=@wake-protocol/source scripts/serve.ts",
    url: `http://localhost:${port}/`,
    env: { PORT: String(port) },
    reuseExistingServer: false,
  },
});

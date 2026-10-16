// Exercise the release loop with a fake npm executable; never contact a registry.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const dirs = ["core/bytes", "core/codec", "core/crypto", "core/protocol", "client", "server"];
for (const scenario of ["exists", "missing", "empty", "network", "auth", "unexpected", "publish-failure"]) {
  test(`npm publish loop: ${scenario}`, (t) => {
    const root = mkdtempSync(join(tmpdir(), "wake-publish-test-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    mkdirSync(join(root, "scripts"));
    mkdirSync(join(root, "bin"));
    for (const dir of dirs) {
      mkdirSync(join(root, dir), { recursive: true });
      writeFileSync(join(root, dir, "package.json"), JSON.stringify({ version: "0.6.0" }));
    }
    const script = join(root, "scripts/publish-npm.sh");
    copyFileSync(new URL("./publish-npm.sh", import.meta.url), script);
    const log = join(root, "calls.jsonl");
    writeFileSync(log, "");
    writeFileSync(join(root, "bin/npm"), `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(process.env.WAKE_TEST_LOG, JSON.stringify(args) + "\\n");
if (args[0] === "publish") process.exit(process.env.WAKE_TEST_SCENARIO === "publish-failure" ? 1 : 0);
switch (process.env.WAKE_TEST_SCENARIO) {
  case "exists": console.log(JSON.stringify("0.6.0")); break;
  case "empty": break;
  case "unexpected": console.log(JSON.stringify("0.5.0")); break;
  case "network": console.log(JSON.stringify({error:{code:"ECONNRESET"}})); process.exit(1);
  case "auth": console.log(JSON.stringify({error:{code:"E401"}})); process.exit(1);
  default: console.log(JSON.stringify({error:{code:"E404"}})); process.exit(1);
}
`, { mode: 0o755 });
    const result = spawnSync("bash", [script], { encoding: "utf8", env: {
      ...process.env, PATH: `${join(root, "bin")}:${process.env.PATH ?? ""}`,
      WAKE_TEST_LOG: log, WAKE_TEST_SCENARIO: scenario,
    } });
    const calls = readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as string[]);
    const published = calls.filter((call) => call[0] === "publish");
    if (["exists", "missing", "empty"].includes(scenario)) {
      assert.equal(result.status, 0, result.stderr);
      assert.equal(calls.filter((call) => call[0] === "view").length, 6);
      assert.equal(published.length, scenario === "exists" ? 0 : 6);
      if (published.length) {
        assert.deepEqual(published.map((call) => call.at(-1)), dirs.map((dir) => join(root, dir)));
        assert.ok(published.every((call) => call.join(" ").includes("--provenance --access public")));
      }
    } else {
      assert.notEqual(result.status, 0, result.stdout);
      assert.equal(published.length, scenario === "publish-failure" ? 1 : 0);
      assert.equal(calls.filter((call) => call[0] === "view").length, 1);
    }
  });
}

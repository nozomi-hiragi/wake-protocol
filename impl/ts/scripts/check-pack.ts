// Build and test npm tarballs from an isolated consumer without workspace resolution.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const PACKAGES = {
  "core/bytes": "@wake-protocol/bytes", "core/codec": "@wake-protocol/codec",
  "core/crypto": "@wake-protocol/crypto", "core/protocol": "@wake-protocol/core",
  client: "@wake-protocol/client", server: "@wake-protocol/server",
};

function run(file: string, args: string[], cwd: string, env = process.env): void {
  execFileSync(file, args, { cwd, env, stdio: "inherit" });
}
function output(file: string, args: string[], cwd: string): string {
  return execFileSync(file, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}

const temp = mkdtempSync(join(tmpdir(), "wake-check-pack-"));
try {
  run("npm", ["run", "build"], ROOT);
  const dependencies: Record<string, string> = {};
  for (const [dir, name] of Object.entries(PACKAGES)) {
    const packed = JSON.parse(output("npm", ["pack", "--json", "--pack-destination", temp], join(ROOT, dir))) as { filename: string }[];
    if (packed.length !== 1 || !packed[0]?.filename) throw new Error(`${name}: expected one tarball`);
    const tarball = resolve(temp, packed[0].filename);
    const files = output("tar", ["-tzf", tarball], temp).trim().split("\n");
    for (const required of ["dist/index.js", "dist/index.d.ts", "README.md", "LICENSE", "package.json"]) {
      if (!files.includes(`package/${required}`)) throw new Error(`${name}: missing ${required}`);
    }
    for (const file of files) {
      if (/(^|\/)(src|tests?|__tests__)\//.test(file)
        || /(^|\/)testing(?:\.|\/|$)/.test(file) || /\.(test|spec)\./.test(file)) {
        throw new Error(`${name}: forbidden path ${file}`);
      }
    }
    console.log(`${name}: tarball verified (${files.length} files)`);
    dependencies[name] = `file:${tarball}`;
  }

  const consumer = join(temp, "consumer");
  mkdirSync(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ private: true, type: "module", dependencies }));
  const consumerEnv = { ...process.env };
  // npm lifecycle exports can turn .npmrc allow-scripts into a forbidden install flag.
  // Drop only that inherited setting; --ignore-scripts still prevents lifecycle scripts.
  for (const key of Object.keys(consumerEnv)) {
    if (/^npm_config_allow[_-]scripts$/i.test(key)) delete consumerEnv[key];
  }
  run("npm", ["install", "--ignore-scripts", "--no-package-lock", "--no-audit", "--no-fund"], consumer, consumerEnv);
  // Use JavaScript so Node 22 does not need TypeScript stripping for this runtime check.
  writeFileSync(join(consumer, "consumer.js"), `
import assert from "node:assert/strict";
import { Bytes, fixedLength } from "@wake-protocol/bytes";
import { utf8ToBytes, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import { sha256 } from "@wake-protocol/crypto";
import { WakeError, LABELS } from "@wake-protocol/core";
import { WakeClient } from "@wake-protocol/client";
import { createWakeServer } from "@wake-protocol/server";
assert.equal(new Bytes(new Uint8Array([1, 2, 3])).length, 3);
assert.equal(typeof fixedLength, "function");
assert.equal(encodeU32LengthPrefixed(utf8ToBytes("hello")).length, 9);
assert.equal((await sha256(utf8ToBytes("hello"))).length, 32);
assert.ok(new WakeError("bad_request") instanceof Error);
assert.ok(Object.keys(LABELS).length > 0);
assert.equal(typeof WakeClient, "function");
assert.equal(typeof createWakeServer, "function");
for (const name of ["@wake-protocol/core/testing", "@wake-protocol/server/testing"]) {
  await assert.rejects(import(name), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
}
console.log("Plain Node consumer passed (6 packages, testing subpaths unavailable)");
`);
  run(process.execPath, ["consumer.js"], consumer);
  writeFileSync(join(consumer, "consumer.ts"), `
import { Bytes, fixedLength } from "@wake-protocol/bytes";
import { utf8ToBytes, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import { sha256 } from "@wake-protocol/crypto";
import { WakeError, LABELS } from "@wake-protocol/core";
import { WakeClient } from "@wake-protocol/client";
import { createWakeServer } from "@wake-protocol/server";
const bytes: Bytes = new Bytes(new Uint8Array([1, 2, 3]));
const branded: Bytes = fixedLength<"Consumer">("consumer", 3)(bytes);
const encoded: Uint8Array = encodeU32LengthPrefixed(utf8ToBytes("hello"));
const digest: Promise<Uint8Array> = sha256(encoded);
const error: WakeError = new WakeError("bad_request");
const labels: typeof LABELS = LABELS;
const client: typeof WakeClient = WakeClient;
const server: typeof createWakeServer = createWakeServer;
void [branded, digest, error, labels, client, server];
// @ts-expect-error testing helpers are unavailable to consumers
import "@wake-protocol/core/testing";
// @ts-expect-error testing helpers are unavailable to consumers
import "@wake-protocol/server/testing";
`);
  writeFileSync(join(consumer, "tsconfig.json"), JSON.stringify({ compilerOptions: {
    target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", strict: true,
    noEmit: true, skipLibCheck: false, types: [], noUncheckedSideEffectImports: true,
  }, include: ["consumer.ts"] }));
  // Reuse the locked compiler rather than fetching a different version in the consumer.
  run(process.execPath, [join(ROOT, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"], consumer);
  console.log("Strict TypeScript consumer passed (declarations checked)");
} finally {
  rmSync(temp, { recursive: true, force: true });
}

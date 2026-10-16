import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { checkVersions } from "./check-version.ts";

const packages = {
  "core/bytes": "@wake-protocol/bytes", "core/codec": "@wake-protocol/codec",
  "core/crypto": "@wake-protocol/crypto", "core/protocol": "@wake-protocol/core",
  client: "@wake-protocol/client", server: "@wake-protocol/server",
};

function fixture(t: TestContext): string {
  const temp = mkdtempSync(join(tmpdir(), "wake-version-"));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  const root = join(temp, "impl", "ts");
  mkdirSync(root, { recursive: true });
  writeFileSync(join(temp, "LICENSE"), "License\n");
  writeFileSync(join(root, "package.json"), JSON.stringify({ private: true, workspaces: ["core/*", "client", "server", "demo"] }));
  for (const [dir, name] of Object.entries({ ...packages, "core/vectors": "@wake-protocol/vectors", demo: "@wake-protocol/demo" })) {
    mkdirSync(join(root, dir), { recursive: true });
    const published = dir in packages;
    writeFileSync(join(root, dir, "package.json"), JSON.stringify({ name, version: published ? "0.6.0" : "0.0.0", ...published ? {} : { private: true } }));
    if (published) {
      writeFileSync(join(root, dir, "jsr.json"), JSON.stringify({ name, version: "0.6.0", imports: { "@wake-protocol/bytes": "jsr:@wake-protocol/bytes@0.6.0" } }));
      writeFileSync(join(root, dir, "LICENSE"), "License\n");
    }
  }
  return root;
}

function patch(root: string, file: string, values: Record<string, unknown>): void {
  const path = join(root, file);
  writeFileSync(path, JSON.stringify({ ...JSON.parse(readFileSync(path, "utf8")), ...values }));
}

function rejects(root: string, expected: string): void {
  const result = checkVersions(root);
  assert.ok(result.errors.some((error) => error.includes(expected)), result.errors.join("\n"));
}

test("consistent versions and exact tag pass", (t) => {
  const root = fixture(t);
  assert.deepEqual(checkVersions(root, "impl/ts/v0.6.0"), { version: "0.6.0", errors: [] });
});
for (const valid of [true, false]) {
  test(`--print-version ${valid ? "prints only a checked version" : "fails on inconsistent versions without stdout"}`, (t) => {
    const root = fixture(t);
    patch(root, "package.json", { type: "module" });
    mkdirSync(join(root, "scripts"));
    const script = join(root, "scripts/check-version.ts");
    copyFileSync(new URL("./check-version.ts", import.meta.url), script);
    if (!valid) patch(root, "server/jsr.json", { version: "0.5.0" });
    const result = spawnSync(process.execPath, [realpathSync(script), "--print-version"], { encoding: "utf8" });
    assert.equal(result.status, valid ? 0 : 1, result.stderr);
    assert.equal(result.stdout, valid ? "0.6.0\n" : "");
    if (!valid) assert.match(result.stderr, /Version mismatch/);
  });
}
for (const file of ["core/bytes/package.json", "server/jsr.json"]) {
  test(`mismatched version in ${file} fails`, (t) => {
    const root = fixture(t);
    patch(root, file, { version: "0.5.0" });
    rejects(root, "Version mismatch");
  });
}
for (const tag of ["v0.6.0", "other/v0.6.0", "x/impl/ts/v0.6.0", "impl/ts/v0.6.0-alpha", "impl/ts/v00.6.0", "impl/ts/v0.5.0", ""]) {
  test(`invalid tag ${JSON.stringify(tag)} fails`, (t) => {
    assert.ok(checkVersions(fixture(t), tag).errors.some((error) => error.includes("Tag")));
  });
}
for (const dir of [".", "core/vectors", "demo"]) {
  test(`${dir} must remain private`, (t) => {
    const root = fixture(t);
    patch(root, `${dir}/package.json`, { private: false });
    rejects(root, "private");
  });
}
test("published package must be public", (t) => {
  const root = fixture(t);
  patch(root, "client/package.json", { private: true });
  rejects(root, "must not");
});
for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
  test(`${section} is checked even with another valid section`, (t) => {
    const root = fixture(t);
    patch(root, "demo/package.json", { dependencies: { "@wake-protocol/core": "0.6.0" }, devDependencies: { "@wake-protocol/core": "0.6.0" }, [section]: { "@wake-protocol/core": "^0.6.0" } });
    rejects(root, section);
  });
}
test("root dependencies are checked", (t) => {
  const root = fixture(t);
  patch(root, "package.json", { optionalDependencies: { "@wake-protocol/bytes": "0.5.0" } });
  rejects(root, "optionalDependencies");
});
test("JSR sibling ranges and aliases fail", (t) => {
  const root = fixture(t);
  patch(root, "client/jsr.json", { imports: { alias: "jsr:@wake-protocol/core@^0.6.0" } });
  rejects(root, "import alias");
});
test("root JSR import mappings are checked", (t) => {
  const root = fixture(t);
  writeFileSync(join(root, "deno.json"), JSON.stringify({ imports: { "@wake-protocol/core": "npm:@wake-protocol/core@0.6.0" } }));
  rejects(root, "deno.json");
});
test("missing JSR config fails", (t) => {
  const root = fixture(t);
  rmSync(join(root, "client/jsr.json"));
  rejects(root, "client/jsr.json: missing");
});
test("LICENSE comparison includes trailing bytes", (t) => {
  const root = fixture(t);
  writeFileSync(join(root, "server/LICENSE"), "License");
  rejects(root, "differs from root LICENSE");
});
test("missing LICENSE fails", (t) => {
  const root = fixture(t);
  rmSync(join(root, "client/LICENSE"));
  rejects(root, "client/LICENSE: missing");
});

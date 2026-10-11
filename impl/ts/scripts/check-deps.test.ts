import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkDependencies } from "./check-deps.ts";

const fixtures = new URL("./fixtures/check-deps/", import.meta.url);
const cases = [
  ["generic-declaration", "package.json", "forbidden dependency"],
  ["generic-import", "src/index.ts", "forbidden dependency"],
  ["generic-core", "src/index.ts", "forbidden dependency"],
  ["production-vectors", "src/index.ts", "forbidden dependency"],
  ["dynamic-template", "src/index.ts", "forbidden dependency"],
  ["commented-import", "src/index.ts", "forbidden dependency"],
  ["relative-escape", "src/index.ts", "relative import leaves package"],
  ["undeclared", "src/index.ts", "undeclared dependency"],
  ["vectors-crypto", "package.json", "forbidden dependency"],
  ["root-workspace-bypass", "src/index.ts", "forbidden dependency"],
  ["root-dev-in-src", "src/index.ts", "forbidden dependency"],
  ["root-dev-as-runtime", "package.json", "forbidden dependency"],
] as const;

for (const [name, file, reason] of cases) {
  test(`dependency checker rejects ${name}`, () => {
    const { offenders } = checkDependencies(fileURLToPath(new URL(name, fixtures)));
    assert.ok(offenders.some((line) => line.includes(file) && line.includes(reason)), offenders.join("\n"));
  });
}

test("dependency checker accepts valid directions and ignores unrelated strings and comments", () => {
  const result = checkDependencies(fileURLToPath(new URL("valid", fixtures)));
  assert.deepEqual(result, { offenders: [], count: 5 });
});

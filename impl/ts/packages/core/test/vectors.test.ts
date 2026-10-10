import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { WakeError, decodeEtRequest, decodeEtResponse, fromHex, hex } from "../src/index.ts";
import { DEFAULT_VECTOR_DIR } from "../scripts/generate-vectors.ts";
import { type Obj, SUITES, runCase } from "../scripts/vector-ops.ts";

interface VectorFile {
  wake: string;
  suite: string;
  vectors: Array<{ name: string; input: Obj; expected?: Obj; expectedError?: string }>;
}

const names = (await readdir(DEFAULT_VECTOR_DIR)).filter((f) => f.endsWith(".json")).sort();
const files: VectorFile[] = [];
for (const n of names) files.push(JSON.parse(await readFile(join(DEFAULT_VECTOR_DIR, n), "utf8")) as VectorFile);

describe("spec/test-vectors", () => {
  it("has exactly one file per suite in spec section 16", () => {
    assert.deepEqual(names, SUITES.map((s) => `${s}.json`).sort());
  });

  for (const file of files) {
    describe(file.suite, () => {
      it("header fields", () => {
        assert.equal(file.wake, "WAKE/1");
        assert.ok((SUITES as readonly string[]).includes(file.suite));
        assert.ok(file.vectors.length > 0);
      });

      for (const v of file.vectors) {
        it(v.name, async () => {
          if (v.expectedError !== undefined) {
            await assert.rejects(
              () => runCase(file.suite, v.input),
              (e: unknown) => e instanceof WakeError && e.code === v.expectedError,
            );
            return;
          }
          assert.ok(v.expected !== undefined, "vector has neither expected nor expectedError");
          assert.deepEqual(await runCase(file.suite, v.input), v.expected);

          // Positive ET vectors must also decode back to their input.
          if (file.suite === "et") {
            const enc = fromHex(v.expected.encoded as string);
            if (v.input.kind === "request") {
              const r = decodeEtRequest(enc);
              assert.equal(r.method, v.input.method);
              assert.equal(r.path, v.input.path);
              assert.equal(r.query, v.input.query);
              assert.equal(hex(r.body), v.input.body);
              assert.equal(r.headers.length, (v.input.headers as unknown[]).length);
            } else {
              const r = decodeEtResponse(enc);
              assert.equal(r.status, v.input.status);
              assert.equal(hex(r.body), v.input.body);
            }
          }
        });
      }
    });
  }
});

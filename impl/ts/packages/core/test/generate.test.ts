// The committed vectors must be exactly what the generator produces today.
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_VECTOR_DIR, writeSuites } from "../scripts/generate-vectors.ts";

describe("generator stability", () => {
  it("re-running the generator reproduces spec/test-vectors byte for byte", async () => {
    const dir = await mkdtemp(join(tmpdir(), "wake-vectors-"));
    try {
      await writeSuites(dir);
      const committed = (await readdir(DEFAULT_VECTOR_DIR)).filter((f) => f.endsWith(".json")).sort();
      assert.deepEqual((await readdir(dir)).sort(), committed);
      for (const f of committed) {
        assert.equal(await readFile(join(dir, f), "utf8"), await readFile(join(DEFAULT_VECTOR_DIR, f), "utf8"), f);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

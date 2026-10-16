// Generic byte-array comparison tests.
import assert from "node:assert/strict";
import test from "node:test";
import { constantTimeEqual } from "../src/index.ts";

test("constantTimeEqual compares equal arrays and empty arrays", () => {
  assert.equal(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  assert.equal(constantTimeEqual(new Uint8Array(), new Uint8Array()), true);
});

test("constantTimeEqual detects differences at the first and last byte", () => {
  assert.equal(constantTimeEqual(new Uint8Array([0, 2, 3]), new Uint8Array([1, 2, 3])), false);
  assert.equal(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
});

test("constantTimeEqual rejects arrays with different lengths", () => {
  assert.equal(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2])), false);
});

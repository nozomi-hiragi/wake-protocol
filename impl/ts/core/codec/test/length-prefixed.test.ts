// Length-prefixed fields and strict field checks.
import assert from "node:assert/strict";
import test from "node:test";
import { checkFieldLengths, encodeU32LengthPrefixed, decodeU32LengthPrefixed } from "../src/index.ts";

test("checkFieldLengths enforces field count and lengths; decodeU32LengthPrefixed rejects truncation", () => {
  const badRequest = (e: unknown) => e instanceof RangeError; // generic layer: standard error
  const cases: [Uint8Array, (number | null)[]][] = [
    [encodeU32LengthPrefixed(Uint8Array.from([1])), [1, 1]], // too few fields → checkFieldLengths
    [encodeU32LengthPrefixed(Uint8Array.from([1]), Uint8Array.from([2])), [1]], // trailing field → checkFieldLengths
    [encodeU32LengthPrefixed(Uint8Array.from([1, 2])), [1]], // wrong length → checkFieldLengths
    [Uint8Array.from([0, 0, 0, 5, 1]), [null]], // truncated field → decodeU32LengthPrefixed
    [Uint8Array.from([0, 0]), [null]], // truncated length → decodeU32LengthPrefixed
  ];
  for (const [input, lengths] of cases) {
    assert.throws(() => checkFieldLengths(decodeU32LengthPrefixed(input), lengths), badRequest);
  }
  assert.deepEqual(decodeU32LengthPrefixed(encodeU32LengthPrefixed(Uint8Array.from([1]), Uint8Array.from([]), Uint8Array.from([2, 3]))).map((f) => f.length), [1, 0, 2]);
  assert.deepEqual(decodeU32LengthPrefixed(Uint8Array.from([])), []);
});

// Standard codecs for byte arrays and text.
import assert from "node:assert/strict";
import test from "node:test";
import { checkFieldLengths, encodeU32LengthPrefixed, decodeU32LengthPrefixed, asciiToBytes, latin1ToBytes, bytesToAscii, bytesToLatin1, bytesToUtf8, utf8ToBytes } from "../src/index.ts";

test("length-prefixed fields respect array view offsets and copy fields, including Buffer inputs", () => {
  const source = Uint8Array.of(9, 1, 2, 9);
  const wire = encodeU32LengthPrefixed(source.subarray(1, 3), new Uint8Array(0));
  source[1] = 8;
  assert.deepEqual(wire, Uint8Array.of(0, 0, 0, 2, 1, 2, 0, 0, 0, 0));
  const padded = Buffer.concat([Buffer.from([9]), wire, Buffer.from([9])]);
  const fields = checkFieldLengths(decodeU32LengthPrefixed(padded.subarray(1, -1)), [2, 0]);
  assert.deepEqual(fields, [Uint8Array.of(1, 2), new Uint8Array(0)]);
  assert.throws(() => checkFieldLengths([asciiToBytes("abc")], [2]), { name: "RangeError", message: "field length 3, want 2" });
  padded.fill(0);
  assert.deepEqual(fields[0], Uint8Array.of(1, 2));
  assert.throws(() => decodeU32LengthPrefixed(Uint8Array.of(0)), { name: "RangeError", message: "truncated length prefix" });
  assert.throws(() => decodeU32LengthPrefixed(Uint8Array.of(0, 0, 0, 2, 1)), { name: "RangeError", message: "truncated field" });
});

test("asciiToBytes, utf8ToBytes and latin1ToBytes round-trip with their inverse codecs and retain strict errors", () => {
  const view = Uint8Array.of(0, 65, 66, 0).subarray(1, 3);
  assert.deepEqual(asciiToBytes("AB"), view);
  assert.equal(bytesToAscii(view), "AB");
  assert.equal(bytesToUtf8(utf8ToBytes("あ\ufeff")), "あ\ufeff");
  assert.equal(bytesToLatin1(latin1ToBytes("é\u0085")), "é\u0085");
  assert.throws(() => asciiToBytes("é"), { name: "RangeError", message: "non-ASCII character" });
  assert.throws(() => bytesToAscii(Uint8Array.of(128)), { name: "RangeError", message: "non-ASCII byte" });
  assert.throws(() => latin1ToBytes("あ"), { name: "RangeError", message: "character above U+00FF" });
  assert.throws(() => utf8ToBytes("\ud800"), { name: "TypeError", message: "lone surrogate" });
  assert.throws(() => bytesToUtf8(Uint8Array.of(255)), TypeError);
});

test("ASCII round-trips 1 MiB and rejects a non-ASCII byte at the end", () => {
  const text = "\u0000ABCDEFGHIJKLMNOPQRSTUVWXYZ\u007f".repeat(37450).slice(0, 1024 * 1024);
  assert.equal(text.length, 1024 * 1024);
  const bytes = asciiToBytes(text);
  assert.equal(bytesToAscii(bytes), text);
  bytes[bytes.length - 1] = 128;
  assert.throws(() => bytesToAscii(bytes), { name: "RangeError", message: "non-ASCII byte" });
});

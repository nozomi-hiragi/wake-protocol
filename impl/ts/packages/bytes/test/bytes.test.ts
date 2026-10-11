// Byte values and integer helpers.
import assert from "node:assert/strict";
import test from "node:test";
import { Byte, Byte2, Byte4, Byte8, Bytes, bigIntToNumber, fixedLength, numberToBigInt } from "../src/index.ts";

test("fixedLength brands bytes without promising a fixed-width class", () => {
  const input = Uint8Array.of(0, 0, 0, 7);
  // @ts-expect-error A class cannot be used as a brand identifier.
  const n: Byte4 = fixedLength<Byte4>("u32", 4)(input);
  assert.equal(n instanceof Byte4, false);
  // @ts-expect-error A byte brand does not provide Byte4.number.
  const branded: Byte4 = fixedLength<"u32">("u32", 4)(input);
  assert.equal(branded instanceof Byte4, false);
  assert.ok(fixedLength<"u32">("u32", 4)(input).equals(new Byte4(7)));
  assert.throws(() => fixedLength<"u32">("u32", 4)(input.subarray(1)), RangeError);
});

test("Bytes owns its input and never exposes mutable storage", () => {
  const source = Uint8Array.of(1, 2, 3);
  const value = new Bytes(source);
  source[0] = 9;
  assert.deepEqual([...value], [1, 2, 3]);

  const copy = value.toUint8Array();
  copy[1] = 9;
  assert.deepEqual([...value], [1, 2, 3]);

  const clone = new Bytes(value);
  const piece = value.slice(1);
  assert.deepEqual([...clone], [1, 2, 3]);
  assert.deepEqual([...piece], [2, 3]);
  assert.equal(value.length, 3);
  assert.equal(value.at(0), 1);
  assert.equal(value.at(-1), 3);
  assert.equal(value.at(3), undefined);
});

test("Bytes.equals compares contents and length", () => {
  const original = new Bytes([1, 2, 3]);
  assert.equal(original.equals(new Bytes([1, 2, 3])), true);
  assert.equal(original.equals(new Bytes([1, 2, 4])), false);
  assert.equal(original.equals(new Bytes([1, 2])), false);
});

test("Bytes.concat joins parts in order", () => {
  assert.ok(Bytes.concat(new Bytes([1]), new Byte2(0x0203), new Bytes([])).equals(new Bytes([1, 2, 3])));
  assert.equal(Bytes.concat().length, 0);
});

test("fixed-width classes are big-endian and expose their number", () => {
  assert.deepEqual([...new Byte(0xa5)], [0xa5]);
  assert.deepEqual([...new Byte2(0x1234)], [0x12, 0x34]);
  assert.deepEqual([...new Byte4(0x89abcdef)], [0x89, 0xab, 0xcd, 0xef]);
  assert.deepEqual([...new Byte8(0x123456789abcdef0n)], [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);

  assert.equal(new Byte(new Bytes([0xa5])).number, 0xa5);
  assert.equal(new Byte2(new Bytes([0x12, 0x34])).number, 0x1234);
  assert.equal(new Byte4(new Bytes([0x89, 0xab, 0xcd, 0xef])).number, 0x89abcdef);
  assert.equal(new Byte8(new Bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])).number, 0x123456789abcdef0n);
});

test("fixed-width classes default to zero", () => {
  assert.deepEqual([...new Byte()], [0]);
  assert.deepEqual([...new Byte2()], [0, 0]);
  assert.deepEqual([...new Byte4()], [0, 0, 0, 0]);
  assert.deepEqual([...new Byte8()], [0, 0, 0, 0, 0, 0, 0, 0]);
});

test("fixed-width classes copy input and retain Bytes behavior", () => {
  const source = new Bytes([0x12, 0x34]);
  const value = new Byte2(source);
  const array = value.toUint8Array();
  array[0] = 0xff;
  assert.equal(value.number, 0x1234);
  assert.ok(value.equals(new Byte2(0x1234)));
  assert.deepEqual([...value.slice(1)], [0x34]);
  assert.equal(value.slice(1) instanceof Byte2, false);
});

test("fixed-width classes reject invalid ranges and lengths directly", () => {
  assert.throws(() => new Byte(-1), { name: "RangeError", message: "u8 out of range" });
  assert.throws(() => new Byte2(0x10000), { name: "RangeError", message: "u16 out of range" });
  assert.throws(() => new Byte4(1.5), { name: "RangeError", message: "u32 out of range" });
  assert.throws(() => new Byte8(1n << 64n), { name: "RangeError", message: "u64 out of range" });
  assert.throws(() => new Byte8(-1n), { name: "RangeError", message: "u64 out of range" });
  assert.throws(() => new Byte8(1 as unknown as bigint), { name: "TypeError", message: "u64 must be a bigint" });
  assert.throws(() => new Byte(new Bytes([0, 0])), { name: "RangeError", message: "u8 length" });
  assert.throws(() => new Byte2(new Bytes([0])), { name: "RangeError", message: "u16 length" });
  assert.throws(() => new Byte4(new Bytes([0, 0, 0, 0, 0])), { name: "RangeError", message: "u32 length" });
  assert.throws(() => new Byte8(new Bytes([])), { name: "RangeError", message: "u64 length" });
});

test("numberToBigInt and bigIntToNumber reject out-of-range values", () => {
  assert.throws(() => numberToBigInt(-1), { name: "RangeError" });
  assert.throws(() => bigIntToNumber(2n ** 53n), { name: "RangeError" });
});

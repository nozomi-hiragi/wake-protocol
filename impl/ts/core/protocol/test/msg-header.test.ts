// Message integer and framing boundaries (spec §4.1, §8.2).
import assert from "node:assert/strict";
import test from "node:test";
import { Byte, Byte4, Byte8 } from "@wake-protocol/bytes";
import {
  Bytes,
  WakeError,
  asIv,
  asRequestId,
  asSessionId,
  DIR_C2S,
  encodeHeader,
  parseWire,
} from "../src/index.ts";
import {
  asciiToBytes,
  encodeU32LengthPrefixed,
} from "@wake-protocol/codec";

test("protocol encoding rejects out-of-range integers", () => {
  assert.throws(
    () => encodeHeader({
      dir: DIR_C2S,
      sessionId: asSessionId(new Uint8Array(32)),
      epoch: -1,
      requestId: asRequestId(new Uint8Array(16)),
      issuedAt: 0,
      context: "ctx",
      iv: asIv(new Uint8Array(12)),
    }),
    { name: "RangeError", message: "u32 out of range" },
  );
});

test("parseWire rejects an issuedAt above 2^53-1 as bad_request", () => {
  const wireWithIssuedAt = (issuedAt: bigint) => {
    const header = encodeU32LengthPrefixed(
      asciiToBytes("WAKE/1 msg"),
      (new Byte(DIR_C2S)).toUint8Array(),
      (asSessionId(new Uint8Array(32))).toUint8Array(),
      (new Byte4(0)).toUint8Array(),
      (asRequestId(new Uint8Array(16))).toUint8Array(),
      (new Byte8(issuedAt)).toUint8Array(),
      asciiToBytes("ctx"),
      (asIv(new Uint8Array(12))).toUint8Array(),
    );
    return Bytes.concat(new Byte4(header.length), new Bytes(header), new Bytes(new Uint8Array(16)));
  };
  assert.equal(parseWire(wireWithIssuedAt(2n ** 53n - 1n)).header.issuedAt, Number.MAX_SAFE_INTEGER);
  assert.throws(
    () => parseWire(wireWithIssuedAt(2n ** 53n)),
    (e: unknown) => e instanceof WakeError && e.code === "bad_request" && e.message.includes("issuedAt"),
  );
});

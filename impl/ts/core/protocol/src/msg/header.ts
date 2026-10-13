// Spec §8.2, §8.7: message headers, wire parsing and plaintext limits.
import { Byte, Byte4, Byte8, Bytes, bigIntToNumber, numberToBigInt } from "@wake-protocol/bytes";
import { asciiToBytes, bytesToAscii } from "@wake-protocol/codec";
import { fail, remap } from "../spec/errors.ts";
import { type Iv, type RequestId, type SessionId, asIv, asRequestId, asSessionId } from "../spec/types.ts";
import { LABELS } from "../spec/labels.ts";
import { labeled, decodeFields, expectLabel } from "../spec/domain.ts";
import { checkMaxLength } from "../spec/limits.ts";

export const DIR_C2S = 0x01;
export const DIR_S2C = 0x02;

const TAG_LEN = 16;
// §8.2: 115 + len(context), with context lengths 1..256.
const MIN_HEADER = 116;
const MAX_HEADER = 371;

/** Default plaintext limit (§8.7), covering the worst-case ET encodings with default limits. */
export const DEFAULT_MAX_PLAINTEXT = 1_128_491;

export interface MsgOptions {
  /** Maximum plaintext length in bytes. Defaults to DEFAULT_MAX_PLAINTEXT. */
  maxPlaintext?: number;
}

/** Fails with `too_large` (§12.3) if the plaintext exceeds the limit. */
export function checkPlaintextLength(length: number, opts?: MsgOptions): void {
  const limit = opts?.maxPlaintext ?? DEFAULT_MAX_PLAINTEXT;
  checkMaxLength(length, limit, "maxPlaintext", "plaintext length");
}

export interface MsgHeader {
  dir: typeof DIR_C2S | typeof DIR_S2C;
  sessionId: SessionId;
  epoch: number;
  requestId: RequestId;
  issuedAt: number; // ms
  context: string; // 1..256 bytes of 0x20..0x7E
  iv: Iv;
}

export function checkContext(context: string): void {
  if (context.length < 1 || context.length > 256) fail("bad_request", "context length");
  for (let i = 0; i < context.length; i++) {
    const c = context.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) fail("bad_request", "context character");
  }
}

/** Throws RangeError for epoch outside u32 or issuedAt outside 0..2^53-1 (integers only). */
export function encodeHeader(h: MsgHeader): Bytes {
  if (h.dir !== DIR_C2S && h.dir !== DIR_S2C) fail("bad_request", "dir");
  checkContext(h.context);
  return labeled(LABELS.msg, new Byte(h.dir), h.sessionId, new Byte4(h.epoch), h.requestId, new Byte8(numberToBigInt(h.issuedAt)), asciiToBytes(h.context), h.iv);
}

export interface ParsedWire {
  header: MsgHeader;
  /** The header bytes exactly as received; used verbatim as AAD (§8.3). */
  headerBytes: Bytes;
  /** Ciphertext ‖ tag. */
  sealed: Bytes;
}

export function parseWire(input: Bytes | Uint8Array, opts?: MsgOptions): ParsedWire {
  const wire = input instanceof Bytes ? input : new Bytes(input);
  if (wire.length < 4) fail("bad_request", "short wire");
  const hlen = new Byte4(wire.slice(0, 4)).number;
  if (hlen < MIN_HEADER || hlen > MAX_HEADER) fail("bad_request", "header length");
  if (wire.length < 4 + hlen + TAG_LEN) fail("bad_request", "short wire");
  const headerBytes = wire.slice(4, 4 + hlen);
  const f = remap("bad_request", () => decodeFields(headerBytes, [asciiToBytes(LABELS.msg).length, 1, 32, 4, 16, 8, null, 12]));
  expectLabel(f[0]!, LABELS.msg, "bad_request");
  const dir = new Byte(f[1]!).number;
  if (dir !== DIR_C2S && dir !== DIR_S2C) fail("bad_request", "dir");
  const context = remap("bad_request", () => bytesToAscii(f[6]!.toUint8Array()));
  checkContext(context);
  checkPlaintextLength(wire.length - 4 - hlen - TAG_LEN, opts);
  const issuedAt = new Byte8(f[5]!).number;
  if (issuedAt > BigInt(Number.MAX_SAFE_INTEGER)) fail("bad_request", "issuedAt exceeds 2^53-1");
  return {
    header: {
      dir,
      sessionId: asSessionId(f[2]!),
      epoch: new Byte4(f[3]!).number,
      requestId: asRequestId(f[4]!),
      issuedAt: bigIntToNumber(issuedAt),
      context,
      iv: asIv(f[7]!),
    },
    headerBytes,
    sealed: wire.slice(4 + hlen),
  };
}

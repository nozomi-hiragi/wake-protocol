// Spec §8.2–8.4: encrypted message format (WAKE-SM).
import {
  type Bytes,
  ascii,
  concat,
  equalBytes,
  lp,
  lpDecode,
  readAscii,
  readU32,
  readU64,
  readU8,
  u32,
  u64,
  u8,
} from "./encoding.ts";
import { aesGcmDecrypt, aesGcmEncrypt, newIv } from "./crypto.ts";
import { fail } from "./errors.ts";
import { timeToU64, u64ToTime } from "./time.ts";
import { type Iv, type RequestId, type SessionId, asIv, asRequestId, asSessionId } from "./types.ts";

export const DIR_C2S = 0x01;
export const DIR_S2C = 0x02;

const LABEL = ascii("WAKE/1 msg");
const TAG_LEN = 16;
const MIN_HEADER = 116;
const MAX_HEADER = 371;

/**
 * Default plaintext limit (§8.7 MUST). The ET body limit (1 MiB, §11.2) plus
 * room for the EtRequest framing (path, query, headers).
 */
export const DEFAULT_MAX_PLAINTEXT = 1024 * 1024 + 64 * 1024;

export interface MsgOptions {
  /** Maximum plaintext length in bytes. Defaults to DEFAULT_MAX_PLAINTEXT. */
  maxPlaintext?: number;
}

/** Fails with `too_large` (§12.3) if the plaintext exceeds the limit. */
export function checkPlaintextLength(length: number, opts?: MsgOptions): void {
  const limit = opts?.maxPlaintext ?? DEFAULT_MAX_PLAINTEXT;
  if (length > limit) fail("too_large", "plaintext length");
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

export function encodeHeader(h: MsgHeader): Bytes {
  if (h.dir !== DIR_C2S && h.dir !== DIR_S2C) fail("bad_request", "dir");
  checkContext(h.context);
  return lp(LABEL, u8(h.dir), h.sessionId, u32(h.epoch), h.requestId, u64(timeToU64(h.issuedAt)), ascii(h.context), h.iv);
}

export interface ParsedWire {
  header: MsgHeader;
  /** The header bytes exactly as received; used verbatim as AAD (§8.3). */
  headerBytes: Bytes;
  /** Ciphertext ‖ tag. */
  sealed: Bytes;
}

export function parseWire(wire: Uint8Array, opts?: MsgOptions): ParsedWire {
  if (wire.length < 4) fail("bad_request", "short wire");
  const hlen = new DataView(wire.buffer, wire.byteOffset, 4).getUint32(0);
  if (hlen < MIN_HEADER || hlen > MAX_HEADER) fail("bad_request", "header length");
  if (wire.length < 4 + hlen + TAG_LEN) fail("bad_request", "short wire");
  const headerBytes = wire.slice(4, 4 + hlen);
  const f = lpDecode(headerBytes, [LABEL.length, 1, 32, 4, 16, 8, null, 12]);
  if (!equalBytes(f[0]!, LABEL)) fail("bad_request", "label");
  const dir = readU8(f[1]!);
  if (dir !== DIR_C2S && dir !== DIR_S2C) fail("bad_request", "dir");
  const context = readAscii(f[6]!);
  checkContext(context);
  checkPlaintextLength(wire.length - 4 - hlen - TAG_LEN, opts);
  return {
    header: {
      dir,
      sessionId: asSessionId(f[2]!),
      epoch: readU32(f[3]!),
      requestId: asRequestId(f[4]!),
      issuedAt: u64ToTime(readU64(f[5]!)),
      context,
      iv: asIv(f[7]!),
    },
    headerBytes,
    sealed: wire.slice(4 + hlen),
  };
}

export type SealInput = Omit<MsgHeader, "iv">;

/** §8.3 Seal. The IV is always generated here, never taken from the caller. */
export async function seal(key: CryptoKey, h: SealInput, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  checkPlaintextLength(plaintext.length, opts);
  const iv = newIv();
  const header = encodeHeader({ ...h, iv });
  const C = await aesGcmEncrypt(key, iv, plaintext, header);
  return concat(u32(header.length), header, C);
}

/**
 * Decrypts a parsed wire with the received header bytes as AAD.
 * Throws `reauth` on authentication failure (§8.3 step 4, §12.3).
 */
export async function openParsed(key: CryptoKey, p: ParsedWire): Promise<Bytes> {
  const pt = await aesGcmDecrypt(key, p.header.iv, p.sealed, p.headerBytes);
  if (pt === null) fail("reauth", "decryption failed");
  return pt;
}

/**
 * Convenience: parse, check the expected direction, then decrypt. Session
 * lookup, epoch acceptance and freshness checks belong to the caller,
 * between parse and decrypt (§8.3).
 */
export async function open(
  key: CryptoKey,
  wire: Uint8Array,
  expectDir: number,
  opts?: MsgOptions,
): Promise<{ header: MsgHeader; plaintext: Bytes }> {
  const p = parseWire(wire, opts);
  if (p.header.dir !== expectDir) fail("bad_request", "unexpected dir");
  return { header: p.header, plaintext: await openParsed(key, p) };
}

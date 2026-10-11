// Spec §8.3: message sealing and opening.
import { Byte4, Bytes } from "@wake-protocol/bytes";
import { type C2sCryptoKey, type S2cCryptoKey, aesGcmDecrypt, aesGcmEncrypt } from "../spec/crypto.ts";
import { fail } from "../spec/errors.ts";
import { newIv } from "../keys/ids.ts";
import { type DIR_C2S, type DIR_S2C, type MsgHeader, type MsgOptions, type ParsedWire, checkPlaintextLength, encodeHeader, parseWire } from "./header.ts";

export type SealInput = Omit<MsgHeader, "iv">;

/** A message key of either role. Internal: the public overloads pair each role with its direction. */
type MessageKey = C2sCryptoKey | S2cCryptoKey;

/**
 * Internal: seal with the IV already in `h`, for any message key. The public
 * overloads check the key role against `h.dir`; this function does not.
 * Shared with testing.ts (sealWithIv).
 *
 * Throws RangeError for out-of-range epoch/issuedAt, TypeError for an incompatible key.
 * §8.3 Seal logic: check the plaintext length, encode the header, encrypt, then format.
 */
export async function sealWithHeaderAnyKey(key: MessageKey, h: MsgHeader, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  checkPlaintextLength(plaintext.length, opts);
  const header = encodeHeader(h);
  const C = await aesGcmEncrypt(key, h.iv, plaintext, header);
  return Bytes.concat(new Byte4(header.length), header, C);
}

/**
 * Internal: decrypt a parsed wire for any message key, after checking the direction.
 * Shared by the public openParsed and open overloads.
 */
async function openParsedAnyKey(key: MessageKey, p: ParsedWire, expectDir: MsgHeader["dir"]): Promise<Bytes> {
  if (p.header.dir !== expectDir) fail("bad_request", "unexpected dir");
  const pt = await aesGcmDecrypt(key, p.header.iv, p.sealed, p.headerBytes);
  if (pt === null) fail("reauth", "decryption failed");
  return pt;
}

/**
 * Internal: seal with the IV already in `h`. Use seal() for real traffic.
 * The key role must match `h.dir`: a C2S key with DIR_C2S, an S2C key with DIR_S2C.
 *
 * Throws RangeError for out-of-range epoch/issuedAt, TypeError for an incompatible key.
 */
export function sealWithHeader(key: C2sCryptoKey, h: MsgHeader & { dir: typeof DIR_C2S }, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes>;
export function sealWithHeader(key: S2cCryptoKey, h: MsgHeader & { dir: typeof DIR_S2C }, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes>;
export function sealWithHeader(key: MessageKey, h: MsgHeader, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  return sealWithHeaderAnyKey(key, h, plaintext, opts);
}

/**
 * §8.3 Seal. The IV is always generated here, never taken from the caller.
 * The key role must match `h.dir`: a C2S key with DIR_C2S, an S2C key with DIR_S2C.
 * Throws RangeError for out-of-range epoch/issuedAt, TypeError for an incompatible key.
 */
export function seal(key: C2sCryptoKey, h: SealInput & { dir: typeof DIR_C2S }, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes>;
export function seal(key: S2cCryptoKey, h: SealInput & { dir: typeof DIR_S2C }, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes>;
export function seal(key: MessageKey, h: SealInput, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  return sealWithHeaderAnyKey(key, { ...h, iv: newIv() }, plaintext, opts);
}

/**
 * Decrypts a parsed wire with the received header bytes as AAD. `expectDir` is
 * checked against the parsed direction before decryption and throws `bad_request`
 * on mismatch (§12.3). Throws `reauth` on authentication failure (§8.3 step 4).
 * An incompatible local key throws TypeError.
 */
export function openParsed(key: C2sCryptoKey, p: ParsedWire, expectDir: typeof DIR_C2S): Promise<Bytes>;
export function openParsed(key: S2cCryptoKey, p: ParsedWire, expectDir: typeof DIR_S2C): Promise<Bytes>;
export function openParsed(key: MessageKey, p: ParsedWire, expectDir: MsgHeader["dir"]): Promise<Bytes> {
  return openParsedAnyKey(key, p, expectDir);
}

/**
 * Convenience: parse, check the expected direction, then decrypt. Session
 * lookup, epoch acceptance and freshness checks belong to the caller,
 * between parse and decrypt (§8.3). Malformed input throws WakeError;
 * an incompatible local key throws TypeError.
 */
export function open(
  key: C2sCryptoKey,
  wire: Bytes | Uint8Array,
  expectDir: typeof DIR_C2S,
  opts?: MsgOptions,
): Promise<{ header: MsgHeader; plaintext: Bytes }>;
export function open(
  key: S2cCryptoKey,
  wire: Bytes | Uint8Array,
  expectDir: typeof DIR_S2C,
  opts?: MsgOptions,
): Promise<{ header: MsgHeader; plaintext: Bytes }>;
export async function open(
  key: MessageKey,
  wire: Bytes | Uint8Array,
  expectDir: MsgHeader["dir"],
  opts?: MsgOptions,
): Promise<{ header: MsgHeader; plaintext: Bytes }> {
  const p = parseWire(wire, opts);
  return { header: p.header, plaintext: await openParsedAnyKey(key, p, expectDir) };
}

// Spec §8.3: message sealing and opening.
import { Byte4, Bytes } from "@wake-protocol/bytes";
import { type C2sCryptoKey, type S2cCryptoKey, aesGcmDecrypt, aesGcmEncrypt } from "../spec/crypto.ts";
import { fail } from "../spec/errors.ts";
import { newIv } from "../keys/ids.ts";
import { type MsgHeader, type MsgOptions, type ParsedWire, checkPlaintextLength, encodeHeader, parseWire } from "./header.ts";

export type SealInput = Omit<MsgHeader, "iv">;

/**
 * Internal: seal with the IV already in `h`. Use seal() for real traffic.
 *
 * Throws RangeError for out-of-range epoch/issuedAt, TypeError for an incompatible key.
 * §8.3 Seal logic: check the plaintext length, encode the header, encrypt, then format.
 */
export async function sealWithHeader(key: C2sCryptoKey | S2cCryptoKey, h: MsgHeader, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  checkPlaintextLength(plaintext.length, opts);
  const header = encodeHeader(h);
  const C = await aesGcmEncrypt(key, h.iv, plaintext, header);
  return Bytes.concat(new Byte4(header.length), header, C);
}

/**
 * §8.3 Seal. The IV is always generated here, never taken from the caller.
 * Throws RangeError for out-of-range epoch/issuedAt, TypeError for an incompatible key.
 */
export async function seal(key: C2sCryptoKey | S2cCryptoKey, h: SealInput, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  return sealWithHeader(key, { ...h, iv: newIv() }, plaintext, opts);
}

/**
 * Decrypts a parsed wire with the received header bytes as AAD.
 * Throws `reauth` on authentication failure (§8.3 step 4, §12.3).
 * An incompatible local key throws TypeError.
 */
export async function openParsed(key: C2sCryptoKey | S2cCryptoKey, p: ParsedWire): Promise<Bytes> {
  const pt = await aesGcmDecrypt(key, p.header.iv, p.sealed, p.headerBytes);
  if (pt === null) fail("reauth", "decryption failed");
  return pt;
}

/**
 * Convenience: parse, check the expected direction, then decrypt. Session
 * lookup, epoch acceptance and freshness checks belong to the caller,
 * between parse and decrypt (§8.3). Malformed input throws WakeError;
 * an incompatible local key throws TypeError.
 */
export async function open(
  key: C2sCryptoKey | S2cCryptoKey,
  wire: Bytes | Uint8Array,
  expectDir: MsgHeader["dir"],
  opts?: MsgOptions,
): Promise<{ header: MsgHeader; plaintext: Bytes }> {
  const p = parseWire(wire, opts);
  if (p.header.dir !== expectDir) fail("bad_request", "unexpected dir");
  return { header: p.header, plaintext: await openParsed(key, p) };
}

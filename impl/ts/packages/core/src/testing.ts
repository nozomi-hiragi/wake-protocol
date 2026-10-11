// Test-only encoding and helpers with fixed randomness (spec §16 vectors). Exposed as the
// testing package subpath, never from the main entry point.
import { Bytes } from "@wake-protocol/bytes";
import { importP256PrivateKey } from "@wake-protocol/crypto";
import { sealWithHeader } from "./msg/aead.ts";
import { type MsgHeader, type MsgOptions } from "./msg/header.ts";
import type { C2sCryptoKey, S2cCryptoKey } from "./spec/crypto.ts";
import type { EcPublicKey } from "./spec/types.ts";

/**
 * Seal with a caller-chosen IV. Never use for real traffic (IV reuse breaks AES-GCM).
 * Throws RangeError for out-of-range epoch/issuedAt or IV length, TypeError for an incompatible key.
 */
export async function sealWithIv(key: C2sCryptoKey | S2cCryptoKey, h: MsgHeader, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  return sealWithHeader(key, h, plaintext, opts);
}

/** Imports a P-256 private scalar (32 bytes) with its public point. */
export async function importEcdhPrivateKey(d: Bytes, publicKey: EcPublicKey): Promise<CryptoKey> {
  return importP256PrivateKey(d.toUint8Array(), publicKey.toUint8Array());
}

export { encodeChallengeInput } from "./kx/challenge.ts";

// Spec §5.1, §8.3: WAKE key imports and message AEAD adapters.
import { Bytes } from "@wake-protocol/bytes";
import * as crypto from "@wake-protocol/crypto";
import type { C2sKey, FinishedKeyC, FinishedKeyS, S2cKey } from "./types.ts";

export type C2sCryptoKey = CryptoKey & { readonly __keyRole: "c2s" };
export type S2cCryptoKey = CryptoKey & { readonly __keyRole: "s2c" };
export type FinishedCryptoKeyC = CryptoKey & { readonly __keyRole: "finishedC" };
export type FinishedCryptoKeyS = CryptoKey & { readonly __keyRole: "finishedS" };

/** Imports a Finished key, preserving its client/server role (§5.6). */
export function hmacKey(raw: FinishedKeyC, extractable?: boolean): Promise<FinishedCryptoKeyC>;
export function hmacKey(raw: FinishedKeyS, extractable?: boolean): Promise<FinishedCryptoKeyS>;
export function hmacKey(raw: FinishedKeyC | FinishedKeyS, extractable?: boolean): Promise<FinishedCryptoKeyC | FinishedCryptoKeyS>;
export function hmacKey(raw: FinishedKeyC | FinishedKeyS, extractable = false): Promise<FinishedCryptoKeyC | FinishedCryptoKeyS> {
  return crypto.hmacKey(raw.toUint8Array(), extractable) as Promise<FinishedCryptoKeyC | FinishedCryptoKeyS>;
}

/** Imports a message key, preserving its direction (§5.6). */
export function aesKey(raw: C2sKey, extractable?: boolean): Promise<C2sCryptoKey>;
export function aesKey(raw: S2cKey, extractable?: boolean): Promise<S2cCryptoKey>;
export function aesKey(raw: C2sKey | S2cKey, extractable?: boolean): Promise<C2sCryptoKey | S2cCryptoKey>;
export function aesKey(raw: C2sKey | S2cKey, extractable = false): Promise<C2sCryptoKey | S2cCryptoKey> {
  return crypto.aesKey(raw.toUint8Array(), extractable) as Promise<C2sCryptoKey | S2cCryptoKey>;
}

export async function aesGcmEncrypt(key: C2sCryptoKey | S2cCryptoKey, iv: Bytes, plaintext: Bytes, aad: Bytes): Promise<Bytes> {
  return new Bytes(await crypto.aesGcmEncrypt(key, iv.toUint8Array(), plaintext.toUint8Array(), aad.toUint8Array()));
}

export async function aesGcmDecrypt(key: C2sCryptoKey | S2cCryptoKey, iv: Bytes, ciphertext: Bytes, aad: Bytes): Promise<Bytes | null> {
  const result = await crypto.aesGcmDecrypt(key, iv.toUint8Array(), ciphertext.toUint8Array(), aad.toUint8Array());
  return result === null ? null : new Bytes(result);
}

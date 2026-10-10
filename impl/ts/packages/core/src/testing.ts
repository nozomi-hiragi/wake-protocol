// Test-only helpers with fixed randomness (spec §16 vectors). Exposed as the
// "@wake-protocol/core/testing" subpath, never from the main entry point.
import { type Bytes, b64u, concat, u32 } from "./encoding.ts";
import { aesGcmEncrypt } from "./crypto.ts";
import { checkPlaintextLength, encodeHeader, type MsgHeader, type MsgOptions } from "./msg.ts";
import type { EcPublicKey } from "./types.ts";

const subtle = globalThis.crypto.subtle;

/** Seal with a caller-chosen IV. Never use for real traffic (IV reuse breaks AES-GCM). */
export async function sealWithIv(key: CryptoKey, h: MsgHeader, plaintext: Bytes, opts?: MsgOptions): Promise<Bytes> {
  checkPlaintextLength(plaintext.length, opts);
  const H = encodeHeader(h);
  const C = await aesGcmEncrypt(key, h.iv, plaintext, H);
  return concat(u32(H.length), H, C);
}

/** Imports a P-256 private scalar (32 bytes) with its public point. */
export async function importEcdhPrivateKey(d: Bytes, publicKey: EcPublicKey): Promise<CryptoKey> {
  return subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: b64u(d), x: b64u(publicKey.slice(1, 33)), y: b64u(publicKey.slice(33)), ext: true },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
}

// Spec §5.1–5.2: primitives over the Web Crypto API (browser and Node alike).
import type { Bytes } from "./encoding.ts";
import { fail } from "./errors.ts";
import {
  type ApprovalId,
  type ApprovalNonce,
  type EcPublicKey,
  type ExchangeId,
  type Iv,
  type RequestId,
  type ServerNonce,
  type SessionId,
  type SharedSecret,
  type TaNonce,
  asApprovalId,
  asApprovalNonce,
  asExchangeId,
  asIv,
  asRequestId,
  asServerNonce,
  asSessionId,
  asSharedSecret,
  asTaNonce,
} from "./types.ts";

const subtle = globalThis.crypto.subtle;

export function randomBytes(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// Random generators return branded values of the spec's fixed lengths.
export const newSessionId = (): SessionId => asSessionId(randomBytes(32));
export const newExchangeId = (): ExchangeId => asExchangeId(randomBytes(16));
export const newRequestId = (): RequestId => asRequestId(randomBytes(16));
export const newApprovalId = (): ApprovalId => asApprovalId(randomBytes(16));
export const newServerNonce = (): ServerNonce => asServerNonce(randomBytes(32));
export const newApprovalNonce = (): ApprovalNonce => asApprovalNonce(randomBytes(32));
export const newTaNonce = (): TaNonce => asTaNonce(randomBytes(16));
/** Fresh 96-bit GCM IV (§8.3). */
export const newIv = (): Iv => asIv(randomBytes(12));

export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

export async function hmacKey(raw: Bytes, extractable = false): Promise<CryptoKey> {
  return subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, extractable, ["sign", "verify"]);
}

export async function hmac(key: CryptoKey | Bytes, data: Bytes): Promise<Bytes> {
  const k = key instanceof Uint8Array ? await hmacKey(key) : key;
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

/** Constant-time verification via subtle.verify (§5.7). */
export async function hmacVerify(key: CryptoKey | Bytes, data: Bytes, mac: Bytes): Promise<boolean> {
  const k = key instanceof Uint8Array ? await hmacKey(key) : key;
  return subtle.verify("HMAC", k, mac, data);
}

export async function hkdf(ikm: Bytes, salt: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, length * 8));
}

export async function aesKey(raw: Bytes, extractable = false): Promise<CryptoKey> {
  if (raw.length !== 32) fail("invalid_key", "AES-256 key must be 32 bytes");
  return subtle.importKey("raw", raw, "AES-GCM", extractable, ["encrypt", "decrypt"]);
}

export async function aesGcmEncrypt(key: CryptoKey, iv: Iv, plaintext: Bytes, aad: Bytes): Promise<Bytes> {
  return new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plaintext),
  );
}

/** Returns null on authentication failure. */
export async function aesGcmDecrypt(key: CryptoKey, iv: Iv, ciphertext: Bytes, aad: Bytes): Promise<Bytes | null> {
  try {
    return new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, ciphertext),
    );
  } catch {
    return null;
  }
}

// --- ECDH P-256 (§5.2) ---

export interface EphemeralKeyPair {
  privateKey: CryptoKey;
  publicKey: EcPublicKey;
}

export async function generateEphemeral(extractable = false): Promise<EphemeralKeyPair> {
  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, extractable, ["deriveBits"]);
  const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, publicKey: await parseEcPublicKey(raw) };
}

/**
 * Boundary check for a received public key: 65 bytes, 0x04 prefix, and
 * importKey verifies the point is on the curve (§5.2).
 */
export async function parseEcPublicKey(raw: Bytes): Promise<EcPublicKey> {
  if (raw.length !== 65 || raw[0] !== 0x04) fail("invalid_public_key", "not a 65-byte uncompressed point");
  try {
    await subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  } catch {
    fail("invalid_public_key", "point not on curve");
  }
  return raw as EcPublicKey;
}

/** Shared secret: fixed-length 32-byte x coordinate (§5.2). */
export async function ecdh(privateKey: CryptoKey, peerPublicKey: EcPublicKey): Promise<SharedSecret> {
  const pub = await subtle.importKey("raw", peerPublicKey, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ss = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256));
  return asSharedSecret(ss);
}

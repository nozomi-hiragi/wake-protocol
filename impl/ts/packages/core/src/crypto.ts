// Spec §5.1–5.2: primitives over the Web Crypto API (browser and Node alike).
import { type Bytes, b64u } from "./encoding.ts";
import { fail } from "./errors.ts";

const subtle = globalThis.crypto.subtle;

export function randomBytes(n: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

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

export async function aesGcmEncrypt(key: CryptoKey, iv: Bytes, plaintext: Bytes, aad: Bytes): Promise<Bytes> {
  return new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plaintext),
  );
}

/** Returns null on authentication failure. */
export async function aesGcmDecrypt(key: CryptoKey, iv: Bytes, ciphertext: Bytes, aad: Bytes): Promise<Bytes | null> {
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
  /** 65-byte SEC1 uncompressed point. */
  publicKey: Bytes;
}

export async function generateEphemeral(extractable = false): Promise<EphemeralKeyPair> {
  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, extractable, ["deriveBits"]);
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)) };
}

/**
 * Checks length and prefix before import, then lets importKey verify the
 * point is on the curve (§5.2).
 */
export async function importPeerPublicKey(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 65 || raw[0] !== 0x04) fail("invalid_public_key", "not a 65-byte uncompressed point");
  try {
    return await subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  } catch {
    fail("invalid_public_key", "point not on curve");
  }
}

/** Shared secret: fixed-length 32-byte x coordinate (§5.2). */
export async function ecdh(privateKey: CryptoKey, peerPublicKey: Bytes): Promise<Bytes> {
  const pub = await importPeerPublicKey(peerPublicKey);
  const ss = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256));
  if (ss.length !== 32) fail("internal", "unexpected shared secret length");
  return ss;
}

/** Imports a P-256 private scalar (32 bytes) with its public point, for test vectors. */
export async function importEcdhPrivateKey(d: Bytes, publicKey: Bytes): Promise<CryptoKey> {
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) fail("invalid_public_key");
  return subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: b64u(d), x: b64u(publicKey.slice(1, 33)), y: b64u(publicKey.slice(33)), ext: true },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
}

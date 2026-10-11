// Random bytes, SHA-256, HMAC-SHA-256 and HKDF-SHA-256.

const subtle = globalThis.crypto.subtle;

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(data);
  return new Uint8Array(await subtle.digest("SHA-256", input));
}

export async function hmacKey(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  return subtle.importKey("raw", new Uint8Array(raw), { name: "HMAC", hash: "SHA-256" }, extractable, ["sign", "verify"]);
}

export async function hmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.sign("HMAC", key, new Uint8Array(data)));
}

/** Constant-time verification via subtle.verify. */
export async function hmacVerify(key: CryptoKey, data: Uint8Array, mac: Uint8Array): Promise<boolean> {
  return subtle.verify("HMAC", key, new Uint8Array(mac), new Uint8Array(data));
}

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", new Uint8Array(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt), info: new Uint8Array(info) }, k, length * 8));
}

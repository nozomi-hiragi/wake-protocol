// AES-256-GCM with a 128-bit tag.

const subtle = globalThis.crypto.subtle;

function checkKeyAndIv(key: CryptoKey, iv: Uint8Array, usage: "encrypt" | "decrypt"): void {
  const algorithm = key.algorithm as AesKeyAlgorithm;
  if (algorithm.name !== "AES-GCM" || algorithm.length !== 256 || !key.usages.includes(usage)) {
    throw new TypeError(`key must be AES-256-GCM with ${usage} usage`);
  }
  if (iv.length !== 12) throw new RangeError("AES-GCM IV must be 12 bytes");
}

/** Throws RangeError unless `raw` is 32 bytes. */
export async function aesKey(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  if (raw.length !== 32) throw new RangeError("AES-256 key must be 32 bytes");
  return subtle.importKey("raw", new Uint8Array(raw), "AES-GCM", extractable, ["encrypt", "decrypt"]);
}

/** Throws TypeError for an incompatible key, RangeError unless the IV is 12 bytes. */
export async function aesGcmEncrypt(key: CryptoKey, iv: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  checkKeyAndIv(key, iv, "encrypt");
  return new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(iv), additionalData: new Uint8Array(aad), tagLength: 128 }, key, new Uint8Array(plaintext)),
  );
}

/** Returns null only on authentication failure; key/IV errors and other failures propagate. */
export async function aesGcmDecrypt(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array | null> {
  checkKeyAndIv(key, iv, "decrypt");
  try {
    return new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv), additionalData: new Uint8Array(aad), tagLength: 128 }, key, new Uint8Array(ciphertext)),
    );
  } catch (e) {
    if (e instanceof DOMException && e.name === "OperationError") return null;
    throw e;
  }
}

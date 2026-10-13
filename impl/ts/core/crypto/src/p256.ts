// ECDH over P-256. Public keys are 65-byte SEC1 uncompressed points.
import { base64urlnopad } from "@scure/base";

const subtle = globalThis.crypto.subtle;
const ALG = { name: "ECDH", namedCurve: "P-256" } as const;

export interface P256KeyPair {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
}

export async function generateP256KeyPair(extractable = false): Promise<P256KeyPair> {
  const kp = await subtle.generateKey(ALG, extractable, ["deriveBits"]);
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)) };
}

/** Throws RangeError unless `raw` is an uncompressed point (0x04, 65 bytes) on the curve. */
export async function checkP256PublicKey(raw: Uint8Array): Promise<void> {
  if (raw.length !== 65 || raw.at(0) !== 0x04) throw new RangeError("not a 65-byte uncompressed point");
  try {
    await subtle.importKey("raw", new Uint8Array(raw), ALG, false, []);
  } catch {
    throw new RangeError("point not on curve");
  }
}

/** The 32-byte x coordinate of the shared point. */
export async function p256SharedSecret(privateKey: CryptoKey, peerPublicKey: Uint8Array): Promise<Uint8Array> {
  const pub = await subtle.importKey("raw", new Uint8Array(peerPublicKey), ALG, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256));
}

/** Imports a P-256 private scalar (32 bytes) with its public point. */
export async function importP256PrivateKey(d: Uint8Array, publicKey: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: base64urlnopad.encode(d), x: base64urlnopad.encode(publicKey.slice(1, 33)), y: base64urlnopad.encode(publicKey.slice(33)), ext: true },
    ALG,
    false,
    ["deriveBits"],
  );
}

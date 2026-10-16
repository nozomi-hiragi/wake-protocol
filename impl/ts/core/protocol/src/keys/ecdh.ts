// Spec §5.2: ephemeral P-256 keys and shared secrets.
import { checkP256PublicKey, generateP256KeyPair, p256SharedSecret } from "@wake-protocol/crypto";
import { Bytes } from "@wake-protocol/bytes";
import { remapAsync } from "../spec/errors.ts";
import {
  type EcPublicKey,
  type SharedSecret,
  asSharedSecret,
} from "../spec/types.ts";

export interface EphemeralKeyPair {
  privateKey: CryptoKey;
  publicKey: EcPublicKey;
}

export async function generateEphemeral(extractable = false): Promise<EphemeralKeyPair> {
  const kp = await generateP256KeyPair(extractable);
  return { privateKey: kp.privateKey, publicKey: await parseEcPublicKey(kp.publicKey) };
}

/**
 * Boundary check for a received public key: 65 bytes, 0x04 prefix, and the
 * point is on the curve (§5.2).
 */
export async function parseEcPublicKey(input: Bytes | Uint8Array): Promise<EcPublicKey> {
  const raw = input instanceof Bytes ? input : new Bytes(input);
  await remapAsync("invalid_public_key", () => checkP256PublicKey(raw.toUint8Array()));
  return raw as EcPublicKey;
}

/** Shared secret: fixed-length 32-byte x coordinate (§5.2). */
export async function ecdh(privateKey: CryptoKey, peerPublicKey: EcPublicKey): Promise<SharedSecret> {
  return asSharedSecret(await p256SharedSecret(privateKey, peerPublicKey.toUint8Array()));
}

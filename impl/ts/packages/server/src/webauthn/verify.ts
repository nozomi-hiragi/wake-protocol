// Spec §6.2–§6.4: assertion validation for the KX ceremony.
import { Bytes, decodeBase64urlField, parseJsonObject, WakeError } from "@wake-protocol/core";
import type { WebAuthnChallenge } from "@wake-protocol/core";
import { utf8ToBytes } from "@wake-protocol/codec";
import {
  ecdsaDerToRaw,
  importP256SpkiPublicKey,
  p256EcdsaVerify,
  sha256,
} from "@wake-protocol/crypto";
import { isObject } from "../http.ts";
import type { ServerOptions } from "../options.ts";
import type { ExchangeUser, WakeCredential } from "../store/types.ts";

function fail(): never {
  throw new WakeError("auth_failed");
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return new Bytes(a).equals(new Bytes(b));
}

export interface VerifiedAssertion {
  credential: WakeCredential;
  signCount: number;
  origin: string;
  counterAnomaly: boolean;
}

// §6.2 steps 1–3: client data, challenge and origin.
function checkClientData(
  clientData: Uint8Array,
  challenge: WebAuthnChallenge,
  options: ServerOptions,
): string {
  const cd = parseJsonObject(clientData, "auth_failed");
  if (cd.type !== "webauthn.get" || !equal(decodeBase64urlField(cd.challenge, "auth_failed", 32), challenge.toUint8Array())) {
    fail();
  }
  if (typeof cd.origin !== "string" || !options.loginOrigins.includes(cd.origin)) {
    fail();
  }
  if ((cd.crossOrigin !== undefined && cd.crossOrigin !== false) || "topOrigin" in cd) {
    fail();
  }
  return cd.origin;
}

// §6.2 steps 4–5: RP binding, presence and verification flags.
async function checkAuthenticatorData(authData: Uint8Array, rpId: string): Promise<void> {
  if (authData.length < 37 || !equal(authData.slice(0, 32), await sha256(utf8ToBytes(rpId)))) {
    fail();
  }
  const flags = authData[32]!;
  if (
    (flags & 0x05) !== 0x05 ||
    (flags & 0x40) !== 0 ||
    ((flags & 0x80) === 0 && authData.length !== 37) ||
    // ED set requires extension data after the fixed 37 bytes.
    ((flags & 0x80) !== 0 && authData.length === 37) ||
    ((flags & 0x10) !== 0 && (flags & 0x08) === 0)
  ) {
    fail();
  }
}

// §6.2 step 6: an active credential must exist.
async function findCredential(rawId: Uint8Array, options: ServerOptions): Promise<WakeCredential> {
  const credential = await options.credentials.getCredential(rawId);
  if (!credential || credential.status !== "active" || credential.algorithm !== -7) {
    fail();
  }
  return credential;
}

// §6.2 step 7: strict ES256 DER signature over the received client data.
async function checkSignature(
  credential: WakeCredential,
  signature: Uint8Array,
  authData: Uint8Array,
  clientData: Uint8Array,
): Promise<void> {
  let rawSignature: Uint8Array;
  try {
    rawSignature = ecdsaDerToRaw(signature, 32);
  } catch (e) {
    if (e instanceof RangeError || e instanceof TypeError || e instanceof SyntaxError) {
      fail();
    }
    throw e;
  }
  const key = await importP256SpkiPublicKey(credential.publicKey);
  const signed = Bytes.concat(new Bytes(authData), new Bytes(await sha256(clientData)));
  if (!await p256EcdsaVerify(key, rawSignature, signed.toUint8Array())) {
    fail();
  }
}

// §6.2 steps 8–9: optional handle and requested user binding.
function checkUser(
  userHandle: unknown,
  credential: WakeCredential,
  user: ExchangeUser,
): void {
  if (userHandle !== undefined && userHandle !== null && !equal(decodeBase64urlField(userHandle, "auth_failed"), credential.userHandle)) {
    fail();
  }
  // Username mode with an unknown user (null) can never succeed.
  if (user.mode === "username" && (user.requestedUserId === null || credential.userId !== user.requestedUserId)) {
    fail();
  }
}

// §6.2 step 10, §6.4: registered backup eligibility controls anomaly acceptance.
function checkCounter(credential: WakeCredential, signCount: number): boolean {
  const anomaly = credential.signCount > 0 && signCount <= credential.signCount;
  if (anomaly && !credential.backupEligible) {
    fail();
  }
  return anomaly;
}

export async function verifyAssertion(
  assertion: Record<string, unknown>,
  challenge: WebAuthnChallenge,
  user: ExchangeUser,
  options: ServerOptions,
): Promise<VerifiedAssertion> {
  if (assertion.type !== "public-key" || !isObject(assertion.response)) {
    fail();
  }
  const rawId = decodeBase64urlField(assertion.rawId, "auth_failed");
  const assertionId = decodeBase64urlField(assertion.id, "auth_failed");
  if (!rawId.length || !equal(rawId, assertionId)) {
    fail();
  }
  const response = assertion.response;
  const clientData = decodeBase64urlField(response.clientDataJSON, "auth_failed");
  const authData = decodeBase64urlField(response.authenticatorData, "auth_failed");
  const signature = decodeBase64urlField(response.signature, "auth_failed");
  const origin = checkClientData(clientData, challenge, options);
  await checkAuthenticatorData(authData, options.rpId);
  const credential = await findCredential(rawId, options);
  await checkSignature(credential, signature, authData, clientData);
  checkUser(response.userHandle, credential, user);
  const signCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0, false);
  const counterAnomaly = checkCounter(credential, signCount);
  return { credential, signCount, origin, counterAnomaly };
}

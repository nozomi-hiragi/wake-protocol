// Spec Appendix C, §5.4–§5.5, §6.2 and §10.3–§10.4: offline approval verification.
import { hex } from "@scure/base";
import { Bytes } from "@wake-protocol/bytes";
import { utf8ToBytes } from "@wake-protocol/codec";
import { ecdsaDerToRaw, importP256SpkiPublicKey, p256EcdsaVerify, sha256 } from "@wake-protocol/crypto";
import { taBinding } from "../kx/binding.ts";
import { taChallenge, taKrChallenge } from "../kx/challenge.ts";
import { fail, remap, WakeError } from "../spec/errors.ts";
import { decodeBase64urlField, parseJsonObject } from "../spec/json.ts";
import { asApprovalId, asApprovalNonce, asRekeyTranscriptHash, asSessionId, asTaNonce } from "../spec/types.ts";
import { checkContent } from "./content.ts";
import { hashInput, operationId, parseOperationIdHex } from "./operation.ts";

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_bundle");
  }
  return value as Record<string, unknown>;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return new Bytes(a).equals(new Bytes(b));
}

/**
 * Accepts a parsed JSON object, JSON text, or UTF-8 JSON bytes. SPKI replaces Appendix C's COSE_Key.
 * The caller supplies the expected rpId (Appendix C step 4); the bundle's own rpId is never trusted.
 * A valid signature does not establish credential ownership, operation status, or the KR transcript's provenance.
 */
export async function verifyApprovalBundle(bundle: unknown, opts: { rpId: string; origins: readonly string[] }): Promise<true> {
  let input: Record<string, unknown>;
  if (bundle instanceof Uint8Array) {
    input = parseJsonObject(bundle, "invalid_bundle");
  } else if (typeof bundle === "string") {
    input = parseJsonObject(remap("invalid_bundle", () => utf8ToBytes(bundle)), "invalid_bundle");
  } else {
    object(bundle);
    const json = remap("invalid_bundle", () => JSON.stringify(bundle));
    input = parseJsonObject(remap("invalid_bundle", () => utf8ToBytes(json)), "invalid_bundle");
  }
  if (input.format !== "WAKE/1 ta-bundle" || typeof input.rpId !== "string" || input.rpId.length === 0 ||
      typeof input.content !== "string") {
    fail("invalid_bundle");
  }
  if (typeof opts.rpId !== "string" || opts.rpId.length === 0) {
    throw new WakeError("invalid_option");
  }
  if (input.rpId !== opts.rpId) {
    fail("bundle_rp_id_mismatch");
  }
  checkContent(input.content);
  if (typeof input.nonce !== "string" || !/^[0-9a-f]{32}$/u.test(input.nonce) ||
      typeof input.operationId !== "string" || !/^[0-9a-f]{64}$/u.test(input.operationId)) {
    fail("invalid_bundle");
  }
  const id = parseOperationIdHex(input.operationId);
  const computed = await operationId(hashInput(input.content, asTaNonce(hex.decode(input.nonce))));
  if (!id.equals(computed)) {
    fail("bundle_operation_mismatch");
  }
  const approval = object(input.approval);
  const ta = await taBinding({
    approvalId: asApprovalId(decodeBase64urlField(approval.approvalId, "invalid_bundle", 16)),
    operationId: id,
    approvalNonce: asApprovalNonce(decodeBase64urlField(approval.approvalNonce, "invalid_bundle", 32)),
    sessionId: asSessionId(decodeBase64urlField(approval.sessionId, "invalid_bundle", 32)),
  });
  const challenge = approval.th === null ? await taChallenge(ta) : await taKrChallenge(
    asRekeyTranscriptHash(decodeBase64urlField(approval.th, "invalid_bundle", 32)), ta,
  );
  const clientData = decodeBase64urlField(approval.clientDataJSON, "invalid_bundle");
  const cd = parseJsonObject(clientData, "bundle_client_data_invalid");
  if (cd.type !== "webauthn.get") {
    fail("bundle_client_data_invalid");
  }
  if (!equal(decodeBase64urlField(cd.challenge, "bundle_challenge_mismatch", 32), challenge.toUint8Array())) {
    fail("bundle_challenge_mismatch");
  }
  if (typeof cd.origin !== "string" || !opts.origins.includes(cd.origin) ||
      (cd.crossOrigin !== undefined && cd.crossOrigin !== false) || "topOrigin" in cd) {
    fail("bundle_origin_invalid");
  }
  const authData = decodeBase64urlField(approval.authenticatorData, "invalid_bundle");
  if (authData.length < 37) {
    fail("bundle_authenticator_data_invalid");
  }
  if (!equal(authData.slice(0, 32), await sha256(utf8ToBytes(opts.rpId)))) {
    fail("bundle_rp_id_mismatch");
  }
  const flags = authData[32]!;
  if ((flags & 0x05) !== 0x05 || (flags & 0x40) !== 0 ||
      ((flags & 0x80) === 0 && authData.length !== 37) ||
      ((flags & 0x80) !== 0 && authData.length === 37) ||
      ((flags & 0x10) !== 0 && (flags & 0x08) === 0)) {
    fail("bundle_authenticator_data_invalid");
  }
  const spki = decodeBase64urlField(approval.credentialPublicKey, "bundle_public_key_invalid");
  let key: CryptoKey;
  try {
    key = await importP256SpkiPublicKey(spki);
  } catch (e) {
    if (e instanceof DOMException && e.name === "DataError") {
      fail("bundle_public_key_invalid");
    }
    throw e;
  }
  const signature = remap("bundle_signature_invalid", () => ecdsaDerToRaw(
    decodeBase64urlField(approval.signature, "bundle_signature_invalid"), 32,
  ));
  const signed = Bytes.concat(new Bytes(authData), new Bytes(await sha256(clientData)));
  if (!await p256EcdsaVerify(key, signature, signed.toUint8Array())) {
    throw new WakeError("bundle_signature_invalid");
  }
  return true;
}

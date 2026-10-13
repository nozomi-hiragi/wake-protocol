// Spec §10.3, §4.5: operation identity and its external form.
import { hex } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { sha256 } from "@wake-protocol/crypto";
import { fail, remap } from "../spec/errors.ts";
import { type OperationId, type TaNonce, asOperationId } from "../spec/types.ts";
import { checkContent } from "./content.ts";

export function hashInput(content: string, nonce: TaNonce): string {
  return `${content}\nWAKE-TA-Nonce: ${hex.encode(nonce.toUint8Array())}`;
}

export async function operationId(hashInputStr: string): Promise<OperationId> {
  return asOperationId(await sha256(remap("invalid_utf8", () => utf8ToBytes(hashInputStr))));
}

/** External form of operationId: exactly 64 lowercase hex characters (§4.5). */
export function parseOperationIdHex(s: string): OperationId {
  if (!/^[0-9a-f]{64}$/.test(s)) fail("bad_request", "operationId must be 64 lowercase hex characters");
  return asOperationId(hex.decode(s));
}

/** Validates content and computes the operation identity (§10.2 step 2–3). */
export async function createOperationIdentity(content: string, nonce: TaNonce): Promise<{ hashInput: string; operationId: string }> {
  checkContent(content);
  const hi = hashInput(content, nonce);
  return { hashInput: hi, operationId: hex.encode((await operationId(hi)).toUint8Array()) };
}

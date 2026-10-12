// Spec §10.2, §10.9, §10.10, Appendix C: server-side operation API (never reachable by users).
import { base64urlnopad, hex } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { createOperationIdentity, newTaNonce, WakeError } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { OperationDecision, OperationRecord, OperationStatus } from "../store/types.ts";
import { operationIdParam } from "./params.ts";

export interface CreateOperationInput {
  content: string;
  approverUserId: string;
  expiresAt: number;
}

export interface CreatedOperation {
  operationId: string;
  nonce: string;
  hashInput: string;
  expiresAt: number;
}

export interface OperationView {
  operationId: string;
  status: OperationStatus;
  content: string;
  nonce: string;
  approverUserId: string;
  createdAt: number;
  expiresAt: number;
  decidedAt: number | null;
  /** Present once decided; for APPROVED it is the §10.10 record. */
  decision: OperationDecision | null;
}

const MAX_NONCE_ATTEMPTS = 8;

function checkInput(input: CreateOperationInput, options: ServerOptions): void {
  if (typeof input !== "object" || input === null || typeof input.content !== "string") {
    throw new WakeError("invalid_request");
  }
  const user = input.approverUserId;
  if (typeof user !== "string" || !user.isWellFormed() || utf8ToBytes(user).length < 1 || utf8ToBytes(user).length > 256) {
    throw new WakeError("invalid_request");
  }
  const now = options.now();
  if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now || input.expiresAt > now + options.maxOperationLifetimeMs) {
    throw new WakeError("invalid_request");
  }
}

/** Throws invalid_content for a content profile violation and invalid_request for the other inputs. */
export async function createOperation(input: CreateOperationInput, options: ServerOptions): Promise<CreatedOperation> {
  checkInput(input, options);
  for (let attempt = 0; attempt < MAX_NONCE_ATTEMPTS; attempt++) {
    const taNonce = newTaNonce();
    const nonce = hex.encode(taNonce.toUint8Array());
    const identity = await createOperationIdentity(input.content, taNonce);
    const created = await options.store.createOperation({
      operationId: identity.operationId,
      content: input.content,
      nonce,
      approverUserId: input.approverUserId,
      status: "PENDING",
      createdAt: options.now(),
      expiresAt: input.expiresAt,
    });
    // §10.2 step 4: on a collision draw a new nonce; never return the existing operation.
    if (created) {
      return { operationId: identity.operationId, nonce, hashInput: identity.hashInput, expiresAt: input.expiresAt };
    }
  }
  throw new Error("operationId collided repeatedly");
}

export async function cancelOperation(
  operationId: string,
  options: ServerOptions,
): Promise<"cancelled" | "already_decided" | "expired"> {
  const result = await options.store.cancelOperation(operationIdParam(operationId), options.now());
  if (result === "not_found") {
    throw new WakeError("not_found");
  }
  return result;
}

function decidedAt(op: OperationRecord): number | null {
  return op.decision?.decidedAt ?? null;
}

/** Returns null for an unknown operation. Never trust a client-reported outcome instead of this record (§10.10). */
export async function getOperation(operationId: string, options: ServerOptions): Promise<OperationView | null> {
  const op = await options.store.getOperation(operationIdParam(operationId), options.now());
  if (!op) {
    return null;
  }
  return {
    operationId: op.operationId,
    status: op.status,
    content: op.content,
    nonce: op.nonce,
    approverUserId: op.approverUserId,
    createdAt: op.createdAt,
    expiresAt: op.expiresAt,
    decidedAt: decidedAt(op),
    decision: op.decision ?? null,
  };
}

/** Appendix C document for an APPROVED operation, or null; credentialPublicKey is SPKI instead of COSE_Key. */
export async function exportApprovalBundle(operationId: string, options: ServerOptions): Promise<Record<string, unknown> | null> {
  const op = await options.store.getOperation(operationIdParam(operationId), options.now());
  const d = op?.decision;
  if (!op || d?.kind !== "approved") {
    return null;
  }
  const b64 = (bytes: Uint8Array) => base64urlnopad.encode(bytes);
  return {
    format: "WAKE/1 ta-bundle",
    rpId: options.rpId,
    operationId: op.operationId,
    content: op.content,
    nonce: op.nonce,
    approval: {
      approvalId: b64(d.approvalId),
      approvalNonce: b64(d.approvalNonce),
      sessionId: b64(d.sessionId),
      th: d.th ? b64(d.th) : null,
      credentialPublicKey: b64(d.credentialPublicKey),
      authenticatorData: b64(d.authenticatorData),
      clientDataJSON: b64(d.clientDataJSON),
      signature: b64(d.signature),
    },
  };
}

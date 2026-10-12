// Spec §10.6: wake/ta/challenge issues a single-use approval attempt, optionally with a bound KR exchange.
import { base64urlnopad } from "@scure/base";
import { newApprovalId, newApprovalNonce, WakeError } from "@wake-protocol/core";
import { prepareRekey, rekeyOffer } from "../kr/start.ts";
import type { ServerOptions } from "../options.ts";
import type { SessionRecord } from "../store/types.ts";
import { sessionWebauthnOptions } from "../webauthn/options.ts";
import { operationIdParam } from "./params.ts";

export async function challengeApproval(
  body: Record<string, unknown>,
  session: SessionRecord,
  options: ServerOptions,
): Promise<unknown> {
  const operationId = operationIdParam(body.operationId);
  if (typeof body.rekey !== "boolean") {
    throw new WakeError("invalid_request");
  }
  const op = await options.store.getOperation(operationId, options.now());
  if (!op || op.approverUserId !== session.userId) {
    throw new WakeError("not_found");
  }
  const webauthn = await sessionWebauthnOptions(session, options);
  const approvalId = newApprovalId();
  const rekey = body.rekey ? await prepareRekey(session, options, approvalId) : null;
  const now = options.now();
  const attempt = {
    approvalId,
    operationId,
    sessionId: session.sessionId,
    approvalNonce: newApprovalNonce(),
    state: "PENDING" as const,
    createdAt: now,
    expiresAt: now + options.approvalTtlMs,
    ...(rekey ? { krExchangeId: rekey.record.exchangeId } : {}),
  };
  const result = await options.store.createApproval({ attempt, rekey, maxActiveApprovals: options.maxActiveApprovals, now });
  if (result !== "created") {
    throw new WakeError(result);
  }
  return {
    approvalId: base64urlnopad.encode(approvalId.toUint8Array()),
    approvalNonce: base64urlnopad.encode(attempt.approvalNonce.toUint8Array()),
    expiresAt: attempt.expiresAt,
    webauthn,
    kr: rekey ? rekeyOffer(rekey.record) : null,
  };
}

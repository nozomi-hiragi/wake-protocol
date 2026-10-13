// Spec §9.2, §9.4, §10.6: reserve a session-bound rekey exchange with atomic pending-limit eviction.
import { base64urlnopad } from "@scure/base";
import { generateEphemeral, newExchangeId, newServerNonce, WakeError } from "@wake-protocol/core";
import type { ApprovalId } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { ExchangeRecord, RekeyStart, SessionRecord } from "../store/types.ts";
import { sessionWebauthnOptions } from "../webauthn/options.ts";

/** Builds a PENDING rekey exchange for the session's next epoch, optionally bound to a TA approval attempt (§10.8). */
export async function prepareRekey(
  session: SessionRecord,
  options: ServerOptions,
  boundApprovalId?: ApprovalId,
): Promise<RekeyStart> {
  if (!session.currentKeys || session.currentEpoch === 0xffffffff) {
    throw new WakeError("reauth");
  }
  const ephemeral = await generateEphemeral();
  const now = options.now();
  const expiresAt = now + options.exchangeTtlMs;
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) {
    throw new RangeError("exchange expiration");
  }
  const record: ExchangeRecord = {
    exchangeId: newExchangeId(),
    sessionId: session.sessionId,
    kind: "rekey",
    state: "PENDING",
    mode: "discoverable",
    targetEpoch: session.currentEpoch + 1,
    prevTh: session.currentKeys.th,
    createdAt: now,
    serverNonce: newServerNonce(),
    serverPublicKey: ephemeral.publicKey,
    serverPrivateKey: ephemeral.privateKey,
    expiresAt,
    ...(boundApprovalId ? { boundApprovalId } : {}),
  };
  return { record, expectedEpoch: session.currentEpoch, now, maxPendingRekeys: options.maxPendingRekeys };
}

/** The exchange members shared by wake/kr/start and wake/ta/challenge. */
export function rekeyOffer(record: ExchangeRecord): Record<string, unknown> {
  return {
    exchangeId: base64urlnopad.encode(record.exchangeId.toUint8Array()),
    epoch: record.targetEpoch,
    serverNonce: base64urlnopad.encode(record.serverNonce.toUint8Array()),
    serverPublicKey: base64urlnopad.encode(record.serverPublicKey.toUint8Array()),
  };
}

export async function startRekey(session: SessionRecord, options: ServerOptions): Promise<unknown> {
  // The credential lookup comes first so the clock is read after any delay it causes.
  const webauthn = await sessionWebauthnOptions(session, options);
  const start = await prepareRekey(session, options);
  const result = await options.store.createRekey(start);
  if (result !== "created") {
    throw new WakeError(result);
  }
  return {
    ...rekeyOffer(start.record),
    expiresAt: start.record.expiresAt,
    webauthn,
  };
}

// Spec §9.2, §9.4: reserve a session-bound rekey exchange with atomic pending-limit eviction.
import { base64urlnopad } from "@scure/base";
import { generateEphemeral, newExchangeId, newServerNonce, WakeError } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { SessionRecord } from "../store/types.ts";

export async function startRekey(session: SessionRecord, options: ServerOptions): Promise<unknown> {
  if (!session.currentKeys || session.currentEpoch === 0xffffffff) {
    throw new WakeError("reauth");
  }
  const credentials = await options.credentials.findUserCredentials(session.userId);
  const ephemeral = await generateEphemeral();
  const exchangeId = newExchangeId();
  const serverNonce = newServerNonce();
  const now = options.now();
  const expiresAt = now + options.exchangeTtlMs;
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) {
    throw new RangeError("exchange expiration");
  }
  const epoch = session.currentEpoch + 1;
  const result = await options.store.createRekey({
    record: {
      exchangeId,
      sessionId: session.sessionId,
      kind: "rekey",
      state: "PENDING",
      mode: "discoverable",
      targetEpoch: epoch,
      prevTh: session.currentKeys.th,
      createdAt: now,
      serverNonce,
      serverPublicKey: ephemeral.publicKey,
      serverPrivateKey: ephemeral.privateKey,
      expiresAt,
    },
    expectedEpoch: session.currentEpoch,
    now,
    maxPendingRekeys: options.maxPendingRekeys,
  });
  if (result !== "created") {
    throw new WakeError(result);
  }
  return {
    exchangeId: base64urlnopad.encode(exchangeId.toUint8Array()),
    epoch,
    serverNonce: base64urlnopad.encode(serverNonce.toUint8Array()),
    serverPublicKey: base64urlnopad.encode(ephemeral.publicKey.toUint8Array()),
    expiresAt,
    webauthn: {
      rpId: options.rpId,
      allowCredentials: credentials.filter(c => c.status === "active" && c.userId === session.userId)
        .map(c => ({ type: "public-key", id: base64urlnopad.encode(c.credentialId) })),
      userVerification: "required",
      timeout: options.webauthnTimeoutMs,
    },
  };
}

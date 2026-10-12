// Spec §9.3–§9.4: session-bound rekey verification, atomic epoch advance and idempotent replay.
import { base64urlnopad } from "@scure/base";
import { constantTimeEqual } from "@wake-protocol/crypto";
import {
  aesKey,
  asClientFinishedMac,
  asExchangeId,
  decodeBase64urlField,
  deriveKeys,
  ecdh,
  krChallenge,
  parseEcPublicKey,
  rekeyTranscriptHash,
  serverFinished,
  verifyClientFinished,
  WakeError,
} from "@wake-protocol/core";
import type { ClientFinishedMac, EcPublicKey, RekeyTranscriptHash } from "@wake-protocol/core";
import { isObject } from "../http.ts";
import type { ServerOptions } from "../options.ts";
import type { ExchangeRecord, SessionRecord } from "../store/types.ts";
import { applySignCountUpdate, prepareSignCountUpdate } from "../webauthn/counter.ts";
import { checkAuthenticatedSession } from "../webauthn/finalize.ts";
import { verifyAssertion } from "../webauthn/verify.ts";

async function publicKey(value: unknown): Promise<EcPublicKey> {
  try {
    return await parseEcPublicKey(decodeBase64urlField(value, "invalid_request"));
  } catch (e) {
    if (e instanceof WakeError && e.code === "invalid_public_key") {
      throw new WakeError("invalid_request");
    }
    throw e;
  }
}

async function transcript(
  ex: ExchangeRecord,
  clientPublicKey: EcPublicKey,
  prevTh: SessionRecord["currentKeys"],
): Promise<RekeyTranscriptHash> {
  const previous = ex.state === "COMPLETED" ? ex.prevTh : prevTh?.th;
  if (!previous || ex.targetEpoch === undefined) {
    throw new WakeError("not_found");
  }
  return rekeyTranscriptHash({
    exchangeId: ex.exchangeId,
    sessionId: ex.sessionId,
    epoch: ex.targetEpoch,
    prevTh: previous,
    serverNonce: ex.serverNonce,
    serverPublicKey: ex.serverPublicKey,
    clientPublicKey,
  });
}

async function replay(
  ex: ExchangeRecord | null,
  th: RekeyTranscriptHash,
  mac: ClientFinishedMac,
  options: ServerOptions,
): Promise<string | null> {
  if (ex?.state !== "COMPLETED" || !ex.th || !ex.clientFinished || ex.response === undefined) {
    return null;
  }
  if (!ex.th.equals(th) || !constantTimeEqual(ex.clientFinished.toUint8Array(), mac.toUint8Array())) {
    throw new WakeError("webauthn_failed");
  }
  const retained = await options.store.getExchange(ex.exchangeId.toUint8Array(), options.now());
  if (retained?.state !== "COMPLETED") {
    return null;
  }
  await checkAuthenticatedSession(retained.sessionId, options, "reauth", retained.reauthenticatedCredentialId);
  if (retained.signCountUpdate) {
    await applySignCountUpdate(retained.signCountUpdate, retained.exchangeId.toUint8Array(), options);
  }
  await checkAuthenticatedSession(retained.sessionId, options, "reauth", retained.reauthenticatedCredentialId);
  return retained.response ?? null;
}

export async function completeRekey(
  body: Record<string, unknown>,
  session: SessionRecord,
  options: ServerOptions,
): Promise<unknown> {
  const exchangeId = asExchangeId(decodeBase64urlField(body.exchangeId, "invalid_request", 16));
  const mac = asClientFinishedMac(decodeBase64urlField(body.clientFinished, "invalid_request", 32));
  if (!isObject(body.assertion)) {
    throw new WakeError("invalid_request");
  }
  const ex = await options.store.getExchange(exchangeId.toUint8Array(), options.now());
  if (!ex || ex.kind !== "rekey" || !ex.sessionId.equals(session.sessionId) || ex.boundApprovalId !== undefined) {
    throw new WakeError("not_found");
  }
  if (ex.state !== "COMPLETED") {
    if (ex.state !== "PENDING" || options.now() >= ex.expiresAt || !ex.serverPrivateKey) {
      throw new WakeError("expired");
    }
    if (ex.targetEpoch !== session.currentEpoch + 1) {
      await options.store.supersedeExchange(exchangeId.toUint8Array());
      throw new WakeError("conflict");
    }
  }
  const clientPublicKey = await publicKey(body.clientPublicKey);
  const th = await transcript(ex, clientPublicKey, session.currentKeys);
  if (ex.state === "COMPLETED") {
    const cached = await replay(ex, th, mac, options);
    if (cached !== null) {
      return JSON.parse(cached) as unknown;
    }
    throw new WakeError("expired");
  }
  const verified = await verifyAssertion(body.assertion, await krChallenge(th), {
    origins: [session.establishedOrigin],
    requiredOrigin: session.establishedOrigin,
    userId: session.userId,
    errorCode: "webauthn_failed",
  }, options);
  const keys = await deriveKeys(await ecdh(ex.serverPrivateKey!, clientPublicKey), th);
  if (!await verifyClientFinished(keys.fkC, th, mac)) {
    throw new WakeError("webauthn_failed");
  }
  const currentKeys = {
    c2s: await aesKey(keys.kC2s),
    s2c: await aesKey(keys.kS2c),
    th,
    c2sCount: 0,
    s2cCount: 0,
  };
  const serverTime = options.now();
  const absoluteExpiresAt = Math.min(session.hardCapAt, serverTime + options.authLifetimeMs);
  const finished = await serverFinished(keys.fkS, {
    th,
    clientFinished: mac,
    serverTime,
    absoluteExpiresAt,
    idleTimeoutSec: session.idleTimeoutSec,
  });
  const response = JSON.stringify({
    epoch: ex.targetEpoch,
    serverTime,
    absoluteExpiresAt,
    idleTimeoutSec: session.idleTimeoutSec,
    serverFinished: base64urlnopad.encode(finished.toUint8Array()),
  });
  const prepared = await prepareSignCountUpdate(verified, options);
  if (!prepared.accepted) {
    const latest = await options.store.getExchange(exchangeId.toUint8Array(), options.now());
    const cached = await replay(latest, th, mac, options);
    if (cached !== null) {
      return JSON.parse(cached) as unknown;
    }
    throw new WakeError(latest?.state === "PENDING" ? "retry" : "webauthn_failed");
  }
  const committed = await options.store.commitRekey({
    exchangeId: exchangeId.toUint8Array(),
    sessionId: session.sessionId.toUint8Array(),
    expectedEpoch: session.currentEpoch,
    now: options.now(),
    authTime: serverTime,
    th,
    clientFinished: mac,
    response,
    currentKeys,
    absoluteExpiresAt,
    epochGraceMs: options.epochGraceMs,
    credentialId: verified.credential.credentialId,
    ...(prepared.update ? { signCountUpdate: prepared.update } : {}),
  });
  if (committed !== "committed") {
    const latest = await options.store.getExchange(exchangeId.toUint8Array(), options.now());
    const cached = await replay(latest, th, mac, options);
    if (cached !== null) {
      return JSON.parse(cached) as unknown;
    }
    throw new WakeError(committed);
  }
  await checkAuthenticatedSession(session.sessionId, options, "reauth", verified.credential.credentialId);
  if (prepared.update) {
    await applySignCountUpdate(prepared.update, exchangeId.toUint8Array(), options);
  }
  await checkAuthenticatedSession(session.sessionId, options, "reauth", verified.credential.credentialId);
  return JSON.parse(response) as unknown;
}

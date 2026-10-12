// Spec §7.5–§7.8: ordered login verification and atomic, idempotent commit.
import { base64urlnopad } from "@scure/base";
import { constantTimeEqual } from "@wake-protocol/crypto";
import {
  aesKey,
  asClientFinishedMac,
  asExchangeId,
  deriveKeys,
  ecdh,
  kxChallenge,
  decodeBase64urlField,
  loginTranscriptHash,
  parseEcPublicKey,
  parseJsonObject,
  serverFinished,
  verifyClientFinished,
  WakeError,
} from "@wake-protocol/core";
import type {
  ClientFinishedMac,
  EcPublicKey,
  ExchangeId,
  LoginTranscriptHash,
} from "@wake-protocol/core";
import { checkContentType, isObject, jsonTextResponse, readBody } from "../http.ts";
import type { ServerOptions } from "../options.ts";
import type { EpochKeys, ExchangeRecord, SessionRecord } from "../store/types.ts";
import { verifyAssertion } from "../webauthn/verify.ts";
import type { VerifiedAssertion } from "../webauthn/verify.ts";
import { applySignCountUpdate, prepareSignCountUpdate } from "../webauthn/counter.ts";
import { checkAuthenticatedSession } from "../webauthn/finalize.ts";

interface CompleteBody {
  exchangeId: ExchangeId;
  clientPublicKey: unknown;
  assertion: Record<string, unknown>;
  clientMac: ClientFinishedMac;
}

interface LoginResult {
  currentKeys: EpochKeys;
  now: number;
  absoluteExpiresAt: number;
  hardCapAt: number;
  response: string;
}

async function parseCompleteBody(req: Request, options: ServerOptions): Promise<CompleteBody> {
  checkContentType(req, "application/json");
  const body = parseJsonObject(await readBody(req, options.maxAuthBody, "bad_request"), "bad_request");
  const exchangeId = asExchangeId(decodeBase64urlField(body.exchangeId, "bad_request", 16));
  const clientMac = asClientFinishedMac(decodeBase64urlField(body.clientFinished, "bad_request", 32));
  if (!isObject(body.assertion)) {
    throw new WakeError("bad_request");
  }
  return { exchangeId, clientPublicKey: body.clientPublicKey, assertion: body.assertion, clientMac };
}

async function parseClientPublicKey(value: unknown): Promise<EcPublicKey> {
  try {
    return await parseEcPublicKey(decodeBase64urlField(value, "bad_request"));
  } catch (e) {
    if (e instanceof WakeError && e.code === "invalid_public_key") {
      throw new WakeError("bad_request");
    }
    throw e;
  }
}

async function replay(
  ex: ExchangeRecord | null,
  th: LoginTranscriptHash,
  mac: ClientFinishedMac,
  options: ServerOptions,
): Promise<Response | null> {
  if (ex?.state !== "COMPLETED" || !ex.th || !ex.clientFinished || ex.response === undefined) {
    return null;
  }
  // §7.6 skips WebAuthn re-verification; §5.7 requires constant-time Finished comparison.
  if (!ex.th.equals(th) || !constantTimeEqual(ex.clientFinished.toUint8Array(), mac.toUint8Array())) {
    throw new WakeError("auth_failed");
  }
  const retained = await options.store.getExchange(ex.exchangeId.toUint8Array(), options.now());
  if (!retained || retained.state !== "COMPLETED") {
    return null;
  }
  await checkAuthenticatedSession(retained.sessionId, options, "auth_failed");
  if (retained.signCountUpdate) {
    await applySignCountUpdate(retained.signCountUpdate, retained.exchangeId.toUint8Array(), options);
  }
  return jsonTextResponse(ex.response);
}

async function verifyLogin(
  ex: ExchangeRecord,
  body: CompleteBody,
  th: LoginTranscriptHash,
  options: ServerOptions,
): Promise<VerifiedAssertion> {
  if (ex.state !== "PENDING" || options.now() >= ex.expiresAt || !ex.serverPrivateKey) {
    throw new WakeError("auth_failed");
  }
  return verifyAssertion(body.assertion, await kxChallenge(th), {
    origins: options.loginOrigins,
    ...(ex.mode === "username" ? { userId: ex.requestedUserId } : {}),
    errorCode: "auth_failed",
  }, options);
}

async function deriveLoginResult(
  ex: ExchangeRecord,
  clientPublicKey: EcPublicKey,
  th: LoginTranscriptHash,
  clientMac: ClientFinishedMac,
  options: ServerOptions,
): Promise<LoginResult> {
  const keys = await deriveKeys(await ecdh(ex.serverPrivateKey!, clientPublicKey), th);
  if (!await verifyClientFinished(keys.fkC, th, clientMac)) {
    throw new WakeError("auth_failed");
  }
  const currentKeys = {
    c2s: await aesKey(keys.kC2s),
    s2c: await aesKey(keys.kS2c),
    th,
    c2sCount: 0,
    s2cCount: 0,
  };
  const now = options.now();
  const absoluteExpiresAt = now + options.authLifetimeMs;
  const hardCapAt = now + options.hardCapMs;
  if (!Number.isSafeInteger(hardCapAt) || hardCapAt < 0) {
    throw new RangeError("session expiration");
  }
  const finished = await serverFinished(keys.fkS, {
    th,
    clientFinished: clientMac,
    serverTime: now,
    absoluteExpiresAt,
    idleTimeoutSec: options.idleTimeoutSec,
  });
  const response = JSON.stringify({
    sessionId: base64urlnopad.encode(ex.sessionId.toUint8Array()),
    epoch: 0,
    serverTime: now,
    absoluteExpiresAt,
    idleTimeoutSec: options.idleTimeoutSec,
    serverFinished: base64urlnopad.encode(finished.toUint8Array()),
  });
  return { currentKeys, now, absoluteExpiresAt, hardCapAt, response };
}

function buildSession(
  ex: ExchangeRecord,
  verified: VerifiedAssertion,
  result: LoginResult,
  options: ServerOptions,
): SessionRecord {
  return {
    sessionId: ex.sessionId,
    userId: verified.credential.userId,
    loginCredentialId: verified.credential.credentialId.slice(),
    lastAuthCredentialId: verified.credential.credentialId.slice(),
    establishedOrigin: verified.origin,
    status: "ACTIVE",
    currentEpoch: 0,
    currentKeys: result.currentKeys,
    authTime: result.now,
    absoluteExpiresAt: result.absoluteExpiresAt,
    hardCapAt: result.hardCapAt,
    idleTimeoutSec: options.idleTimeoutSec,
    lastActivityAt: result.now,
  };
}

async function commitLogin(
  body: CompleteBody,
  th: LoginTranscriptHash,
  session: SessionRecord,
  result: LoginResult,
  verified: VerifiedAssertion,
  options: ServerOptions,
): Promise<Response> {
  const prepared = await prepareSignCountUpdate(verified, options);
  if (!prepared.accepted) {
    const ex = await options.store.getExchange(body.exchangeId.toUint8Array(), options.now());
    const cached = await replay(ex, th, body.clientMac, options);
    if (cached) {
      return cached;
    }
    throw new WakeError(ex?.state === "PENDING" ? "retry" : "auth_failed");
  }
  const update = prepared.update;
  const committed = await options.store.commitLogin({
    exchangeId: body.exchangeId.toUint8Array(),
    now: options.now(),
    th,
    clientFinished: body.clientMac,
    response: result.response,
    session,
    ...(update ? { signCountUpdate: update } : {}),
  });
  if (!committed) {
    const ex = await options.store.getExchange(body.exchangeId.toUint8Array(), options.now());
    const cached = await replay(ex, th, body.clientMac, options);
    if (cached) {
      return cached;
    }
    throw new WakeError("auth_failed");
  }
  await checkAuthenticatedSession(session.sessionId, options, "auth_failed");
  if (update) {
    await applySignCountUpdate(update, body.exchangeId.toUint8Array(), options);
  }
  return jsonTextResponse(result.response);
}

export async function complete(req: Request, options: ServerOptions): Promise<Response> {
  const body = await parseCompleteBody(req, options);
  const ex = await options.store.getExchange(body.exchangeId.toUint8Array(), options.now());
  if (!ex || ex.kind !== "login") {
    throw new WakeError("auth_failed");
  }
  const clientPublicKey = await parseClientPublicKey(body.clientPublicKey);
  const th = await loginTranscriptHash({
    exchangeId: ex.exchangeId,
    sessionId: ex.sessionId,
    serverNonce: ex.serverNonce,
    serverPublicKey: ex.serverPublicKey,
    clientPublicKey,
  });
  // Re-read to enforce retention even if parsing/crypto crossed its boundary.
  if (ex.state === "COMPLETED") {
    const retained = await options.store.getExchange(body.exchangeId.toUint8Array(), options.now());
    const cached = await replay(retained, th, body.clientMac, options);
    if (cached) {
      return cached;
    }
    throw new WakeError("auth_failed");
  }
  const verified = await verifyLogin(ex, body, th, options);
  const result = await deriveLoginResult(ex, clientPublicKey, th, body.clientMac, options);
  const session = buildSession(ex, verified, result, options);
  return commitLogin(body, th, session, result, verified, options);
}

// Spec §10.7–§10.8: wake/ta/approve, with the optional KR part decided independently of the TA part.
import {
  asApprovalId,
  asClientFinishedMac,
  asExchangeId,
  decodeBase64urlField,
  parseOperationIdHex,
  rekeyTranscriptHash,
  taBinding,
  taChallenge,
  taKrChallenge,
  WakeError,
} from "@wake-protocol/core";
import type { ApprovalId, ClientFinishedMac, EcPublicKey, ExchangeId, RekeyTranscriptHash, WebAuthnChallenge } from "@wake-protocol/core";
import { isObject } from "../http.ts";
import { finishRekey, parseClientPublicKey } from "../kr/finish.ts";
import type { ServerOptions } from "../options.ts";
import type {
  ApprovalCommit,
  ApprovalKrOutcome,
  ApprovalRecord,
  ExchangeRecord,
  OperationRecord,
  SessionRecord,
  SignCountUpdate,
} from "../store/types.ts";
import { applySignCountUpdate, prepareSignCountUpdate } from "../webauthn/counter.ts";
import { checkAuthenticatedSession } from "../webauthn/finalize.ts";
import { verifyAssertion } from "../webauthn/verify.ts";
import type { VerifiedAssertion } from "../webauthn/verify.ts";
import { operationIdParam } from "./params.ts";

interface KrRequest {
  exchangeId: ExchangeId;
  clientPublicKey: EcPublicKey;
  mac: ClientFinishedMac;
}

interface ApproveRequest {
  approvalId: ApprovalId;
  operationId: string;
  assertion: Record<string, unknown>;
  kr: KrRequest | null;
}

async function parseRequest(body: Record<string, unknown>): Promise<ApproveRequest> {
  const approvalId = asApprovalId(decodeBase64urlField(body.approvalId, "invalid_request", 16));
  const operationId = operationIdParam(body.operationId);
  if (!isObject(body.assertion)) {
    throw new WakeError("invalid_request");
  }
  // The ceremony follows from this member alone: null selects TA, an object selects TA+KR (§10.7).
  const kr = body.kr;
  if (kr === null) {
    return { approvalId, operationId, assertion: body.assertion, kr: null };
  }
  if (!isObject(kr)) {
    throw new WakeError("invalid_request");
  }
  return {
    approvalId,
    operationId,
    assertion: body.assertion,
    kr: {
      exchangeId: asExchangeId(decodeBase64urlField(kr.exchangeId, "invalid_request", 16)),
      clientPublicKey: await parseClientPublicKey(kr.clientPublicKey),
      mac: asClientFinishedMac(decodeBase64urlField(kr.clientFinished, "invalid_request", 32)),
    },
  };
}

/** The exchange must be this attempt's bound rekey exchange of the same session (§10.7). */
async function boundExchange(
  kr: KrRequest,
  att: ApprovalRecord,
  session: SessionRecord,
  options: ServerOptions,
): Promise<ExchangeRecord> {
  const ex = await options.store.getExchange(kr.exchangeId.toUint8Array(), options.now());
  if (
    !ex || ex.kind !== "rekey" || !ex.sessionId.equals(session.sessionId) ||
    !ex.boundApprovalId?.equals(att.approvalId) || !att.krExchangeId?.equals(ex.exchangeId)
  ) {
    throw new WakeError("not_found");
  }
  return ex;
}

async function replay(att: ApprovalRecord, options: ServerOptions): Promise<unknown> {
  if (att.result === undefined) {
    throw new WakeError("expired");
  }
  await checkAuthenticatedSession(att.sessionId, options, "reauth");
  if (att.signCountUpdate) {
    await applySignCountUpdate(att.signCountUpdate, att.approvalId.toUint8Array(), options);
  }
  await checkAuthenticatedSession(att.sessionId, options, "reauth");
  return JSON.parse(att.result) as unknown;
}

function krOutcomeJson(kr: ApprovalKrOutcome | null, committed: Record<string, unknown> | null): unknown {
  if (kr === null) {
    return null;
  }
  return kr === "committed" ? { result: "committed", ...committed } : { result: kr };
}

interface Plan {
  challenge: WebAuthnChallenge;
  /** Present for TA+KR. */
  kr: { ex: ExchangeRecord; req: KrRequest; th: RekeyTranscriptHash; } | null;
}

async function plan(req: ApproveRequest, att: ApprovalRecord, session: SessionRecord, options: ServerOptions): Promise<Plan> {
  const ta = await taBinding({
    approvalId: att.approvalId,
    operationId: parseOperationIdHex(att.operationId),
    approvalNonce: att.approvalNonce,
    sessionId: session.sessionId,
  });
  if (!req.kr) {
    return { challenge: await taChallenge(ta), kr: null };
  }
  const ex = await boundExchange(req.kr, att, session, options);
  if (!ex.prevTh || ex.targetEpoch === undefined) {
    throw new WakeError("not_found");
  }
  // prevTh is the th the exchange was created against (the session's cur_th then). A later epoch change shows up
  // as a KR conflict while the signature, made over that th, still verifies for the TA part (§10.8).
  const th = await rekeyTranscriptHash({
    exchangeId: ex.exchangeId,
    sessionId: session.sessionId,
    epoch: ex.targetEpoch,
    prevTh: ex.prevTh,
    serverNonce: ex.serverNonce,
    serverPublicKey: ex.serverPublicKey,
    clientPublicKey: req.kr.clientPublicKey,
  });
  return { challenge: await taKrChallenge(th, ta), kr: { ex, req: req.kr, th } };
}

async function buildCommit(
  req: ApproveRequest,
  att: ApprovalRecord,
  p: Plan,
  verified: VerifiedAssertion,
  signCountUpdate: SignCountUpdate | undefined,
  session: SessionRecord,
  options: ServerOptions,
): Promise<ApprovalCommit> {
  let rekey: NonNullable<ApprovalCommit["kr"]>["rekey"] = null;
  let committed: Record<string, unknown> | null = null;
  if (p.kr) {
    const { ex, req: kr, th } = p.kr;
    // Only a usable exchange can derive keys; otherwise the KR part is reported as expired (§10.8).
    if (ex.state === "PENDING" && options.now() < ex.expiresAt && ex.serverPrivateKey) {
      const finish = await finishRekey(ex.serverPrivateKey, ex.targetEpoch!, th, kr.clientPublicKey, kr.mac, session, options);
      committed = finish.response;
      rekey = {
        exchangeId: ex.exchangeId.toUint8Array(),
        sessionId: session.sessionId.toUint8Array(),
        expectedEpoch: session.currentEpoch,
        now: options.now(),
        authTime: finish.serverTime,
        th,
        clientFinished: kr.mac,
        response: JSON.stringify(finish.response),
        currentKeys: finish.currentKeys,
        absoluteExpiresAt: finish.absoluteExpiresAt,
        epochGraceMs: options.epochGraceMs,
        credentialId: verified.credential.credentialId,
      };
    }
  }
  return {
    approvalId: att.approvalId.toUint8Array(),
    operationId: req.operationId,
    sessionId: session.sessionId.toUint8Array(),
    now: options.now(),
    record: {
      decidedByUserId: session.userId,
      decidedByCredentialId: verified.credential.credentialId.slice(),
      credentialPublicKey: verified.credential.publicKey.slice(),
      sessionId: session.sessionId.toUint8Array(),
      approvalId: att.approvalId.toUint8Array(),
      approvalNonce: att.approvalNonce.toUint8Array(),
      th: p.kr ? p.kr.th.toUint8Array() : null,
      authenticatorData: verified.authenticatorData,
      clientDataJSON: verified.clientDataJSON,
      signature: verified.signature,
    },
    kr: p.kr ? { exchangeId: p.kr.ex.exchangeId.toUint8Array(), rekey } : null,
    result: (taResult, krResult, status) => JSON.stringify({
      operationId: req.operationId,
      ta: { result: taResult, status },
      kr: krOutcomeJson(krResult, committed),
    }),
    ...(signCountUpdate ? { signCountUpdate } : {}),
  };
}

/** CAS loss on the counter (BE=0): replay a consumed attempt, retry while it is still pending, else fail. */
async function counterLost(att: ApprovalRecord, options: ServerOptions): Promise<unknown> {
  const latest = await options.store.getApproval(att.approvalId.toUint8Array(), options.now());
  if (latest?.state === "CONSUMED") {
    return replay(latest, options);
  }
  throw new WakeError(latest?.state === "PENDING" ? "retry" : "webauthn_failed");
}

async function loadAttempt(req: ApproveRequest, session: SessionRecord, options: ServerOptions): Promise<ApprovalRecord> {
  const att = await options.store.getApproval(req.approvalId.toUint8Array(), options.now());
  if (!att || !att.sessionId.equals(session.sessionId)) {
    throw new WakeError("not_found");
  }
  return att;
}

async function loadOperation(
  req: ApproveRequest,
  att: ApprovalRecord,
  session: SessionRecord,
  options: ServerOptions,
): Promise<OperationRecord> {
  const op = await options.store.getOperation(att.operationId, options.now());
  if (!op) {
    throw new WakeError("not_found");
  }
  if (req.operationId !== op.operationId) {
    throw new WakeError("invalid_request");
  }
  if (session.userId !== op.approverUserId) {
    throw new WakeError("not_found");
  }
  return op;
}

export async function approve(body: Record<string, unknown>, session: SessionRecord, options: ServerOptions): Promise<unknown> {
  const req = await parseRequest(body);
  const att = await loadAttempt(req, session, options);
  if (att.state === "CONSUMED") {
    return replay(att, options);
  }
  if (att.state !== "PENDING") {
    throw new WakeError("expired");
  }
  const op = await loadOperation(req, att, session, options);
  const p = await plan(req, att, session, options);
  const verified = await verifyAssertion(req.assertion, p.challenge, {
    origins: options.taOrigins,
    requiredOrigin: session.establishedOrigin,
    userId: session.userId,
    approverUserId: op.approverUserId,
    errorCode: "webauthn_failed",
  }, options);
  // Like KX and KR, a BE=0 counter is advanced by compare-and-set before anything is committed (§6.4).
  const counter = await prepareSignCountUpdate(verified, options);
  if (!counter.accepted) {
    return counterLost(att, options);
  }
  const commit = await buildCommit(req, att, p, verified, counter.update, session, options);
  const result = await options.store.commitApproval(commit);
  if (result.state === "consumed") {
    return replay({ ...att, state: "CONSUMED", result: result.response }, options);
  }
  if (result.state !== "committed") {
    throw new WakeError(result.state);
  }
  await checkAuthenticatedSession(session.sessionId, options, "reauth", verified.credential.credentialId);
  if (counter.update) {
    await applySignCountUpdate(counter.update, att.approvalId.toUint8Array(), options);
  }
  await checkAuthenticatedSession(session.sessionId, options, "reauth", verified.credential.credentialId);
  return JSON.parse(result.response) as unknown;
}

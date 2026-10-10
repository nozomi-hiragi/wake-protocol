// Spec §5.3–5.7: transcript, TA binding, WebAuthn challenge, key schedule, Finished.
import { type Bytes, EMPTY, ascii, lp, u8, u32, u64 } from "./encoding.ts";
import { hkdf, hmac, hmacVerify, sha256 } from "./crypto.ts";
import { fail } from "./errors.ts";
import { timeToU64 } from "./time.ts";
import {
  type ApprovalId,
  type ApprovalNonce,
  type C2sKey,
  type ClientFinishedMac,
  type EcPublicKey,
  type ExchangeId,
  type FinishedKeyC,
  type FinishedKeyS,
  type LoginTranscriptHash,
  type OperationId,
  type RekeyTranscriptHash,
  type S2cKey,
  type ServerFinishedMac,
  type ServerNonce,
  type SessionId,
  type SharedSecret,
  type TaBindingHash,
  type TranscriptHash,
  type WebAuthnChallenge,
  asClientFinishedMac,
  asC2sKey,
  asFinishedKeyC,
  asFinishedKeyS,
  asLoginTranscriptHash,
  asRekeyTranscriptHash,
  asS2cKey,
  asServerFinishedMac,
  asTaBindingHash,
  asWebAuthnChallenge,
} from "./types.ts";

export const MODE_LOGIN = 0x01;
export const MODE_REKEY = 0x02;

interface TranscriptCommon {
  exchangeId: ExchangeId;
  sessionId: SessionId;
  serverNonce: ServerNonce;
  serverPublicKey: EcPublicKey;
  clientPublicKey: EcPublicKey;
}

/** KX (mode 0x01): epoch is 0 and prevTh is ε, so neither is a field. */
export type LoginTranscriptInput = TranscriptCommon;

/** KR (mode 0x02): new epoch (>= 1) and the previous transcript hash. */
export interface RekeyTranscriptInput extends TranscriptCommon {
  epoch: number;
  prevTh: TranscriptHash;
}

function encodeTranscript(
  mode: number,
  t: TranscriptCommon,
  epoch: number,
  prevTh: Bytes,
): Bytes {
  return lp(
    ascii("WAKE/1 kx-transcript"),
    u8(mode),
    t.exchangeId,
    t.sessionId,
    u32(epoch),
    prevTh,
    t.serverNonce,
    t.serverPublicKey,
    t.clientPublicKey,
  );
}

export function encodeLoginTranscript(t: LoginTranscriptInput): Bytes {
  return encodeTranscript(MODE_LOGIN, t, 0, EMPTY);
}

export function encodeRekeyTranscript(t: RekeyTranscriptInput): Bytes {
  if (!Number.isInteger(t.epoch) || t.epoch < 1) fail("bad_request", "rekey epoch must be >= 1");
  return encodeTranscript(MODE_REKEY, t, t.epoch, t.prevTh);
}

export async function loginTranscriptHash(t: LoginTranscriptInput): Promise<LoginTranscriptHash> {
  return asLoginTranscriptHash(await sha256(encodeLoginTranscript(t)));
}

export async function rekeyTranscriptHash(t: RekeyTranscriptInput): Promise<RekeyTranscriptHash> {
  return asRekeyTranscriptHash(await sha256(encodeRekeyTranscript(t)));
}

export interface TaBindingInput {
  approvalId: ApprovalId;
  operationId: OperationId;
  approvalNonce: ApprovalNonce;
  sessionId: SessionId;
}

export function encodeTaBinding(t: TaBindingInput): Bytes {
  return lp(ascii("WAKE/1 ta-approve"), t.approvalId, t.operationId, t.approvalNonce, t.sessionId);
}

export async function taBinding(t: TaBindingInput): Promise<TaBindingHash> {
  return asTaBindingHash(await sha256(encodeTaBinding(t)));
}

/**
 * §5.5 encoding only: LP(label, th, ta). Which of th / ta is ε is decided by
 * the ceremony-specific generators below, not here.
 */
export function encodeChallengeInput(th: Bytes, ta: Bytes): Bytes {
  return lp(ascii("WAKE/1 webauthn-challenge"), th, ta);
}

async function challenge(th: Bytes, ta: Bytes): Promise<WebAuthnChallenge> {
  return asWebAuthnChallenge(await sha256(encodeChallengeInput(th, ta)));
}

/** KX: th only. */
export const kxChallenge = (th: LoginTranscriptHash): Promise<WebAuthnChallenge> => challenge(th, EMPTY);
/** KR: th only. */
export const krChallenge = (th: RekeyTranscriptHash): Promise<WebAuthnChallenge> => challenge(th, EMPTY);
/** TA: ta only. */
export const taChallenge = (ta: TaBindingHash): Promise<WebAuthnChallenge> => challenge(EMPTY, ta);
/** TA combined with KR: both. */
export const taKrChallenge = (th: RekeyTranscriptHash, ta: TaBindingHash): Promise<WebAuthnChallenge> =>
  challenge(th, ta);

export interface KeySchedule {
  kC2s: C2sKey;
  kS2c: S2cKey;
  fkC: FinishedKeyC;
  fkS: FinishedKeyS;
}

/** §5.6. Returns raw key bytes; wrap them with aesKey / hmacKey as needed. */
export async function deriveKeys(ss: SharedSecret, th: TranscriptHash): Promise<KeySchedule> {
  const [kC2s, kS2c, fkC, fkS] = await Promise.all([
    hkdf(ss, th, ascii("WAKE/1 key c2s"), 32),
    hkdf(ss, th, ascii("WAKE/1 key s2c"), 32),
    hkdf(ss, th, ascii("WAKE/1 finished c2s"), 32),
    hkdf(ss, th, ascii("WAKE/1 finished s2c"), 32),
  ]);
  return { kC2s: asC2sKey(kC2s), kS2c: asS2cKey(kS2c), fkC: asFinishedKeyC(fkC), fkS: asFinishedKeyS(fkS) };
}

function clientFinishedInput(th: TranscriptHash): Bytes {
  return lp(ascii("WAKE/1 client finished"), th);
}

export async function clientFinished(fkC: FinishedKeyC | CryptoKey, th: TranscriptHash): Promise<ClientFinishedMac> {
  return asClientFinishedMac(await hmac(fkC, clientFinishedInput(th)));
}

export async function verifyClientFinished(
  fkC: FinishedKeyC | CryptoKey,
  th: TranscriptHash,
  mac: ClientFinishedMac,
): Promise<boolean> {
  return hmacVerify(fkC, clientFinishedInput(th), mac);
}

export interface ServerFinishedInput {
  th: TranscriptHash;
  clientFinished: ClientFinishedMac;
  /** ms since epoch. */
  serverTime: number;
  /** ms since epoch. */
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
}

function serverFinishedInput(i: ServerFinishedInput): Bytes {
  return lp(
    ascii("WAKE/1 server finished"),
    i.th,
    i.clientFinished,
    u64(timeToU64(i.serverTime)),
    u64(timeToU64(i.absoluteExpiresAt)),
    u32(i.idleTimeoutSec),
  );
}

export async function serverFinished(fkS: FinishedKeyS | CryptoKey, i: ServerFinishedInput): Promise<ServerFinishedMac> {
  return asServerFinishedMac(await hmac(fkS, serverFinishedInput(i)));
}

export async function verifyServerFinished(
  fkS: FinishedKeyS | CryptoKey,
  i: ServerFinishedInput,
  mac: ServerFinishedMac,
): Promise<boolean> {
  return hmacVerify(fkS, serverFinishedInput(i), mac);
}

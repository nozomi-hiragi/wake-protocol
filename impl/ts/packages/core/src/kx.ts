// Spec §5.3–5.7: transcript, TA binding, WebAuthn challenge, key schedule, Finished.
import { type Bytes, EMPTY, ascii, lp, u8, u32, u64 } from "./encoding.ts";
import { hkdf, hmac, hmacVerify, sha256 } from "./crypto.ts";
import { fail } from "./errors.ts";

export const MODE_LOGIN = 0x01;
export const MODE_REKEY = 0x02;

export interface TranscriptInput {
  mode: typeof MODE_LOGIN | typeof MODE_REKEY;
  exchangeId: Bytes; // 16B
  sessionId: Bytes; // 32B
  epoch: number; // KX: 0, KR: new epoch
  prevTh: Bytes; // KX: ε, KR: 32B
  serverNonce: Bytes; // 32B
  serverPublicKey: Bytes; // 65B
  clientPublicKey: Bytes; // 65B
}

function checkLen(name: string, b: Uint8Array, n: number): void {
  if (b.length !== n) fail("bad_request", `${name} must be ${n} bytes`);
}

export function encodeTranscript(t: TranscriptInput): Bytes {
  if (t.mode !== MODE_LOGIN && t.mode !== MODE_REKEY) fail("bad_request", "unknown mode");
  checkLen("exchangeId", t.exchangeId, 16);
  checkLen("sessionId", t.sessionId, 32);
  checkLen("serverNonce", t.serverNonce, 32);
  checkLen("serverPublicKey", t.serverPublicKey, 65);
  checkLen("clientPublicKey", t.clientPublicKey, 65);
  if (t.mode === MODE_LOGIN) {
    if (t.epoch !== 0) fail("bad_request", "login epoch must be 0");
    checkLen("prevTh", t.prevTh, 0);
  } else {
    if (t.epoch < 1) fail("bad_request", "rekey epoch must be >= 1");
    checkLen("prevTh", t.prevTh, 32);
  }
  return lp(
    ascii("WAKE/1 kx-transcript"),
    u8(t.mode),
    t.exchangeId,
    t.sessionId,
    u32(t.epoch),
    t.prevTh,
    t.serverNonce,
    t.serverPublicKey,
    t.clientPublicKey,
  );
}

export async function transcriptHash(t: TranscriptInput): Promise<Bytes> {
  return sha256(encodeTranscript(t));
}

export interface TaBindingInput {
  approvalId: Bytes; // 16B
  operationId: Bytes; // 32B raw
  approvalNonce: Bytes; // 32B
  sessionId: Bytes; // 32B
}

export function encodeTaBinding(t: TaBindingInput): Bytes {
  checkLen("approvalId", t.approvalId, 16);
  checkLen("operationId", t.operationId, 32);
  checkLen("approvalNonce", t.approvalNonce, 32);
  checkLen("sessionId", t.sessionId, 32);
  return lp(ascii("WAKE/1 ta-approve"), t.approvalId, t.operationId, t.approvalNonce, t.sessionId);
}

export async function taBinding(t: TaBindingInput): Promise<Bytes> {
  return sha256(encodeTaBinding(t));
}

export type Ceremony = "kx" | "kr" | "ta" | "ta+kr";

/**
 * §5.5. The ceremony fixes which fields must be present, so undefined
 * combinations (both ε, or a field the ceremony does not use) are rejected.
 * The caller is responsible for `th` having been computed with the mode the
 * ceremony implies (kx → login, kr / ta+kr → rekey).
 */
export function encodeChallengeInput(ceremony: Ceremony, th: Bytes | null, ta: Bytes | null): Bytes {
  const needTh = ceremony !== "ta";
  const needTa = ceremony === "ta" || ceremony === "ta+kr";
  if (ceremony !== "kx" && ceremony !== "kr" && ceremony !== "ta" && ceremony !== "ta+kr") {
    fail("bad_request", "unknown ceremony");
  }
  if (needTh !== (th !== null) || needTa !== (ta !== null)) fail("bad_request", "undefined challenge combination");
  if (th) checkLen("th", th, 32);
  if (ta) checkLen("ta", ta, 32);
  return lp(ascii("WAKE/1 webauthn-challenge"), th ?? EMPTY, ta ?? EMPTY);
}

export async function webauthnChallenge(ceremony: Ceremony, th: Bytes | null, ta: Bytes | null): Promise<Bytes> {
  return sha256(encodeChallengeInput(ceremony, th, ta));
}

export interface KeySchedule {
  kC2s: Bytes;
  kS2c: Bytes;
  fkC: Bytes;
  fkS: Bytes;
}

/** §5.6. Returns raw key bytes; wrap them with aesKey / hmacKey as needed. */
export async function deriveKeys(ss: Bytes, th: Bytes): Promise<KeySchedule> {
  checkLen("ss", ss, 32);
  checkLen("th", th, 32);
  const [kC2s, kS2c, fkC, fkS] = await Promise.all([
    hkdf(ss, th, ascii("WAKE/1 key c2s"), 32),
    hkdf(ss, th, ascii("WAKE/1 key s2c"), 32),
    hkdf(ss, th, ascii("WAKE/1 finished c2s"), 32),
    hkdf(ss, th, ascii("WAKE/1 finished s2c"), 32),
  ]);
  return { kC2s, kS2c, fkC, fkS };
}

export async function clientFinished(fkC: CryptoKey | Bytes, th: Bytes): Promise<Bytes> {
  return hmac(fkC, lp(ascii("WAKE/1 client finished"), th));
}

export async function verifyClientFinished(fkC: CryptoKey | Bytes, th: Bytes, mac: Bytes): Promise<boolean> {
  return hmacVerify(fkC, lp(ascii("WAKE/1 client finished"), th), mac);
}

export interface ServerFinishedInput {
  th: Bytes;
  clientFinished: Bytes;
  serverTime: number;
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
}

function serverFinishedInput(i: ServerFinishedInput): Bytes {
  return lp(
    ascii("WAKE/1 server finished"),
    i.th,
    i.clientFinished,
    u64(i.serverTime),
    u64(i.absoluteExpiresAt),
    u32(i.idleTimeoutSec),
  );
}

export async function serverFinished(fkS: CryptoKey | Bytes, i: ServerFinishedInput): Promise<Bytes> {
  return hmac(fkS, serverFinishedInput(i));
}

export async function verifyServerFinished(fkS: CryptoKey | Bytes, i: ServerFinishedInput, mac: Bytes): Promise<boolean> {
  return hmacVerify(fkS, serverFinishedInput(i), mac);
}

// Spec §5.3: login and rekey transcripts.
import { Byte, Byte4, Bytes, EMPTY } from "@wake-protocol/bytes";
import { sha256 } from "@wake-protocol/crypto";
import { LABELS } from "../spec/labels.ts";
import { labeled } from "../spec/domain.ts";
import {
  type EcPublicKey,
  type ExchangeId,
  type LoginTranscriptHash,
  type RekeyTranscriptHash,
  type ServerNonce,
  type SessionId,
  type TranscriptHash,
  asLoginTranscriptHash,
  asRekeyTranscriptHash,
} from "../spec/types.ts";

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
  return labeled(
    LABELS.kxTranscript,
    new Byte(mode),
    t.exchangeId,
    t.sessionId,
    new Byte4(epoch),
    prevTh,
    t.serverNonce,
    t.serverPublicKey,
    t.clientPublicKey,
  );
}

export function encodeLoginTranscript(t: LoginTranscriptInput): Bytes {
  return encodeTranscript(MODE_LOGIN, t, 0, EMPTY);
}

/** Throws RangeError unless the caller-supplied epoch is an integer in 1..2^32-1. */
export function encodeRekeyTranscript(t: RekeyTranscriptInput): Bytes {
  if (!Number.isInteger(t.epoch) || t.epoch < 1 || t.epoch > 0xffffffff) throw new RangeError("rekey epoch must be an integer in 1..2^32-1");
  return encodeTranscript(MODE_REKEY, t, t.epoch, t.prevTh);
}

export async function loginTranscriptHash(t: LoginTranscriptInput): Promise<LoginTranscriptHash> {
  return asLoginTranscriptHash(await sha256(encodeLoginTranscript(t).toUint8Array()));
}

/** Throws RangeError unless the caller-supplied epoch is an integer in 1..2^32-1. */
export async function rekeyTranscriptHash(t: RekeyTranscriptInput): Promise<RekeyTranscriptHash> {
  return asRekeyTranscriptHash(await sha256(encodeRekeyTranscript(t).toUint8Array()));
}

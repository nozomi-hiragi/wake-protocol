// Spec §5.7: client and server Finished.
import { Byte4, Byte8, Bytes, numberToBigInt } from "@wake-protocol/bytes";
import { hmac, hmacKey, hmacVerify } from "@wake-protocol/crypto";
import type { FinishedCryptoKeyC, FinishedCryptoKeyS } from "../spec/crypto.ts";
import { LABELS } from "../spec/labels.ts";
import { labeled } from "../spec/domain.ts";
import {
  type ClientFinishedMac,
  type FinishedKeyC,
  type FinishedKeyS,
  type ServerFinishedMac,
  type TranscriptHash,
  asClientFinishedMac,
  asServerFinishedMac,
} from "../spec/types.ts";

/** Finished keys may be raw bytes or an imported CryptoKey. */
function finishedKey(key: Bytes | CryptoKey): Promise<CryptoKey> | CryptoKey {
  return key instanceof Bytes ? hmacKey(key.toUint8Array()) : key;
}

function clientFinishedInput(th: TranscriptHash): Bytes {
  return labeled(LABELS.clientFinished, th);
}

export async function clientFinished(fkC: FinishedKeyC | FinishedCryptoKeyC, th: TranscriptHash): Promise<ClientFinishedMac> {
  return asClientFinishedMac(await hmac(await finishedKey(fkC), clientFinishedInput(th).toUint8Array()));
}

export async function verifyClientFinished(
  fkC: FinishedKeyC | FinishedCryptoKeyC,
  th: TranscriptHash,
  mac: ClientFinishedMac,
): Promise<boolean> {
  return hmacVerify(await finishedKey(fkC), clientFinishedInput(th).toUint8Array(), mac.toUint8Array());
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
  return labeled(
    LABELS.serverFinished,
    i.th,
    i.clientFinished,
    new Byte8(numberToBigInt(i.serverTime)),
    new Byte8(numberToBigInt(i.absoluteExpiresAt)),
    new Byte4(i.idleTimeoutSec),
  );
}

/** Throws RangeError for times outside 0..2^53-1 or idleTimeoutSec outside u32 (integers only). */
export async function serverFinished(fkS: FinishedKeyS | FinishedCryptoKeyS, i: ServerFinishedInput): Promise<ServerFinishedMac> {
  return asServerFinishedMac(await hmac(await finishedKey(fkS), serverFinishedInput(i).toUint8Array()));
}

/** Throws RangeError for times outside 0..2^53-1 or idleTimeoutSec outside u32 (integers only). */
export async function verifyServerFinished(
  fkS: FinishedKeyS | FinishedCryptoKeyS,
  i: ServerFinishedInput,
  mac: ServerFinishedMac,
): Promise<boolean> {
  return hmacVerify(await finishedKey(fkS), serverFinishedInput(i).toUint8Array(), mac.toUint8Array());
}

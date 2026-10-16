// Spec §5.6: key schedule.
import { asciiToBytes } from "@wake-protocol/codec";
import { hkdf } from "@wake-protocol/crypto";
import { LABELS } from "../spec/labels.ts";
import {
  type C2sKey,
  type FinishedKeyC,
  type FinishedKeyS,
  type S2cKey,
  type SharedSecret,
  type TranscriptHash,
  asC2sKey,
  asFinishedKeyC,
  asFinishedKeyS,
  asS2cKey,
} from "../spec/types.ts";

export interface KeySchedule {
  kC2s: C2sKey;
  kS2c: S2cKey;
  fkC: FinishedKeyC;
  fkS: FinishedKeyS;
}

/** §5.6. Returns raw key bytes; wrap them with aesKey / hmacKey as needed. */
export async function deriveKeys(ss: SharedSecret, th: TranscriptHash): Promise<KeySchedule> {
  const secret = ss.toUint8Array();
  const salt = th.toUint8Array();
  const [kC2s, kS2c, fkC, fkS] = await Promise.all([
    hkdf(secret, salt, asciiToBytes(LABELS.keyC2s), 32),
    hkdf(secret, salt, asciiToBytes(LABELS.keyS2c), 32),
    hkdf(secret, salt, asciiToBytes(LABELS.finishedC2s), 32),
    hkdf(secret, salt, asciiToBytes(LABELS.finishedS2c), 32),
  ]);
  return { kC2s: asC2sKey(kC2s), kS2c: asS2cKey(kS2c), fkC: asFinishedKeyC(fkC), fkS: asFinishedKeyS(fkS) };
}

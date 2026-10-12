// Spec §5.6–§5.7, §9.4 steps 5–6: key agreement and Finished handling shared by KR and TA+KR.
import { base64urlnopad } from "@scure/base";
import {
  aesKey,
  decodeBase64urlField,
  deriveKeys,
  ecdh,
  parseEcPublicKey,
  serverFinished,
  verifyClientFinished,
  WakeError,
} from "@wake-protocol/core";
import type { ClientFinishedMac, EcPublicKey, RekeyTranscriptHash } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { EpochKeys, SessionRecord } from "../store/types.ts";

export async function parseClientPublicKey(value: unknown): Promise<EcPublicKey> {
  try {
    return await parseEcPublicKey(decodeBase64urlField(value, "invalid_request"));
  } catch (e) {
    if (e instanceof WakeError && e.code === "invalid_public_key") {
      throw new WakeError("invalid_request");
    }
    throw e;
  }
}

export interface RekeyFinish {
  currentKeys: EpochKeys;
  serverTime: number;
  absoluteExpiresAt: number;
  /** The members of the KR response: epoch, serverTime, absoluteExpiresAt, idleTimeoutSec, serverFinished. */
  response: Record<string, unknown>;
}

/** Derives the new epoch's keys and verifies clientFinished (webauthn_failed on mismatch). */
export async function finishRekey(
  serverPrivateKey: CryptoKey,
  epoch: number,
  th: RekeyTranscriptHash,
  clientPublicKey: EcPublicKey,
  mac: ClientFinishedMac,
  credentialId: Uint8Array,
  session: SessionRecord,
  options: ServerOptions,
): Promise<RekeyFinish> {
  const keys = await deriveKeys(await ecdh(serverPrivateKey, clientPublicKey), th);
  if (!await verifyClientFinished(keys.fkC, th, mac)) {
    throw new WakeError("webauthn_failed");
  }
  const serverTime = options.now();
  const currentKeys = {
    c2s: await aesKey(keys.kC2s),
    s2c: await aesKey(keys.kS2c),
    th,
    c2sCount: 0,
    s2cCount: 0,
    authTime: serverTime,
    credentialId: credentialId.slice(),
  };
  const absoluteExpiresAt = Math.min(session.hardCapAt, serverTime + options.authLifetimeMs);
  const finished = await serverFinished(keys.fkS, {
    th,
    clientFinished: mac,
    serverTime,
    absoluteExpiresAt,
    idleTimeoutSec: session.idleTimeoutSec,
  });
  return {
    currentKeys,
    serverTime,
    absoluteExpiresAt,
    response: {
      epoch,
      serverTime,
      absoluteExpiresAt,
      idleTimeoutSec: session.idleTimeoutSec,
      serverFinished: base64urlnopad.encode(finished.toUint8Array()),
    },
  };
}

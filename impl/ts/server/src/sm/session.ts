// Spec §8.1, §8.7, §12.2: authenticated session metadata.
import { base64urlnopad } from "@scure/base";
import type { SessionRecord } from "../store/types.ts";

export function sessionInfo(session: SessionRecord, now: number): Record<string, unknown> {
  return {
    sessionId: base64urlnopad.encode(session.sessionId.toUint8Array()),
    epoch: session.currentEpoch,
    authTime: session.authTime,
    absoluteExpiresAt: session.absoluteExpiresAt,
    hardCapAt: session.hardCapAt,
    idleTimeoutSec: session.idleTimeoutSec,
    serverTime: now,
    rekeyRecommended: (session.currentKeys?.c2sCount ?? 0) >= 2 ** 24 || (session.currentKeys?.s2cCount ?? 0) >= 2 ** 24,
  };
}

// Spec §8.1: shared session expiration rules, independent of storage.
import type { SessionRecord } from "../store/types.ts";

export function sessionExpired(session: SessionRecord, now: number): boolean {
  return now >= session.absoluteExpiresAt ||
    now >= session.hardCapAt ||
    now >= session.lastActivityAt + session.idleTimeoutSec * 1000;
}

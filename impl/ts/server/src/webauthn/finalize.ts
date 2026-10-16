// Spec §6.5, §8.1, §8.9: recheck session and credentials after commit or replay.
import { Bytes, WakeError } from "@wake-protocol/core";
import type { SessionId } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import { sessionExpired } from "../sm/lifetime.ts";

export async function checkAuthenticatedSession(
  sessionId: SessionId,
  options: ServerOptions,
  errorCode: "auth_failed" | "reauth",
  authenticatedCredentialId?: Uint8Array,
): Promise<void> {
  const id = sessionId.toUint8Array();
  const session = await options.store.getSession(id);
  if (!session || session.status !== "ACTIVE") {
    throw new WakeError(errorCode);
  }
  if (sessionExpired(session, options.now())) {
    await options.store.expireSession(id, options.now());
    throw new WakeError(errorCode);
  }
  const checked: Uint8Array[] = [];
  for (const credentialId of [session.loginCredentialId, session.lastAuthCredentialId, authenticatedCredentialId]) {
    if (!credentialId) {
      continue;
    }
    if (checked.some(previous => new Bytes(previous).equals(new Bytes(credentialId)))) {
      continue;
    }
    checked.push(credentialId);
    const credential = await options.credentials.getCredential(credentialId);
    if (!credential || credential.status !== "active" || credential.userId !== session.userId) {
      await options.store.revokeSessionsByCredential(credentialId);
      // A later KR may already have replaced lastAuthCredentialId. Revoke this session as well.
      await options.store.revokeSession(id);
      throw new WakeError(errorCode);
    }
  }
  // Credential-store calls can yield to logout or revocation.
  const latest = await options.store.getSession(id);
  if (!latest || latest.status !== "ACTIVE" || sessionExpired(latest, options.now())) {
    await options.store.expireSession(id, options.now());
    throw new WakeError(errorCode);
  }
}

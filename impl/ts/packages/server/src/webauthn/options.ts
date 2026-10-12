// Spec §6.1: WebAuthn options for an authenticated session's user (KR, TA and TA+KR).
import { base64urlnopad } from "@scure/base";
import type { ServerOptions } from "../options.ts";
import type { SessionRecord } from "../store/types.ts";

/** allowCredentials lists the user's active credentials without transports (SPEC-NOTES, M2). */
export async function sessionWebauthnOptions(session: SessionRecord, options: ServerOptions): Promise<Record<string, unknown>> {
  const credentials = await options.credentials.findUserCredentials(session.userId);
  return {
    rpId: options.rpId,
    allowCredentials: credentials.filter(c => c.status === "active" && c.userId === session.userId)
      .map(c => ({ type: "public-key", id: base64urlnopad.encode(c.credentialId) })),
    userVerification: "required",
    timeout: options.webauthnTimeoutMs,
  };
}

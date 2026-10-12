// Spec §7, §8, §12: fetch-compatible routing and server-side revocation.
import { WakeError } from "@wake-protocol/core";
import { authError, jsonResponse, outerError } from "./http.ts";
import { complete } from "./kx/complete.ts";
import { start } from "./kx/start.ts";
import { checkOptions } from "./options.ts";
import type { WakeServerOptions } from "./options.ts";
import { transport, up } from "./sm/up.ts";
import { cancelOperation, createOperation, exportApprovalBundle, getOperation } from "./ta/operations.ts";
import type { CreatedOperation, CreateOperationInput, OperationView } from "./ta/operations.ts";

export interface WakeServer {
  handle(req: Request): Promise<Response | null>;
  revokeSession(sessionId: Uint8Array): Promise<void>;
  revokeSessionsByUser(userId: string): Promise<void>;
  revokeSessionsByCredential(credentialId: Uint8Array): Promise<void>;
  /** §10.2. Throws WakeError invalid_content (profile) or invalid_request (approverUserId, expiresAt). */
  createOperation(input: CreateOperationInput): Promise<CreatedOperation>;
  /** §10.9. Throws WakeError not_found for an unknown operation. */
  cancelOperation(operationId: string): Promise<"cancelled" | "already_decided" | "expired">;
  /** §10.10. Null for an unknown operation. */
  getOperation(operationId: string): Promise<OperationView | null>;
  /** Appendix C document for an APPROVED operation (SPKI instead of COSE_Key), else null. */
  exportApprovalBundle(operationId: string): Promise<Record<string, unknown> | null>;
}

export function createWakeServer(options: WakeServerOptions): WakeServer {
  const config = checkOptions(options);
  return {
    async handle(req) {
      const path = new URL(req.url).pathname;
      if (path !== "/auth/start" && path !== "/auth/complete" && path !== "/wake/up" && path !== "/wake/transport") {
        return null;
      }
      const encrypted = path === "/wake/up" || path === "/wake/transport";
      if (req.method !== "POST") {
        const response = jsonResponse(
          encrypted ? { wakeError: "bad_request" } : { error: "bad_request" },
          405,
        );
        response.headers.set("allow", "POST");
        return response;
      }
      try {
        if (path === "/auth/start") {
          return await start(req, config);
        }
        if (path === "/auth/complete") {
          return await complete(req, config);
        }
        if (path === "/wake/transport") {
          return await transport(req, config);
        }
        return await up(req, config);
      } catch (e) {
        const allowed = encrypted ?
          ["bad_request", "too_large", "reauth", "epoch_retired", "rate_limited", "retry"] :
          ["bad_request", "auth_failed", "rate_limited", "retry"];
        const code = e instanceof WakeError && allowed.includes(e.code) ? e.code : "retry";
        return encrypted ? outerError(code, config.retryAfterSec) : authError(code, config.retryAfterSec);
      }
    },
    revokeSession: sessionId => config.store.revokeSession(sessionId),
    revokeSessionsByUser: userId => config.store.revokeSessionsByUser(userId),
    revokeSessionsByCredential: credentialId => config.store.revokeSessionsByCredential(credentialId),
    createOperation: input => createOperation(input, config),
    cancelOperation: operationId => cancelOperation(operationId, config),
    getOperation: operationId => getOperation(operationId, config),
    exportApprovalBundle: operationId => exportApprovalBundle(operationId, config),
  };
}

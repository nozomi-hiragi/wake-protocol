// Spec §7, §8, §12: fetch-compatible routing and server-side revocation.
import { WakeError } from "@wake-protocol/core";
import { authError, jsonResponse, outerError } from "./http.ts";
import { complete } from "./kx/complete.ts";
import { start } from "./kx/start.ts";
import { checkOptions } from "./options.ts";
import type { WakeServerOptions } from "./options.ts";
import { up } from "./sm/up.ts";

export interface WakeServer {
  handle(req: Request): Promise<Response | null>;
  revokeSession(sessionId: Uint8Array): Promise<void>;
  revokeSessionsByUser(userId: string): Promise<void>;
  revokeSessionsByCredential(credentialId: Uint8Array): Promise<void>;
}

export function createWakeServer(options: WakeServerOptions): WakeServer {
  const config = checkOptions(options);
  return {
    async handle(req) {
      const path = new URL(req.url).pathname;
      if (path !== "/auth/start" && path !== "/auth/complete" && path !== "/wake/up") {
        return null;
      }
      if (req.method !== "POST") {
        const response = jsonResponse(
          path === "/wake/up" ? { wakeError: "bad_request" } : { error: "bad_request" },
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
        return await up(req, config);
      } catch (e) {
        const allowed = path === "/wake/up" ?
          ["bad_request", "too_large", "reauth", "epoch_retired", "rate_limited", "retry"] :
          ["bad_request", "auth_failed", "rate_limited", "retry"];
        const code = e instanceof WakeError && allowed.includes(e.code) ? e.code : "retry";
        return path === "/wake/up" ? outerError(code, config.retryAfterSec) : authError(code, config.retryAfterSec);
      }
    },
    revokeSession: sessionId => config.store.revokeSession(sessionId),
    revokeSessionsByUser: userId => config.store.revokeSessionsByUser(userId),
    revokeSessionsByCredential: credentialId => config.store.revokeSessionsByCredential(credentialId),
  };
}

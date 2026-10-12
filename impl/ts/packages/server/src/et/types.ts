// Spec §11.5: in-process ET route registration, request and auth objects.
import type { EtHeader, EtMethod } from "@wake-protocol/core";

/** §11.5: identity of the authenticated session, passed as an in-process object and never as headers. */
export interface EtAuth {
  userId: string;
  /** base64url without padding. */
  sessionId: string;
  /** Epoch of the request being served. */
  epoch: number;
  /** The session's last authenticated credential ID, base64url without padding. */
  credentialId: string;
  authTime: number;
  /** base64url without padding. */
  requestId: string;
}

export interface EtRouteRequest {
  method: EtMethod;
  path: string;
  /** Raw query string without "?", passed unnormalized. */
  query: string;
  headers: readonly EtHeader[];
  body: Uint8Array;
}

export interface EtRouteResponse {
  status: number;
  headers?: readonly EtHeader[];
  body?: Uint8Array;
}

/** A route matches only an exact method and path; the query is passed to the handler, never matched. */
export interface EtRoute {
  method: EtMethod;
  path: string;
  handler(req: EtRouteRequest, auth: EtAuth): Promise<EtRouteResponse> | EtRouteResponse;
}

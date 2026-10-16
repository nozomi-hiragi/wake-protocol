// Spec §11.5: in-process ET handler, request and auth objects.
import type { EtHeader } from "@wake-protocol/core";

/** §11.5: identity of the authenticated session, passed as an in-process object and never as headers. */
export interface EtAuth {
  userId: string;
  /** base64url without padding. */
  sessionId: string;
  /** Epoch of the request being served. */
  epoch: number;
  /** The credential that authenticated for this request's epoch, base64url without padding. */
  credentialId: string;
  /** When the authentication for this request's epoch happened. */
  authTime: number;
  /** base64url without padding. */
  requestId: string;
}

export interface EtHandlerRequest {
  method: string;
  url: string;
  headers: readonly EtHeader[];
  body: Uint8Array;
}

export interface EtHandlerResponse {
  status: number;
  headers?: readonly EtHeader[];
  body?: Uint8Array;
}

export type EtHandler = (req: EtHandlerRequest, auth: EtAuth) => Promise<EtHandlerResponse> | EtHandlerResponse;

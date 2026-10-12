// Spec §11.2, §11.5, §11.6: WAKE-ET route registration and in-process dispatch.
import { base64urlnopad } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { Bytes, checkPath, decodeEtRequest, ET_METHODS, encodeEtResponse, WakeError } from "@wake-protocol/core";
import type { MsgHeader } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { SessionRecord } from "../store/types.ts";
import type { EtAuth, EtRoute, EtRouteResponse } from "./types.ts";

/** Keeps the route table validated and indexed by exact method and path. Throws invalid_option. */
export function checkRoutes(routes: unknown): EtRoute[] {
  if (routes === undefined) {
    return [];
  }
  if (!Array.isArray(routes)) {
    throw new WakeError("invalid_option");
  }
  const seen = new Set<string>();
  const checked: EtRoute[] = [];
  for (const route of routes as unknown[]) {
    if (typeof route !== "object" || route === null) {
      throw new WakeError("invalid_option");
    }
    const { method, path, handler } = route as Record<string, unknown>;
    if (typeof method !== "string" || !(ET_METHODS as readonly string[]).includes(method)) {
      throw new WakeError("invalid_option");
    }
    if (typeof path !== "string" || typeof handler !== "function") {
      throw new WakeError("invalid_option");
    }
    try {
      checkPath(path);
    } catch (e) {
      throw e instanceof WakeError ? new WakeError("invalid_option") : e;
    }
    // §11.5: WAKE internal endpoints are never reachable through ET.
    if (path.startsWith("/wake/")) {
      throw new WakeError("invalid_option");
    }
    const key = `${method} ${path}`;
    if (seen.has(key)) {
      throw new WakeError("invalid_option");
    }
    seen.add(key);
    checked.push({ method: method as EtRoute["method"], path, handler: handler as EtRoute["handler"] });
  }
  return checked;
}

// The fixed error bodies are always small, so they are exempt from a custom body limit.
function etError(status: number, code: string): Bytes {
  return encodeEtResponse({
    status,
    headers: [["content-type", "application/json"]],
    body: new Bytes(utf8ToBytes(JSON.stringify({ error: { code } }))),
  });
}

function checkHandlerResponse(value: EtRouteResponse, bodyLimit: number): Bytes {
  return encodeEtResponse({
    status: value.status,
    headers: value.headers ?? [],
    body: new Bytes(value.body ?? new Uint8Array()),
  }, { bodyLimit });
}

const DECODE_STATUSES: Record<string, number> = {
  invalid_request: 400,
  invalid_method: 400,
  invalid_path: 400,
  invalid_header: 400,
  too_large: 413,
};

/** §11.6: routes the plaintext EtRequest and returns the plaintext EtResponse. Never leaks handler errors. */
export async function serveEt(
  plaintext: Uint8Array,
  header: MsgHeader,
  session: SessionRecord,
  options: ServerOptions,
): Promise<Uint8Array> {
  const bodyLimit = options.etBodyLimit;
  let request;
  try {
    request = decodeEtRequest(plaintext, { bodyLimit });
  } catch (e) {
    const status = e instanceof WakeError ? DECODE_STATUSES[e.code] : undefined;
    if (status === undefined) {
      throw e;
    }
    return etError(status, (e as WakeError).code).toUint8Array();
  }
  const route = options.routes.find(r => r.method === request.method && r.path === request.path);
  if (!route) {
    return etError(404, "route_not_found").toUint8Array();
  }
  // The request was sealed with the epoch's keys, so it carries that epoch's authentication, not the newest one.
  const keys = header.epoch === session.currentEpoch ? session.currentKeys :
    header.epoch === session.currentEpoch - 1 ? session.prevKeys : undefined;
  if (!keys) {
    throw new WakeError("reauth");
  }
  const auth: EtAuth = {
    userId: session.userId,
    sessionId: base64urlnopad.encode(header.sessionId.toUint8Array()),
    epoch: header.epoch,
    credentialId: base64urlnopad.encode(keys.credentialId),
    authTime: keys.authTime,
    requestId: base64urlnopad.encode(header.requestId.toUint8Array()),
  };
  try {
    const result = await route.handler({
      method: request.method,
      path: request.path,
      query: request.query,
      headers: request.headers.map(([name, value]) => [name, value] as const),
      body: request.body.toUint8Array(),
    }, auth);
    return checkHandlerResponse(result, bodyLimit).toUint8Array();
  } catch {
    // A thrown handler error or an invalid handler response: no message leaves the server.
    return etError(500, "internal").toUint8Array();
  }
}

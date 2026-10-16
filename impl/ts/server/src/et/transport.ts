// Spec §11.2, §11.5, §11.6: WAKE-ET in-process request handling.
import { base64urlnopad } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { Bytes, decodeEtRequest, encodeEtResponse, WakeError } from "@wake-protocol/core";
import type { MsgHeader } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { SessionRecord } from "../store/types.ts";
import type { EtAuth, EtHandlerResponse } from "./types.ts";

function etError(status: number, code: string, bodyLimit: number): Bytes {
  return encodeEtResponse({
    status,
    headers: [["content-type", "application/json"]],
    body: new Bytes(utf8ToBytes(JSON.stringify({ error: { code } }))),
  }, { bodyLimit });
}

function checkHandlerResponse(value: EtHandlerResponse, bodyLimit: number): Bytes {
  return encodeEtResponse({
    status: value.status,
    headers: value.headers ?? [],
    body: new Bytes(value.body ?? new Uint8Array()),
  }, { bodyLimit });
}

const DECODE_STATUSES: Record<string, number> = {
  invalid_request: 400,
  invalid_method: 400,
  invalid_url: 400,
  invalid_header: 400,
  too_large: 413,
};

/** §11.6: handles the plaintext EtRequest and returns the plaintext EtResponse. Never leaks handler errors. */
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
    return etError(status, (e as WakeError).code, bodyLimit).toUint8Array();
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
    const result = await options.etHandler!({
      method: request.method,
      url: request.url,
      headers: request.headers.map(([name, value]) => [name, value] as const),
      body: request.body.toUint8Array(),
    }, auth);
    return checkHandlerResponse(result, bodyLimit).toUint8Array();
  } catch {
    // A thrown handler error or an invalid handler response: no message leaves the server.
    return etError(500, "internal", bodyLimit).toUint8Array();
  }
}

// Spec §11.2: ET request and response encoding.
import { Byte2, Bytes } from "@wake-protocol/bytes";
import { asciiToBytes, latin1ToBytes, bytesToLatin1, encodeU32LengthPrefixed, decodeU32LengthPrefixed } from "@wake-protocol/codec";
import { fail, remap } from "../spec/errors.ts";
import { LABELS } from "../spec/labels.ts";
import { decodeFields, expectLabel, labeled } from "../spec/domain.ts";
import { checkMaxLength } from "../spec/limits.ts";
import { type EtHeader, type EtOptions, type EtRequest, type EtResponse, ET_BODY_MAX } from "./types.ts";
import { checkMethod, checkPath, checkQuery, checkRequestHeaders, checkResponseHeaders, checkStatus } from "./validate.ts";

function encodeHeaders(headers: readonly EtHeader[]): Bytes {
  const flat: Uint8Array[] = [];
  for (const [name, value] of headers) flat.push(asciiToBytes(name), remap("invalid_header", () => latin1ToBytes(value)));
  return new Bytes(encodeU32LengthPrefixed(...flat));
}

function decodeHeaders(b: Bytes): EtHeader[] {
  const f = remap("invalid_request", () => decodeU32LengthPrefixed(b.toUint8Array()));
  if (f.length % 2 !== 0) fail("invalid_request", "headers must be name/value pairs");
  const out: EtHeader[] = [];
  for (let i = 0; i < f.length; i += 2) {
    out.push([bytesToLatin1(f[i]!), bytesToLatin1(f[i + 1]!)]);
  }
  return out;
}

function checkBody(body: Bytes, opts: EtOptions): void {
  const limit = opts.bodyLimit ?? ET_BODY_MAX;
  checkMaxLength(body.length, limit, "bodyLimit", "body too large");
}

export function encodeEtRequest(r: EtRequest, opts: EtOptions = {}): Bytes {
  checkMethod(r.method);
  checkPath(r.path);
  checkQuery(r.query);
  checkRequestHeaders(r.headers);
  checkBody(r.body, opts);
  return labeled(
    LABELS.etReq,
    asciiToBytes(r.method),
    asciiToBytes(r.path),
    asciiToBytes(r.query),
    encodeHeaders(r.headers),
    r.body,
  );
}

export function decodeEtRequest(bytes: Bytes | Uint8Array, opts: EtOptions = {}): EtRequest {
  const f = remap("invalid_request", () => decodeFields(bytes, [asciiToBytes(LABELS.etReq).length, null, null, null, null, null]));
  expectLabel(f[0]!, LABELS.etReq, "invalid_request");
  const method = bytesToLatin1(f[1]!.toUint8Array());
  checkMethod(method);
  const path = bytesToLatin1(f[2]!.toUint8Array());
  checkPath(path);
  const query = bytesToLatin1(f[3]!.toUint8Array());
  checkQuery(query);
  const headers = decodeHeaders(f[4]!);
  checkRequestHeaders(headers);
  const body = f[5]!;
  checkBody(body, opts);
  return { method, path, query, headers, body };
}

export function encodeEtResponse(r: EtResponse, opts: EtOptions = {}): Bytes {
  checkStatus(r.status);
  checkResponseHeaders(r.headers);
  checkBody(r.body, opts);
  return labeled(LABELS.etRes, new Byte2(r.status), encodeHeaders(r.headers), r.body);
}

export function decodeEtResponse(bytes: Bytes | Uint8Array, opts: EtOptions = {}): EtResponse {
  const f = remap("invalid_request", () => decodeFields(bytes, [asciiToBytes(LABELS.etRes).length, 2, null, null]));
  expectLabel(f[0]!, LABELS.etRes, "invalid_request");
  const status = new Byte2(f[1]!).number;
  checkStatus(status);
  const headers = decodeHeaders(f[2]!);
  checkResponseHeaders(headers);
  const body = f[3]!;
  checkBody(body, opts);
  return { status, headers, body };
}

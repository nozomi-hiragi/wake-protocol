// Spec §11.2–11.4, §11.6: WAKE-ET logical request / response encoding and validation.
import { type Bytes, ascii, lp, lpDecode, lpDecodeAll, readU16, u16 } from "./encoding.ts";
import { WakeError, fail } from "./errors.ts";

export const ET_REQ_LABEL = "WAKE/1 et-req";
export const ET_RES_LABEL = "WAKE/1 et-res";
export const ET_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type EtMethod = (typeof ET_METHODS)[number];

export const ET_PATH_MAX = 2048;
export const ET_QUERY_MAX = 4096;
export const ET_HEADERS_MAX = 8192;
export const ET_BODY_MAX = 1024 * 1024;

/** A header as a [field name, field value] pair, in received order. */
export type EtHeader = readonly [name: string, value: string];
/** HTTP fields whose definitions do not permit combining repeated field lines. */
const NON_COMBINABLE_FIELDS: ReadonlySet<string> = new Set([
  "content-type",
  "host",
  "content-disposition",
  "etag",
  "last-modified",
  "location",
  "retry-after",
  "if-modified-since",
  "if-unmodified-since",
  "idempotency-key",
]);

/** Optional per-deployment settings. */
export interface EtOptions {
  bodyLimit?: number;
}

export interface EtRequest {
  method: EtMethod;
  /** Raw path, not normalized. Must pass checkPath. */
  path: string;
  /** Query string without the leading "?". Must pass checkQuery. */
  query: string;
  headers: readonly EtHeader[];
  body: Uint8Array;
}

export interface EtResponse {
  status: number;
  headers: readonly EtHeader[];
  body: Uint8Array;
}

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER_VALUE = /^[\t\x20-\x7e\x80-\xff]*$/;
// ET carries an origin-form target without normalization: reject delimiters and
// characters that cannot appear literally in an HTTP request target, but do not
// impose path-segment or percent-encoding normalization policies.
const PATH_CHARS = /^[\x21-\x7e]*$/;
const QUERY_CHARS = /^[\x21-\x7e]*$/;
const LOCATION = /^\/(?!\/)[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*$/;

export function checkMethod(method: string): asserts method is EtMethod {
  if (!(ET_METHODS as readonly string[]).includes(method)) fail("invalid_method", "method not allowed");
}

/** Every percent-encoding must be "%" followed by two hex digits. */
function checkPercentEncoding(s: string, code: string): void {
  const re = /^%[0-9A-Fa-f]{2}$/;
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "%") continue;
    if (!re.test(s.slice(i, i + 3))) fail(code, "bad percent-encoding");
    i += 2;
  }
}

/** §11.3. Validates an absolute-path request target without normalizing it. */
export function checkPath(path: string): void {
  if (path.length === 0 || path.length > ET_PATH_MAX) fail("invalid_path", "path length");
  if (path[0] !== "/") fail("invalid_path", "path must start with /");
  if (!PATH_CHARS.test(path) || path.includes("?") || path.includes("#")) fail("invalid_path", "invalid request-target path character");
  checkPercentEncoding(path, "invalid_path");
}

/** §11.2. Query is carried unchanged; only request-target delimiters/control bytes are rejected. */
export function checkQuery(query: string): void {
  if (query.length > ET_QUERY_MAX) fail("invalid_path", "query too long");
  if (!QUERY_CHARS.test(query) || query.includes("#")) fail("invalid_path", "invalid request-target query character");
  checkPercentEncoding(query, "invalid_path");
}

function checkHeaderList(headers: readonly EtHeader[], extraCheck?: (name: string, value: string) => void): void {
  const seen = new Set<string>();
  let total = 0;
  for (const [name, value] of headers) {
    if (!TOKEN.test(name)) fail("invalid_header", "header name must be an HTTP token");
    if (!HEADER_VALUE.test(value)) fail("invalid_header", "header value character");
    const lowerName = name.toLowerCase();
    if (NON_COMBINABLE_FIELDS.has(lowerName) && seen.has(lowerName)) fail("invalid_header", `duplicate non-combinable field: ${name}`);
    seen.add(lowerName);
    extraCheck?.(lowerName, value);
    total += name.length + value.length;
  }
  if (total > ET_HEADERS_MAX) fail("invalid_header", "headers exceed 8 KiB");
}

export function checkRequestHeaders(headers: readonly EtHeader[]): void {
  checkHeaderList(headers);
}

export function checkResponseHeaders(headers: readonly EtHeader[]): void {
  checkHeaderList(headers, (name, value) => {
      // §11.4: location is path-absolute only (RFC 3986), same origin.
      if (name === "location" && (!LOCATION.test(value) || value.includes("#"))) fail("invalid_header", "location must be a path-absolute reference");
      if (name === "location") checkPercentEncoding(value, "invalid_header");
  });
}

/** §11.2: status is 200..599. A structural field error, reported as invalid_request (§12.4). */
export function checkStatus(status: number): void {
  if (!Number.isInteger(status) || status < 200 || status > 599) fail("invalid_request", "status out of 200..599");
}

function encodeHeaders(headers: readonly EtHeader[]): Bytes {
  const flat: Bytes[] = [];
  for (const [name, value] of headers) flat.push(ascii(name), latin1Bytes(value));
  return lp(...flat);
}

function decodeHeaders(b: Bytes): EtHeader[] {
  const f = lpDecodeAll(b);
  if (f.length % 2 !== 0) fail("invalid_request", "headers must be name/value pairs");
  const out: EtHeader[] = [];
  for (let i = 0; i < f.length; i += 2) out.push([latin1(f[i]!), latin1(f[i + 1]!)]);
  return out;
}

/** Bytes to a string one char per byte. Non-ASCII then fails the checks. */
function latin1(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return s;
}

function latin1Bytes(s: string): Bytes {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0xff) fail("invalid_header", "header value must map to HTTP field octets");
    b[i] = c;
  }
  return b;
}

function checkBody(body: Uint8Array, opts: EtOptions): void {
  const limit = opts.bodyLimit ?? ET_BODY_MAX;
  if (!(Number.isSafeInteger(limit) && limit >= 0)) {
    fail("invalid_option", "bodyLimit must be a non-negative safe integer");
  }
  if (body.length > limit) fail("too_large", "body too large");
}

/**
 * Runs a decoder and turns structural failures (bad_request from LP framing,
 * the label, or field counts) into invalid_request (§12.4). Other codes pass through.
 */
function asInvalidRequest<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof WakeError && e.code === "bad_request") fail("invalid_request", e.message);
    throw e;
  }
}

export function encodeEtRequest(r: EtRequest, opts: EtOptions = {}): Bytes {
  checkMethod(r.method);
  checkPath(r.path);
  checkQuery(r.query);
  checkRequestHeaders(r.headers);
  checkBody(r.body, opts);
  return lp(
    ascii(ET_REQ_LABEL),
    ascii(r.method),
    ascii(r.path),
    ascii(r.query),
    encodeHeaders(r.headers),
    r.body,
  );
}

export function decodeEtRequest(bytes: Uint8Array, opts: EtOptions = {}): EtRequest {
  return asInvalidRequest(() => {
    const f = lpDecode(bytes, [ascii(ET_REQ_LABEL).length, null, null, null, null, null]);
    if (!equalAscii(f[0]!, ET_REQ_LABEL)) fail("invalid_request", "label");
    const method = latin1(f[1]!);
    checkMethod(method);
    const path = latin1(f[2]!);
    checkPath(path);
    const query = latin1(f[3]!);
    checkQuery(query);
    const headers = decodeHeaders(f[4]!);
    checkRequestHeaders(headers);
    const body = f[5]!;
    checkBody(body, opts);
    return { method, path, query, headers, body };
  });
}

export function encodeEtResponse(r: EtResponse, opts: EtOptions = {}): Bytes {
  checkStatus(r.status);
  checkResponseHeaders(r.headers);
  checkBody(r.body, opts);
  return lp(ascii(ET_RES_LABEL), u16(r.status), encodeHeaders(r.headers), r.body);
}

export function decodeEtResponse(bytes: Uint8Array, opts: EtOptions = {}): EtResponse {
  return asInvalidRequest(() => {
    const f = lpDecode(bytes, [ascii(ET_RES_LABEL).length, 2, null, null]);
    if (!equalAscii(f[0]!, ET_RES_LABEL)) fail("invalid_request", "label");
    const status = readU16(f[1]!);
    checkStatus(status);
    const headers = decodeHeaders(f[2]!);
    checkResponseHeaders(headers);
    const body = f[3]!;
    checkBody(body, opts);
    return { status, headers, body };
  });
}

function equalAscii(b: Uint8Array, s: string): boolean {
  const want = ascii(s);
  if (b.length !== want.length) return false;
  for (let i = 0; i < b.length; i++) if (b[i] !== want[i]) return false;
  return true;
}

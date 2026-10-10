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

/** A header as a [lowercase name, value] pair. */
export type EtHeader = readonly [name: string, value: string];

/** §11.4 の既定で許可する要求ヘッダー。 */
export const ET_DEFAULT_REQUEST_HEADERS: ReadonlySet<string> = new Set([
  "accept",
  "accept-language",
  "content-type",
  "content-language",
  "if-match",
  "if-none-match",
  "if-modified-since",
  "if-unmodified-since",
  "idempotency-key",
]);

/** §11.4 の既定で許可する応答ヘッダー。 */
export const ET_DEFAULT_RESPONSE_HEADERS: ReadonlySet<string> = new Set([
  "content-type",
  "content-language",
  "content-disposition",
  "etag",
  "last-modified",
  "cache-control",
  "retry-after",
  "location",
]);

/** §11.4 の常に拒否する要求ヘッダー（完全一致）。 */
const ALWAYS_REJECTED_REQUEST: ReadonlySet<string> = new Set([
  "host",
  "cookie",
  "authorization",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "content-length",
  "expect",
  "forwarded",
  "x-real-ip",
  "via",
  "origin",
]);
/** §11.4 の常に拒否する要求ヘッダー（接頭辞）。 */
const ALWAYS_REJECTED_REQUEST_PREFIXES = ["proxy-", "x-forwarded-", "sec-", "x-wake-"];
/** §11.4 の常に拒否する応答ヘッダー。 */
const ALWAYS_REJECTED_RESPONSE: ReadonlySet<string> = new Set(["set-cookie"]);

/** §11.4: fields that may appear only once; a repeat is `invalid_header`. */
export const ET_SINGLETON_HEADERS: ReadonlySet<string> = new Set([
  "content-type",
  "content-disposition",
  "etag",
  "last-modified",
  "location",
  "retry-after",
  "if-modified-since",
  "if-unmodified-since",
  "idempotency-key",
]);

/** Optional per-deployment settings; `*Headers` extend the default allowlists. */
export interface EtOptions {
  requestHeaders?: Iterable<string>;
  responseHeaders?: Iterable<string>;
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

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
const HEADER_VALUE = /^[\t\x20-\x7e]*$/;
/** RFC 3986 pchar, "/" and "%" (percent-encoding is checked separately). */
const PCHAR_SET = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$/;
/** RFC 3986 query = *( pchar / "/" / "?" ), plus "%" for percent-encoding. */
const QUERY_SET = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*$/;
/** path-absolute with optional query: "/" not followed by "/", then (backslash excluded by the charset) pchar / "/" / "?" / "%". */
const LOCATION = /^\/(?!\/)[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*$/;
const UNRESERVED_BYTE = /^[A-Za-z0-9\-._~]$/;

export function checkMethod(method: string): asserts method is EtMethod {
  if (!(ET_METHODS as readonly string[]).includes(method)) fail("invalid_method", "method not allowed");
}

/** Every percent-encoding must be "%" followed by two hex digits (uppercase only for paths). */
function checkPercentEncoding(s: string, code: string, upperOnly: boolean): void {
  const re = upperOnly ? /^%[0-9A-F]{2}$/ : /^%[0-9A-Fa-f]{2}$/;
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "%") continue;
    if (!re.test(s.slice(i, i + 3))) fail(code, upperOnly ? "percent-encoding must be uppercase hex" : "bad percent-encoding");
    i += 2;
  }
}

/** §11.3. Rejects rather than normalizes. */
export function checkPath(path: string): void {
  if (path.length === 0 || path.length > ET_PATH_MAX) fail("invalid_path", "path length");
  if (path[0] !== "/") fail("invalid_path", "path must start with /");
  if (!PCHAR_SET.test(path)) fail("invalid_path", "path has characters outside pchar");
  if (path.includes("#") || path.includes("//")) fail("invalid_path", "path has // or #");
  checkPercentEncoding(path, "invalid_path", true);
  for (let i = 0; i < path.length; i++) {
    if (path[i] !== "%") continue;
    const code = parseInt(path.slice(i + 1, i + 3), 16);
    if (code === 0x2f || code === 0x5c || code === 0x00) fail("invalid_path", "encoded / \\ or NUL");
    if (UNRESERVED_BYTE.test(String.fromCharCode(code))) fail("invalid_path", "encoded unreserved character");
    i += 2;
  }
  for (const seg of path.split("/")) {
    if (seg === "." || seg === "..") fail("invalid_path", "dot segment");
  }
}

/**
 * §11.2 with RFC 3986 `query = *( pchar / "/" / "?" )`. Raw spaces, '#',
 * '[', ']', '"', '<', '>', '\\', '^', '`', '{', '|', '}' are rejected.
 * Percent-encoding hex digits may be upper- or lowercase (§11.2).
 */
export function checkQuery(query: string): void {
  if (query.length > ET_QUERY_MAX) fail("invalid_path", "query too long");
  if (!QUERY_SET.test(query)) fail("invalid_path", "query has characters outside RFC 3986 query");
  checkPercentEncoding(query, "invalid_path", false);
}

function checkHeaderList(
  headers: readonly EtHeader[],
  allowed: ReadonlySet<string>,
  extra: Iterable<string> | undefined,
  alwaysRejected: (name: string) => boolean,
  extraCheck?: (name: string, value: string) => void,
): void {
  const extraSet = new Set(extra ?? []);
  const seen = new Set<string>();
  let total = 0;
  for (const [name, value] of headers) {
    if (!TOKEN.test(name)) fail("invalid_header", "header name must be lowercase token");
    if (!HEADER_VALUE.test(value)) fail("invalid_header", "header value character");
    if (alwaysRejected(name)) fail("invalid_header", `header not allowed: ${name}`);
    if (!allowed.has(name) && !extraSet.has(name)) fail("invalid_header", `header not in allowlist: ${name}`);
    if (ET_SINGLETON_HEADERS.has(name) && seen.has(name)) fail("invalid_header", `duplicate header: ${name}`);
    seen.add(name);
    extraCheck?.(name, value);
    total += name.length + value.length;
  }
  if (total > ET_HEADERS_MAX) fail("invalid_header", "headers exceed 8 KiB");
}

export function checkRequestHeaders(headers: readonly EtHeader[], extraAllowed?: Iterable<string>): void {
  checkHeaderList(headers, ET_DEFAULT_REQUEST_HEADERS, extraAllowed, (n) => {
    return ALWAYS_REJECTED_REQUEST.has(n) || ALWAYS_REJECTED_REQUEST_PREFIXES.some((p) => n.startsWith(p));
  });
}

export function checkResponseHeaders(headers: readonly EtHeader[], extraAllowed?: Iterable<string>): void {
  checkHeaderList(
    headers,
    ET_DEFAULT_RESPONSE_HEADERS,
    extraAllowed,
    (n) => ALWAYS_REJECTED_RESPONSE.has(n),
    (name, value) => {
      // §11.4: location is path-absolute only (RFC 3986), same origin.
      if (name === "location" && !LOCATION.test(value)) fail("invalid_header", "location must be a path-absolute reference");
      if (name === "location") checkPercentEncoding(value, "invalid_header", false);
    },
  );
}

/** §11.2: status is 200..599. A structural field error, reported as invalid_request (§12.4). */
export function checkStatus(status: number): void {
  if (!Number.isInteger(status) || status < 200 || status > 599) fail("invalid_request", "status out of 200..599");
}

function encodeHeaders(headers: readonly EtHeader[]): Bytes {
  const flat: Bytes[] = [];
  for (const [name, value] of headers) flat.push(ascii(name), ascii(value));
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
  checkRequestHeaders(r.headers, opts.requestHeaders);
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
    checkRequestHeaders(headers, opts.requestHeaders);
    const body = f[5]!;
    checkBody(body, opts);
    return { method, path, query, headers, body };
  });
}

export function encodeEtResponse(r: EtResponse, opts: EtOptions = {}): Bytes {
  checkStatus(r.status);
  checkResponseHeaders(r.headers, opts.responseHeaders);
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
    checkResponseHeaders(headers, opts.responseHeaders);
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

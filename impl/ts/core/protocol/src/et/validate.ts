// Spec §11.2–11.4: ET method, target, header and status validation.
import { fail } from "../spec/errors.ts";
import { type EtHeader, type EtMethod, ET_HEADERS_MAX, ET_METHODS, ET_PATH_MAX, ET_QUERY_MAX } from "./types.ts";

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

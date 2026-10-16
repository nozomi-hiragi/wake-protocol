// Spec §11.2–11.4: ET method, target, header and status validation.
import { fail } from "../spec/errors.ts";
import { type EtHeader, ET_HEADERS_MAX, ET_METHOD_MAX, ET_URL_MAX } from "./types.ts";

// Unlike $, the end assertion also rejects a trailing newline.
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+(?![\s\S])/;
const HEADER_VALUE = /^[\t\x20-\x7e\x80-\xff]*(?![\s\S])/;
const URI_CHAR = "[A-Za-z0-9\\-._~!$&'()*+,;=]";
const URI_ATOM = `(?:${URI_CHAR}|%[0-9A-Fa-f]{2})`;
const USERINFO = new RegExp(`^(?:${URI_ATOM}|:)*$`);
const REG_NAME = new RegExp(`^${URI_ATOM}*$`);
const PATH = new RegExp(`^(?:${URI_ATOM}|[:@/])*$`);
const QUERY = new RegExp(`^(?:${URI_ATOM}|[:@/?])*$`);

export function checkMethod(method: string): void {
  if (method.length > ET_METHOD_MAX || !TOKEN.test(method) || /^(CONNECT|TRACE|TRACK)$/i.test(method)) {
    fail("invalid_method", "invalid or forbidden method");
  }
}

function ipv4(address: string): boolean {
  const parts = address.split(".");
  return parts.length === 4 && parts.every(p => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
}

// RFC 3986 Appendix A: IPv6 uses eight h16 slots; a final IPv4address occupies two.
function ipv6(address: string): boolean {
  const halves = address.split("::");
  if (halves.length > 2) return false;
  const parts = halves.flatMap(h => h === "" ? [] : h.split(":"));
  let slots = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    if (part.includes(".")) {
      if (i !== parts.length - 1 || !address.endsWith(part) || !ipv4(part)) return false;
      slots += 2;
    } else {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) return false;
      slots++;
    }
  }
  return halves.length === 2 ? slots < 8 : slots === 8;
}

function checkAuthority(authority: string): void {
  const at = authority.indexOf("@");
  if (at >= 0) {
    if (!USERINFO.test(authority.slice(0, at))) fail("invalid_url", "invalid userinfo");
    authority = authority.slice(at + 1);
  }
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    const literal = authority.slice(1, end);
    if (end < 0 || !(ipv6(literal) || /^[vV][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+$/.test(literal))) {
      fail("invalid_url", "invalid IP literal");
    }
    if (!/^(?::[0-9]*)?$/.test(authority.slice(end + 1))) fail("invalid_url", "invalid port");
  } else {
    const colon = authority.indexOf(":");
    const host = colon < 0 ? authority : authority.slice(0, colon);
    if (!REG_NAME.test(host) || (colon >= 0 && !/^[0-9]*$/.test(authority.slice(colon + 1)))) {
      fail("invalid_url", "invalid host or port");
    }
  }
}

/** §11.3: validates RFC 3986 URI-reference grammar, excluding fragments, without normalization. */
export function checkUrl(url: string): void {
  if (url.length > ET_URL_MAX || /[^\x21-\x7e]|#/.test(url)) fail("invalid_url", "URL length or fragment");
  const query = url.indexOf("?");
  let path = query < 0 ? url : url.slice(0, query);
  if (query >= 0 && !QUERY.test(url.slice(query + 1))) fail("invalid_url", "invalid query");
  const colon = path.indexOf(":");
  const slash = path.indexOf("/");
  if (colon >= 0 && (slash < 0 || colon < slash)) {
    if (!/^[A-Za-z][A-Za-z0-9+.-]*$/.test(path.slice(0, colon))) fail("invalid_url", "invalid scheme");
    path = path.slice(colon + 1);
  }
  if (path.startsWith("//")) {
    const end = path.indexOf("/", 2);
    checkAuthority(path.slice(2, end < 0 ? undefined : end));
    path = end < 0 ? "" : path.slice(end);
  }
  if (!PATH.test(path)) fail("invalid_url", "invalid path");
}

function checkHeaderList(headers: readonly EtHeader[]): void {
  let total = 0;
  for (const [name, value] of headers) {
    if (!TOKEN.test(name)) fail("invalid_header", "header name must be an HTTP token");
    if (!HEADER_VALUE.test(value)) fail("invalid_header", "header value character");
    total += name.length + value.length;
  }
  if (total > ET_HEADERS_MAX) fail("invalid_header", "headers exceed 8 KiB");
}

export function checkRequestHeaders(headers: readonly EtHeader[]): void {
  checkHeaderList(headers);
}

export function checkResponseHeaders(headers: readonly EtHeader[]): void {
  checkHeaderList(headers);
}

/** §11.2: status is 200..599. A structural field error, reported as invalid_request (§12.4). */
export function checkStatus(status: number): void {
  if (!Number.isInteger(status) || status < 200 || status > 599) fail("invalid_request", "status out of 200..599");
}

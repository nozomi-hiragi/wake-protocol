// Spec §4: common encodings.
import { fail } from "./errors.ts";

export type Bytes = Uint8Array<ArrayBuffer>;

export const EMPTY: Bytes = new Uint8Array(0);

// --- integers (§4.1) ---

export function u8(x: number): Bytes {
  if (!Number.isInteger(x) || x < 0 || x > 0xff) fail("invalid_integer", "u8 out of range");
  return Uint8Array.of(x);
}

export function u16(x: number): Bytes {
  if (!Number.isInteger(x) || x < 0 || x > 0xffff) fail("invalid_integer", "u16 out of range");
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, x);
  return b;
}

export function u32(x: number): Bytes {
  if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) fail("invalid_integer", "u32 out of range");
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x);
  return b;
}

/** Full range 0..2^64-1. Time usage limits live in time.ts. */
export function u64(x: bigint): Bytes {
  if (typeof x !== "bigint" || x < 0n || x > 0xffffffffffffffffn) fail("invalid_integer", "u64 out of range");
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, x);
  return b;
}

export function readU8(b: Bytes): number {
  if (b.length !== 1) fail("bad_request", "u8 length");
  return b[0]!;
}

export function readU16(b: Bytes): number {
  if (b.length !== 2) fail("bad_request", "u16 length");
  return new DataView(b.buffer, b.byteOffset, 2).getUint16(0);
}

export function readU32(b: Bytes): number {
  if (b.length !== 4) fail("bad_request", "u32 length");
  return new DataView(b.buffer, b.byteOffset, 4).getUint32(0);
}

export function readU64(b: Bytes): bigint {
  if (b.length !== 8) fail("bad_request", "u64 length");
  return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0);
}

// --- byte helpers ---

export function concat(...parts: Uint8Array[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- LP (§4.2) ---

export function lp(...fields: Uint8Array[]): Bytes {
  const parts: Uint8Array[] = [];
  for (const f of fields) parts.push(u32(f.length), f);
  return concat(...parts);
}

/**
 * Strict LP decoding. `lengths` fixes the field count; a number entry
 * requires that exact length, `null` allows any length.
 */
export function lpDecode(buf: Uint8Array, lengths: readonly (number | null)[]): Bytes[] {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out: Bytes[] = [];
  let o = 0;
  for (const want of lengths) {
    if (o + 4 > buf.length) fail("bad_request", "truncated LP length");
    const len = view.getUint32(o);
    o += 4;
    if (o + len > buf.length) fail("bad_request", "truncated LP field");
    if (want !== null && len !== want) fail("bad_request", `LP field length ${len}, want ${want}`);
    out.push(buf.slice(o, o + len));
    o += len;
  }
  if (o !== buf.length) fail("bad_request", "trailing bytes after LP");
  return out;
}

/** Decodes an LP sequence with an unknown, unconstrained number of fields. */
export function lpDecodeAll(buf: Uint8Array): Bytes[] {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out: Bytes[] = [];
  let o = 0;
  while (o < buf.length) {
    if (o + 4 > buf.length) fail("bad_request", "truncated LP length");
    const len = view.getUint32(o);
    o += 4;
    if (o + len > buf.length) fail("bad_request", "truncated LP field");
    out.push(buf.slice(o, o + len));
    o += len;
  }
  return out;
}

// --- strings (§4.3) ---

export function ascii(s: string): Bytes {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) fail("invalid_ascii");
    b[i] = c;
  }
  return b;
}

export function readAscii(b: Uint8Array): string {
  for (const c of b) if (c > 0x7f) fail("invalid_ascii");
  return String.fromCharCode(...b);
}

export function utf8(s: string): Bytes {
  if (!s.isWellFormed()) fail("invalid_utf8", "lone surrogate");
  return new TextEncoder().encode(s);
}

const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function readUtf8(b: Uint8Array): string {
  try {
    return strictDecoder.decode(b);
  } catch {
    fail("invalid_utf8");
  }
}

// --- base64url (§4.4) ---

const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64u(b: Uint8Array): string {
  let s = "";
  let i = 0;
  for (; i + 3 <= b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    s += B64U[n >> 18]! + B64U[(n >> 12) & 63]! + B64U[(n >> 6) & 63]! + B64U[n & 63]!;
  }
  const rest = b.length - i;
  if (rest === 1) {
    const n = b[i]! << 16;
    s += B64U[n >> 18]! + B64U[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    s += B64U[n >> 18]! + B64U[(n >> 12) & 63]! + B64U[(n >> 6) & 63]!;
  }
  return s;
}

/** Canonical-only decoding: the result must re-encode to the same string. */
export function fromB64u(s: string): Bytes {
  if (s.length % 4 === 1) fail("invalid_base64url", "impossible length");
  const vals: number[] = [];
  for (const ch of s) {
    const v = B64U.indexOf(ch);
    if (v < 0) fail("invalid_base64url", "character outside alphabet");
    vals.push(v);
  }
  const out = new Uint8Array(Math.floor((vals.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const v of vals) {
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (b64u(out) !== s) fail("invalid_base64url", "non-canonical");
  return out;
}

// --- hex (§4.5) ---

export function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** Accepts upper- and lowercase; output of hex() is always lowercase. */
export function fromHex(s: string): Bytes {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) fail("invalid_hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

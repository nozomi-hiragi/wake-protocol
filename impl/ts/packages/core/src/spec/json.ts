// Spec §4.4, §4.8: strict JSON objects and canonical unpadded base64url fields.
import { base64urlnopad } from "@scure/base";
import { bytesToUtf8, parseIJson } from "@wake-protocol/codec";
import { fail, remap } from "./errors.ts";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Parses strict UTF-8 and I-JSON (no duplicate keys, no lone surrogates) and requires an object.
 * Only RangeError, TypeError and SyntaxError from the generic layers become WakeError(code).
 */
export function parseJsonObject(bytes: Uint8Array, code: string): Record<string, unknown> {
  const text = remap(code, () => bytesToUtf8(bytes));
  const value = remap(code, () => parseIJson(text));
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(code);
  }
  return value as Record<string, unknown>;
}

/**
 * Decodes a canonical unpadded base64url string (§4.4). Alphabet, length and trailing bits are
 * checked before decoding, so unexpected failures of @scure/base are never mistaken for bad input.
 */
export function decodeBase64urlField(value: unknown, code: string, length?: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    fail(code);
  }
  const remainder = value.length % 4;
  const last = ALPHABET.indexOf(value.at(-1) ?? "A");
  if ((remainder === 2 && (last & 15) !== 0) || (remainder === 3 && (last & 3) !== 0)) {
    fail(code);
  }
  const bytes = base64urlnopad.decode(value);
  if (length !== undefined && bytes.length !== length) {
    fail(code);
  }
  return bytes;
}

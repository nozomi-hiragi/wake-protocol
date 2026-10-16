// Spec §4.4, §4.8: strict JSON objects and canonical unpadded base64url fields.
import { IJsonError, parse } from "@nozomi-hiragi/i-json";
import { base64urlnopad } from "@scure/base";
import { fail } from "./errors.ts";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Parses strict UTF-8 I-JSON and requires a non-array object.
 * Duplicate keys, lone surrogates, noncharacters and nesting above 64 are rejected.
 * Only IJsonError from the parser becomes WakeError(code); any other error propagates.
 */
export function parseJsonObject(bytes: Uint8Array, code: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = parse(bytes, { strict: true, maxDepth: 64 });
  } catch (e) {
    if (e instanceof IJsonError) fail(code, e.message);
    throw e;
  }
  // i-json strict only checks plain integer literals; spec §4.8 rejects every integer of
  // 2^53 or more, e.g. `1e300`, `9007199254740992.0`.
  rejectUnsafeIntegers(value, code);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(code);
  }
  return value as Record<string, unknown>;
}

function rejectUnsafeIntegers(value: unknown, code: string): void {
  if (typeof value === "number") {
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) fail(code);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) rejectUnsafeIntegers(item, code);
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const item of Object.values(value)) rejectUnsafeIntegers(item, code);
  }
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

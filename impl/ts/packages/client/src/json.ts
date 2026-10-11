// Spec §4.4, §4.8: internal received JSON and binary field helpers.
import { base64urlnopad } from "@scure/base";
import { bytesToUtf8, parseIJson } from "@wake-protocol/codec";
import { WakeError } from "@wake-protocol/core";

/** Maps standard parsing errors to the specified WAKE boundary code. */
function remap<T>(code: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof RangeError || e instanceof TypeError || e instanceof SyntaxError) {
      throw new WakeError(code);
    }
    throw e;
  }
}

/** Requires a received JSON object rather than null, an array or a scalar. */
export function object(value: unknown, code = "bad_request"): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new WakeError(code);
  }
  return value as Record<string, unknown>;
}

/** Requires a nonnegative safe integer at or below the field's maximum. */
export function integer(value: unknown, max = Number.MAX_SAFE_INTEGER, code = "bad_request"): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new WakeError(code);
  }
  return value;
}

/** Decodes only canonical unpadded base64url, remapping received input errors. */
export function decodeBinary(value: unknown, code = "bad_request"): Uint8Array {
  if (typeof value !== "string") {
    throw new WakeError(code);
  }
  let raw: Uint8Array;
  try {
    raw = base64urlnopad.decode(value);
  } catch (e) {
    // scure uses plain Error for malformed alphabets and padding.
    if (e instanceof Error) {
      throw new WakeError(code);
    }
    throw e;
  }
  if (base64urlnopad.encode(raw) !== value) {
    throw new WakeError(code);
  }
  return raw;
}

/** Parses strict UTF-8 and I-JSON, remapping received input errors. */
export function parseJson(bytes: Uint8Array, code = "bad_request"): unknown {
  const text = remap(code, () => bytesToUtf8(bytes));
  return remap(code, () => parseIJson(text));
}

/** Reads a response as a strict JSON object; body transport failures propagate. */
export async function responseJson(response: Response, code = "bad_request"): Promise<Record<string, unknown>> {
  return object(parseJson(new Uint8Array(await response.arrayBuffer()), code), code);
}

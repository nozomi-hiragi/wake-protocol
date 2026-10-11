// Spec §4.4, §4.8: received JSON object and integer field helpers.
import { WakeError, parseJsonObject } from "@wake-protocol/core";

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

/** Reads a response as a strict JSON object; body transport failures propagate. */
export async function responseJson(response: Response, code = "bad_request"): Promise<Record<string, unknown>> {
  return parseJsonObject(new Uint8Array(await response.arrayBuffer()), code);
}

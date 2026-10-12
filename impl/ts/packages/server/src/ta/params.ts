// Spec §4.5, §4.8, §10.6: strict request members shared by the wake/ta/* contexts.
import { WakeError, parseOperationIdHex } from "@wake-protocol/core";

/** Returns the 64 lowercase hex operationId; anything else is invalid_request. */
export function operationIdParam(value: unknown): string {
  if (typeof value !== "string") {
    throw new WakeError("invalid_request");
  }
  try {
    parseOperationIdHex(value);
  } catch (e) {
    if (e instanceof WakeError && e.code === "bad_request") {
      throw new WakeError("invalid_request");
    }
    throw e;
  }
  return value;
}

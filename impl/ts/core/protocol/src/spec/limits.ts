// Size limit checking for options and lengths (spec §12.3).
import { fail } from "./errors.ts";

/**
 * Checks a per-deployment size option and a length against it: a malformed
 * option fails with invalid_option, an over-limit length with too_large (§12.3).
 */
export function checkMaxLength(length: number, limit: number, optionName: string, tooLargeMessage: string): void {
  if (!(Number.isSafeInteger(limit) && limit >= 0)) fail("invalid_option", `${optionName} must be a non-negative safe integer`);
  if (length > limit) fail("too_large", tooLargeMessage);
}

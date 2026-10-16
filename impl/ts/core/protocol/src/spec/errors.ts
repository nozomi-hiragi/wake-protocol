/**
 * Error raised by WAKE primitives. `code` is either a wire error code from
 * spec §12 (e.g. `bad_request`, `invalid_content`) or a local code for
 * low-level validation that the spec does not name (e.g. `invalid_base64url`).
 */
export class WakeError extends Error {
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "WakeError";
    this.code = code;
  }
}

export function fail(code: string, message?: string): never {
  throw new WakeError(code, message);
}

function isStandardError(e: unknown): e is RangeError | TypeError | SyntaxError {
  return e instanceof RangeError || e instanceof TypeError || e instanceof SyntaxError;
}

/**
 * Runs `fn` at a WAKE boundary: standard errors thrown by the generic layers
 * (RangeError, TypeError, SyntaxError) become WakeError(code). WakeErrors pass through.
 */
export function remap<T>(code: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (isStandardError(e)) fail(code, e.message);
    throw e;
  }
}

/** Async twin of remap. */
export async function remapAsync<T>(code: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (isStandardError(e)) fail(code, e.message);
    throw e;
  }
}

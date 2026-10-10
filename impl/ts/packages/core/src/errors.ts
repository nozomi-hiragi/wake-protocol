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

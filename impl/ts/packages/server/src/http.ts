// Spec §4.4, §4.8, §12: strict input boundaries and HTTP responses.
import { WakeError } from "@wake-protocol/core";

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function jsonResponse(body: unknown, status = 200): Response {
  return jsonTextResponse(JSON.stringify(body), status);
}

export function jsonTextResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function withRetryAfter(response: Response, code: string, retryAfterSec: number): Response {
  if (code === "rate_limited") {
    response.headers.set("retry-after", String(retryAfterSec));
  }
  return response;
}

export function outerError(code: string, retryAfterSec: number): Response {
  const statuses: Record<string, number> = {
    bad_request: 400,
    too_large: 413,
    reauth: 401,
    epoch_retired: 401,
    rate_limited: 429,
    retry: 503,
  };
  return withRetryAfter(jsonResponse({ wakeError: code }, statuses[code] ?? 503), code, retryAfterSec);
}

export function authError(code: string, retryAfterSec: number): Response {
  const statuses: Record<string, number> = {
    bad_request: 400,
    auth_failed: 401,
    rate_limited: 429,
    retry: 503,
  };
  return withRetryAfter(jsonResponse({ error: code }, statuses[code] ?? 503), code, retryAfterSec);
}

export function checkContentType(req: Request, expected: string): void {
  if (req.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() !== expected) {
    throw new WakeError("bad_request");
  }
}

/** Cap streaming reads even when Content-Length is absent or misleading. */
export async function readBody(req: Request, max: number, code: string): Promise<Uint8Array> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d+$/u.test(declared)) {
      throw new WakeError("bad_request");
    }
    if (BigInt(declared) > BigInt(max)) {
      throw new WakeError(code);
    }
  }
  if (!req.body) {
    return new Uint8Array();
  }
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      length += value.length;
      if (length > max) {
        // Cancellation is cleanup; preserve the primary size error even if it
        // rejects or never settles, and never wait for an untrusted source.
        void reader.cancel().catch(() => {});
        throw new WakeError(code);
      }
      chunks.push(value.slice());
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

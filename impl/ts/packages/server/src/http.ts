// Spec §4.4, §4.8, §12: strict input boundaries and HTTP responses.
import { base64urlnopad } from "@scure/base";
import { bytesToUtf8, parseIJson } from "@wake-protocol/codec";
import { WakeError } from "@wake-protocol/core";

export function remapInput<T>(code: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof RangeError || e instanceof TypeError || e instanceof SyntaxError) {
      throw new WakeError(code);
    }
    throw e;
  }
}

export function parseObject(bytes: Uint8Array, code: string): Record<string, unknown> {
  const text = remapInput(code, () => bytesToUtf8(bytes));
  const value = remapInput(code, () => parseIJson(text));
  if (!isObject(value)) {
    throw new WakeError(code);
  }
  return value;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function decodeBinary(value: unknown, code: string, length?: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    throw new WakeError(code);
  }
  // @scure/base reports invalid padding bits as Error, so reject known input
  // violations before decoding without remapping unexpected library failures.
  const remainder = value.length % 4;
  const last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(value.at(-1) ?? "A");
  if ((remainder === 2 && (last & 15) !== 0) || (remainder === 3 && (last & 3) !== 0)) {
    throw new WakeError(code);
  }
  const bytes = remapInput(code, () => base64urlnopad.decode(value));
  if ((length !== undefined && bytes.length !== length) || base64urlnopad.encode(bytes) !== value) {
    throw new WakeError(code);
  }
  return bytes;
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

export function outerError(code: string): Response {
  const statuses: Record<string, number> = {
    bad_request: 400,
    too_large: 413,
    reauth: 401,
    epoch_retired: 401,
    rate_limited: 429,
    retry: 503,
  };
  return jsonResponse({ wakeError: code }, statuses[code] ?? 503);
}

export function authError(code: string): Response {
  const statuses: Record<string, number> = {
    bad_request: 400,
    auth_failed: 401,
    rate_limited: 429,
    retry: 503,
  };
  return jsonResponse({ error: code }, statuses[code] ?? 503);
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

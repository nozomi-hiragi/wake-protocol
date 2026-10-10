// Spec §10.3–10.4: content profile, hashInput and operationId (WAKE-TA).
import { type Bytes, hex, utf8 } from "./encoding.ts";
import { sha256 } from "./crypto.ts";
import { fail } from "./errors.ts";

const MAX_CONTENT_BYTES = 65536;

function forbidden(cp: number): boolean {
  return (
    (cp <= 0x1f && cp !== 0x0a) ||
    (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0xad ||
    cp === 0x061c ||
    cp === 0x200e ||
    cp === 0x200f ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069) ||
    cp === 0x200b ||
    (cp >= 0x2060 && cp <= 0x2064) ||
    cp === 0xfeff ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    (cp >= 0xfff9 && cp <= 0xfffb) ||
    (cp >= 0xe000 && cp <= 0xf8ff) ||
    (cp >= 0xf0000 && cp <= 0xffffd) ||
    (cp >= 0x100000 && cp <= 0x10fffd) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    (cp >= 0xfdd0 && cp <= 0xfdef) ||
    (cp & 0xfffe) === 0xfffe
  );
}

const EDGE = new Set([0x20, 0x0a, 0x3000]);

/** Throws `invalid_content` if `content` violates the profile (§10.4). */
export function checkContent(content: string): void {
  if (!content.isWellFormed()) fail("invalid_content", "not well-formed UTF-16/UTF-8");
  const len = new TextEncoder().encode(content).length;
  if (len < 1 || len > MAX_CONTENT_BYTES) fail("invalid_content", "length");
  if (content.normalize("NFC") !== content) fail("invalid_content", "not NFC");
  const cps = Array.from(content, (c) => c.codePointAt(0)!);
  for (const cp of cps) if (forbidden(cp)) fail("invalid_content", `forbidden code point U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
  if (EDGE.has(cps[0]!) || EDGE.has(cps[cps.length - 1]!)) fail("invalid_content", "leading/trailing whitespace or LF");
  for (let i = 1; i < cps.length; i++) {
    if (cps[i] === 0x0a && (cps[i - 1] === 0x20 || cps[i - 1] === 0x3000)) fail("invalid_content", "trailing space before LF");
  }
}

export function hashInput(content: string, nonce: Bytes): string {
  if (nonce.length !== 16) fail("bad_request", "TA nonce must be 16 bytes");
  return `${content}\nWAKE-TA-Nonce: ${hex(nonce)}`;
}

export async function operationId(hashInputStr: string): Promise<Bytes> {
  return sha256(utf8(hashInputStr));
}

/** Validates content and computes the operation identity (§10.2 step 2–3). */
export async function createOperationIdentity(content: string, nonce: Bytes): Promise<{ hashInput: string; operationId: string }> {
  checkContent(content);
  const hi = hashInput(content, nonce);
  return { hashInput: hi, operationId: hex(await operationId(hi)) };
}

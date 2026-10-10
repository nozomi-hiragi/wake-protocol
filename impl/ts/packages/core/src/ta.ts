// Spec §10.3–10.4: content profile, hashInput and operationId (WAKE-TA).
import { fromHex, hex, utf8 } from "./encoding.ts";
import { sha256 } from "./crypto.ts";
import { fail } from "./errors.ts";
import { type OperationId, type TaNonce, asOperationId } from "./types.ts";

const MAX_CONTENT_BYTES = 65536;

/** General category Cc: U+0000-U+001F and U+007F-U+009F (LF, CR and TAB included). */
function isControl(cp: number): boolean {
  return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f);
}

const EDGE = new Set([0x20, 0x3000]);

/** Throws `invalid_content` if `content` violates the profile (§10.4). */
export function checkContent(content: string): void {
  if (!content.isWellFormed()) fail("invalid_content", "not well-formed UTF-16/UTF-8");
  const len = new TextEncoder().encode(content).length;
  if (len < 1 || len > MAX_CONTENT_BYTES) fail("invalid_content", "length");
  if (content.normalize("NFC") !== content) fail("invalid_content", "not NFC");
  const cps = Array.from(content, (c) => c.codePointAt(0)!);
  for (const cp of cps) if (isControl(cp)) fail("invalid_content", `control character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
  if (EDGE.has(cps[0]!) || EDGE.has(cps[cps.length - 1]!)) fail("invalid_content", "leading/trailing space");
}

export function hashInput(content: string, nonce: TaNonce): string {
  return `${content}\nWAKE-TA-Nonce: ${hex(nonce)}`;
}

export async function operationId(hashInputStr: string): Promise<OperationId> {
  return asOperationId(await sha256(utf8(hashInputStr)));
}

/** External form of operationId: exactly 64 lowercase hex characters (§4.5). */
export function parseOperationIdHex(s: string): OperationId {
  if (!/^[0-9a-f]{64}$/.test(s)) fail("bad_request", "operationId must be 64 lowercase hex characters");
  return asOperationId(fromHex(s));
}

/** Validates content and computes the operation identity (§10.2 step 2–3). */
export async function createOperationIdentity(content: string, nonce: TaNonce): Promise<{ hashInput: string; operationId: string }> {
  checkContent(content);
  const hi = hashInput(content, nonce);
  return { hashInput: hi, operationId: hex(await operationId(hi)) };
}

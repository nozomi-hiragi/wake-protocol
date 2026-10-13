// Spec §10.4: content profile.
import { fail } from "../spec/errors.ts";

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

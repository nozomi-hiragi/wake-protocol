// Spec §10.11 step 5: character-by-character rendering model for the approval screen.

export type SegmentKind = "plain" | "space" | "special" | "newline-marker";

export interface DisplaySegment {
  /** The exact source text of the segment. Joining all `text` values reproduces the input. */
  text: string;
  /** The first code point of `text`. */
  codePoint: number;
  /** Index of the first code point of `text` in the input, counted in code points. */
  index: number;
  kind: SegmentKind;
}

export interface SegmentOptions {
  /**
   * Presentation only; the segments' `text` always reproduces the input exactly.
   * "literal" (default): a backslash and "n" are two plain segments.
   * "break": each backslash-n pair becomes one "newline-marker" segment, left to right and non-overlapping.
   */
  newlines?: "literal" | "break";
}

// Cc is excluded here: LF is the hashInput separator and other controls are special below.
const SPECIAL = /^[\p{Cf}\p{Co}\p{Cs}\p{Cn}\p{Zl}\p{Zp}\p{Mn}\p{Me}\p{Variation_Selector}\p{Noncharacter_Code_Point}\p{Default_Ignorable_Code_Point}\u2800]$/u;
const SPACE_SEPARATOR = /^\p{Zs}$/u;
const CONTROL = /^\p{Cc}$/u;

/**
 * Splits a hashInput into one segment per code point (never per UTF-16 unit or grapheme), so that an invisible or
 * bidirectional control character can be drawn as its own element. The only real line break in a hashInput is the
 * LF before the Nonce line; it is a "newline-marker" in both modes. Other Cc characters, format characters
 * (including bidi controls, ZWJ, ZWNJ, ZWSP), variation selectors, private use, noncharacters, unassigned code points,
 * combining marks, default-ignorable code points (e.g. U+115F, U+3164, U+FFA0), U+2800 and every space except U+0020 are "special".
 */
export function segmentHashInput(hashInput: string, options: SegmentOptions = {}): DisplaySegment[] {
  const breakNewlines = options.newlines === "break";
  const chars = Array.from(hashInput);
  const segments: DisplaySegment[] = [];
  for (let i = 0; i < chars.length; i++) {
    const index = i;
    const ch = chars[i]!;
    const codePoint = ch.codePointAt(0)!;
    let text = ch;
    let kind: SegmentKind;
    if (ch === "\n") {
      kind = "newline-marker";
    } else if (breakNewlines && ch === "\\" && chars[i + 1] === "n") {
      text = "\\n";
      kind = "newline-marker";
      i++;
    } else if (ch === " ") {
      kind = "space";
    } else if (CONTROL.test(ch) || SPECIAL.test(ch) || SPACE_SEPARATOR.test(ch)) {
      kind = "special";
    } else {
      kind = "plain";
    }
    segments.push({ text, codePoint, index, kind });
  }
  return segments;
}

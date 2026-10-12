// Spec §10.11 step 5: segmentation of hashInput for the approval screen.
import assert from "node:assert/strict";
import { test } from "node:test";
import { segmentHashInput } from "../src/index.ts";
import type { DisplaySegment } from "../src/index.ts";

const kinds = (s: string, options?: Parameters<typeof segmentHashInput>[1]) => segmentHashInput(s, options).map(x => x.kind);
const join = (segments: DisplaySegment[]) => segments.map(x => x.text).join("");

test("ASCII text is plain and U+0020 is a space", () => {
  assert.deepEqual(kinds("a b"), ["plain", "space", "plain"]);
});

for (const [name, ch] of [
  ["RLO", "‮"], ["LRI", "⁦"], ["PDI", "⁩"], ["RLM", "‏"],
  ["ZWSP", "​"], ["ZWNJ", "‌"], ["ZWJ", "‍"], ["word joiner", "⁠"], ["BOM", "﻿"], ["soft hyphen", "­"],
  ["VS16", "️"], ["VS1", "︀"], ["VS17", "\u{e0100}"], ["VS256", "\u{e01ef}"], ["tag", "\u{e0041}"],
  ["private use BMP", ""], ["private use end", ""], ["plane 15 PUA", "\u{f0000}"], ["plane 16 PUA", "\u{10fffd}"],
  ["noncharacter FDD0", "﷐"], ["noncharacter FFFF", "￿"], ["noncharacter 1FFFE", "\u{1fffe}"],
  ["ideographic space", "　"], ["NBSP", " "], ["en space", " "], ["line separator", " "], ["paragraph separator", " "],
  ["combining acute", "́"], ["enclosing circle", "⃝"], ["NUL", "\u0000"], ["TAB", "\t"], ["DEL", "\u007f"],
  ["unassigned", "\u{e0080}"],
] as const) {
  test(`${name} is special and keeps its own code point`, () => {
    const segments = segmentHashInput(`a${ch}b`);
    assert.deepEqual(segments.map(x => x.kind), ["plain", "special", "plain"]);
    assert.equal(segments[1]!.text, ch);
    assert.equal(segments[1]!.codePoint, ch.codePointAt(0));
    assert.equal(segments[1]!.index, 1);
  });
}

test("emoji, CJK and symbols are plain, one segment per code point", () => {
  const input = "送金😀€é";
  const segments = segmentHashInput(input);
  assert.equal(segments.length, 5);
  assert.deepEqual(segments.map(x => x.kind), ["plain", "plain", "plain", "plain", "plain"]);
  assert.equal(segments[2]!.codePoint, 0x1f600);
  assert.equal(segments[2]!.text, "😀");
  assert.deepEqual(segments.map(x => x.index), [0, 1, 2, 3, 4]);
});

test("a ZWJ sequence is split so the joiner is visible", () => {
  const family = "👨‍👩‍👧";
  assert.deepEqual(kinds(family), ["plain", "special", "plain", "special", "plain"]);
});

test("a bidi control stays its own segment in order and does not merge with neighbours", () => {
  const input = "abc‮def‬";
  const segments = segmentHashInput(input);
  assert.deepEqual(segments.map(x => x.codePoint), [0x61, 0x62, 0x63, 0x202e, 0x64, 0x65, 0x66, 0x202c]);
  assert.equal(join(segments), input);
});

test("backslash-n is two plain segments in literal mode (the default)", () => {
  const segments = segmentHashInput("a\\nb");
  assert.deepEqual(segments.map(x => x.text), ["a", "\\", "n", "b"]);
  assert.deepEqual(segments.map(x => x.kind), ["plain", "plain", "plain", "plain"]);
  assert.deepEqual(segmentHashInput("a\\nb", { newlines: "literal" }), segments);
});

test("break mode only changes presentation: one newline-marker segment whose text is still backslash-n", () => {
  const input = "a\\nb\\n\\nc";
  const literal = segmentHashInput(input, { newlines: "literal" });
  const broken = segmentHashInput(input, { newlines: "break" });
  assert.deepEqual(broken.map(x => x.kind), ["plain", "newline-marker", "plain", "newline-marker", "newline-marker", "plain"]);
  assert.equal(join(broken), input);
  assert.equal(join(literal), input);
  assert.deepEqual(broken.map(x => x.index), [0, 1, 3, 4, 6, 8]);
  assert.equal(broken[1]!.text, "\\n");
  // A lone backslash or a lone n is not a marker.
  assert.deepEqual(kinds("\\x n \\", { newlines: "break" }).filter(k => k === "newline-marker"), []);
  assert.equal(join(segmentHashInput("trailing\\", { newlines: "break" })), "trailing\\");
});

test("the real LF separator before the Nonce line is a newline-marker in both modes", () => {
  const input = "Title\\nBody\nWAKE-TA-Nonce: 3f9a1c7e5b2d4f6081a3c5e7092b4d6f";
  for (const newlines of ["literal", "break"] as const) {
    const segments = segmentHashInput(input, { newlines });
    assert.equal(join(segments), input);
    assert.equal(segments.filter(x => x.kind === "special").length, 0);
    const lf = segments.find(x => x.text === "\n")!;
    assert.equal(lf.kind, "newline-marker");
    assert.equal(lf.codePoint, 10);
  }
  assert.equal(segmentHashInput(input).filter(x => x.kind === "newline-marker").length, 1);
  assert.equal(segmentHashInput(input, { newlines: "break" }).filter(x => x.kind === "newline-marker").length, 2);
});

test("joining the segments reproduces any input exactly, in every mode", () => {
  const inputs = [
    "",
    "plain",
    "‮⁦x⁩️　́\\n\n\\\\n😀‍🧑",
    "\\n\\n\\",
    "a\u{10ffff}b﷐",
  ];
  for (const input of inputs) {
    for (const newlines of ["literal", "break"] as const) {
      assert.equal(join(segmentHashInput(input, { newlines })), input);
    }
  }
});

test("segmenting never changes the input string", () => {
  const input = "x‮y\\nz";
  const copy = String(input);
  segmentHashInput(input, { newlines: "break" });
  assert.equal(input, copy);
});

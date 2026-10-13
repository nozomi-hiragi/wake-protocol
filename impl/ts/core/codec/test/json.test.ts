// Strict I-JSON parser.
import assert from "node:assert/strict";
import test from "node:test";
import { parseIJson } from "../src/index.ts";

const syntax = { name: "SyntaxError" };
const nest = (n: number) => "[".repeat(n) + "]".repeat(n);

test("valid values of every type match JSON.parse", () => {
  const inputs = [
    "null", "true", "false", "0", "-0", "1.5", "-2.25", "1e2", "1E+2", "1e-2", "0.5e1", "123456789",
    '""', '"abc"', '"a\\"b\\\\c\\/d\\b\\f\\n\\r\\t"', '"\\u0041\\u00e9\\u3042"', '"\\ud83d\\ude00"', '"😀あ"',
    "[]", "{}", "[1,2,3]", '{"a":1,"b":[true,null,{"c":"d"}]}', ' \t\r\n[ 1 , { "a" : [ ] } ]\n ',
    '{"":1}', '{"a\\u0062":2}', "[[[[]]]]", '[{"a":{"b":{"c":[1,[2,[3]]]}}}]',
  ];
  for (const text of inputs) assert.deepEqual(parseIJson(text), JSON.parse(text), text);
  assert.ok(Object.is(parseIJson("-0"), -0));
  assert.equal(parseIJson("1e2"), 100);
  assert.equal(parseIJson("1.5"), 1.5);
  assert.ok(Array.isArray(parseIJson("[1]")));
});

test("safe integer boundary is checked on both sides", () => {
  assert.equal(parseIJson("9007199254740991"), 2 ** 53 - 1);
  assert.equal(parseIJson("-9007199254740991"), -(2 ** 53 - 1));
  assert.throws(() => parseIJson("9007199254740992"), syntax);
  assert.throws(() => parseIJson("-9007199254740992"), syntax);
  assert.throws(() => parseIJson("1e300"), syntax);
  assert.throws(() => parseIJson("9007199254740992.0"), syntax);
  assert.throws(() => parseIJson("1e400"), syntax);
  assert.throws(() => parseIJson("-1e400"), syntax);
  assert.throws(() => parseIJson('{"a":[9007199254740993]}'), syntax);
});

test("duplicate member names are rejected, including after unescaping", () => {
  assert.throws(() => parseIJson('{"a":1,"a":2}'), syntax);
  assert.throws(() => parseIJson('{"a":1,"\\u0061":2}'), syntax);
  assert.throws(() => parseIJson('{"x":{"a":1,"a":1}}'), syntax);
  assert.deepEqual(parseIJson('{"a":{"a":1},"b":{"a":2}}'), { a: { a: 1 }, b: { a: 2 } });
  assert.deepEqual(parseIJson('[{"a":1},{"a":2}]'), [{ a: 1 }, { a: 2 }]);
});

test("lone surrogates are rejected, escaped or raw; pairs are accepted", () => {
  assert.throws(() => parseIJson('"\\ud800"'), syntax);
  assert.throws(() => parseIJson('"\\udc00"'), syntax);
  assert.throws(() => parseIJson('"\\ud800a"'), syntax);
  assert.throws(() => parseIJson('"\\ud800\\ud800"'), syntax);
  assert.throws(() => parseIJson('"\\udc00\\ud800"'), syntax);
  assert.throws(() => parseIJson('"\ud800"'), syntax);
  assert.throws(() => parseIJson('"\udc00"'), syntax);
  assert.throws(() => parseIJson('{"\\ud800":1}'), syntax);
  assert.equal(parseIJson('"\\ud83d\\ude00"'), "\u{1F600}");
  assert.equal(parseIJson('"\ud83d\ude00"'), "\u{1F600}");
  assert.equal(parseIJson('"\\ud83d\ude00"'), "\u{1F600}");
});

test("__proto__ is an own data property and does not change the prototype", () => {
  const value = parseIJson('{"__proto__":{"polluted":true},"a":1}') as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.deepEqual(Object.keys(value), ["__proto__", "a"]);
  assert.deepEqual(Object.getOwnPropertyDescriptor(value, "__proto__"), {
    value: { polluted: true }, enumerable: true, writable: true, configurable: true,
  });
  assert.equal((value as { polluted?: unknown }).polluted, undefined);
  assert.equal(({} as { polluted?: unknown }).polluted, undefined);
});

test("nesting depth 64 is accepted and 65 throws RangeError", () => {
  assert.doesNotThrow(() => parseIJson(nest(64)));
  assert.throws(() => parseIJson(nest(65)), { name: "RangeError" });
  assert.doesNotThrow(() => parseIJson('{"a":'.repeat(63) + "[]" + "}".repeat(63)));
  assert.throws(() => parseIJson('{"a":'.repeat(64) + "[]" + "}".repeat(64)), { name: "RangeError" });
  assert.throws(() => parseIJson("[".repeat(100000)), { name: "RangeError" });
});

test("malformed syntax is rejected with SyntaxError", () => {
  const bad = [
    "", " ", "\ufeff1", "1 2", "[] x", "{}}", "[1,]", '{"a":1,}', "[,1]", "[1 2]", '{"a" 1}', '{"a":}', "{a:1}", "{'a':1}",
    "[", "{", '"abc', '{"a":1', "01", "-01", "00", "+1", "1.", ".5", "-", "1e", "1e+", "0x10", "1.5.2", "--1", "1-1",
    "NaN", "Infinity", "-Infinity", "nul", "True", "undefined", "tru", "nullx",
    "// c\n1", "/* c */1", "[1,/* c */2]", "1 // c",
    '"\\x41"', '"\\u12"', '"\\u12G4"', '"\\a"', '"\\', '"\\U0041"',
    '"\u0000"', '"\u001f"', '"a\nb"', '"a\tb"',
    "\u00a01", "1\u00a0", "\v1", "\f1", "\u20281",
  ];
  for (const text of bad) assert.throws(() => parseIJson(text), syntax, JSON.stringify(text));
});

test("only space, tab, LF and CR are whitespace, and trailing whitespace is fine", () => {
  assert.deepEqual(parseIJson(" \t\n\r[\t1\n,\r2 ] \n"), [1, 2]);
});

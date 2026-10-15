// Strict JSON object parsing and canonical base64url fields (spec §4.4, §4.8).
import assert from "node:assert/strict";
import test from "node:test";
import { utf8ToBytes } from "@wake-protocol/codec";
import { WakeError, decodeBase64urlField, parseJsonObject } from "../src/index.ts";

function rejects(fn: () => unknown, code: string): void {
  assert.throws(fn, e => e instanceof WakeError && e.code === code);
}

test("parseJsonObject accepts an object", () => {
  assert.deepEqual(parseJsonObject(utf8ToBytes('{"a":1,"b":[true,null]}'), "bad_request"), { a: 1, b: [true, null] });
});

test("parseJsonObject rejects non-objects", () => {
  for (const text of ["[]", "1", '"x"', "null", "true"]) {
    rejects(() => parseJsonObject(utf8ToBytes(text), "bad_request"), "bad_request");
  }
});

test("parseJsonObject rejects duplicate keys, invalid JSON and invalid UTF-8 with the given code", () => {
  rejects(() => parseJsonObject(utf8ToBytes('{"a":1,"a":2}'), "invalid_request"), "invalid_request");
  rejects(() => parseJsonObject(utf8ToBytes("{"), "invalid_request"), "invalid_request");
  rejects(() => parseJsonObject(utf8ToBytes('{"a":"\\ud800"}'), "invalid_request"), "invalid_request");
  rejects(() => parseJsonObject(new Uint8Array([0x7b, 0xff, 0x7d]), "invalid_request"), "invalid_request");
});

const objectWith = (value: string) => utf8ToBytes(`{"v":${value}}`);

test("parseJsonObject accepts safe integers and rejects 2^53 and above, including exponent and fraction forms", () => {
  assert.equal(parseJsonObject(objectWith("9007199254740991"), "bad_request").v, 2 ** 53 - 1);
  assert.equal(parseJsonObject(objectWith("-9007199254740991"), "bad_request").v, -(2 ** 53 - 1));
  assert.equal(parseJsonObject(objectWith("9007199254740991.0"), "bad_request").v, 2 ** 53 - 1);
  for (const value of ["9007199254740992", "-9007199254740992", "1e300", "9007199254740992.0", "1e400", "-1e400"]) {
    rejects(() => parseJsonObject(objectWith(value), "bad_request"), "bad_request");
  }
  rejects(() => parseJsonObject(utf8ToBytes('{"v":[9007199254740993]}'), "bad_request"), "bad_request");
});

test("parseJsonObject rejects duplicate keys after unescaping and allows the same key in siblings", () => {
  rejects(() => parseJsonObject(utf8ToBytes('{"a":1,"\\u0061":2}'), "bad_request"), "bad_request");
  rejects(() => parseJsonObject(utf8ToBytes('{"x":{"a":1,"a":1}}'), "bad_request"), "bad_request");
  assert.deepEqual(parseJsonObject(utf8ToBytes('{"a":{"a":1},"b":{"a":2}}'), "bad_request"), { a: { a: 1 }, b: { a: 2 } });
  assert.deepEqual(parseJsonObject(utf8ToBytes('{"v":[{"a":1},{"a":2}]}'), "bad_request"), { v: [{ a: 1 }, { a: 2 }] });
});

test("parseJsonObject rejects escaped lone surrogates and accepts surrogate pairs", () => {
  for (const value of ['"\\ud800"', '"\\udc00"', '"\\ud800a"', '"\\ud800\\ud800"', '"\\udc00\\ud800"']) {
    rejects(() => parseJsonObject(objectWith(value), "bad_request"), "bad_request");
  }
  rejects(() => parseJsonObject(utf8ToBytes('{"\\ud800":1}'), "bad_request"), "bad_request");
  assert.equal(parseJsonObject(objectWith('"\\ud83d\\ude00"'), "bad_request").v, "\u{1F600}");
});

test("parseJsonObject rejects noncharacters", () => {
  rejects(() => parseJsonObject(utf8ToBytes('{"v":"\\uffff"}'), "bad_request"), "bad_request");
});

test("parseJsonObject keeps __proto__ as an own property", () => {
  const value = parseJsonObject(utf8ToBytes('{"__proto__":{"polluted":true},"a":1}'), "bad_request");
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
  assert.deepEqual(Object.keys(value), ["__proto__", "a"]);
  assert.deepEqual(Object.getOwnPropertyDescriptor(value, "__proto__"), {
    value: { polluted: true }, enumerable: true, writable: true, configurable: true,
  });
  assert.equal((value as { polluted?: unknown }).polluted, undefined);
  assert.equal(({} as { polluted?: unknown }).polluted, undefined);
});

test("parseJsonObject accepts nesting depth 64 and rejects 65", () => {
  // The wrapper object counts toward the depth: 63 nested arrays plus the wrapper is 64.
  const wrapped = (n: number) => utf8ToBytes(`{"v":${"[".repeat(n)}${"]".repeat(n)}}`);
  assert.deepEqual(parseJsonObject(wrapped(63), "bad_request").v, JSON.parse("[".repeat(63) + "]".repeat(63)));
  rejects(() => parseJsonObject(wrapped(64), "bad_request"), "bad_request");
  const objects = (n: number) => '{"a":'.repeat(n) + "[]" + "}".repeat(n);
  assert.deepEqual(parseJsonObject(utf8ToBytes(objects(63)), "bad_request"), JSON.parse(objects(63)));
  rejects(() => parseJsonObject(utf8ToBytes(objects(64)), "bad_request"), "bad_request");
  rejects(() => parseJsonObject(utf8ToBytes(`{"v":${"[".repeat(100000)}}`), "bad_request"), "bad_request");
});

test("parseJsonObject rejects malformed JSON, a UTF-8 BOM and non-whitespace", () => {
  const bad = [
    "", " ", "\ufeff1", "1 2", "[] x", "{}}", "[1,]", '{"a":1,}', "[,1]", "[1 2]", '{"a" 1}', '{"a":}', "{a:1}", "{'a':1}",
    "[", "{", '"abc', '{"a":1', "01", "-01", "00", "+1", "1.", ".5", "-", "1e", "1e+", "0x10", "1.5.2", "--1", "1-1",
    "NaN", "Infinity", "-Infinity", "nul", "True", "undefined", "tru", "nullx",
    "// c\n1", "/* c */1", "[1,/* c */2]", "1 // c",
    '"\\x41"', '"\\u12"', '"\\u12G4"', '"\\a"', '"\\', '"\\U0041"',
    '"\u0000"', '"\u001f"', '"a\nb"', '"a\tb"',
    "\u00a01", "1\u00a0", "\v1", "\f1", "\u20281",
  ];
  for (const text of bad) {
    rejects(() => parseJsonObject(utf8ToBytes(text), "bad_request"), "bad_request");
    // Wrapped so a top-level scalar is not rejected only for being a non-object.
    rejects(() => parseJsonObject(utf8ToBytes(`{"v":${text}}`), "bad_request"), "bad_request");
  }
  rejects(() => parseJsonObject(Uint8Array.of(0xef, 0xbb, 0xbf, 0x7b, 0x7d), "bad_request"), "bad_request");
});

test("parseJsonObject accepts only space, tab, LF and CR as whitespace", () => {
  assert.deepEqual(parseJsonObject(utf8ToBytes(" \t\n\r{\t\"v\"\n:\r[1,2] }\n"), "bad_request"), { v: [1, 2] });
});

test("decodeBase64urlField decodes canonical values at both sides of the length", () => {
  const value = "AAECAwQFBgcICQoLDA0ODw";
  assert.equal(decodeBase64urlField(value, "bad_request").length, 16);
  assert.equal(decodeBase64urlField(value, "bad_request", 16).length, 16);
  rejects(() => decodeBase64urlField(value, "bad_request", 15), "bad_request");
  rejects(() => decodeBase64urlField(value, "bad_request", 17), "bad_request");
  assert.equal(decodeBase64urlField("", "bad_request", 0).length, 0);
});

test("decodeBase64urlField rejects non-zero trailing bits", () => {
  // Two-character tail carries 4 spare bits; three-character tail carries 2.
  assert.deepEqual([...decodeBase64urlField("AA", "x")], [0]);
  rejects(() => decodeBase64urlField("AB", "x"), "x");
  assert.deepEqual([...decodeBase64urlField("AAA", "x")], [0, 0]);
  rejects(() => decodeBase64urlField("AAB", "x"), "x");
});

test("decodeBase64urlField rejects padding, bad characters, bad lengths and non-strings", () => {
  rejects(() => decodeBase64urlField("AA==", "x"), "x");
  rejects(() => decodeBase64urlField("AA+/", "x"), "x");
  rejects(() => decodeBase64urlField("AA A", "x"), "x");
  rejects(() => decodeBase64urlField("A", "x"), "x");
  rejects(() => decodeBase64urlField("AAAAA", "x"), "x");
  rejects(() => decodeBase64urlField(undefined, "x"), "x");
  rejects(() => decodeBase64urlField(1, "x"), "x");
  rejects(() => decodeBase64urlField(null, "x"), "x");
});

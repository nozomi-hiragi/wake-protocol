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

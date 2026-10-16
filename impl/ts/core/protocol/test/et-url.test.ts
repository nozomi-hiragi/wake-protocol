// Spec §11.2–11.4: URI-reference grammar, method tokens and null-body semantics.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Byte2 } from "@wake-protocol/bytes";
import { asciiToBytes, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import {
  Bytes, WakeError, ET_METHOD_MAX, ET_URL_MAX, checkUrl, checkMethod,
  encodeEtRequest, decodeEtRequest, encodeEtResponse, decodeEtResponse,
} from "../src/index.ts";

const empty = new Uint8Array();
const hasCode = (code: string) => (e: unknown) => e instanceof WakeError && e.code === code;
const request = (url: string, method = "POST", body = empty) => ({ method, url, headers: [], body: new Bytes(body) });
const rawRequest = (url: string, method = "POST", body = empty) => encodeU32LengthPrefixed(
  asciiToBytes("WAKE/1 et-req"), asciiToBytes(method), asciiToBytes(url), empty, body,
);

const validUrls = [
  "", "wake://app/members?id=1", "https://h/x?y=1", "/members?id=1", "a/b", "//host/x", "a:b",
  "?query", "?", "/", "a:", "a:/", "a:rootless", "a://", "//", "///a", "//host:",
  "//user:pass@host:80/a", "//%41!$&'()*+,;=:@h%6fst/", "//192.0.2.1/x", "//999.01.2.3/",
  "/a/../b//%2f/%2F/%41?x=/a?b", "/!$&'()*+,;=:@-._~", "a/b:c", "/?q=%5b%5D",
  "http://[::1]:8080/x", "http://[::]/", "//[1:2:3:4:5:6:7:8]/", "//[1::]/", "//[1:2:3:4:5:6:7::]/",
  "//[::1:2:3:4:5:6:7]/", "//[1:2:3:4:5:6:192.0.2.1]/", "//[::ffff:192.0.2.1]/", "//[::192.0.2.1]/",
  "//[1:2:3:4:5::192.0.2.1]/", "http://[v1.a]/", "//[VF.a:b!$&'()*+,;=]/", "a".repeat(ET_URL_MAX),
];
for (const [i, url] of validUrls.entries()) {
  test(`URI-reference accepted unchanged ${i}`, () => {
    assert.doesNotThrow(() => checkUrl(url));
    assert.equal(decodeEtRequest(encodeEtRequest(request(url))).url, url);
    assert.equal(decodeEtRequest(rawRequest(url)).url, url);
  });
}

const invalidUrls = [
  "1a:b", ":b", "a_b:c", "/a[b", "/a]b", "?q=[x]", "/x#y", "#", "/a b", '/a"b', "/a\\b",
  "/a\n", "/a\r", "/a\u2028", "/あ", "/%zz", "/%", "/%0", "/%0g", "//h%zz/", "//user%0@h/",
  "http://[::1", "http://[1:2:3:4:5:6:7:8:9]/", "http://h:80a/", "//h:1:2/", "//a@b@h/",
  "//h]/", "//[::1]extra/", "//[::1]:x/", "//[]/", "//[1:2:3:4:5:6:7]/", "//[1:2:3:4:5:6:7:8::]/",
  "//[:::]/", "//[1::2::3]/", "//[1:2:3:4:5:6:7:]/", "//[:1:2:3:4:5:6:7]/", "//[12345::]/",
  "//[1:2:3:4:5:6:7:192.0.2.1]/", "//[::ffff:192.00.2.1]/", "//[::ffff:256.0.2.1]/", "//[192.0.2.1::]/",
  "//[::ffff:192.0.2]/", "//[::ffff:192.0.2.1:1]/", "//[v.a]/", "//[v1.]/", "//[v1.%41]/",
  "a".repeat(ET_URL_MAX + 1),
];
for (const [i, url] of invalidUrls.entries()) {
  test(`invalid URI-reference rejected on encode and decode ${i}`, () => {
    assert.throws(() => checkUrl(url), hasCode("invalid_url"));
    assert.throws(() => encodeEtRequest(request(url)), hasCode("invalid_url"));
    // Raw decoder tests use ASCII bytes; non-ASCII octets are covered by et-decode.test.ts.
    if (/^[\x00-\x7f]*$/.test(url)) assert.throws(() => decodeEtRequest(rawRequest(url)), hasCode("invalid_url"));
  });
}

for (const method of ["get", "hEaD", "OPTIONS", "x-Custom", "!#$%&'*+-.^_`|~", "X".repeat(ET_METHOD_MAX)]) {
  test(`method token preserved: ${method}`, () => {
    assert.doesNotThrow(() => checkMethod(method));
    assert.equal(decodeEtRequest(encodeEtRequest(request("/", method))).method, method);
    assert.equal(decodeEtRequest(rawRequest("/", method)).method, method);
  });
}
for (const method of ["", "X".repeat(ET_METHOD_MAX + 1), "a b", "a/b", "a:b", "a\n", "a\r", "é", "CONNECT", "connect", "cOnNeCt", "TRACE", "trace", "TrAcE", "TRACK", "track", "TrAcK"]) {
  test(`invalid method rejected: ${JSON.stringify(method)}`, () => {
    assert.throws(() => checkMethod(method), hasCode("invalid_method"));
    assert.throws(() => encodeEtRequest(request("/", method)), hasCode("invalid_method"));
    if (/^[\x00-\x7f]*$/.test(method)) assert.throws(() => decodeEtRequest(rawRequest("/", method)), hasCode("invalid_method"));
  });
}

for (const method of ["GET", "get", "HEAD", "hEaD"]) {
  test(`${method} accepts an empty body and rejects a nonempty body`, () => {
    assert.equal(decodeEtRequest(encodeEtRequest(request("/", method))).body.length, 0);
    assert.throws(() => encodeEtRequest(request("/", method, Uint8Array.of(1))), hasCode("invalid_request"));
    assert.throws(() => decodeEtRequest(rawRequest("/", method, Uint8Array.of(1))), hasCode("invalid_request"));
    assert.throws(() => encodeEtRequest(request("/", method, Uint8Array.of(1)), { bodyLimit: 0 }), hasCode("too_large"));
    assert.throws(() => decodeEtRequest(rawRequest("/", method, Uint8Array.of(1)), { bodyLimit: 0 }), hasCode("too_large"));
  });
}
for (const status of [204, 205, 304]) {
  test(`${status} accepts an empty body and rejects a nonempty body`, () => {
    assert.equal(decodeEtResponse(encodeEtResponse({ status, headers: [], body: new Bytes([]) })).body.length, 0);
    const response = { status, headers: [], body: new Bytes([1]) };
    const raw = encodeU32LengthPrefixed(asciiToBytes("WAKE/1 et-res"), new Byte2(status).toUint8Array(), empty, Uint8Array.of(1));
    assert.throws(() => encodeEtResponse(response), hasCode("invalid_request"));
    assert.throws(() => decodeEtResponse(raw), hasCode("invalid_request"));
    assert.throws(() => encodeEtResponse(response, { bodyLimit: 0 }), hasCode("too_large"));
    assert.throws(() => decodeEtResponse(raw, { bodyLimit: 0 }), hasCode("too_large"));
  });
}

test("duplicate headers and opaque locations survive both codecs", () => {
  const headers = [["Content-Type", "a"], ["content-type", "b"], ["Host", "a"], ["host", "b"],
    ["Location", "https://other.example/"], ["location", "//other.example/x"]] as const;
  assert.deepEqual(decodeEtRequest(encodeEtRequest({ ...request("/"), headers })).headers, headers);
  assert.deepEqual(decodeEtResponse(encodeEtResponse({ status: 302, headers, body: new Bytes([]) })).headers, headers);
  for (const value of ["x\n", "x\r", "x\r\n"]) {
    assert.throws(() => encodeEtRequest({ ...request("/"), headers: [["x", value]] }), hasCode("invalid_header"));
    assert.throws(() => encodeEtRequest({ ...request("/"), headers: [[value, "x"]] }), hasCode("invalid_header"));
  }
});

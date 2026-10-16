// v0.5 rule changes: TA profile (§10.4) and ET URL/headers (§11.2–11.4).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Bytes,
  WakeError,
  checkContent,
  checkUrl,
  checkResponseHeaders,
  checkRequestHeaders,
  decodeEtResponse,
  encodeEtResponse,
} from "../src/index.ts";

const code = (fn: () => void): string | undefined => {
  try {
    fn();
  } catch (e) {
    if (e instanceof WakeError) return e.code;
    throw e;
  }
  return undefined;
};

const splitU32LengthPrefixed = (wire: Uint8Array): Uint8Array[] => {
  const fields: Uint8Array[] = [];
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  let offset = 0;
  while (offset < wire.length) {
    const length = view.getUint32(offset);
    offset += 4;
    fields.push(wire.slice(offset, offset + length));
    offset += length;
  }
  assert.equal(offset, wire.length);
  return fields;
};

describe("TA profile v0.5", () => {
  it("rejects every Cc character, LF included", () => {
    for (const cp of [0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x7f, 0x85, 0x9f]) {
      assert.equal(code(() => checkContent(`a${String.fromCodePoint(cp)}b`)), "invalid_content", cp.toString(16));
    }
  });
  it("accepts non-Cc special characters", () => {
    for (const cp of [0xad, 0x200b, 0x202e, 0x2028, 0xe000, 0xfffe, 0xe0001]) {
      assert.equal(code(() => checkContent(`a${String.fromCodePoint(cp)}b`)), undefined, cp.toString(16));
    }
  });
  it("rejects leading/trailing U+0020 and U+3000 only", () => {
    assert.equal(code(() => checkContent(" a")), "invalid_content");
    assert.equal(code(() => checkContent("a　")), "invalid_content");
    assert.equal(code(() => checkContent("a b")), undefined);
  });
});

describe("ET v0.5", () => {
  it("paths under /wake/ are no longer rejected by the codec", () => {
    assert.equal(code(() => checkUrl("/wake/x")), undefined);
  });
  it("percent-encoding accepts either hex case and rejects malformed escapes", () => {
    assert.equal(code(() => checkUrl("?q=%e3%81%82")), undefined);
    assert.equal(code(() => checkUrl("?q=%zz")), "invalid_url");
    assert.equal(code(() => checkUrl("/a%e3")), undefined);
    assert.equal(code(() => checkUrl("/a%3")), "invalid_url");
  });
  it("preserves arbitrary headers and duplicates", () => {
    assert.equal(code(() => checkRequestHeaders([["accept", "a"], ["accept", "b"]])), undefined);
    assert.equal(code(() => checkRequestHeaders([["X-Trace-Id", "a"]])), undefined);
    assert.equal(code(() => checkRequestHeaders([["cookie", "a=b"]])), undefined);
    for (const n of ["content-type", "idempotency-key", "if-modified-since", "CONTENT-TYPE"]) {
      assert.equal(code(() => checkRequestHeaders([[n, "a"], [n, "b"]])), undefined, n);
    }
    assert.equal(code(() => checkRequestHeaders([["Content-Type", "a"], ["content-type", "b"]])), undefined);
    assert.equal(code(() => checkResponseHeaders([["etag", "a"], ["etag", "b"]])), undefined);
  });
  it("accepts duplicate Host lines", () => {
    assert.equal(code(() => checkRequestHeaders([["Host", "a.example"]])), undefined);
    assert.equal(code(() => checkRequestHeaders([["Host", "a.example"], ["host", "b.example"]])), undefined);
  });
  it("round-trips field case, obs-text bytes, order, and separate Set-Cookie fields", () => {
    const headers = [["X-Trace-Id", "opaque-\u00e9"], ["Set-Cookie", "a=1"], ["set-cookie", "b=2"]] as const;
    const wire = encodeEtResponse({ status: 200, headers, body: new Bytes([]) });
    const wireHeaders = splitU32LengthPrefixed(splitU32LengthPrefixed(wire.toUint8Array())[2]!);
    assert.deepEqual(Array.from(wireHeaders[1]!), [111, 112, 97, 113, 117, 101, 45, 0xe9]);
    assert.deepEqual(decodeEtResponse(wire).headers, headers);
    assert.equal(code(() => checkResponseHeaders([["X-Opaque", "\u0085"]])), undefined);
    assert.equal(code(() => checkResponseHeaders([["X-Opaque", "\u0100"]])), "invalid_header");
    assert.equal(code(() => checkResponseHeaders([["X-Opaque", "x\u0000y"]])), "invalid_header");
    assert.equal(code(() => checkResponseHeaders([["x", "é".repeat(8191)]])), undefined);
    assert.equal(code(() => checkResponseHeaders([["x", "é".repeat(8192)]])), "invalid_header");
  });
  it("location values are opaque field octets", () => {
    for (const value of ["/a/b?x=1", "//e.example", "https://e.example/", "x/y", "./x", "../x", "", "/a%zz"]) {
      assert.doesNotThrow(() => checkResponseHeaders([["location", value], ["Location", value]]));
    }
  });
});

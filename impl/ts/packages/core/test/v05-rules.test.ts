// v0.5 rule changes: TA profile (§10.4) and ET headers/query/location (§11.2–11.4).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ET_SINGLETON_HEADERS, WakeError, checkContent, checkPath, checkQuery, checkResponseHeaders, checkRequestHeaders } from "../src/index.ts";

const code = (fn: () => void): string | undefined => {
  try {
    fn();
  } catch (e) {
    if (e instanceof WakeError) return e.code;
    throw e;
  }
  return undefined;
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
    assert.equal(code(() => checkPath("/wake/x")), undefined);
  });
  it("query percent-encoding may be lowercase; paths still uppercase", () => {
    assert.equal(code(() => checkQuery("q=%e3%81%82")), undefined);
    assert.equal(code(() => checkQuery("q=%zz")), "invalid_path");
    assert.equal(code(() => checkPath("/a%e3")), "invalid_path");
  });
  it("duplicate non-singleton headers are allowed, singletons are not", () => {
    assert.equal(code(() => checkRequestHeaders([["accept", "a"], ["accept", "b"]])), undefined);
    for (const n of ["content-type", "idempotency-key", "if-modified-since"]) {
      assert.ok(ET_SINGLETON_HEADERS.has(n));
      assert.equal(code(() => checkRequestHeaders([[n, "a"], [n, "b"]])), "invalid_header", n);
    }
    assert.equal(code(() => checkResponseHeaders([["etag", "a"], ["etag", "b"]])), "invalid_header");
  });
  it("location accepts only path-absolute references", () => {
    const loc = (v: string) => code(() => checkResponseHeaders([["location", v]]));
    assert.equal(loc("/a/b?x=1"), undefined);
    for (const v of ["//e.example", "https://e.example/", "/\\e.example", "x/y", "./x", "../x", "", "/a%zz"]) {
      assert.equal(loc(v), "invalid_header", v);
    }
  });
});

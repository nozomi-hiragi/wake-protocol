// Spec §11.6: fixed ET error bodies fit the minimum deployment body limit.
import assert from "node:assert/strict";
import { test } from "node:test";
import { utf8ToBytes } from "@wake-protocol/codec";
import { ET_BODY_MIN } from "../src/index.ts";

test("every fixed server ET error body fits ET_BODY_MIN", () => {
  for (const code of [
    "invalid_request", "invalid_method", "invalid_path", "invalid_header",
    "too_large", "route_not_found", "internal",
  ]) {
    const body = utf8ToBytes(JSON.stringify({ error: { code } }));
    assert.ok(body.length <= ET_BODY_MIN, code);
  }
});

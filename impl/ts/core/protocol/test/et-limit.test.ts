// ET bodyLimit validation (§11.2): encodeEtRequest and decodeEtRequest reject a malformed limit.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Bytes,
  WakeError,
  decodeEtRequest,
  encodeEtRequest,
  type EtRequest,
} from "../src/index.ts";

const req: EtRequest = { method: "POST", url: "/api/limit", headers: [], body: new Bytes(new Uint8Array(4)) };
const isInvalidOption = (e: unknown) => e instanceof WakeError && e.code === "invalid_option";

describe("bodyLimit validation (§11.2)", () => {
  for (const limit of [NaN, Infinity, -1, 1.5]) {
    it(`encodeEtRequest and decodeEtRequest reject bodyLimit ${limit} with invalid_option`, () => {
      const bytes = encodeEtRequest(req);
      assert.throws(() => encodeEtRequest(req, { bodyLimit: limit }), isInvalidOption);
      assert.throws(() => decodeEtRequest(bytes, { bodyLimit: limit }), isInvalidOption);
    });
  }

  it("a bodyLimit of 0 accepts an empty body and round-trips", () => {
    const empty: EtRequest = { ...req, body: new Bytes(new Uint8Array(0)) };
    const bytes = encodeEtRequest(empty, { bodyLimit: 0 });
    assert.ok(decodeEtRequest(bytes, { bodyLimit: 0 }).body.equals(new Bytes([])));
  });
});

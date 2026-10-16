// §8.7 plaintext length limit: seal, parseWire and open enforce it with `too_large`.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_MAX_PLAINTEXT,
  DIR_C2S,
  DIR_S2C,
  ET_BODY_MAX,
  ET_HEADERS_MAX,
  ET_PATH_MAX,
  ET_QUERY_MAX,
  ET_REQUEST_MAX_ENCODED,
  ET_RESPONSE_MAX_ENCODED,
  Bytes,
  WakeError,
  aesKey,
  asC2sKey,
  asS2cKey,
  decodeEtRequest,
  decodeEtResponse,
  encodeEtRequest,
  encodeEtResponse,
  newRequestId,
  newSessionId,
  open,
  parseWire,
  seal,
} from "../src/index.ts";

const header = () => ({
  dir: DIR_C2S,
  sessionId: newSessionId(),
  epoch: 0,
  requestId: newRequestId(),
  issuedAt: 1767225600000,
  context: "POST /api/limit",
}) as const;

const key = async () => aesKey(asC2sKey(new Uint8Array(32).fill(7)));

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof WakeError && e.code === code);
}

describe("plaintext length limit (§8.7)", () => {
  it("default limit covers the worst-case encoded ET request and response", () => {
    assert.equal(ET_REQUEST_MAX_ENCODED, 1_128_491);
    assert.equal(ET_RESPONSE_MAX_ENCODED, 1_122_335);
    assert.ok(DEFAULT_MAX_PLAINTEXT >= Math.max(ET_REQUEST_MAX_ENCODED, ET_RESPONSE_MAX_ENCODED));
  });

  it("the worst-case ET request encodes and seals with default options", async () => {
    const request = {
      method: "DELETE",
      path: "/" + "a".repeat(ET_PATH_MAX - 1),
      query: "q".repeat(ET_QUERY_MAX),
      headers: Array.from({ length: ET_HEADERS_MAX }, () => ["x", ""] as const),
      body: new Bytes(new Uint8Array(ET_BODY_MAX)),
    } as const;
    const encoded = encodeEtRequest(request);
    assert.equal(encoded.length, ET_REQUEST_MAX_ENCODED);
    const k = await key();
    const wire = await seal(k, header(), encoded);
    const opened = await open(k, wire, DIR_C2S);
    assert.ok(opened.plaintext.equals(encoded));
    const decoded = decodeEtRequest(opened.plaintext);
    assert.equal(decoded.method, request.method);
    assert.equal(decoded.path, request.path);
    assert.equal(decoded.query, request.query);
    assert.deepEqual(decoded.headers, request.headers);
    assert.ok(decoded.body.equals(request.body));
  });

  it("the worst-case ET response encodes and seals with default options", async () => {
    const response = {
      status: 599,
      headers: Array.from({ length: ET_HEADERS_MAX }, () => ["x", ""] as const),
      body: new Bytes(new Uint8Array(ET_BODY_MAX)),
    };
    const encoded = encodeEtResponse(response);
    assert.equal(encoded.length, ET_RESPONSE_MAX_ENCODED);
    const k = await aesKey(asS2cKey(new Uint8Array(32).fill(7)));
    const wire = await seal(k, { ...header(), dir: DIR_S2C }, encoded);
    const opened = await open(k, wire, DIR_S2C);
    assert.ok(opened.plaintext.equals(encoded));
    const decoded = decodeEtResponse(opened.plaintext);
    assert.equal(decoded.status, response.status);
    assert.deepEqual(decoded.headers, response.headers);
    assert.ok(decoded.body.equals(response.body));
  });

  it("seal rejects plaintext over a custom limit with too_large", async () => {
    const k = await key();
    await expectCode(seal(k, header(), new Bytes(new Uint8Array(17)), { maxPlaintext: 16 }), "too_large");
    await expectCode(seal(k, header(), new Bytes(new Uint8Array(DEFAULT_MAX_PLAINTEXT + 1))), "too_large");
  });

  it("a plaintext exactly at the limit round-trips", async () => {
    const k = await key();
    const plaintext = new Bytes(Uint8Array.from({ length: 16 }, (_, i) => i));
    const opts = { maxPlaintext: 16 };
    const wire = await seal(k, header(), plaintext, opts);
    const got = await open(k, wire, DIR_C2S, opts);
    assert.ok(got.plaintext.equals(plaintext));
  });

  it("parseWire and open reject a wire whose ciphertext exceeds a custom limit with too_large", async () => {
    const k = await key();
    const wire = await seal(k, header(), new Bytes(new Uint8Array(40)));
    assert.equal(parseWire(wire).sealed.length - 16, 40);
    assert.throws(() => parseWire(wire, { maxPlaintext: 39 }), (e: unknown) => e instanceof WakeError && e.code === "too_large");
    await expectCode(open(k, wire, DIR_C2S, { maxPlaintext: 39 }), "too_large");
    // The limit is checked before decryption: a tampered tag still reports too_large.
    const tampered = wire.toUint8Array();
    tampered[tampered.length - 1]! ^= 1;
    await expectCode(open(k, tampered, DIR_C2S, { maxPlaintext: 39 }), "too_large");
    // Within the limit the same wire opens.
    assert.equal((await open(k, wire, DIR_C2S, { maxPlaintext: 40 })).plaintext.length, 40);
  });
});

describe("maxPlaintext validation", () => {
  for (const limit of [NaN, Infinity, -1, 1.5]) {
    it(`seal and parseWire reject maxPlaintext ${limit} with invalid_option`, async () => {
      const k = await key();
      const wire = await seal(k, header(), new Bytes(new Uint8Array(4)));
      await expectCode(seal(k, header(), new Bytes(new Uint8Array(4)), { maxPlaintext: limit }), "invalid_option");
      assert.throws(
        () => parseWire(wire, { maxPlaintext: limit }),
        (e: unknown) => e instanceof WakeError && e.code === "invalid_option",
      );
    });
  }

  it("a limit of 0 accepts an empty plaintext", async () => {
    const k = await key();
    const opts = { maxPlaintext: 0 };
    const wire = await seal(k, header(), new Bytes([]), opts);
    assert.equal((await open(k, wire, DIR_C2S, opts)).plaintext.length, 0);
  });
});

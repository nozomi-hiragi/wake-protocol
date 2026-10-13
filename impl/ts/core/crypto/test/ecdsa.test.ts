import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import test from "node:test";
import {
  ecdsaDerToRaw,
  ecdsaRawToDer,
  importP256SpkiPublicKey,
  p256EcdsaVerify,
} from "../src/ecdsa.ts";

function derInteger(value: Uint8Array): Uint8Array {
  const body = (value[0]! & 0x80) !== 0 ? Uint8Array.of(0, ...value) : value;
  return Uint8Array.of(0x02, body.length, ...body);
}

function derSignature(r: Uint8Array, s: Uint8Array): Uint8Array {
  const rb = derInteger(r);
  const sb = derInteger(s);
  const body = Uint8Array.of(...rb, ...sb);
  return Uint8Array.of(0x30, body.length, ...body);
}

function expectRangeError(input: Uint8Array, size = 32): void {
  assert.throws(() => ecdsaDerToRaw(input, size), RangeError);
}

function expectRangeErrorMessage(input: Uint8Array, message: string, size = 32): void {
  assert.throws(
    () => ecdsaDerToRaw(input, size),
    (error: unknown) => error instanceof RangeError && error.message === message,
  );
}

test("DER and IEEE-P1363 signatures round trip with minimal DER integers", () => {
  const raw = new Uint8Array(64);
  raw[31] = 0x80;
  raw[32] = 0x01;
  raw[63] = 0x7f;
  const der = ecdsaRawToDer(raw);
  assert.deepEqual(ecdsaDerToRaw(der, 32), raw);
  assert.deepEqual(ecdsaRawToDer(ecdsaDerToRaw(der, 32)), der);

  const padded = new Uint8Array(64);
  padded[31] = 1;
  padded[63] = 2;
  assert.deepEqual(ecdsaDerToRaw(ecdsaRawToDer(padded), 32), padded);
});

test("DER parser rejects every malformed signature form", () => {
  const good = derSignature(Uint8Array.of(1), Uint8Array.of(2));
  expectRangeError(
    Uint8Array.of(0x31, ...good.slice(1)),
  ); // Wrong sequence tag.
  expectRangeError(
    Uint8Array.of(0x30, 0x81, good[1]!, ...good.slice(2)),
  ); // Long-form sequence length.
  expectRangeError(
    Uint8Array.of(0x30, 0x80, ...good.slice(2)),
  ); // Indefinite sequence length.
  expectRangeError(
    Uint8Array.of(0x30, 7, 0x02, 0x81, 1, 1, 0x02, 1, 2),
  ); // Long-form INTEGER length.
  expectRangeError(
    Uint8Array.of(0x30, 6, 0x02, 0x80, 0x02, 1, 2),
  ); // Indefinite INTEGER length.
  expectRangeError(
    Uint8Array.of(0x30, good[1]! - 1, ...good.slice(2)),
  ); // Sequence length too short.
  expectRangeError(
    Uint8Array.of(...good, 0),
  ); // Trailing bytes outside sequence.
  expectRangeError(
    Uint8Array.of(0x30, good[1]! + 1, ...good.slice(2), 0),
  ); // Trailing bytes inside sequence.

  const wrongIntegerTag = good.slice();
  wrongIntegerTag[2] = 0x03;
  expectRangeError(wrongIntegerTag);
  expectRangeErrorMessage(
    Uint8Array.of(0x30, 5, 0x02, 0, 0x02, 1, 2),
    "DER INTEGER must not be empty",
  ); // Empty INTEGER.
  const wrongSecondIntegerTag = good.slice();
  wrongSecondIntegerTag[5] = 0x03;
  expectRangeError(wrongSecondIntegerTag);
  expectRangeError(
    Uint8Array.of(0x30, 7, 0x02, 1, 0x80, 0x02, 2, 1, 2),
  ); // Negative INTEGER.
  expectRangeError(
    Uint8Array.of(0x30, 8, 0x02, 2, 0, 1, 0x02, 2, 1, 2),
  ); // Redundant sign byte.
  expectRangeError(
    derSignature(new Uint8Array(33).fill(1), Uint8Array.of(2)),
  ); // Too wide after sign removal.
  const oversizedValue = new Uint8Array(33);
  oversizedValue[0] = 0x80;
  oversizedValue.fill(1, 1);
  expectRangeError(
    derSignature(oversizedValue, Uint8Array.of(2)),
  ); // Valid sign byte, then 33-byte value.
  expectRangeError(
    Uint8Array.of(0x30, 6, 0x02, 1, 0, 0x02, 1, 2),
  ); // Zero r.
  expectRangeError(
    Uint8Array.of(0x30, 6, 0x02, 1, 1, 0x02, 1, 0),
  ); // Zero s.
  expectRangeError(
    Uint8Array.of(0x30, 6, 0x02, 2, 1, 0x02, 1, 2),
  ); // Truncated INTEGER.
  expectRangeError(
    Uint8Array.of(0x30, 6, 0x02, 1, 1, 0x02, 1, 2),
    0,
  ); // Invalid width.
});

test("raw-to-DER rejects zero and malformed raw widths", () => {
  assert.throws(
    () => ecdsaRawToDer(new Uint8Array(0)),
    RangeError,
  );
  assert.throws(
    () => ecdsaRawToDer(new Uint8Array(3)),
    RangeError,
  );
  assert.throws(
    () => ecdsaRawToDer(new Uint8Array(64)),
    RangeError,
  );

  const largestShortForm = new Uint8Array(120);
  largestShortForm[0] = 0x80;
  largestShortForm[60] = 0x80;
  const maxDer = ecdsaRawToDer(largestShortForm);
  assert.equal(maxDer[1], 126);

  const beyondShortForm = new Uint8Array(122);
  beyondShortForm[0] = 0x80;
  beyondShortForm[61] = 0x80;
  assert.throws(
    () => ecdsaRawToDer(beyondShortForm),
    RangeError,
  );
  assert.throws(
    () => ecdsaRawToDer({} as Uint8Array),
    TypeError,
  );
  assert.throws(
    () => ecdsaDerToRaw({} as Uint8Array, 32),
    TypeError,
  );
  assert.throws(
    () => ecdsaDerToRaw(new Uint8Array(), 1.5),
    RangeError,
  );
});

test("P-256 helpers match Node DER and IEEE-P1363 signatures", async () => {
  const { privateKey, publicKey } = generateKeyPairSync(
    "ec",
    { namedCurve: "prime256v1" },
  );
  const spki = new Uint8Array(
    publicKey.export({ type: "spki", format: "der" }),
  );
  const webKey = await importP256SpkiPublicKey(spki);
  assert.equal(webKey.extractable, false);
  assert.deepEqual(webKey.usages, ["verify"]);
  await assert.rejects(importP256SpkiPublicKey({} as Uint8Array), TypeError);

  const conditions = {
    leadingZeroR: false,
    leadingZeroS: false,
    highBitR: false,
    highBitS: false,
  };
  let checked = 0;
  for (
    let i = 0;
    i < 5000 && (checked < 80 || Object.values(conditions).some((seen) => !seen));
    i++
  ) {
    const data = new Uint8Array(32);
    globalThis.crypto.getRandomValues(data);
    const der = new Uint8Array(
      nodeSign("sha256", data, { key: privateKey, dsaEncoding: "der" }),
    );
    const nodeRaw = new Uint8Array(
      nodeSign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" }),
    );
    const raw = ecdsaDerToRaw(der, 32);
    assert.equal(
      nodeVerify("sha256", data, { key: publicKey, dsaEncoding: "der" }, der),
      true,
    );
    assert.equal(
      nodeVerify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, raw),
      true,
    );
    assert.equal(
      nodeVerify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, nodeRaw),
      true,
    );
    assert.equal(
      nodeVerify(
        "sha256",
        data,
        { key: publicKey, dsaEncoding: "der" },
        ecdsaRawToDer(nodeRaw),
      ),
      true,
    );
    assert.deepEqual(
      ecdsaDerToRaw(ecdsaRawToDer(nodeRaw), 32),
      nodeRaw,
    );
    assert.equal(await p256EcdsaVerify(webKey, raw, data), true);
    const wrongData = data.slice();
    wrongData[0] = wrongData[0]! ^ 1;
    assert.equal(await p256EcdsaVerify(webKey, raw, wrongData), false);

    conditions.leadingZeroR ||= raw[0] === 0;
    conditions.leadingZeroS ||= raw[32] === 0;
    conditions.highBitR ||= (raw[0]! & 0x80) !== 0;
    conditions.highBitS ||= (raw[32]! & 0x80) !== 0;
    checked++;
  }
  assert.equal(checked >= 80, true);
  assert.deepEqual(
    conditions,
    { leadingZeroR: true, leadingZeroS: true, highBitR: true, highBitS: true },
  );

  await assert.rejects(
    p256EcdsaVerify(webKey, new Uint8Array(63), new Uint8Array()),
    RangeError,
  );
  await assert.rejects(
    p256EcdsaVerify(webKey, {} as Uint8Array, new Uint8Array()),
    TypeError,
  );
});

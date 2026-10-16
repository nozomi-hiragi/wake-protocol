// Standard array crypto boundaries.
import assert from "node:assert/strict";
import test from "node:test";
import { createHash, hkdfSync } from "node:crypto";
import { aesGcmDecrypt, aesGcmEncrypt, aesKey, checkP256PublicKey, generateP256KeyPair, hkdf, hmac, hmacKey, hmacVerify, p256SharedSecret, randomBytes, sha256 } from "../src/index.ts";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

test("generic hash, HMAC, HKDF and AES accept array views and return standard arrays", async () => {
  const data = utf8("abc");
  const raw = new Uint8Array(34).fill(7).subarray(1, 33);
  const digest = await sha256(data);
  assert.ok(digest instanceof Uint8Array);
  assert.equal(hex(digest), createHash("sha256").update(data).digest("hex"));
  assert.ok(randomBytes(16) instanceof Uint8Array);
  const signingKey = await hmacKey(raw);
  const mac = await hmac(signingKey, data);
  assert.ok(mac instanceof Uint8Array);
  assert.equal(await hmacVerify(signingKey, data, mac), true);
  mac[0]! ^= 1;
  assert.equal(await hmacVerify(signingKey, data, mac), false);
  const derived = await hkdf(raw, data, utf8("info"), 32);
  assert.deepEqual(derived, new Uint8Array(hkdfSync("sha256", raw, data, utf8("info"), 32)));
  const key = await aesKey(raw);
  const iv = new Uint8Array(14).subarray(1, 13);
  const sealed = await aesGcmEncrypt(key, iv, data, digest);
  assert.ok(sealed instanceof Uint8Array);
  assert.deepEqual(await aesGcmDecrypt(key, iv, sealed, digest), data);
  sealed[0]! ^= 1;
  assert.equal(await aesGcmDecrypt(key, iv, sealed, digest), null);
  await assert.rejects(aesKey(data), { name: "RangeError", message: "AES-256 key must be 32 bytes" });
});

test("generic P-256 uses standard public-key and shared-secret arrays", async () => {
  const client = await generateP256KeyPair();
  const server = await generateP256KeyPair();
  assert.ok(client.publicKey instanceof Uint8Array);
  await checkP256PublicKey(client.publicKey);
  const secret = await p256SharedSecret(client.privateKey, server.publicKey);
  assert.ok(secret instanceof Uint8Array);
  assert.equal(secret.length, 32);
  assert.deepEqual(secret, await p256SharedSecret(server.privateKey, client.publicKey));
});

test("AES validates IV length and key usages before calling Web Crypto", async () => {
  const key = await aesKey(new Uint8Array(32));
  const data = new Uint8Array(0);
  for (const length of [0, 11, 13, 16]) {
    await assert.rejects(aesGcmEncrypt(key, new Uint8Array(length), data, data), RangeError);
    await assert.rejects(aesGcmDecrypt(key, new Uint8Array(length), data, data), RangeError);
  }
  const iv = new Uint8Array(12);
  const encryptOnly = await globalThis.crypto.subtle.importKey("raw", new Uint8Array(32), "AES-GCM", false, ["encrypt"]);
  const decryptOnly = await globalThis.crypto.subtle.importKey("raw", new Uint8Array(32), "AES-GCM", false, ["decrypt"]);
  await assert.rejects(aesGcmDecrypt(encryptOnly, iv, data, data), TypeError);
  await assert.rejects(aesGcmEncrypt(decryptOnly, iv, data, data), TypeError);
});

test("AES decrypt propagates failures other than authentication failure", async (t) => {
  const key = await aesKey(new Uint8Array(32));
  const iv = new Uint8Array(12);
  const data = new Uint8Array(0);
  const namedError = new Error("failure");
  namedError.name = "OperationError";
  const errors = [new TypeError("internal failure"), new DOMException("wrong access", "InvalidAccessError"), namedError];
  for (const error of errors) {
    const mock = t.mock.method(globalThis.crypto.subtle, "decrypt", async () => { throw error; });
    await assert.rejects(aesGcmDecrypt(key, iv, data, data), (e: unknown) => e === error);
    mock.mock.restore();
  }
});

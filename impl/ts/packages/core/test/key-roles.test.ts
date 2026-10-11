// Key roles survive imports; incompatible local keys are programming errors.
import assert from "node:assert/strict";
import test from "node:test";
import {
  type C2sCryptoKey,
  type S2cCryptoKey,
  type FinishedCryptoKeyC,
  type FinishedCryptoKeyS,
  type MsgHeader,
  type ParsedWire,
  type ServerFinishedInput,
  Bytes,
  DIR_C2S,
  WakeError,
  aesKey,
  asC2sKey,
  asS2cKey,
  asFinishedKeyC,
  asFinishedKeyS,
  asIv,
  asTranscriptHash,
  clientFinished,
  hmacKey,
  newRequestId,
  newSessionId,
  open,
  openParsed,
  parseWire,
  seal,
  serverFinished,
  verifyClientFinished,
  verifyServerFinished,
} from "../src/index.ts";
import { sealWithIv } from "../src/testing.ts";

const raw = new Uint8Array(32).fill(7);
const th = asTranscriptHash(new Uint8Array(32));
const header = (): MsgHeader => ({
  dir: DIR_C2S,
  sessionId: newSessionId(),
  epoch: 0,
  requestId: newRequestId(),
  issuedAt: 0,
  context: "ctx",
  iv: asIv(new Uint8Array(12)),
});

// Checked by tsc, never executed: every invalid public call must remain an error.
async function checkTypes(h: MsgHeader, p: ParsedWire, input: ServerFinishedInput, unbranded: CryptoKey): Promise<void> {
  const c2s: C2sCryptoKey = await aesKey(asC2sKey(raw));
  const s2c: S2cCryptoKey = await aesKey(asS2cKey(raw));
  const fkC: FinishedCryptoKeyC = await hmacKey(asFinishedKeyC(raw));
  const fkS: FinishedCryptoKeyS = await hmacKey(asFinishedKeyS(raw));
  // @ts-expect-error Finished bytes cannot become a message key.
  await aesKey(asFinishedKeyC(raw));
  // @ts-expect-error Finished bytes cannot become a message key.
  await aesKey(asFinishedKeyS(raw));
  // @ts-expect-error Message bytes cannot become a Finished key.
  await hmacKey(asC2sKey(raw));
  // @ts-expect-error Message bytes cannot become a Finished key.
  await hmacKey(asS2cKey(raw));
  // @ts-expect-error Unbranded bytes have no key role.
  await aesKey(new Bytes(raw));
  // @ts-expect-error Client and server imported Finished keys are distinct.
  await clientFinished(fkS, th);
  // @ts-expect-error Client and server imported Finished keys are distinct.
  await verifyClientFinished(fkS, th, input.clientFinished);
  // @ts-expect-error Client and server imported Finished keys are distinct.
  await serverFinished(fkC, input);
  // @ts-expect-error Client and server imported Finished keys are distinct.
  await verifyServerFinished(fkC, input, await serverFinished(fkS, input));
  // @ts-expect-error A message key is not a Finished key.
  await clientFinished(c2s, th);
  // @ts-expect-error A Finished key is not a message key.
  await seal(fkC, h, new Bytes([]));
  // @ts-expect-error Imported message keys must have a role.
  await open(unbranded, new Bytes([]), DIR_C2S);
  // @ts-expect-error Imported message keys must have a role.
  await openParsed(unbranded, p);
  // @ts-expect-error Testing helpers enforce message key roles too.
  await sealWithIv(fkS, h, new Bytes([]));
  // @ts-expect-error Only the two message directions are valid.
  await open(s2c, new Bytes([]), 3);
}

test("imported Finished keys produce and verify the same MACs as raw keys", async () => {
  const fkC = asFinishedKeyC(raw);
  const fkS = asFinishedKeyS(new Uint8Array(32).fill(8));
  const importedC: FinishedCryptoKeyC = await hmacKey(fkC);
  const importedS: FinishedCryptoKeyS = await hmacKey(fkS);
  const cf = await clientFinished(importedC, th);
  assert.ok(cf.equals(await clientFinished(fkC, th)));
  assert.equal(await verifyClientFinished(importedC, th, cf), true);
  const input = { th, clientFinished: cf, serverTime: 0, absoluteExpiresAt: 1, idleTimeoutSec: 1 };
  const sf = await serverFinished(importedS, input);
  assert.ok(sf.equals(await serverFinished(fkS, input)));
  assert.equal(await verifyServerFinished(importedS, input, sf), true);
});

test("seal/open reject AES-128, wrong algorithms and missing key usages with TypeError", async () => {
  const h = header();
  const plaintext = new Bytes([1, 2, 3]);
  const wire = await seal(await aesKey(asC2sKey(raw)), h, plaintext);
  const parsed = parseWire(wire);
  const subtle = globalThis.crypto.subtle;
  const invalid = [
    await subtle.importKey("raw", new Uint8Array(16), "AES-GCM", false, ["encrypt", "decrypt"]),
    await hmacKey(asFinishedKeyC(raw)),
  ];
  for (const key of invalid) {
    // Cast to exercise callers bypassing compile-time roles.
    const unsafe = key as C2sCryptoKey;
    await assert.rejects(seal(unsafe, h, plaintext), TypeError);
    await assert.rejects(sealWithIv(unsafe, h, plaintext), TypeError);
    await assert.rejects(open(unsafe, wire, DIR_C2S), TypeError);
    await assert.rejects(openParsed(unsafe, parsed), TypeError);
  }
  const encryptOnly = await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]) as C2sCryptoKey;
  const decryptOnly = await subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]) as C2sCryptoKey;
  await assert.rejects(open(encryptOnly, wire, DIR_C2S), TypeError);
  await assert.rejects(seal(decryptOnly, h, plaintext), TypeError);
});

test("authentication failure still requests reauthentication", async () => {
  const key = await aesKey(asC2sKey(raw));
  const wire = (await seal(key, header(), new Bytes([1]))).toUint8Array();
  wire[wire.length - 1]! ^= 1;
  await assert.rejects(open(key, wire, DIR_C2S), (e: unknown) => e instanceof WakeError && e.code === "reauth");
});

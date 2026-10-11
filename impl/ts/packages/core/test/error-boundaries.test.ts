// Received framing errors are mapped; local numeric errors remain standard errors.
import assert from "node:assert/strict";
import test from "node:test";
import { Byte4 } from "@wake-protocol/bytes";
import { decodeU32LengthPrefixed, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import {
  type MsgOptions,
  type MsgHeader,
  type EtOptions,
  Bytes,
  DIR_C2S,
  WakeError,
  asClientFinishedMac,
  asFinishedKeyS,
  asIv,
  asTranscriptHash,
  decodeEtRequest,
  decodeEtResponse,
  encodeEtRequest,
  encodeEtResponse,
  encodeHeader,
  encodeRekeyTranscript,
  generateEphemeral,
  newExchangeId,
  newRequestId,
  newServerNonce,
  newSessionId,
  parseWire,
  rekeyTranscriptHash,
  serverFinished,
  verifyServerFinished,
} from "../src/index.ts";

const hasCode = (code: string) => (e: unknown): boolean => e instanceof WakeError && e.code === code;
const header = (): MsgHeader => ({
  dir: DIR_C2S,
  sessionId: newSessionId(),
  epoch: 0,
  requestId: newRequestId(),
  issuedAt: 0,
  context: "ctx",
  iv: asIv(new Uint8Array(12)),
});
const frame = (h: Bytes): Bytes => Bytes.concat(new Byte4(h.length), h, new Bytes(new Uint8Array(16)));

test("parseWire maps received LP and ASCII failures to bad_request", () => {
  const encoded = encodeHeader(header());
  const fields = decodeU32LengthPrefixed(encoded.toUint8Array());
  fields[6] = Uint8Array.of(0x80);
  assert.throws(() => parseWire(frame(new Bytes(encodeU32LengthPrefixed(...fields)))), hasCode("bad_request"));
  const malformed = encoded.toUint8Array();
  new DataView(malformed.buffer).setUint32(0, 0xffffffff);
  assert.throws(() => parseWire(frame(new Bytes(malformed))), hasCode("bad_request"));
});

test("decoder option errors outside generic codecs propagate unchanged", () => {
  const error = new TypeError("local option access failed");
  const msgOpts: MsgOptions = { get maxPlaintext(): number { throw error; } };
  const etOpts: EtOptions = { get bodyLimit(): number { throw error; } };
  const request = encodeEtRequest({ method: "GET", path: "/", query: "", headers: [], body: new Bytes([]) });
  const response = encodeEtResponse({ status: 200, headers: [], body: new Bytes([]) });
  assert.throws(() => parseWire(frame(encodeHeader(header())), msgOpts), (e: unknown) => e === error);
  assert.throws(() => decodeEtRequest(request, etOpts), (e: unknown) => e === error);
  assert.throws(() => decodeEtResponse(response, etOpts), (e: unknown) => e === error);
});

test("rekey epoch rejects non-integers and values outside 1..u32 with RangeError", async () => {
  const { publicKey } = await generateEphemeral();
  const input = {
    exchangeId: newExchangeId(),
    sessionId: newSessionId(),
    serverNonce: newServerNonce(),
    serverPublicKey: publicKey,
    clientPublicKey: publicKey,
    prevTh: asTranscriptHash(new Uint8Array(32)),
  };
  for (const epoch of [NaN, Infinity, -Infinity, -1, 0, 0.5, 1.5, 0x100000000]) {
    assert.throws(() => encodeRekeyTranscript({ ...input, epoch }), RangeError);
    await assert.rejects(rekeyTranscriptHash({ ...input, epoch }), RangeError);
  }
  for (const epoch of [1, 0xffffffff]) {
    const fields = decodeU32LengthPrefixed(encodeRekeyTranscript({ ...input, epoch }).toUint8Array());
    assert.equal(new Byte4(new Bytes(fields[4]!)).number, epoch);
  }
});

test("header and server Finished retain RangeError for out-of-range local numbers", async () => {
  for (const epoch of [-1, 1.5, 0x100000000]) assert.throws(() => encodeHeader({ ...header(), epoch }), RangeError);
  for (const issuedAt of [-1, 1.5, 2 ** 53]) assert.throws(() => encodeHeader({ ...header(), issuedAt }), RangeError);
  const key = asFinishedKeyS(new Uint8Array(32));
  const input = {
    th: asTranscriptHash(new Uint8Array(32)),
    clientFinished: asClientFinishedMac(new Uint8Array(32)),
    serverTime: 0,
    absoluteExpiresAt: 0,
    idleTimeoutSec: 0,
  };
  const mac = await serverFinished(key, input);
  for (const field of ["serverTime", "absoluteExpiresAt", "idleTimeoutSec"] as const) {
    for (const value of [-1, 1.5, field === "idleTimeoutSec" ? 0x100000000 : 2 ** 53]) {
      await assert.rejects(serverFinished(key, { ...input, [field]: value }), RangeError);
      await assert.rejects(verifyServerFinished(key, { ...input, [field]: value }, mac), RangeError);
    }
  }
});

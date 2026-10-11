import { hex } from "@scure/base";
// End-to-end: KX key agreement, Finished, WAKE-SM seal/open, and tamper detection.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Bytes,
  DIR_C2S,
  DIR_S2C,
  type KeySchedule,
  WakeError,
  asClientFinishedMac,
  aesKey,
  clientFinished,
  deriveKeys,
  ecdh,
  generateEphemeral,
  open,
  newExchangeId,
  newRequestId,
  newServerNonce,
  newSessionId,
  seal,
  serverFinished,
  loginTranscriptHash,
  verifyClientFinished,
  verifyServerFinished,
} from "../src/index.ts";
import { utf8ToBytes } from "@wake-protocol/codec";

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof WakeError && e.code === code);
}

const hexAll = (k: KeySchedule): Record<string, string> =>
  Object.fromEntries(Object.entries(k).map(([name, v]) => [name, hex.encode(v.toUint8Array())]));

describe("login round trip", async () => {
  const exchangeId = newExchangeId();
  const sessionId = newSessionId();
  const serverNonce = newServerNonce();
  const client = await generateEphemeral();
  const server = await generateEphemeral();
  const th = await loginTranscriptHash({
    exchangeId,
    sessionId,
    serverNonce,
    serverPublicKey: server.publicKey,
    clientPublicKey: client.publicKey,
  });

  it("both sides agree on the shared secret and the derived keys", async () => {
    const ssC = await ecdh(client.privateKey, server.publicKey);
    const ssS = await ecdh(server.privateKey, client.publicKey);
    assert.equal(hex.encode(ssC.toUint8Array()), hex.encode(ssS.toUint8Array()));
    const kc = await deriveKeys(ssC, th);
    const ks = await deriveKeys(ssS, th);
    assert.deepEqual(hexAll(kc), hexAll(ks));
  });

  it("client and server Finished verify, and tampering makes them fail", async () => {
    const ss = await ecdh(client.privateKey, server.publicKey);
    const k = await deriveKeys(ss, th);
    const cf = await clientFinished(k.fkC, th);
    assert.equal(await verifyClientFinished(k.fkC, th, cf), true);

    const input = { th, clientFinished: cf, serverTime: 1767225600000, absoluteExpiresAt: 1767229200000, idleTimeoutSec: 1800 };
    const sf = await serverFinished(k.fkS, input);
    assert.equal(await verifyServerFinished(k.fkS, input, sf), true);

    const badMac = cf.toUint8Array();
    badMac[0]! ^= 1;
    assert.equal(await verifyClientFinished(k.fkC, th, asClientFinishedMac(badMac)), false);
    assert.equal(await verifyServerFinished(k.fkS, { ...input, serverTime: input.serverTime + 1 }, sf), false);
    assert.equal(await verifyServerFinished(k.fkS, { ...input, idleTimeoutSec: 1801 }, sf), false);
  });

  it("c2s message seals with kC2s, opens with the server's kC2s, and rejects tampering", async () => {
    const ss = await ecdh(client.privateKey, server.publicKey);
    const kc = await deriveKeys(ss, th);
    const ssS = await ecdh(server.privateKey, client.publicKey);
    const ks = await deriveKeys(ssS, th);

    const sendKey = await aesKey(kc.kC2s);
    const recvKey = await aesKey(ks.kC2s);
    const header = {
      dir: DIR_C2S,
      sessionId,
      epoch: 0,
      requestId: newRequestId(),
      issuedAt: 1767225600000,
      context: "POST /api/transfer",
    } as const;
    const plaintext = new Bytes(utf8ToBytes('{"amount":10000}'));
    const wire = await seal(sendKey, header, plaintext);

    const got = await open(recvKey, wire, DIR_C2S);
    assert.equal(hex.encode(got.plaintext.toUint8Array()), hex.encode(plaintext.toUint8Array()));
    assert.equal(hex.encode(got.header.sessionId.toUint8Array()), hex.encode(sessionId.toUint8Array()));
    assert.equal(got.header.context, "POST /api/transfer");

    const tagFlip = wire.toUint8Array();
    tagFlip[tagFlip.length - 1]! ^= 1;
    await expectCode(open(recvKey, tagFlip, DIR_C2S), "reauth");

    const bodyFlip = wire.toUint8Array();
    bodyFlip[wire.length - 17]! ^= 1;
    await expectCode(open(recvKey, bodyFlip, DIR_C2S), "reauth");

    // The s2c key must not open a c2s message (a deliberate role mismatch).
    // @ts-expect-error The key role does not match the direction.
    await expectCode(open(await aesKey(ks.kS2c), wire, DIR_C2S), "reauth");
    // Wrong direction is rejected before decryption (a deliberate role mismatch).
    // @ts-expect-error The key role does not match the direction.
    await expectCode(open(recvKey, wire, DIR_S2C), "bad_request");
  });

  it("s2c message round-trips with kS2c", async () => {
    const ks = await deriveKeys(await ecdh(server.privateKey, client.publicKey), th);
    const kc = await deriveKeys(await ecdh(client.privateKey, server.publicKey), th);
    const wire = await seal(await aesKey(ks.kS2c), {
      dir: DIR_S2C,
      sessionId,
      epoch: 0,
      requestId: newRequestId(),
      issuedAt: 1767225600500,
      context: "wake-et",
    }, new Bytes(utf8ToBytes('{"status":"ok"}')));
    const got = await open(await aesKey(kc.kS2c), wire, DIR_S2C);
    assert.equal(new TextDecoder().decode(got.plaintext.toUint8Array()), '{"status":"ok"}');
  });
});

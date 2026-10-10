// End-to-end: KX key agreement, Finished, WAKE-SM seal/open, and tamper detection.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  DIR_C2S,
  DIR_S2C,
  WakeError,
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
  utf8,
  verifyClientFinished,
  verifyServerFinished,
} from "../src/index.ts";

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof WakeError && e.code === code);
}

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
    assert.deepEqual(ssC, ssS);
    const kc = await deriveKeys(ssC, th);
    const ks = await deriveKeys(ssS, th);
    assert.deepEqual(kc, ks);
  });

  it("client and server Finished verify, and tampering makes them fail", async () => {
    const ss = await ecdh(client.privateKey, server.publicKey);
    const k = await deriveKeys(ss, th);
    const cf = await clientFinished(k.fkC, th);
    assert.equal(await verifyClientFinished(k.fkC, th, cf), true);

    const input = { th, clientFinished: cf, serverTime: 1767225600000, absoluteExpiresAt: 1767229200000, idleTimeoutSec: 1800 };
    const sf = await serverFinished(k.fkS, input);
    assert.equal(await verifyServerFinished(k.fkS, input, sf), true);

    const badMac = Uint8Array.from(cf) as typeof cf;
    badMac[0]! ^= 1;
    assert.equal(await verifyClientFinished(k.fkC, th, badMac), false);
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
    const plaintext = utf8('{"amount":10000}');
    const wire = await seal(sendKey, header, plaintext);

    const got = await open(recvKey, wire, DIR_C2S);
    assert.deepEqual(got.plaintext, plaintext);
    assert.deepEqual(got.header.sessionId, sessionId);
    assert.equal(got.header.context, "POST /api/transfer");

    const tagFlip = Uint8Array.from(wire);
    tagFlip[tagFlip.length - 1]! ^= 1;
    await expectCode(open(recvKey, tagFlip, DIR_C2S), "reauth");

    const bodyFlip = Uint8Array.from(wire);
    bodyFlip[wire.length - 17]! ^= 1;
    await expectCode(open(recvKey, bodyFlip, DIR_C2S), "reauth");

    // The s2c key must not open a c2s message.
    await expectCode(open(await aesKey(ks.kS2c), wire, DIR_C2S), "reauth");
    // Wrong direction is rejected before decryption.
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
    }, utf8('{"status":"ok"}'));
    const got = await open(await aesKey(kc.kS2c), wire, DIR_S2C);
    assert.equal(new TextDecoder().decode(got.plaintext), '{"status":"ok"}');
  });
});

// Spec §5.3–§5.7, §9: independent test client for encrypted key rotation.
import assert from "node:assert/strict";
import { bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import {
  Bytes, DIR_C2S, DIR_S2C, aesKey, asExchangeId, asServerNonce, asServerFinishedMac,
  clientFinished, deriveKeys, ecdh, generateEphemeral, krChallenge, newRequestId, open,
  parseEcPublicKey, parseWire, rekeyTranscriptHash, seal, verifyServerFinished,
} from "@wake-protocol/core";
import type { C2sCryptoKey, S2cCryptoKey, SessionId, TranscriptHash } from "@wake-protocol/core";
import type { AssertionTamper, GetAssertionOptions, SoftAuthenticator } from "../src/testing.ts";
import { decode, encode, sendWire } from "./helpers.ts";
import type { Fixture, Login } from "./helpers.ts";

export interface KrClient {
  sessionId: SessionId;
  epoch: number;
  th: TranscriptHash;
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
}

export interface KrStart {
  exchangeId: string;
  epoch: number;
  serverNonce: string;
  serverPublicKey: string;
  expiresAt: number;
  webauthn: Omit<GetAssertionOptions, "challenge">;
}

export function krClient(login: Login): KrClient {
  return { ...login, epoch: 0 };
}

export async function krWire(f: Fixture, client: KrClient, context: string, body: unknown = {}): Promise<Bytes> {
  const plaintext = typeof body === "string" ? utf8ToBytes(body) :
    body instanceof Uint8Array ? body : utf8ToBytes(JSON.stringify(body));
  return seal(client.c2s, {
    dir: DIR_C2S,
    sessionId: client.sessionId,
    epoch: client.epoch,
    requestId: newRequestId(),
    issuedAt: f.clock.now,
    context,
  }, new Bytes(plaintext));
}

export async function krOpen(client: KrClient, request: Bytes, response: Response) {
  assert.equal(response.status, 200, await response.clone().text());
  assert.match(response.headers.get("content-type")!, /application\/wake/);
  const opened = await open(client.s2c, new Uint8Array(await response.arrayBuffer()), DIR_S2C);
  const header = parseWire(request).header;
  assert.ok(opened.header.sessionId.equals(header.sessionId));
  assert.ok(opened.header.requestId.equals(header.requestId));
  assert.equal(opened.header.context, header.context);
  assert.equal(opened.header.epoch, header.epoch);
  const text = bytesToUtf8(opened.plaintext.toUint8Array());
  return { ...opened, text, json: JSON.parse(text) as Record<string, unknown> };
}

export async function krRequest(f: Fixture, client: KrClient, context: string, body: unknown = {}) {
  const request = await krWire(f, client, context, body);
  return krOpen(client, request, await sendWire(f, request));
}

export async function krStart(f: Fixture, client: KrClient): Promise<KrStart> {
  const result = await krRequest(f, client, "wake/kr/start");
  assert.equal(result.json.epoch, client.epoch + 1, result.text);
  return result.json as unknown as KrStart;
}

export async function prepareKr(
  f: Fixture,
  client: KrClient,
  tamper: AssertionTamper = {},
  auth: SoftAuthenticator = f.auth,
  info?: KrStart,
) {
  info ??= await krStart(f, client);
  const pair = await generateEphemeral();
  const publicKey = await parseEcPublicKey(decode(info.serverPublicKey));
  const th = await rekeyTranscriptHash({
    exchangeId: asExchangeId(decode(info.exchangeId)),
    sessionId: client.sessionId,
    epoch: info.epoch,
    prevTh: client.th,
    serverNonce: asServerNonce(decode(info.serverNonce)),
    serverPublicKey: publicKey,
    clientPublicKey: pair.publicKey,
  });
  const challenge = await krChallenge(th);
  const assertion = await auth.getAssertion({ ...info.webauthn, allowCredentials: [], challenge: challenge.toUint8Array() }, tamper);
  const keys = await deriveKeys(await ecdh(pair.privateKey, publicKey), th);
  const finished = await clientFinished(keys.fkC, th);
  return {
    info,
    th,
    challenge,
    keys,
    finished,
    body: {
      exchangeId: info.exchangeId,
      clientPublicKey: encode(pair.publicKey.toUint8Array()),
      assertion,
      clientFinished: encode(finished.toUint8Array()),
    },
    next: {
      sessionId: client.sessionId,
      epoch: info.epoch,
      th,
      c2s: await aesKey(keys.kC2s),
      s2c: await aesKey(keys.kS2c),
    } satisfies KrClient,
  };
}

export async function completeKr(f: Fixture, client: KrClient, prepared: Awaited<ReturnType<typeof prepareKr>>) {
  const result = await krRequest(f, client, "wake/kr/complete", prepared.body);
  assert.deepEqual(Object.keys(result.json).sort(), ["absoluteExpiresAt", "epoch", "idleTimeoutSec", "serverFinished", "serverTime"]);
  assert.equal(result.json.epoch, prepared.next.epoch);
  assert.ok(await verifyServerFinished(prepared.keys.fkS, {
    th: prepared.th,
    clientFinished: prepared.finished,
    serverTime: result.json.serverTime as number,
    absoluteExpiresAt: result.json.absoluteExpiresAt as number,
    idleTimeoutSec: result.json.idleTimeoutSec as number,
  }, asServerFinishedMac(decode(result.json.serverFinished as string))));
  return result;
}

export async function krError(f: Fixture, client: KrClient, context: string, body: unknown, code: string): Promise<void> {
  assert.deepEqual((await krRequest(f, client, context, body)).json, { error: { code } });
}

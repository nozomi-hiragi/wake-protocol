// Spec §7, §8, §9: independent in-memory peer using only core primitives.
import assert from "node:assert/strict";
import { base64urlnopad } from "@scure/base";
import { Bytes } from "@wake-protocol/bytes";
import { bytesToUtf8, parseIJson, utf8ToBytes } from "@wake-protocol/codec";
import {
  aesKey,
  asExchangeId,
  asClientFinishedMac,
  deriveKeys,
  ecdh,
  generateEphemeral,
  kxChallenge,
  loginTranscriptHash,
  rekeyTranscriptHash,
  krChallenge,
  parseJsonObject,
  decodeBase64urlField,
  newExchangeId,
  newServerNonce,
  newSessionId,
  openParsed,
  parseEcPublicKey,
  parseWire,
  seal,
  serverFinished,
  verifyClientFinished,
  DIR_C2S,
  DIR_S2C,
} from "@wake-protocol/core";
import type { C2sCryptoKey, S2cCryptoKey, MsgHeader, TranscriptHash } from "@wake-protocol/core";
import { WakeClient } from "../src/index.ts";
import type { GetAssertion, GetAssertionOptions, WakeClientOptions } from "../src/index.ts";

export const TTL = 120_000;

export const encode = (b: Bytes) => base64urlnopad.encode(b.toUint8Array());

export const jsonResponse = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status,
  headers: { "Content-Type": "application/json" },
});

export const readJson = (text: string) => parseIJson(text) as Record<string, unknown>;

export const hasCode = (code: string) => (e: unknown) => e instanceof Error && "code" in e && e.code === code;

export async function fixture(options: Partial<WakeClientOptions> = {}) {
  const pair = await generateEphemeral();
  const exchangeId = newExchangeId();
  const sessionId = newSessionId();
  const serverNonce = newServerNonce();
  let c2s: C2sCryptoKey;
  let s2c: S2cCryptoKey;
  let currentTh: TranscriptHash;
  const epochs = new Map<number, { c2s: C2sCryptoKey; s2c: S2cCryptoKey }>();
  const exchanges = new Map<string, {
    pair: typeof pair;
    nonce: typeof serverNonce;
    prevTh: TranscriptHash;
    epoch: number;
    response?: Record<string, unknown>;
  }>();
  const f = {
    localTime: 1_000_000,
    serverTime: 2_000_000,
    assertionCalls: 0,
    onAssertion: undefined as (() => void) | undefined,
    start: {
      version: "WAKE/1",
      exchangeId: encode(exchangeId),
      sessionId: encode(sessionId),
      epoch: 0,
      serverNonce: encode(serverNonce),
      serverPublicKey: encode(pair.publicKey),
      // Server clock; deliberately unrelated to the client clock.
      serverTime: 2_000_000,
      expiresAt: 2_000_000 + TTL,
      webauthn: {
        rpId: "example.com",
        allowCredentials: [],
        userVerification: "required",
        timeout: TTL - 30_000,
      },
    } as Record<string, unknown>,
    startResponse: undefined as Response | undefined,
    completeBodies: [] as string[],
    startBodies: [] as string[],
    completeAction: undefined as ((attempt: number) => Response | undefined) | undefined,
    completeMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    completeResponse: undefined as ((value: Record<string, unknown>) => Response) | undefined,
    currentEpoch: 0,
    authTime: 2_000_000,
    absoluteExpiresAt: 3_000_000,
    krStartMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    krCompleteMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    krCompleteError: undefined as string | undefined,
    krCompleteBodies: [] as string[],
    krCompleteResponse: undefined as ((attempt: number, response: Response) => Response | Promise<Response>) | undefined,
    upResponse: undefined as ((header: MsgHeader, response: Response) => Response | Promise<Response>) | undefined,
    upPlaintext: undefined as ((header: MsgHeader, plaintext: Uint8Array) => Uint8Array) | undefined,
    upAction: undefined as (() => Response | undefined) | undefined,
    headerMutate: undefined as ((header: MsgHeader) => void) | undefined,
    tamper: false,
    revoked: false,
    plaintext: undefined as Uint8Array | undefined,
    requests: [] as MsgHeader[],
    wires: [] as Uint8Array[],
    assertionOptions: undefined as GetAssertionOptions | undefined,
    sleeps: [] as number[],
    client: undefined as unknown as WakeClient,
  };
  const getAssertion: GetAssertion = async (opts) => {
    f.assertionCalls++;
    f.onAssertion?.();
    f.assertionOptions = opts;
    return {
      id: "AQ",
      rawId: "AQ",
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64urlnopad.encode(utf8ToBytes(JSON.stringify({
          type: "webauthn.get",
          challenge: base64urlnopad.encode(opts.challenge),
          origin: "https://example.com",
        }))),
        authenticatorData: "AQ",
        signature: "AQ",
        userHandle: "AQ",
      },
    };
  };
  const fetch: typeof globalThis.fetch = async (url, init) => {
    assert.equal(init?.method, "POST");
    const contentType = new Headers(init?.headers).get("content-type");
    const path = new URL(String(url), "https://example.com").pathname;
    if (path === "/auth/start") {
      assert.equal(contentType, "application/json");
      f.startBodies.push(init!.body as string);
      return f.startResponse ?? jsonResponse(f.start);
    }
    if (path === "/auth/complete") {
      assert.equal(contentType, "application/json");
      const text = init!.body as string;
      f.completeBodies.push(text);
      const early = f.completeAction?.(f.completeBodies.length);
      if (early) {
        return early;
      }
      const body = readJson(text);
      assert.equal(body.exchangeId, encode(exchangeId));
      const clientPublicKey = await parseEcPublicKey(base64urlnopad.decode(body.clientPublicKey as string));
      const th = await loginTranscriptHash({
        exchangeId,
        sessionId,
        serverNonce,
        serverPublicKey: pair.publicKey,
        clientPublicKey,
      });
      const assertion = body.assertion as {
        response: {
          clientDataJSON: string;
        };
      };
      const clientData = readJson(bytesToUtf8(base64urlnopad.decode(assertion.response.clientDataJSON)));
      assert.equal(clientData.challenge, encode(await kxChallenge(th)));
      const raw = await deriveKeys(await ecdh(pair.privateKey, clientPublicKey), th);
      const cf = asClientFinishedMac(base64urlnopad.decode(body.clientFinished as string));
      assert.equal(await verifyClientFinished(raw.fkC, th, cf), true);
      c2s = await aesKey(raw.kC2s);
      s2c = await aesKey(raw.kS2c);
      currentTh = th;
      f.currentEpoch = 0;
      f.authTime = f.serverTime;
      f.absoluteExpiresAt = 3_000_000;
      f.revoked = false;
      epochs.clear();
      epochs.set(0, { c2s, s2c });
      assert.equal(c2s.extractable, false);
      const info = {
        serverTime: f.serverTime,
        absoluteExpiresAt: 3_000_000,
        idleTimeoutSec: 60,
      };
      const value: Record<string, unknown> = {
        ...info,
        sessionId: encode(sessionId),
        epoch: 0,
        serverFinished: encode(await serverFinished(raw.fkS, {
          ...info,
          th,
          clientFinished: cf,
        })),
      };
      f.completeMutate?.(value);
      return f.completeResponse?.(value) ?? jsonResponse(value);
    }
    assert.equal(path, "/wake/up");
    assert.equal(contentType, "application/wake");
    const rawWire = init!.body as Uint8Array;
    f.wires.push(rawWire);
    const p = parseWire(rawWire);
    f.requests.push(p.header);
    const early = f.upAction?.();
    if (early) {
      return early;
    }
    assert.equal(f.revoked, false);
    const requestKeys = epochs.get(p.header.epoch)!;
    const request = await openParsed(requestKeys.c2s, p, DIR_C2S);
    let plaintext = f.plaintext;
    if (!plaintext) {
      if (p.header.context === "wake/kr/start") {
        assert.equal(bytesToUtf8(request.toUint8Array()), "{}");
        const krPair = await generateEphemeral(false);
        const krExchangeId = newExchangeId();
        const nonce = newServerNonce();
        const epoch = f.currentEpoch + 1;
        exchanges.set(encode(krExchangeId), { pair: krPair, nonce, prevTh: currentTh, epoch });
        const value: Record<string, unknown> = {
          exchangeId: encode(krExchangeId),
          epoch,
          serverNonce: encode(nonce),
          serverPublicKey: encode(krPair.publicKey),
          expiresAt: f.serverTime + TTL,
          webauthn: { ...f.start.webauthn as Record<string, unknown>, allowCredentials: [{ type: "public-key", id: "AQ" }] },
        };
        f.krStartMutate?.(value);
        plaintext = utf8ToBytes(JSON.stringify(value));
      } else if (p.header.context === "wake/kr/complete") {
        f.krCompleteBodies.push(bytesToUtf8(request.toUint8Array()));
        if (f.krCompleteError) {
          const value: Record<string, unknown> = { error: { code: f.krCompleteError } };
          f.krCompleteMutate?.(value);
          plaintext = utf8ToBytes(JSON.stringify(value));
        } else {
          const body = parseJsonObject(request.toUint8Array(), "invalid_request");
          const exchange = exchanges.get(body.exchangeId as string)!;
          if (!exchange.response) {
            const clientPublicKey = await parseEcPublicKey(decodeBase64urlField(body.clientPublicKey, "invalid_request"));
            const th = await rekeyTranscriptHash({
              exchangeId: asExchangeId(decodeBase64urlField(body.exchangeId, "invalid_request")),
              sessionId,
              epoch: exchange.epoch,
              prevTh: exchange.prevTh,
              serverNonce: exchange.nonce,
              serverPublicKey: exchange.pair.publicKey,
              clientPublicKey,
            });
            const assertion = body.assertion as { response: { clientDataJSON: string } };
            const clientData = parseJsonObject(
              decodeBase64urlField(assertion.response.clientDataJSON, "invalid_request"), "invalid_request",
            );
            assert.equal(clientData.challenge, encode(await krChallenge(th)));
            const raw = await deriveKeys(await ecdh(exchange.pair.privateKey, clientPublicKey), th);
            const cf = asClientFinishedMac(decodeBase64urlField(body.clientFinished, "invalid_request"));
            assert.equal(await verifyClientFinished(raw.fkC, th, cf), true);
            epochs.set(exchange.epoch, { c2s: await aesKey(raw.kC2s), s2c: await aesKey(raw.kS2c) });
            f.currentEpoch = exchange.epoch;
            f.authTime = f.serverTime;
            f.absoluteExpiresAt = 3_500_000;
            currentTh = th;
            const info = { serverTime: f.serverTime, absoluteExpiresAt: 3_500_000, idleTimeoutSec: 60 };
            exchange.response = {
              ...info,
              epoch: exchange.epoch,
              serverFinished: encode(await serverFinished(raw.fkS, { ...info, th, clientFinished: cf })),
            };
          }
          const value = { ...exchange.response };
          f.krCompleteMutate?.(value);
          plaintext = utf8ToBytes(JSON.stringify(value));
        }
      } else if (p.header.context === "wake/session") {
        assert.equal(bytesToUtf8(request.toUint8Array()), "{}");
        plaintext = utf8ToBytes(JSON.stringify({
          sessionId: encode(sessionId),
          epoch: f.currentEpoch,
          authTime: f.authTime,
          absoluteExpiresAt: f.absoluteExpiresAt,
          hardCapAt: 4_000_000,
          idleTimeoutSec: 60,
          serverTime: f.serverTime,
          rekeyRecommended: false,
        }));
      } else if (p.header.context === "wake/logout") {
        assert.equal(bytesToUtf8(request.toUint8Array()), "{}");
        f.revoked = true;
        plaintext = utf8ToBytes("{}");
      } else {
        plaintext = request.toUint8Array();
      }
    }
    const header: MsgHeader = {
      ...p.header,
      dir: DIR_S2C,
      issuedAt: f.serverTime,
    };
    plaintext = f.upPlaintext?.(p.header, plaintext) ?? plaintext;
    f.headerMutate?.(header);
    const wire = header.dir === DIR_C2S
      ? await seal(requestKeys.c2s, {
        ...header,
        dir: DIR_C2S,
      }, new Bytes(plaintext))
      : await seal(requestKeys.s2c, {
        ...header,
        dir: DIR_S2C,
      }, new Bytes(plaintext));
    const bytes = wire.toUint8Array();
    if (f.tamper) {
      bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    }
    const response = new Response(new Uint8Array(bytes), { headers: { "Content-Type": "application/wake" } });
    if (p.header.context === "wake/kr/complete" && f.krCompleteResponse) {
      return f.krCompleteResponse(f.krCompleteBodies.length, response);
    }
    return f.upResponse?.(p.header, response) ?? response;
  };
  f.client = new WakeClient({
    baseUrl: "https://example.com/",
    getAssertion,
    fetch,
    now: () => f.localTime,
    sleep: async (ms) => {
      f.sleeps.push(ms);
      f.localTime += ms;
    },
    ...options,
  });
  return f;
}

// Spec §7, §8, §9: independent in-memory peer using only core primitives.
import assert from "node:assert/strict";
import { base64urlnopad, hex } from "@scure/base";
import { Bytes } from "@wake-protocol/bytes";
import { bytesToUtf8, parseIJson, utf8ToBytes } from "@wake-protocol/codec";
import {
  aesKey,
  asExchangeId,
  asClientFinishedMac,
  decodeEtRequest,
  encodeEtResponse,
  deriveKeys,
  ecdh,
  generateEphemeral,
  kxChallenge,
  loginTranscriptHash,
  rekeyTranscriptHash,
  krChallenge,
  taBinding,
  taChallenge,
  taKrChallenge,
  asApprovalId,
  asApprovalNonce,
  asTaNonce,
  parseOperationIdHex,
  createOperationIdentity,
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
import type { EtRequest, C2sCryptoKey, S2cCryptoKey, MsgHeader, TranscriptHash, RekeyTranscriptHash, WebAuthnChallenge } from "@wake-protocol/core";
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
    boundApproval?: string;
  }>();
  const operations = new Map<string, { content: string; nonce: string; status: string }>();
  const approvals = new Map<string, { operationId: string; nonce: Uint8Array; id: Uint8Array; rekey: string | undefined; response?: Record<string, unknown> }>();
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
    operations,
    taRequests: [] as { context: string; body: Record<string, unknown> }[],
    taGetMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    taListMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    taChallengeMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    taApproveError: undefined as string | undefined,
    taApproveBodies: [] as string[],
    taApproveResponse: undefined as ((attempt: number, response: Response) => Response | Promise<Response>) | undefined,
    taKrResult: undefined as "conflict" | "expired" | undefined,
    taApproveMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    taApproveKrMutate: undefined as ((value: Record<string, unknown>) => void) | undefined,
    paths: [] as string[],
    etRequests: [] as EtRequest[],
    etHandler: undefined as ((request: EtRequest) => Uint8Array) | undefined,
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
    addOperation: undefined as unknown as (content: string, nonce?: string) => Promise<{ hashInput: string; operationId: string }>,
  };
  const commitKr = async (
    exchange: { pair: typeof pair; nonce: typeof serverNonce; prevTh: TranscriptHash; epoch: number; response?: Record<string, unknown> },
    body: Record<string, unknown>,
    challengeFor: (th: RekeyTranscriptHash) => Promise<WebAuthnChallenge>,
  ) => {
    if (exchange.response) {
      return;
    }
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
    assert.equal(clientData.challenge, encode(await challengeFor(th)));
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
  };
  const taFail = (code: string) => utf8ToBytes(JSON.stringify({ error: { code } }));
  const handleTa = async (context: string, request: Uint8Array): Promise<Uint8Array> => {
    const body = parseJsonObject(request, "invalid_request");
    f.taRequests.push({ context, body });
    const view = (id: string) => {
      const op = operations.get(id)!;
      return { operationId: id, ...op, createdAt: 1_791_590_400_000, expiresAt: 1_791_676_800_000 };
    };
    if (context === "wake/ta/list") {
      const value: Record<string, unknown> = { operations: [...operations.keys()].map(view), nextCursor: null };
      f.taListMutate?.(value);
      return utf8ToBytes(JSON.stringify(value));
    }
    if (context === "wake/ta/get") {
      const id = body.operationId as string;
      if (!operations.has(id)) {
        return taFail("not_found");
      }
      const value: Record<string, unknown> = { ...view(id), decidedAt: null };
      f.taGetMutate?.(value);
      return utf8ToBytes(JSON.stringify(value));
    }
    if (context === "wake/ta/reject") {
      const id = body.operationId as string;
      if (!operations.has(id)) {
        return taFail("not_found");
      }
      operations.get(id)!.status = "REJECTED";
      return utf8ToBytes(JSON.stringify({ result: "rejected", status: "REJECTED" }));
    }
    if (context === "wake/ta/challenge") {
      const id = body.operationId as string;
      if (!operations.has(id)) {
        return taFail("not_found");
      }
      const approvalId = crypto.getRandomValues(new Uint8Array(16));
      const approvalNonce = crypto.getRandomValues(new Uint8Array(32));
      const key = encode(new Bytes(approvalId));
      let kr: Record<string, unknown> | null = null;
      let rekey: string | undefined;
      if (body.rekey === true) {
        const krPair = await generateEphemeral(false);
        const krExchangeId = newExchangeId();
        const nonce = newServerNonce();
        rekey = encode(krExchangeId);
        exchanges.set(rekey, { pair: krPair, nonce, prevTh: currentTh, epoch: f.currentEpoch + 1, boundApproval: key });
        kr = {
          exchangeId: rekey,
          epoch: f.currentEpoch + 1,
          serverNonce: encode(nonce),
          serverPublicKey: encode(krPair.publicKey),
        };
      }
      approvals.set(key, { operationId: id, nonce: approvalNonce, id: approvalId, rekey });
      const value: Record<string, unknown> = {
        approvalId: key,
        approvalNonce: encode(new Bytes(approvalNonce)),
        expiresAt: f.serverTime + 300_000,
        webauthn: { ...f.start.webauthn as Record<string, unknown>, allowCredentials: [{ type: "public-key", id: "AQ" }] },
        kr,
      };
      f.taChallengeMutate?.(value);
      return utf8ToBytes(JSON.stringify(value));
    }
    assert.equal(context, "wake/ta/approve");
    f.taApproveBodies.push(bytesToUtf8(request));
    if (f.taApproveError) {
      return taFail(f.taApproveError);
    }
    // An unknown approvalId falls back to the latest approval of the operation, as if the server matched it by operation.
    const approval = approvals.get(body.approvalId as string) ??
      [...approvals.values()].filter(x => x.operationId === body.operationId).at(-1)!;
    if (!approval.response) {
      // The server recomputes ta from ITS OWN approval record and the operationId in the request.
      const operationId = parseOperationIdHex(body.operationId as string);
      assert.equal(body.operationId, approval.operationId);
      const ta = await taBinding({
        approvalId: asApprovalId(approval.id),
        operationId,
        approvalNonce: asApprovalNonce(approval.nonce),
        sessionId,
      });
      const assertion = body.assertion as { response: { clientDataJSON: string } };
      const clientData = parseJsonObject(
        decodeBase64urlField(assertion.response.clientDataJSON, "invalid_request"), "invalid_request",
      );
      const response: Record<string, unknown> = {
        operationId: approval.operationId,
        ta: { result: "approved", status: "APPROVED" },
        kr: null,
      };
      if (body.kr === null) {
        assert.equal(approval.rekey, undefined);
        if (clientData.challenge !== encode(await taChallenge(ta))) {
          return taFail("webauthn_failed");
        }
      } else {
        const kr = body.kr as Record<string, unknown>;
        assert.equal(kr.exchangeId, approval.rekey);
        const exchange = exchanges.get(approval.rekey!)!;
        if (f.taKrResult) {
          response.kr = { result: f.taKrResult };
        } else {
          await commitKr(exchange, { ...kr, assertion: body.assertion }, async (th) => taKrChallenge(th, ta));
          const value: Record<string, unknown> = { result: "committed", ...exchange.response };
          f.taApproveKrMutate?.(value);
          response.kr = value;
        }
      }
      operations.get(approval.operationId)!.status = "APPROVED";
      approval.response = response;
    }
    const value = structuredClone(approval.response);
    f.taApproveMutate?.(value);
    return utf8ToBytes(JSON.stringify(value));
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
    assert.ok(path === "/wake/up" || path === "/wake/transport");
    f.paths.push(path);
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
          await commitKr(exchange, body, async (th) => krChallenge(th));
          const value = { ...exchange.response };
          f.krCompleteMutate?.(value);
          plaintext = utf8ToBytes(JSON.stringify(value));
        }
      } else if (p.header.context === "wake-et") {
        assert.equal(path, "/wake/transport");
        const etRequest = decodeEtRequest(request.toUint8Array());
        f.etRequests.push(etRequest);
        plaintext = f.etHandler
          ? f.etHandler(etRequest)
          : encodeEtResponse({ status: 200, headers: [], body: new Bytes(new Uint8Array(0)) }).toUint8Array();
      } else if (p.header.context.startsWith("wake/ta/")) {
        plaintext = await handleTa(p.header.context, request.toUint8Array());
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
    if (p.header.context === "wake/ta/approve" && f.taApproveResponse) {
      return f.taApproveResponse(f.taApproveBodies.length, response);
    }
    return f.upResponse?.(p.header, response) ?? response;
  };
  f.addOperation = async (content: string, nonce = "3f9a1c7e5b2d4f6081a3c5e7092b4d6f") => {
    const identity = await createOperationIdentity(content, asTaNonce(hex.decode(nonce)));
    operations.set(identity.operationId, { content, nonce, status: "PENDING" });
    return identity;
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

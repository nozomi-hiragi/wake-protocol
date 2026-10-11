// Tests for WAKE server behavior (spec §5, §7, §8).
import assert from "node:assert/strict";
import { base64urlnopad } from "@scure/base";
import { bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import {
  Bytes,
  DIR_C2S,
  DIR_S2C,
  aesKey,
  asExchangeId,
  asServerNonce,
  asSessionId,
  asServerFinishedMac,
  clientFinished,
  deriveKeys,
  ecdh,
  generateEphemeral,
  kxChallenge,
  loginTranscriptHash,
  newRequestId,
  open,
  parseEcPublicKey,
  seal,
  verifyServerFinished,
} from "@wake-protocol/core";
import type { C2sCryptoKey, S2cCryptoKey, KeySchedule, LoginTranscriptHash, SessionId } from "@wake-protocol/core";
import { createWakeServer, MemoryCredentialStore, MemoryWakeStore } from "../src/index.ts";
import type { WakeServerOptions, WakeServer } from "../src/index.ts";
import { SoftAuthenticator } from "../src/testing.ts";
import type { AssertionTamper, AuthenticationResponseJSON, GetAssertionOptions } from "../src/testing.ts";

export const RP = "example.com";

export const ORIGIN = "https://example.com";

export const decode = base64urlnopad.decode;

export const encode = base64urlnopad.encode;

export interface StartResponse {
  version: string;
  exchangeId: string;
  sessionId: string;
  epoch: number;
  serverNonce: string;
  serverPublicKey: string;
  expiresAt: number;
  webauthn: Omit<GetAssertionOptions, "challenge">;
}

export interface CompleteBody {
  exchangeId: string;
  clientPublicKey: string;
  assertion: AuthenticationResponseJSON;
  clientFinished: string;
}

export interface Fixture {
  auth: SoftAuthenticator;
  credentials: MemoryCredentialStore;
  store: MemoryWakeStore;
  server: WakeServer;
  clock: { now: number; };
}

export async function fixture(
  overrides: Partial<WakeServerOptions> = {},
  authInit: Parameters<typeof SoftAuthenticator.create>[0] = { rpId: RP, origin: ORIGIN, userId: "u1" }
): Promise<Fixture> {
  const auth = await SoftAuthenticator.create(authInit);
  const credentials = new MemoryCredentialStore();
  credentials.setCredential(auth.credential, "alice");
  const store = new MemoryWakeStore(overrides.completedRetentionMs ?? 600000);
  const clock = { now: 1000000 };
  const server = createWakeServer(
    {
      rpId: RP,
      loginOrigins: [ORIGIN],
      secret: new Uint8Array(32).fill(7),
      credentials,
      store,
      now: () => clock.now,
      ...overrides
    }
  );
  return { auth, credentials, store, server, clock };
}

export async function jsonRequest(
  server: WakeServer,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return response(
    await server.handle(
      new Request(`${ORIGIN}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body)
      })
    )
  );
}

export function response(value: Response | null): Response {
  assert.ok(value);
  return value;
}

export async function expectError(result: Response, status: number, code: string, outer = false): Promise<void> {
  assert.equal(result.status, status);
  assert.match(result.headers.get("content-type")!, /application\/json/);
  assert.deepEqual(await result.json(), outer ? { wakeError: code } : { error: code });
}

export async function start(f: Fixture, body: unknown = { mode: "discoverable" }): Promise<StartResponse> {
  const res = await jsonRequest(f.server, "/auth/start", body);
  assert.equal(res.status, 200);
  return await res.json() as StartResponse;
}

export async function prepare(
  f: Fixture,
  tamper: AssertionTamper = {},
  mode: unknown = { mode: "discoverable" },
  bypassAllow = false
) {
  const info = await start(f, mode);
  const ephemeral = await generateEphemeral();
  const sessionId = asSessionId(decode(info.sessionId));
  const th = await loginTranscriptHash(
    {
      exchangeId: asExchangeId(decode(info.exchangeId)),
      sessionId,
      serverNonce: asServerNonce(decode(info.serverNonce)),
      serverPublicKey: await parseEcPublicKey(decode(info.serverPublicKey)),
      clientPublicKey: ephemeral.publicKey
    }
  );
  const assertionOptions = { ...info.webauthn, challenge: (await kxChallenge(th)).toUint8Array() };
  if (bypassAllow) {
    assertionOptions.allowCredentials = [];
  }
  const assertion = await f.auth.getAssertion(assertionOptions, tamper);
  const keys = await deriveKeys(await ecdh(ephemeral.privateKey, await parseEcPublicKey(decode(info.serverPublicKey))), th);
  const finished = await clientFinished(keys.fkC, th);
  const body: CompleteBody = {
    exchangeId: info.exchangeId,
    clientPublicKey: encode(ephemeral.publicKey.toUint8Array()),
    assertion,
    clientFinished: encode(finished.toUint8Array())
  };
  return {
    info,
    th,
    keys,
    body,
    sessionId,
    c2s: await aesKey(keys.kC2s),
    s2c: await aesKey(keys.kS2c)
  };
}

export interface Login {
  info: StartResponse;
  th: LoginTranscriptHash;
  keys: KeySchedule;
  body: CompleteBody;
  sessionId: SessionId;
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
}

export async function login(f: Fixture, tamper: AssertionTamper = {}): Promise<Login> {
  const prepared = await prepare(f, tamper);
  const res = await jsonRequest(f.server, "/auth/complete", prepared.body);
  assert.equal(res.status, 200, await res.clone().text());
  const result = await res.json() as { serverTime: number; absoluteExpiresAt: number; idleTimeoutSec: number; serverFinished: string; };
  assert.ok(
    await verifyServerFinished(
      prepared.keys.fkS,
      {
        th: prepared.th,
        clientFinished: await clientFinished(prepared.keys.fkC, prepared.th),
        serverTime: result.serverTime,
        absoluteExpiresAt: result.absoluteExpiresAt,
        idleTimeoutSec: result.idleTimeoutSec
      },
      asServerFinishedMac(decode(result.serverFinished))
    )
  );
  return prepared;
}

export async function wire(
  f: Fixture,
  l: Login,
  context = "wake/session",
  plaintext: string | Uint8Array = "{}",
  epoch = 0,
  issuedAt = f.clock.now
): Promise<Bytes> {
  return seal(
    l.c2s,
    {
      dir: DIR_C2S,
      sessionId: l.sessionId,
      epoch,
      requestId: newRequestId(),
      issuedAt,
      context
    },
    new Bytes(typeof plaintext === "string" ? utf8ToBytes(plaintext) : plaintext)
  );
}

export async function sendWire(f: Fixture, bytes: Bytes | Uint8Array, headers: Record<string, string> = {}): Promise<Response> {
  return response(
    await f.server.handle(
      new Request(`${ORIGIN}/wake/up`, {
        method: "POST",
        headers: { "content-type": "application/wake", ...headers },
        body: new Uint8Array(bytes instanceof Bytes ? bytes.toUint8Array() : bytes)
      })
    )
  );
}

export async function opened(l: Login, res: Response) {
  assert.equal(res.status, 200, await res.clone().text());
  assert.match(res.headers.get("content-type")!, /application\/wake/);
  const result = await open(l.s2c, new Uint8Array(await res.arrayBuffer()), DIR_S2C);
  return {
    ...result,
    json: JSON.parse(bytesToUtf8(result.plaintext.toUint8Array())) as Record<string, unknown>
  };
}

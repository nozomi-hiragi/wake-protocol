// Spec §5.4–§5.5, §10: independent test client for operations, approvals and TA+KR.
import assert from "node:assert/strict";
import {
  aesKey,
  asApprovalId,
  asApprovalNonce,
  asExchangeId,
  asServerFinishedMac,
  asServerNonce,
  clientFinished,
  deriveKeys,
  ecdh,
  generateEphemeral,
  parseEcPublicKey,
  parseOperationIdHex,
  rekeyTranscriptHash,
  taBinding,
  taChallenge,
  taKrChallenge,
  verifyServerFinished,
} from "@wake-protocol/core";
import type { RekeyTranscriptHash } from "@wake-protocol/core";
import { SoftAuthenticator } from "../src/testing.ts";
import type { AssertionTamper, AuthenticationResponseJSON, GetAssertionOptions } from "../src/testing.ts";
import { decode, encode, fixture, login, ORIGIN, RP } from "./helpers.ts";
import type { Fixture } from "./helpers.ts";
import { krClient, krRequest } from "./kr-helpers.ts";
import type { KrClient } from "./kr-helpers.ts";
import type { WakeServerOptions } from "../src/index.ts";

export interface TaChallenge {
  approvalId: string;
  approvalNonce: string;
  expiresAt: number;
  webauthn: Omit<GetAssertionOptions, "challenge">;
  kr: null | { exchangeId: string; epoch: number; serverNonce: string; serverPublicKey: string; };
}

export interface Setup {
  f: Fixture;
  client: KrClient;
}

export async function setup(
  overrides: Partial<WakeServerOptions> = {},
  authInit?: Parameters<typeof fixture>[1],
): Promise<Setup> {
  const f = await fixture(overrides, authInit);
  return { f, client: krClient(await login(f)) };
}

/** A second user with their own credential and session on the same server. */
export async function secondUser(f: Fixture): Promise<{ auth: SoftAuthenticator; client: KrClient; }> {
  const auth = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
  f.credentials.setCredential(auth.credential, "bob");
  return { auth, client: krClient(await login({ ...f, auth })) };
}

export async function newOperation(
  f: Fixture,
  over: { content?: string; approverUserId?: string; ttlMs?: number; } = {},
) {
  return f.server.createOperation({
    content: over.content ?? "Transfer 100 JPY",
    approverUserId: over.approverUserId ?? "u1",
    expiresAt: f.clock.now + (over.ttlMs ?? 3_600_000),
  });
}

export async function ta(f: Fixture, client: KrClient, context: string, body: unknown) {
  return krRequest(f, client, `wake/ta/${context}`, body);
}

export async function taError(f: Fixture, client: KrClient, context: string, body: unknown, code: string): Promise<void> {
  const result = await ta(f, client, context, body);
  assert.deepEqual(result.json, { error: { code } }, result.text);
}

export async function challenge(f: Fixture, client: KrClient, operationId: string, rekey = false): Promise<TaChallenge> {
  const result = await ta(f, client, "challenge", { operationId, rekey });
  assert.ok(typeof result.json.approvalId === "string", result.text);
  return result.json as unknown as TaChallenge;
}

export interface PrepareOptions {
  auth?: SoftAuthenticator;
  tamper?: AssertionTamper;
  /** Send a kr object (default: the challenge offered a rekey). */
  kr?: boolean;
  /** Sign the TA+KR challenge (default: same as kr). */
  signKr?: boolean;
  /** Sign for another attempt / operation than the one in the request body. */
  signFor?: { ch: TaChallenge; operationId: string; };
  corruptFinished?: boolean;
}

export async function prepareTa(f: Fixture, client: KrClient, ch: TaChallenge, operationId: string, o: PrepareOptions = {}) {
  const target = o.signFor ?? { ch, operationId };
  const binding = await taBinding({
    approvalId: asApprovalId(decode(target.ch.approvalId)),
    operationId: parseOperationIdHex(target.operationId),
    approvalNonce: asApprovalNonce(decode(target.ch.approvalNonce)),
    sessionId: client.sessionId,
  });
  const sendKr = o.kr ?? ch.kr !== null;
  const signKr = o.signKr ?? sendKr;
  const info = ch.kr ?? target.ch.kr;
  let th: RekeyTranscriptHash | undefined;
  let pair: Awaited<ReturnType<typeof generateEphemeral>> | undefined;
  let serverPublicKey: Awaited<ReturnType<typeof parseEcPublicKey>> | undefined;
  if (sendKr || signKr) {
    assert.ok(info, "the challenge did not offer a rekey");
    pair = await generateEphemeral();
    serverPublicKey = await parseEcPublicKey(decode(info.serverPublicKey));
    th = await rekeyTranscriptHash({
      exchangeId: asExchangeId(decode(info.exchangeId)),
      sessionId: client.sessionId,
      epoch: info.epoch,
      prevTh: client.th,
      serverNonce: asServerNonce(decode(info.serverNonce)),
      serverPublicKey,
      clientPublicKey: pair.publicKey,
    });
  }
  const webauthnChallenge = signKr ? await taKrChallenge(th!, binding) : await taChallenge(binding);
  const auth = o.auth ?? f.auth;
  const assertion: AuthenticationResponseJSON = await auth.getAssertion(
    { ...ch.webauthn, allowCredentials: [], challenge: webauthnChallenge.toUint8Array() },
    o.tamper,
  );
  let keys: Awaited<ReturnType<typeof deriveKeys>> | undefined;
  let finished: Awaited<ReturnType<typeof clientFinished>> | undefined;
  let next: KrClient | undefined;
  let kr: unknown = null;
  if (sendKr) {
    keys = await deriveKeys(await ecdh(pair!.privateKey, serverPublicKey!), th!);
    finished = await clientFinished(keys.fkC, th!);
    next = {
      sessionId: client.sessionId,
      epoch: info!.epoch,
      th: th!,
      c2s: await aesKey(keys.kC2s),
      s2c: await aesKey(keys.kS2c),
    };
    kr = {
      exchangeId: info!.exchangeId,
      clientPublicKey: encode(pair!.publicKey.toUint8Array()),
      clientFinished: o.corruptFinished ? encode(new Uint8Array(32)) : encode(finished.toUint8Array()),
    };
  }
  return {
    body: { approvalId: ch.approvalId, operationId, assertion, kr },
    assertion,
    th,
    keys,
    finished,
    next,
  };
}

export type PreparedTa = Awaited<ReturnType<typeof prepareTa>>;

export async function approve(f: Fixture, client: KrClient, prepared: PreparedTa) {
  return ta(f, client, "approve", prepared.body);
}

export async function verifyKrCommitted(prepared: PreparedTa, kr: Record<string, unknown>): Promise<void> {
  assert.equal(kr.result, "committed");
  assert.deepEqual(Object.keys(kr).sort(), [
    "absoluteExpiresAt", "epoch", "idleTimeoutSec", "result", "serverFinished", "serverTime",
  ]);
  assert.equal(kr.epoch, prepared.next!.epoch);
  assert.ok(await verifyServerFinished(prepared.keys!.fkS, {
    th: prepared.th!,
    clientFinished: prepared.finished!,
    serverTime: kr.serverTime as number,
    absoluteExpiresAt: kr.absoluteExpiresAt as number,
    idleTimeoutSec: kr.idleTimeoutSec as number,
  }, asServerFinishedMac(decode(kr.serverFinished as string))));
}

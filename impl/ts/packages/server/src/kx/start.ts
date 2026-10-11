// Spec §6.6, §7.2: reserve a login exchange and supply WebAuthn options.
import { base64urlnopad } from "@scure/base";
import { Byte4 } from "@wake-protocol/bytes";
import { asciiToBytes, utf8ToBytes, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import { hmac, hmacKey } from "@wake-protocol/crypto";
import { generateEphemeral, newExchangeId, newSessionId, newServerNonce, parseJsonObject, WakeError } from "@wake-protocol/core";
import { checkContentType, jsonResponse, readBody } from "../http.ts";
import type { ServerOptions } from "../options.ts";

// No `transports` on any descriptor: only some credentials have them stored, and a fake descriptor must be
// indistinguishable from a real one (§6.6). Browsers discover transports themselves.
interface Descriptor {
  type: "public-key";
  id: string;
}

interface UsernameResolution {
  requestedUserId: string | null;
  allowCredentials: Descriptor[];
}

/** Deterministic pseudo-random bytes: HMAC blocks with a block counter in the LP input. */
async function fakeCredentialId(key: CryptoKey, username: string, index: number, length: number): Promise<Uint8Array> {
  const id = new Uint8Array(length);
  for (let block = 0; block * 32 < length; block++) {
    const input = encodeU32LengthPrefixed(
      asciiToBytes("wake-server fake-credential"),
      utf8ToBytes(username),
      new Byte4(index).toUint8Array(),
      new Byte4(block).toUint8Array(),
    );
    id.set((await hmac(key, input)).slice(0, length - block * 32), block * 32);
  }
  return id;
}

async function createFakeCredentials(username: string, options: ServerOptions): Promise<Descriptor[]> {
  const key = await hmacKey(options.secret);
  const fake: Descriptor[] = [];
  for (let i = 0; i < options.fakeCredentialCount; i++) {
    fake.push({
      type: "public-key",
      id: base64urlnopad.encode(await fakeCredentialId(key, username, i, options.fakeCredentialIdLength)),
    });
  }
  return fake;
}

async function resolveUsername(username: unknown, options: ServerOptions): Promise<UsernameResolution> {
  // Limit is 256 UTF-16 code units; I-JSON has already rejected lone surrogates.
  if (typeof username !== "string" || !username.length || username.length > 256) {
    throw new WakeError("bad_request");
  }
  const user = await options.credentials.findUserByUsername(username);
  // Equal HMAC work for known and unknown usernames, before selecting the list.
  const fake = await createFakeCredentials(username, options);
  const active = user?.credentials
    .filter(c => c.status === "active")
    .map(c => ({
      type: "public-key" as const,
      id: base64urlnopad.encode(c.credentialId),
    })) ?? [];
  return {
    requestedUserId: active.length ? user!.userId : null,
    allowCredentials: active.length ? active : fake,
  };
}

export async function start(req: Request, options: ServerOptions): Promise<Response> {
  checkContentType(req, "application/json");
  const body = parseJsonObject(await readBody(req, options.maxAuthBody, "bad_request"), "bad_request");
  if (body.mode !== "discoverable" && body.mode !== "username") {
    throw new WakeError("bad_request");
  }
  const username = body.mode === "username" ? await resolveUsername(body.username, options) : undefined;
  const exchangeId = newExchangeId();
  const sessionId = newSessionId();
  const serverNonce = newServerNonce();
  const ephemeral = await generateEphemeral();
  const serverTime = options.now();
  const expiresAt = serverTime + options.exchangeTtlMs;
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0) {
    throw new RangeError("exchange expiration");
  }
  await options.store.createExchange({
    exchangeId,
    sessionId,
    kind: "login",
    state: "PENDING",
    serverNonce,
    serverPublicKey: ephemeral.publicKey,
    serverPrivateKey: ephemeral.privateKey,
    expiresAt,
    ...(username ?
      { mode: "username" as const, requestedUserId: username.requestedUserId } :
      { mode: "discoverable" as const }),
  });
  return jsonResponse({
    version: "WAKE/1",
    exchangeId: base64urlnopad.encode(exchangeId.toUint8Array()),
    sessionId: base64urlnopad.encode(sessionId.toUint8Array()),
    epoch: 0,
    serverNonce: base64urlnopad.encode(serverNonce.toUint8Array()),
    serverPublicKey: base64urlnopad.encode(ephemeral.publicKey.toUint8Array()),
    serverTime,
    expiresAt,
    webauthn: {
      rpId: options.rpId,
      allowCredentials: username?.allowCredentials ?? [],
      userVerification: "required",
      timeout: options.webauthnTimeoutMs,
    },
  });
}

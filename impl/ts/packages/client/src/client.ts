// Spec §7.7–7.8, §8.2–8.9, §12: in-memory KX and SM client.
import { base64urlnopad } from "@scure/base";
import { Bytes } from "@wake-protocol/bytes";
import { utf8ToBytes } from "@wake-protocol/codec";
import {
  WakeError,
  asExchangeId,
  asSessionId,
  asServerNonce,
  asServerFinishedMac,
  aesKey,
  hmacKey,
  generateEphemeral,
  parseEcPublicKey,
  ecdh,
  deriveKeys,
  loginTranscriptHash,
  kxChallenge,
  clientFinished,
  verifyServerFinished,
  newRequestId,
  seal,
  parseWire,
  openParsed,
  DIR_C2S,
  DIR_S2C,
} from "@wake-protocol/core";
import type {
  SessionId,
  RequestId,
  C2sCryptoKey,
  S2cCryptoKey,
  FinishedCryptoKeyS,
  ClientFinishedMac,
  LoginTranscriptHash,
} from "@wake-protocol/core";
import type { GetAssertion, GetAssertionOptions } from "./assertion.ts";
import { decodeBinary, integer, object, parseJson, responseJson } from "./json.ts";

export interface WakeClientOptions {
  baseUrl: string;
  getAssertion: GetAssertion;
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Integer in 1..2**28; reservations include failed transmissions. */
  maxEncryptionsPerKey?: number;
}

export interface SessionInfo {
  sessionId: string;
  epoch: number;
  serverTime: number;
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
}

export interface WakeSessionInfo extends SessionInfo {
  authTime: number;
  hardCapAt: number;
  rekeyRecommended: boolean;
}

interface SessionState {
  sessionId: SessionId;
  epoch: number;
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
  th: LoginTranscriptHash;
  offset: number;
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
  encryptions: number;
}

interface PreparedLogin {
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
  fkS: FinishedCryptoKeyS;
  th: LoginTranscriptHash;
  finished: ClientFinishedMac;
  body: string;
}

interface PendingRequest {
  requestId: RequestId;
  context: string;
  wire: Bytes;
}

interface ReceivedResponse {
  response: Response;
  bytes: Uint8Array;
  arrivedAt: number;
}

const OUTER_CODES = new Set(["bad_request", "too_large", "reauth", "epoch_retired", "rate_limited", "retry"]);
const EMPTY_JSON = utf8ToBytes("{}");

function encodeBinary(bytes: Bytes): string {
  return base64urlnopad.encode(bytes.toUint8Array());
}

function isJsonResponse(response: Response): boolean {
  return response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

async function parseStart(value: Record<string, unknown>) {
  if (value.version !== "WAKE/1" || value.epoch !== 0) {
    throw new WakeError("bad_request");
  }
  const exchangeId = asExchangeId(decodeBinary(value.exchangeId));
  const sessionId = asSessionId(decodeBinary(value.sessionId));
  const serverNonce = asServerNonce(decodeBinary(value.serverNonce));
  let serverPublicKey;
  try {
    serverPublicKey = await parseEcPublicKey(decodeBinary(value.serverPublicKey));
  } catch (e) {
    if (e instanceof WakeError) {
      throw new WakeError("bad_request");
    }
    throw e;
  }
  const expiresAt = integer(value.expiresAt);
  const w = object(value.webauthn);
  if (typeof w.rpId !== "string" || w.userVerification !== "required" || !Array.isArray(w.allowCredentials)) {
    throw new WakeError("bad_request");
  }
  const allowCredentials = w.allowCredentials.map((entry) => {
    const c = object(entry);
    if (c.type !== "public-key" || typeof c.id !== "string") {
      throw new WakeError("bad_request");
    }
    decodeBinary(c.id);
    if (c.transports !== undefined && (!Array.isArray(c.transports) || !c.transports.every((t) => typeof t === "string"))) {
      throw new WakeError("bad_request");
    }
    return {
      type: "public-key" as const,
      id: c.id,
      ...(c.transports === undefined ? {} : { transports: c.transports as string[] }),
    };
  });
  const webauthn: Omit<GetAssertionOptions, "challenge"> = {
    rpId: w.rpId,
    userVerification: "required",
    timeout: integer(w.timeout, 0xffffffff),
    allowCredentials,
  };
  return {
    exchangeId,
    sessionId,
    serverNonce,
    serverPublicKey,
    expiresAt,
    webauthn,
  };
}

type LoginStart = Awaited<ReturnType<typeof parseStart>>;
type LoginRequest = { mode: "discoverable" } | {
  mode: "username";
  username: string;
};

function parseEncryptedError(plaintext: Uint8Array): string | undefined {
  let json: unknown;
  try {
    json = parseJson(plaintext);
  } catch (e) {
    if (!(e instanceof WakeError)) {
      throw e;
    }
    // Generic application plaintext may be arbitrary binary, not JSON.
  }
  if (json !== null && typeof json === "object" && !Array.isArray(json) && Object.keys(json).length === 1 && "error" in json) {
    const error = json.error;
    if (error !== null && typeof error === "object" && !Array.isArray(error) && "code" in error && typeof error.code === "string") {
      return error.code;
    }
  }
  return undefined;
}

/** Memory-only: a page reload requires a new WebAuthn login (§8.11). */
export class WakeClient {
  readonly #baseUrl: string;
  readonly #getAssertion: GetAssertion;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #maxEncryptions: number;
  #state: SessionState | undefined;
  #generation = 0;

  constructor(options: WakeClientOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#getAssertion = options.getAssertion;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#now = options.now ?? Date.now;
    this.#sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    const limit = options.maxEncryptionsPerKey ?? 2 ** 28;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 2 ** 28) {
      throw new WakeError("invalid_option");
    }
    this.#maxEncryptions = limit;
  }

  get loggedIn(): boolean {
    return this.#state !== undefined;
  }

  #post(path: string, body: string | Uint8Array<ArrayBuffer>, contentType: string): Promise<Response> {
    return this.#fetch(this.#baseUrl + path, {
      method: "POST",
      headers: { "Content-Type": contentType },
      body,
    });
  }

  /** A new login invalidates any previous or pending login on this instance. */
  async login(req: LoginRequest): Promise<SessionInfo> {
    const generation = ++this.#generation;
    this.#state = undefined;
    const start = await this.#startLogin(req);
    const prepared = await this.#prepareLogin(start);
    const completed = await this.#completeWithRetry(prepared.body, start.expiresAt, generation);
    const info = await this.#verifyLogin(start, prepared, completed.json);
    if (generation !== this.#generation) {
      throw new WakeError("auth_failed");
    }
    this.#state = {
      sessionId: start.sessionId,
      epoch: 0,
      c2s: prepared.c2s,
      s2c: prepared.s2c,
      th: prepared.th,
      offset: info.serverTime - completed.arrivedAt,
      absoluteExpiresAt: info.absoluteExpiresAt,
      idleTimeoutSec: info.idleTimeoutSec,
      encryptions: 0,
    };
    return info;
  }

  async #startLogin(req: LoginRequest): Promise<LoginStart> {
    const response = await this.#post("/auth/start", JSON.stringify(req), "application/json");
    const json = await responseJson(response);
    if (response.status !== 200 || typeof json.error === "string") {
      throw new WakeError(typeof json.error === "string" ? json.error : "auth_failed");
    }
    return parseStart(json);
  }

  async #prepareLogin(start: LoginStart): Promise<PreparedLogin> {
    // This scope ends before retries, releasing the ephemeral secret and raw keys.
    const pair = await generateEphemeral(false);
    const th = await loginTranscriptHash({
      ...start,
      clientPublicKey: pair.publicKey,
    });
    const assertion = await this.#getAssertion({
      ...start.webauthn,
      challenge: (await kxChallenge(th)).toUint8Array(),
    });
    const raw = await deriveKeys(await ecdh(pair.privateKey, start.serverPublicKey), th);
    const [c2s, s2c, fkC, fkS] = await Promise.all([
      aesKey(raw.kC2s, false),
      aesKey(raw.kS2c, false),
      hmacKey(raw.fkC, false),
      hmacKey(raw.fkS, false),
    ]);
    const finished = await clientFinished(fkC, th);
    const body = JSON.stringify({
      exchangeId: encodeBinary(start.exchangeId),
      clientPublicKey: encodeBinary(pair.publicKey),
      assertion,
      clientFinished: encodeBinary(finished),
    });
    return {
      c2s,
      s2c,
      fkS,
      th,
      finished,
      body,
    };
  }

  async #completeWithRetry(body: string, expiresAt: number, generation: number) {
    let delay = 100;
    for (;;) {
      if (generation !== this.#generation || this.#now() >= expiresAt) {
        throw new WakeError("auth_failed");
      }
      let response: Response | undefined;
      try {
        response = await this.#post("/auth/complete", body, "application/json");
      } catch {
        // Only fetch failures are retried; parsing/verification errors are final.
      }
      const arrivedAt = this.#now();
      let json: Record<string, unknown> | undefined;
      if (response && (response.status !== 503 || isJsonResponse(response))) {
        json = await responseJson(response, "auth_failed");
      }
      if (!response || response.status === 503 || json?.error === "retry") {
        const remaining = expiresAt - this.#now();
        if (remaining <= 0) {
          throw new WakeError("auth_failed");
        }
        await this.#sleep(Math.min(delay, remaining));
        delay = Math.min(delay * 2, 2000);
        continue;
      }
      if (response.status !== 200 || json!.error !== undefined) {
        const code = json!.error;
        throw new WakeError(typeof code === "string" ? code : "auth_failed");
      }
      return {
        json: json!,
        arrivedAt,
      };
    }
  }

  async #verifyLogin(start: LoginStart, prepared: PreparedLogin, value: Record<string, unknown>): Promise<SessionInfo> {
    if (value.epoch !== 0 || value.sessionId !== encodeBinary(start.sessionId)) {
      throw new WakeError("auth_failed");
    }
    const info: SessionInfo = {
      sessionId: encodeBinary(start.sessionId),
      epoch: 0,
      serverTime: integer(value.serverTime, Number.MAX_SAFE_INTEGER, "auth_failed"),
      absoluteExpiresAt: integer(value.absoluteExpiresAt, Number.MAX_SAFE_INTEGER, "auth_failed"),
      idleTimeoutSec: integer(value.idleTimeoutSec, 0xffffffff, "auth_failed"),
    };
    const macBytes = decodeBinary(value.serverFinished, "auth_failed");
    if (macBytes.length !== 32) {
      throw new WakeError("auth_failed");
    }
    const valid = await verifyServerFinished(
      prepared.fkS,
      {
        th: prepared.th,
        clientFinished: prepared.finished,
        ...info,
      },
      asServerFinishedMac(macBytes),
    );
    if (!valid) {
      throw new WakeError("auth_failed");
    }
    return info;
  }

  /** A stale_request is retried once; other network failures propagate. */
  request(context: string, plaintext: Uint8Array): Promise<Uint8Array> {
    return this.#request(context, plaintext);
  }

  async #request(context: string, plaintext: Uint8Array, ignoreTransportFailure = false): Promise<Uint8Array> {
    const state = this.#state;
    if (!state) {
      throw new WakeError("reauth");
    }
    const bytes = new Bytes(plaintext);
    for (let attempt = 0; attempt < 2; attempt++) {
      const pending = await this.#sealRequest(state, context, bytes);
      const received = await this.#sendRequest(state, pending, ignoreTransportFailure);
      if (!received) {
        return new Uint8Array(EMPTY_JSON);
      }
      const result = await this.#acceptResponse(state, pending, received);
      const error = parseEncryptedError(result);
      if (error === "stale_request" && attempt === 0) {
        continue;
      }
      if (error !== undefined) {
        throw new WakeError(error);
      }
      return result;
    }
    throw new WakeError("stale_request");
  }

  async #sealRequest(state: SessionState, context: string, plaintext: Bytes): Promise<PendingRequest> {
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    if (state.encryptions >= this.#maxEncryptions || this.#now() + state.offset >= state.absoluteExpiresAt) {
      this.#state = undefined;
      throw new WakeError("reauth");
    }
    // Reserve synchronously before Web Crypto yields, including concurrent calls.
    state.encryptions++;
    const requestId = newRequestId();
    const wire = await seal(state.c2s, {
      dir: DIR_C2S,
      sessionId: state.sessionId,
      epoch: state.epoch,
      requestId,
      context,
      issuedAt: Math.max(0, Math.floor(this.#now() + state.offset)),
    }, plaintext);
    return {
      requestId,
      context,
      wire,
    };
  }

  async #sendRequest(state: SessionState, pending: PendingRequest, ignoreTransportFailure: boolean) {
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    let response: Response;
    try {
      response = await this.#post("/wake/up", new Uint8Array(pending.wire.toUint8Array()), "application/wake");
    } catch (e) {
      if (ignoreTransportFailure) {
        return undefined;
      }
      throw e;
    }
    const arrivedAt = this.#now();
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch (e) {
      if (ignoreTransportFailure) {
        return undefined;
      }
      throw e;
    }
    return {
      response,
      bytes,
      arrivedAt,
    };
  }

  async #acceptResponse(state: SessionState, pending: PendingRequest, received: ReceivedResponse): Promise<Uint8Array> {
    if (received.response.status !== 200 || isJsonResponse(received.response)) {
      const json = object(parseJson(received.bytes));
      const code = json.wakeError;
      if (typeof code !== "string" || !OUTER_CODES.has(code)) {
        throw new WakeError("bad_request");
      }
      if (code === "reauth" && this.#state === state) {
        this.#state = undefined;
      }
      throw new WakeError(code);
    }
    const parsed = parseWire(received.bytes);
    const h = parsed.header;
    if (h.dir !== DIR_S2C || !h.sessionId.equals(state.sessionId) || h.epoch !== state.epoch ||
        !h.requestId.equals(pending.requestId) || h.context !== pending.context) {
      throw new WakeError("bad_request");
    }
    const result = (await openParsed(state.s2c, parsed, DIR_S2C)).toUint8Array();
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    state.offset = h.issuedAt - received.arrivedAt;
    return result;
  }

  async session(): Promise<WakeSessionInfo> {
    const state = this.#state;
    const value = object(parseJson(await this.request("wake/session", EMPTY_JSON)));
    const id = asSessionId(decodeBinary(value.sessionId));
    const epoch = integer(value.epoch, 0xffffffff);
    if (!state || !id.equals(state.sessionId) || epoch !== state.epoch || typeof value.rekeyRecommended !== "boolean") {
      throw new WakeError("bad_request");
    }
    return {
      sessionId: encodeBinary(id),
      epoch,
      authTime: integer(value.authTime),
      absoluteExpiresAt: integer(value.absoluteExpiresAt),
      hardCapAt: integer(value.hardCapAt),
      idleTimeoutSec: integer(value.idleTimeoutSec, 0xffffffff),
      serverTime: integer(value.serverTime),
      rekeyRecommended: value.rekeyRecommended,
    };
  }

  /** Deletes local keys even on failure. Transport failures resolve; protocol errors propagate. */
  async logout(): Promise<void> {
    const state = this.#state;
    ++this.#generation;
    try {
      if (!state) {
        return;
      }
      object(parseJson(await this.#request("wake/logout", EMPTY_JSON, true)));
    } finally {
      if (this.#state === state) {
        this.#state = undefined;
      }
    }
  }
}

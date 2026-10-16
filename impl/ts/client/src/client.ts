// Spec §7.7–7.8, §8.2–8.9, §8.11, §9, §12: KX, SM and KR client with a pluggable session store.
import { base64urlnopad } from "@scure/base";
import { Bytes } from "@wake-protocol/bytes";
import { utf8ToBytes } from "@wake-protocol/codec";
import {
  WakeError,
  decodeBase64urlField,
  parseJsonObject,
  asExchangeId,
  asSessionId,
  asTranscriptHash,
  asServerNonce,
  asServerFinishedMac,
  aesKey,
  hmacKey,
  generateEphemeral,
  parseEcPublicKey,
  ecdh,
  deriveKeys,
  loginTranscriptHash,
  rekeyTranscriptHash,
  krChallenge,
  taBinding,
  taChallenge,
  taKrChallenge,
  parseOperationIdHex,
  asApprovalId,
  asApprovalNonce,
  kxChallenge,
  clientFinished,
  verifyServerFinished,
  newRequestId,
  seal,
  parseWire,
  encodeEtRequest,
  decodeEtResponse,
  openParsed,
  DIR_C2S,
  DIR_S2C,
  ET_BODY_MIN,
  ET_BODY_MAX,
  ET_REQUEST_MAX_ENCODED,
  ET_RESPONSE_MAX_ENCODED,
  DEFAULT_MAX_PLAINTEXT,
} from "@wake-protocol/core";
import type {
  EtHeader,
  SessionId,
  RequestId,
  C2sCryptoKey,
  S2cCryptoKey,
  FinishedCryptoKeyS,
  ClientFinishedMac,
  LoginTranscriptHash,
  TranscriptHash,
  RekeyTranscriptHash,
  WebAuthnChallenge,
} from "@wake-protocol/core";
import type { AuthenticationResponseJSON, GetAssertion, GetAssertionOptions } from "./assertion.ts";
import { integer, object, responseJson } from "./json.ts";
import { memorySessionStore } from "./store.ts";
import type { SessionStore, StoredEpoch, StoredSession } from "./store.ts";
import { OPERATION_STATUSES, parseOperationList, parseResult, verifiedOperation } from "./ta.ts";
import type {
  OperationList,
  OperationStatus,
  TaApproveResult,
  TaRejectResult,
  VerifiedOperation,
} from "./ta.ts";

export interface WakeClientOptions {
  baseUrl: string;
  getAssertion: GetAssertion;
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Integer in 1..2**28; reservations include failed transmissions. */
  maxEncryptionsPerKey?: number;
  /** Safe integer ET body limit of at least ET_BODY_MIN bytes (§11.2). Defaults to ET_BODY_MAX. */
  etBodyLimit?: number;
  /** Positive safe integer plaintext limit; must cover ET request and response encoding. */
  maxPlaintext?: number;
  /** Safe integer >= 1. Encryption quota is reserved in blocks of this size (§8.7). Defaults to 4096. */
  encryptionBlockSize?: number;
  /** Shared session record. Default: a private in-memory store, so instances do not share a login. */
  store?: SessionStore;
}

/** What another tab needs in order to adopt a stored session without its keys. */
export interface StoredSessionInfo {
  sessionId: string;
  epoch: number;
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
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

export type RekeyInfo = Omit<SessionInfo, "sessionId">;

export interface ApproveOptions {
  /** Run TA+KR (§10.8): one WebAuthn signature authenticates the approval and the key rotation. */
  rekey?: boolean;
}

export type TaKrResult = ({ result: "committed" } & RekeyInfo) | { result: "conflict" } | { result: "expired" };

export interface ApproveInfo {
  operationId: string;
  ta: { result: TaApproveResult; status: string };
  /** Present only when `rekey` was requested. */
  kr?: TaKrResult;
}

interface EpochState {
  epoch: number;
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
  th: TranscriptHash;
  /** Remaining encryptions already reserved from the store. Zero means the next seal must reserve a block. */
  budget: number;
  /** One in-flight reservation shared by concurrent seals of this epoch (§8.7). */
  reserving?: Promise<number>;
}

interface SessionState {
  sessionId: SessionId;
  current: EpochState;
  offset: number;
  absoluteExpiresAt: number;
  idleTimeoutSec: number;
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
  keys: EpochState;
}

interface ReceivedResponse {
  response: Response;
  bytes: Uint8Array;
  arrivedAt: number;
}

const OUTER_CODES = new Set(["bad_request", "too_large", "reauth", "epoch_retired", "rate_limited", "retry"]);
// Authenticated rejections leave the pending generation uncommitted. Keep legacy encrypted retry/epoch_retired errors.
const ROTATION_REJECTION_CODES = new Set([
  "invalid_request", "invalid_context", "not_found", "expired", "already_decided", "webauthn_failed", "conflict",
  "rate_limited", "retry", "epoch_retired",
]);
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
  const exchangeId = asExchangeId(decodeBase64urlField(value.exchangeId, "bad_request"));
  const sessionId = asSessionId(decodeBase64urlField(value.sessionId, "bad_request"));
  const serverNonce = asServerNonce(decodeBase64urlField(value.serverNonce, "bad_request"));
  let serverPublicKey;
  try {
    serverPublicKey = await parseEcPublicKey(decodeBase64urlField(value.serverPublicKey, "bad_request"));
  } catch (e) {
    if (e instanceof WakeError) {
      throw new WakeError("bad_request");
    }
    throw e;
  }
  // Both are server time. Only their difference is used (the remaining lifetime of the exchange).
  const serverTime = integer(value.serverTime);
  const expiresAt = integer(value.expiresAt);
  if (expiresAt <= serverTime) {
    throw new WakeError("bad_request");
  }
  const webauthn = parseWebAuthn(value.webauthn);
  return {
    exchangeId,
    sessionId,
    serverNonce,
    serverPublicKey,
    ttl: expiresAt - serverTime,
    webauthn,
  };
}

function parseWebAuthn(value: unknown): Omit<GetAssertionOptions, "challenge"> {
  const w = object(value);
  if (typeof w.rpId !== "string" || w.userVerification !== "required" || !Array.isArray(w.allowCredentials)) {
    throw new WakeError("bad_request");
  }
  const allowCredentials = w.allowCredentials.map((entry) => {
    const c = object(entry);
    if (c.type !== "public-key" || typeof c.id !== "string") {
      throw new WakeError("bad_request");
    }
    decodeBase64urlField(c.id, "bad_request");
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
  return webauthn;
}

async function parseRekeyKey(value: Record<string, unknown>, currentEpoch: number) {
  const epoch = integer(value.epoch, 0xffffffff);
  if (epoch !== currentEpoch + 1) {
    throw new WakeError("bad_request");
  }
  const exchangeId = asExchangeId(decodeBase64urlField(value.exchangeId, "bad_request"));
  const serverNonce = asServerNonce(decodeBase64urlField(value.serverNonce, "bad_request"));
  let serverPublicKey;
  try {
    serverPublicKey = await parseEcPublicKey(decodeBase64urlField(value.serverPublicKey, "bad_request"));
  } catch (e) {
    if (e instanceof WakeError) {
      throw new WakeError("bad_request");
    }
    throw e;
  }
  return { exchangeId, epoch, serverNonce, serverPublicKey };
}

async function parseRekeyStart(value: Record<string, unknown>, currentEpoch: number) {
  return {
    ...await parseRekeyKey(value, currentEpoch),
    expiresAt: integer(value.expiresAt),
    webauthn: parseWebAuthn(value.webauthn),
  };
}

type RotationStart = Awaited<ReturnType<typeof parseRekeyKey>> & { webauthn: Omit<GetAssertionOptions, "challenge"> };

interface PreparedRotation {
  keys: EpochState;
  th: RekeyTranscriptHash;
  fkS: FinishedCryptoKeyS;
  finished: ClientFinishedMac;
  clientPublicKey: Bytes;
  assertion: AuthenticationResponseJSON;
}

type ParsedStart = Awaited<ReturnType<typeof parseStart>>;
type LoginStart = ParsedStart & { deadline: number };
type LoginRequest = { mode: "discoverable" } | {
  mode: "username";
  username: string;
};

export interface WakeFetchInit {
  method?: string;
  headers?: readonly (readonly [string, string])[] | Record<string, string>;
  body?: Uint8Array | string;
}

function parseEncryptedError(plaintext: Uint8Array, reserved = false): string | undefined {
  let json: Record<string, unknown> | undefined;
  try {
    json = parseJsonObject(plaintext, "bad_request");
  } catch (e) {
    if (!(e instanceof WakeError)) {
      throw e;
    }
    // Generic application plaintext may be arbitrary binary, not JSON.
  }
  if (json !== undefined && (reserved || Object.keys(json).length === 1) && "error" in json) {
    const error = json.error;
    if (error !== null && typeof error === "object" && !Array.isArray(error) && "code" in error && typeof error.code === "string") {
      return error.code;
    }
  }
  return undefined;
}

/**
 * Keys live in `options.store`. The default store is private to this instance, so a reload needs a new login.
 * A shared store is how several tabs share one session (§8.11): call `reload` on focus, and after `epoch_retired`.
 */
export class WakeClient {
  readonly #baseUrl: string;
  readonly #getAssertion: GetAssertion;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #maxEncryptions: number;
  readonly #blockSize: number;
  readonly #store: SessionStore;
  readonly #etBodyLimit: number;
  readonly #maxPlaintext: number;
  #state: SessionState | undefined;
  #generation = 0;
  /** Rotation lock names this instance currently holds. Inner requests re-enter; a second rotation does not. */
  #rotating = new Set<string>();

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
    const block = options.encryptionBlockSize ?? 4096;
    if (!Number.isSafeInteger(block) || block < 1) {
      throw new WakeError("invalid_option");
    }
    this.#blockSize = block;
    this.#store = options.store ?? memorySessionStore();
    const bodyLimit = options.etBodyLimit === undefined ? ET_BODY_MAX : options.etBodyLimit;
    if (!Number.isSafeInteger(bodyLimit) || bodyLimit < ET_BODY_MIN) {
      throw new WakeError("invalid_option");
    }
    this.#etBodyLimit = bodyLimit;
    const maxPlaintext = options.maxPlaintext === undefined ? DEFAULT_MAX_PLAINTEXT : options.maxPlaintext;
    if (!Number.isSafeInteger(maxPlaintext) || maxPlaintext < 1 ||
        maxPlaintext < ET_REQUEST_MAX_ENCODED - ET_BODY_MAX + bodyLimit ||
        maxPlaintext < ET_RESPONSE_MAX_ENCODED - ET_BODY_MAX + bodyLimit) {
      throw new WakeError("invalid_option");
    }
    this.#maxPlaintext = maxPlaintext;
  }

  get loggedIn(): boolean {
    return this.#state !== undefined;
  }

  /** The session this instance has adopted. Undefined before `reload` adopts a record written by another tab. */
  get currentSession(): StoredSessionInfo | undefined {
    return this.#state === undefined ? undefined : this.#sessionInfo(this.#state);
  }

  /**
   * Reads the store and merges it into this instance. Does not bump `#generation`, so a login
   * whose passkey prompt is still open survives a focus reload.
   * A newer epoch of the same session replaces `state.current` in place and keeps the local offset.
   * If `#state` or its current epoch object changed during the read, that read is stale and is ignored.
   */
  async reload(): Promise<StoredSessionInfo | undefined> {
    const before = this.#state;
    const beforeCurrent = before?.current;
    const record = await this.#store.load();
    if (this.#state !== before || this.#state?.current !== beforeCurrent) {
      return this.currentSession;
    }
    if (record === undefined || record.baseUrl !== this.#baseUrl) {
      if (this.#state !== undefined) {
        this.#state = undefined;
      }
      return undefined;
    }
    const state = this.#state;
    if (state === undefined || encodeBinary(state.sessionId) !== record.sessionId) {
      this.#state = {
        sessionId: asSessionId(base64urlnopad.decode(record.sessionId)),
        current: this.#restoreEpoch(record.current),
        offset: record.offset,
        absoluteExpiresAt: record.absoluteExpiresAt,
        idleTimeoutSec: record.idleTimeoutSec,
      };
      return this.currentSession;
    }
    if (record.current.epoch > state.current.epoch) {
      state.current = this.#restoreEpoch(record.current);
      state.absoluteExpiresAt = record.absoluteExpiresAt;
      state.idleTimeoutSec = record.idleTimeoutSec;
    }
    return this.#sessionInfo(state);
  }

  #sessionInfo(state: SessionState): StoredSessionInfo {
    return {
      sessionId: encodeBinary(state.sessionId),
      epoch: state.current.epoch,
      absoluteExpiresAt: state.absoluteExpiresAt,
      idleTimeoutSec: state.idleTimeoutSec,
    };
  }

  #storedEpoch(keys: EpochState): StoredEpoch {
    return { epoch: keys.epoch, c2s: keys.c2s, s2c: keys.s2c, th: keys.th.toUint8Array() };
  }

  #restoreEpoch(stored: StoredEpoch): EpochState {
    return {
      epoch: stored.epoch,
      c2s: stored.c2s,
      s2c: stored.s2c,
      th: asTranscriptHash(stored.th),
      budget: 0,
    };
  }

  #sessionRecord(state: SessionState, current: EpochState, pending?: EpochState): StoredSession {
    const record: StoredSession = {
      baseUrl: this.#baseUrl,
      sessionId: encodeBinary(state.sessionId),
      current: this.#storedEpoch(current),
      offset: state.offset,
      absoluteExpiresAt: state.absoluteExpiresAt,
      idleTimeoutSec: state.idleTimeoutSec,
    };
    if (pending !== undefined) {
      record.pending = this.#storedEpoch(pending);
    }
    return record;
  }

  /** Forgets the session locally and removes it from the store when it is still that session. */
  async #drop(state: SessionState): Promise<void> {
    if (this.#state === state) {
      this.#state = undefined;
    }
    await this.#store.clear({ sessionId: encodeBinary(state.sessionId) });
  }

  /**
   * Exclusive KR for this session (§9.7). A second call while one is running rejects with conflict.
   * Requests made by the rotation itself re-enter instead of deadlocking on the same name.
   */
  async #withRotationLock<T>(sessionId: string, fn: () => Promise<T>): Promise<T> {
    const name = "wake-kr:" + sessionId;
    return this.#store.lock(name, async () => {
      this.#rotating.add(name);
      try {
        return await fn();
      } finally {
        this.#rotating.delete(name);
      }
    });
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
    const completed = await this.#completeWithRetry(prepared.body, start.deadline, generation);
    const info = await this.#verifyLogin(start, prepared, completed.json);
    if (generation !== this.#generation) {
      throw new WakeError("auth_failed");
    }
    const offset = info.serverTime - completed.arrivedAt;
    // A new login replaces whatever another tab had stored. No expect.
    await this.#store.save({
      baseUrl: this.#baseUrl,
      sessionId: info.sessionId,
      current: {
        epoch: 0,
        c2s: prepared.c2s,
        s2c: prepared.s2c,
        th: prepared.th.toUint8Array(),
      },
      offset,
      absoluteExpiresAt: info.absoluteExpiresAt,
      idleTimeoutSec: info.idleTimeoutSec,
    });
    if (generation !== this.#generation) {
      // Logout or a newer login won while the record was written. Don't adopt it here.
      await this.#store.clear({ sessionId: info.sessionId });
      throw new WakeError("auth_failed");
    }
    this.#state = {
      sessionId: start.sessionId,
      current: {
        epoch: 0,
        c2s: prepared.c2s,
        s2c: prepared.s2c,
        th: prepared.th,
        budget: 0,
      },
      offset,
      absoluteExpiresAt: info.absoluteExpiresAt,
      idleTimeoutSec: info.idleTimeoutSec,
    };
    return info;
  }

  async #startLogin(req: LoginRequest): Promise<LoginStart> {
    const response = await this.#post("/auth/start", JSON.stringify(req), "application/json");
    const json = await responseJson(response);
    if (response.status !== 200 || typeof json.error === "string") {
      throw new WakeError(typeof json.error === "string" ? json.error : "auth_failed");
    }
    const arrivedAt = this.#now();
    const start = await parseStart(json);
    // The offset is not known yet, so the retry limit is local: arrival time plus the remaining lifetime.
    return {
      ...start,
      deadline: arrivedAt + start.ttl,
    };
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

  /** The first attempt is always sent; later ones only before the local deadline. */
  async #completeWithRetry(body: string, deadline: number, generation: number) {
    let delay = 100;
    for (let attempt = 0;; attempt++) {
      if (generation !== this.#generation || (attempt > 0 && this.#now() >= deadline)) {
        throw new WakeError("auth_failed");
      }
      const received = await this.#tryComplete(body);
      if (received) {
        return received;
      }
      const remaining = deadline - this.#now();
      if (remaining <= 0) {
        throw new WakeError("auth_failed");
      }
      await this.#sleep(Math.min(delay, remaining));
      delay = Math.min(delay * 2, 2000);
    }
  }

  /** Returns undefined when the same body must be resent (§7.7 step 5, §7.8). */
  async #tryComplete(body: string): Promise<{ json: Record<string, unknown>; arrivedAt: number } | undefined> {
    let response: Response;
    let bytes: Uint8Array | undefined;
    let arrivedAt: number;
    try {
      response = await this.#post("/auth/complete", body, "application/json");
      arrivedAt = this.#now();
      if (response.status >= 500 && !isJsonResponse(response)) {
        return undefined;
      }
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch {
      // Only transport failures (including a broken body stream) are retried.
      return undefined;
    }
    const json = parseJsonObject(bytes, "auth_failed");
    if (json.error === "retry") {
      return undefined;
    }
    if (response.status !== 200 || json.error !== undefined) {
      const code = json.error;
      throw new WakeError(typeof code === "string" ? code : "auth_failed");
    }
    return {
      json,
      arrivedAt,
    };
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
    const macBytes = decodeBase64urlField(value.serverFinished, "auth_failed");
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

  /** One rotation at a time for this session, across tabs (§9.7). */
  async rekey(): Promise<RekeyInfo> {
    const state = this.#state;
    if (!state) {
      throw new WakeError("reauth");
    }
    const generation = this.#generation;
    return this.#withRotationLock(encodeBinary(state.sessionId), () => this.#rekeyLocked(state, generation));
  }

  async #rekeyLocked(state: SessionState, generation: number): Promise<RekeyInfo> {
    await this.reload();
    this.#checkRotation(state, generation);
    const previous = state.current;
    const sessionId = encodeBinary(state.sessionId);
    let committed = false;
    try {
      const value = parseJsonObject(await this.#request("wake/kr/start", EMPTY_JSON), "bad_request");
      this.#checkRotation(state, generation);
      const start = await parseRekeyStart(value, previous.epoch);
      const deadline = start.expiresAt - state.offset;
      const prepared = await this.#prepareRotation(state, generation, previous, start, async (th) => krChallenge(th));
      await this.#savePending(state, generation, previous, prepared.keys);
      const plaintext = new Bytes(utf8ToBytes(JSON.stringify({
        exchangeId: encodeBinary(start.exchangeId),
        clientPublicKey: encodeBinary(prepared.clientPublicKey),
        assertion: prepared.assertion,
        clientFinished: encodeBinary(prepared.finished),
      })));
      const completed = await this.#completeRotation(
        state, generation, previous, "wake/kr/complete", plaintext, deadline, prepared.keys,
      );
      const info = completed.recovered ? completed.info : await this.#verifyRotation(state, prepared, completed.plaintext);
      await this.#commitRotation(state, generation, previous, prepared.keys, info);
      committed = true;
      return info;
    } catch (e) {
      // §9.6: a conflict means another tab already moved the epoch. Adopt that record.
      if (e instanceof WakeError && e.code === "conflict" && this.#state === state) {
        await this.reload();
      }
      throw e;
    } finally {
      if (!committed) {
        await this.#discardPending(sessionId, previous.epoch);
      }
    }
  }

  /** Verifies serverFinished for the pending generation; any failure drops the session (security event). */
  async #verifyRotation(state: SessionState, prepared: PreparedRotation, input: Uint8Array | Record<string, unknown>): Promise<RekeyInfo> {
    try {
      const json = input instanceof Uint8Array ? parseJsonObject(input, "auth_failed") : input;
      const info: RekeyInfo = {
        epoch: integer(json.epoch, 0xffffffff, "auth_failed"),
        serverTime: integer(json.serverTime, Number.MAX_SAFE_INTEGER, "auth_failed"),
        absoluteExpiresAt: integer(json.absoluteExpiresAt, Number.MAX_SAFE_INTEGER, "auth_failed"),
        idleTimeoutSec: integer(json.idleTimeoutSec, 0xffffffff, "auth_failed"),
      };
      const mac = decodeBase64urlField(json.serverFinished, "auth_failed");
      if (info.epoch !== prepared.keys.epoch || mac.length !== 32 || !await verifyServerFinished(prepared.fkS, {
        th: prepared.th,
        clientFinished: prepared.finished,
        ...info,
      }, asServerFinishedMac(mac))) {
        throw new WakeError("auth_failed");
      }
      return info;
    } catch (e) {
      if (this.#state === state) {
        await this.#drop(state);
      }
      throw e;
    }
  }

  /**
   * Pending requests keep their own old keys. Ordinary sends now select only this generation.
   * The clock offset stays as #acceptResponse set it from the accepted header (§8.5). A replayed
   * completion's plaintext serverTime is the original commit time (§9.4) and must not replace it.
   * The store switches first, and only while it still names `previous`, so a lost race cannot roll the epoch back.
   */
  async #commitRotation(
    state: SessionState,
    generation: number,
    previous: EpochState,
    keys: EpochState,
    info: RekeyInfo,
  ): Promise<void> {
    this.#checkRotation(state, generation);
    const sessionId = encodeBinary(state.sessionId);
    const wrote = await this.#store.save({
      baseUrl: this.#baseUrl,
      sessionId,
      current: this.#storedEpoch(keys),
      offset: state.offset,
      absoluteExpiresAt: info.absoluteExpiresAt,
      idleTimeoutSec: info.idleTimeoutSec,
    }, { sessionId, epoch: previous.epoch });
    if (!wrote) {
      await this.reload();
      this.#checkRotation(state, generation);
      if (state.current.epoch >= keys.epoch) {
        state.absoluteExpiresAt = info.absoluteExpiresAt;
        state.idleTimeoutSec = info.idleTimeoutSec;
        return;
      }
      throw new WakeError("conflict");
    }
    state.current = keys;
    state.absoluteExpiresAt = info.absoluteExpiresAt;
    state.idleTimeoutSec = info.idleTimeoutSec;
  }

  /** Publishes the uncommitted next epoch before kr/complete or TA+KR approve leaves this tab. */
  async #savePending(state: SessionState, generation: number, previous: EpochState, pending: EpochState): Promise<void> {
    const wrote = await this.#store.save(
      this.#sessionRecord(state, previous, pending),
      { sessionId: encodeBinary(state.sessionId), epoch: previous.epoch },
    );
    if (!wrote) {
      await this.reload();
      this.#checkRotation(state, generation);
      throw new WakeError("conflict");
    }
  }

  /** Drops `pending` only while the stored current epoch is still the one this rotation started from. */
  async #discardPending(sessionId: string, epoch: number): Promise<void> {
    const record = await this.#store.load();
    if (record === undefined || record.sessionId !== sessionId || record.current.epoch !== epoch || record.pending === undefined) {
      return;
    }
    await this.#store.save({
      baseUrl: record.baseUrl,
      sessionId: record.sessionId,
      current: record.current,
      offset: record.offset,
      absoluteExpiresAt: record.absoluteExpiresAt,
      idleTimeoutSec: record.idleTimeoutSec,
    }, { sessionId, epoch });
  }

  async #prepareRotation(
    state: SessionState,
    generation: number,
    previous: EpochState,
    start: RotationStart,
    challenge: (th: RekeyTranscriptHash) => Promise<WebAuthnChallenge>,
  ): Promise<PreparedRotation> {
    // Ephemeral private key and raw derived keys leave scope before any transport retries.
    const pair = await generateEphemeral(false);
    const th: RekeyTranscriptHash = await rekeyTranscriptHash({
      ...start,
      sessionId: state.sessionId,
      prevTh: previous.th,
      clientPublicKey: pair.publicKey,
    });
    this.#checkRotation(state, generation);
    const assertion = await this.#getAssertion({
      ...start.webauthn,
      challenge: (await challenge(th)).toUint8Array(),
    });
    this.#checkRotation(state, generation);
    const raw = await deriveKeys(await ecdh(pair.privateKey, start.serverPublicKey), th);
    const [c2s, s2c, fkC, fkS] = await Promise.all([
      aesKey(raw.kC2s, false),
      aesKey(raw.kS2c, false),
      hmacKey(raw.fkC, false),
      hmacKey(raw.fkS, false),
    ]);
    const keys: EpochState = { epoch: start.epoch, th, c2s, s2c, budget: 0 };
    const finished = await clientFinished(fkC, th);
    return { keys, th, fkS, finished, clientPublicKey: pair.publicKey, assertion };
  }

  #checkRotation(state: SessionState, generation: number): void {
    if (this.#state !== state || generation !== this.#generation) {
      throw new WakeError("auth_failed");
    }
  }

  /**
   * Sends one idempotent plaintext, resending it with a fresh requestId until the deadline.
   * A rotation is sealed with `previous`. When `currentKeys` is set (TA-only approve), each attempt is sealed
   * with the epoch that function returns at send time. With `recoverKeys`, an unknown outcome is probed with
   * the pending generation (§9.6).
   */
  async #completeRotation(
    state: SessionState,
    generation: number,
    previous: EpochState,
    context: string,
    plaintext: Bytes,
    deadline: number,
    recoverKeys: EpochState | undefined,
    currentKeys?: () => EpochState,
  ): Promise<
    { recovered: false; plaintext: Uint8Array } |
    { recovered: true; info: WakeSessionInfo }
  > {
    let delay = 100;
    let sent = false;
    let knownFailure = false;
    try {
      for (;;) {
        this.#checkRotation(state, generation);
        if (this.#now() >= deadline) {
          throw new WakeError("expired");
        }
        // Read at send time. `previous` is the object captured before WebAuthn; a TA-only approval must not keep it.
        const keys = currentKeys === undefined ? previous : currentKeys();
        const pending = await this.#sealRequest(state, context, plaintext, keys);
        this.#checkRotation(state, generation);
        sent = true;
        const received = await this.#sendRequest(state, pending, true);
        this.#checkRotation(state, generation);
        if (received && !(received.response.status >= 500 && !isJsonResponse(received.response))) {
          // Classify only a well-formed outer error as a hint; local parsing/decryption failures have unknown outcomes.
          let outerCode: string | undefined;
          if (received.response.status !== 200 || isJsonResponse(received.response)) {
            const json = parseJsonObject(received.bytes, "bad_request");
            if (typeof json.wakeError === "string" && OUTER_CODES.has(json.wakeError)) {
              outerCode = json.wakeError;
            }
          }
          let result: Uint8Array | undefined;
          try {
            result = await this.#acceptResponse(state, pending, received, recoverKeys !== undefined);
          } catch (e) {
            if (outerCode === "epoch_retired" && recoverKeys !== undefined) {
              return await this.#recoverRotation(state, generation, recoverKeys);
            }
            if (outerCode !== "retry") {
              knownFailure = outerCode !== undefined;
              throw e;
            }
          }
          if (result !== undefined) {
            const json = parseJsonObject(result, "bad_request");
            const error = parseEncryptedError(result, true);
            if ("error" in json && error === undefined) {
              throw new WakeError("bad_request");
            }
            if (error !== undefined && error !== "stale_request") {
              knownFailure = ROTATION_REJECTION_CODES.has(error);
              throw new WakeError(error);
            }
            if (error === undefined) {
              return { recovered: false, plaintext: result };
            }
          }
        }
        const remaining = deadline - this.#now();
        if (remaining <= 0) {
          throw new WakeError("expired");
        }
        await this.#sleep(Math.min(delay, remaining));
        delay = Math.min(delay * 2, 2000);
      }
    } catch (e) {
      // Every unknown failure after sending may follow a committed rotation, including failures between retries.
      if (!knownFailure && sent && recoverKeys !== undefined && this.#state === state && generation === this.#generation) {
        return await this.#recoverRotation(state, generation, recoverKeys);
      }
      throw e;
    }
  }

  async #recoverRotation(state: SessionState, generation: number, keys: EpochState) {
    try {
      this.#checkRotation(state, generation);
      const pending = await this.#sealRequest(state, "wake/session", new Bytes(EMPTY_JSON), keys);
      this.#checkRotation(state, generation);
      const received = await this.#sendRequest(state, pending, false);
      const result = await this.#acceptResponse(state, pending, received!);
      const error = parseEncryptedError(result, true);
      if (error !== undefined) {
        throw new WakeError(error);
      }
      const info = this.#parseSession(result, state, keys.epoch);
      this.#checkRotation(state, generation);
      return { recovered: true as const, info };
    } catch (e) {
      if (this.#state === state) {
        await this.#drop(state);
      }
      throw e;
    }
  }

  /** A stale_request is retried once; other network failures propagate. */
  async request(context: string, plaintext: Uint8Array): Promise<Uint8Array> {
    // §8.8: wake/ and wake- are reserved; wake/session and wake/logout use the private path.
    if (context.startsWith("wake/") || context.startsWith("wake-")) {
      throw new WakeError("bad_request");
    }
    return this.#request(context, plaintext);
  }

  async #request(context: string, plaintext: Uint8Array, ignoreTransportFailure = false, endpoint = "/wake/up"): Promise<Uint8Array> {
    const state = this.#state;
    if (!state) {
      throw new WakeError("reauth");
    }
    const bytes = new Bytes(plaintext);
    for (let attempt = 0; attempt < 2; attempt++) {
      const outcome = await this.#sendOnce(state, context, bytes, endpoint, ignoreTransportFailure, true);
      if (outcome === "stale") {
        if (attempt === 0) {
          continue;
        }
        throw new WakeError("stale_request");
      }
      if (typeof outcome === "number") {
        // The rejected request was not processed. Resend once under the epoch the store now has.
        await this.#adoptRetiredEpoch(state, outcome);
        const resent = await this.#sendOnce(state, context, bytes, endpoint, ignoreTransportFailure, false);
        if (resent === "stale") {
          throw new WakeError("stale_request");
        }
        if (typeof resent === "number") {
          throw new WakeError("reauth");
        }
        return resent;
      }
      return outcome;
    }
    throw new WakeError("stale_request");
  }

  /** `adoptRetired` asks the caller to follow epoch_retired instead of dropping the session here. */
  async #sendOnce(
    state: SessionState,
    context: string,
    bytes: Bytes,
    endpoint: string,
    ignoreTransportFailure: boolean,
    adoptRetired: boolean,
  ): Promise<Uint8Array | "stale" | number> {
    const pending = await this.#sealRequest(state, context, bytes);
    const received = await this.#sendRequest(state, pending, ignoreTransportFailure, endpoint);
    if (!received) {
      return new Uint8Array(EMPTY_JSON);
    }
    try {
      const result = await this.#acceptResponse(state, pending, received, false, adoptRetired);
      const error = parseEncryptedError(result, context.startsWith("wake/"));
      if (error === "stale_request") {
        return "stale";
      }
      if (error !== undefined) {
        throw new WakeError(error);
      }
      return result;
    } catch (e) {
      if (adoptRetired && e instanceof WakeError && e.code === "epoch_retired" && this.#state === state && pending.keys === state.current) {
        return pending.keys.epoch;
      }
      throw e;
    }
  }

  /**
   * An ordinary request sealed with the current epoch was rejected as epoch_retired (§8.6, §9.6).
   * Prefer an epoch another tab already committed; otherwise probe this tab's pending generation.
   */
  async #adoptRetiredEpoch(state: SessionState, sealedEpoch: number): Promise<void> {
    await this.reload();
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    if (state.current.epoch > sealedEpoch) {
      return;
    }
    const sessionId = encodeBinary(state.sessionId);
    const record = await this.#store.load();
    const pendingEpoch = sealedEpoch + 1;
    if (record === undefined || record.baseUrl !== this.#baseUrl || record.sessionId !== sessionId
        || record.pending === undefined || record.pending.epoch !== pendingEpoch) {
      await this.#drop(state);
      throw new WakeError("reauth");
    }
    const name = "wake-kr:" + sessionId;
    let acquired = false;
    try {
      const probe = async () => {
        await this.reload();
        if (this.#state !== state) {
          throw new WakeError("reauth");
        }
        if (state.current.epoch > sealedEpoch) {
          return;
        }
        const fresh = await this.#store.load();
        if (fresh === undefined || fresh.baseUrl !== this.#baseUrl || fresh.sessionId !== sessionId
            || fresh.pending === undefined || fresh.pending.epoch !== pendingEpoch) {
          await this.#drop(state);
          throw new WakeError("reauth");
        }
        const keys = this.#restoreEpoch(fresh.pending);
        const pending = await this.#sealRequest(state, "wake/session", new Bytes(EMPTY_JSON), keys);
        const received = await this.#sendRequest(state, pending, false);
        if (!received) {
          throw new WakeError("reauth");
        }
        const result = await this.#acceptResponse(state, pending, received);
        const error = parseEncryptedError(result, true);
        if (error !== undefined) {
          throw new WakeError(error);
        }
        const info = this.#parseSession(result, state, keys.epoch);
        const wrote = await this.#store.save({
          baseUrl: this.#baseUrl,
          sessionId,
          current: this.#storedEpoch(keys),
          offset: state.offset,
          absoluteExpiresAt: info.absoluteExpiresAt,
          idleTimeoutSec: info.idleTimeoutSec,
        }, { sessionId, epoch: sealedEpoch });
        if (!wrote) {
          await this.reload();
          if (this.#state === state && state.current.epoch > sealedEpoch) {
            return;
          }
          await this.#drop(state);
          throw new WakeError("reauth");
        }
        state.current = keys;
        state.absoluteExpiresAt = info.absoluteExpiresAt;
        state.idleTimeoutSec = info.idleTimeoutSec;
      };
      if (this.#rotating.has(name)) {
        await probe();
        return;
      }
      await this.#store.lock(name, async () => {
        acquired = true;
        await probe();
      });
    } catch (e) {
      // Another tab is finishing this rotation. Keep the session and surface the retirement.
      if (!acquired && e instanceof WakeError && e.code === "conflict") {
        throw new WakeError("epoch_retired");
      }
      if (this.#state === state) {
        await this.#drop(state);
      }
      if (e instanceof WakeError && e.code === "reauth") {
        throw e;
      }
      throw new WakeError("reauth");
    }
  }

  /**
   * §11 WAKE-ET: sends one HTTP-like request through POST /wake/transport and returns the tunnelled response.
   * The URI-reference is sent unchanged. Validation errors are thrown before anything is sent.
   * A string body is UTF-8 encoded. Application error responses are returned as ordinary Responses.
   */
  async wakeFetch(url: string, init: WakeFetchInit = {}): Promise<Response> {
    const headers: EtHeader[] = init.headers === undefined ? [] : Array.isArray(init.headers)
      ? (init.headers as readonly EtHeader[]).map(([n, v]) => [n, v] as const)
      : Object.entries(init.headers as Record<string, string>);
    const body = typeof init.body === "string" ? utf8ToBytes(init.body) : init.body ?? new Uint8Array(0);
    const encoded = encodeEtRequest({
      method: init.method ?? "GET",
      url,
      headers,
      body: new Bytes(body),
    }, { bodyLimit: this.#etBodyLimit });
    const result = await this.#request("wake-et", encoded.toUint8Array(), false, "/wake/transport");
    const et = decodeEtResponse(result, { bodyLimit: this.#etBodyLimit });
    const out = new Headers();
    for (const [name, value] of et.headers) {
      out.append(name, value);
    }
    return new Response(et.body.length === 0 ? null : new Uint8Array(et.body.toUint8Array()), {
      status: et.status,
      headers: out,
    });
  }

  async #sealRequest(state: SessionState, context: string, plaintext: Bytes, keys = state.current): Promise<PendingRequest> {
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    if (this.#now() + state.offset >= state.absoluteExpiresAt) {
      await this.#drop(state);
      throw new WakeError("reauth");
    }
    // One shared reservation per epoch, then take a unit before Web Crypto yields.
    while (keys.budget === 0) {
      if (keys.reserving === undefined) {
        const sessionId = encodeBinary(state.sessionId);
        keys.reserving = this.#store.reserveEncryptions(sessionId, keys.epoch, this.#blockSize, this.#maxEncryptions)
          .then((granted) => {
            keys.budget += granted;
            return granted;
          })
          .finally(() => {
            keys.reserving = undefined;
          });
      }
      const reserving = keys.reserving;
      const granted = await reserving;
      if (this.#state !== state) {
        throw new WakeError("reauth");
      }
      if (granted === 0) {
        await this.#drop(state);
        throw new WakeError("reauth");
      }
    }
    keys.budget--;
    const requestId = newRequestId();
    const wire = await seal(keys.c2s, {
      dir: DIR_C2S,
      sessionId: state.sessionId,
      epoch: keys.epoch,
      requestId,
      context,
      issuedAt: Math.max(0, Math.floor(this.#now() + state.offset)),
    }, plaintext, { maxPlaintext: this.#maxPlaintext });
    return {
      requestId,
      context,
      wire,
      keys,
    };
  }

  async #sendRequest(state: SessionState, pending: PendingRequest, ignoreTransportFailure: boolean, endpoint = "/wake/up") {
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    let response: Response;
    try {
      response = await this.#post(endpoint, new Uint8Array(pending.wire.toUint8Array()), "application/wake");
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

  /**
   * `keepOnRetired` is set only for a rotation completion, where an outer epoch_retired may mean the commit happened (§9.6).
   * `adoptRetired` is set for an ordinary request: epoch_retired on the current epoch is handed back so the caller can
   * reload or probe a pending generation instead of dropping immediately. Every other current-epoch retirement still drops.
   */
  async #acceptResponse(
    state: SessionState,
    pending: PendingRequest,
    received: ReceivedResponse,
    keepOnRetired = false,
    adoptRetired = false,
  ): Promise<Uint8Array> {
    if (received.response.status !== 200 || isJsonResponse(received.response)) {
      const json = parseJsonObject(received.bytes, "bad_request");
      const code = json.wakeError;
      if (typeof code !== "string" || !OUTER_CODES.has(code)) {
        throw new WakeError("bad_request");
      }
      if (code === "reauth" && this.#state === state) {
        await this.#drop(state);
      }
      if (code === "epoch_retired" && !keepOnRetired && this.#state === state && pending.keys === state.current) {
        if (adoptRetired) {
          throw new WakeError("epoch_retired");
        }
        await this.#drop(state);
        throw new WakeError("reauth");
      }
      throw new WakeError(code);
    }
    const parsed = parseWire(received.bytes, { maxPlaintext: this.#maxPlaintext });
    const h = parsed.header;
    if (h.dir !== DIR_S2C || !h.sessionId.equals(state.sessionId) || h.epoch !== pending.keys.epoch ||
        !h.requestId.equals(pending.requestId) || h.context !== pending.context) {
      throw new WakeError("bad_request");
    }
    const result = (await openParsed(pending.keys.s2c, parsed, DIR_S2C)).toUint8Array();
    if (this.#state !== state) {
      throw new WakeError("reauth");
    }
    state.offset = h.issuedAt - received.arrivedAt;
    return result;
  }

  async session(): Promise<WakeSessionInfo> {
    const state = this.#state;
    const result = await this.#request("wake/session", EMPTY_JSON);
    if (!state || this.#state !== state) {
      throw new WakeError("reauth");
    }
    return this.#parseSession(result, state, state.current.epoch);
  }

  #parseSession(result: Uint8Array, state: SessionState, expectedEpoch: number): WakeSessionInfo {
    const value = parseJsonObject(result, "bad_request");
    const id = asSessionId(decodeBase64urlField(value.sessionId, "bad_request"));
    const epoch = integer(value.epoch, 0xffffffff);
    if (!id.equals(state.sessionId) || epoch !== expectedEpoch || typeof value.rekeyRecommended !== "boolean") {
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

  /** §10.6 wake/ta/list. Every entry is checked like wake/ta/get; one inconsistent entry rejects the page. */
  async listOperations(query: { status?: OperationStatus; limit?: number; cursor?: string } = {}): Promise<OperationList> {
    if (query.status !== undefined && !(OPERATION_STATUSES as readonly string[]).includes(query.status)) {
      throw new WakeError("bad_request");
    }
    if (query.limit !== undefined && (!Number.isSafeInteger(query.limit) || query.limit < 1 || query.limit > 20)) {
      throw new WakeError("bad_request");
    }
    if (query.cursor !== undefined && (typeof query.cursor !== "string" || query.cursor.length === 0)) {
      throw new WakeError("bad_request");
    }
    const body = {
      ...(query.status === undefined ? {} : { status: query.status }),
      ...(query.limit === undefined ? {} : { limit: query.limit }),
      ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
    };
    return parseOperationList(await this.#taCall("wake/ta/list", body));
  }

  /**
   * §10.11 steps 1-4: the content is trusted only if SHA-256 of the locally assembled hashInput equals the
   * REQUESTED operationId (an `operation_mismatch` error otherwise).
   */
  async getOperation(operationIdHex: string): Promise<VerifiedOperation> {
    parseOperationIdHex(operationIdHex);
    return verifiedOperation(await this.#taCall("wake/ta/get", { operationId: operationIdHex }), operationIdHex);
  }

  /** §10.6 wake/ta/reject. No WebAuthn is involved (§10.9). */
  async reject(operationIdHex: string): Promise<{ result: TaRejectResult; status: string }> {
    parseOperationIdHex(operationIdHex);
    const value = await this.#taCall("wake/ta/reject", { operationId: operationIdHex });
    if (typeof value.status !== "string") {
      throw new WakeError("bad_request");
    }
    return { result: parseResult(value.result, ["rejected", "already_decided", "expired"] as const), status: value.status };
  }

  /**
   * §10.11 steps 6-8. The challenge is computed over the CALLER's operationId, never one named by the server.
   * With `rekey`, the same signature also commits a key rotation (§10.8); the new epoch is adopted only when the
   * server reports `committed` and serverFinished verifies. That TA+KR request stays sealed with the epoch
   * captured before WebAuthn (§10.7). A TA-only approval is not epoch-bound, so each send uses the epoch current
   * at send time: a rekey that commits while the prompt is open must not leave the approval on a retired generation.
   */
  async approve(operationIdHex: string, options: ApproveOptions = {}): Promise<ApproveInfo> {
    const id = parseOperationIdHex(operationIdHex);
    const rekey = options.rekey === true;
    const state = this.#state;
    if (!state) {
      throw new WakeError("reauth");
    }
    const generation = this.#generation;
    const run = () => this.#approveBody(state, generation, id, operationIdHex, rekey);
    if (!rekey) {
      return run();
    }
    return this.#withRotationLock(encodeBinary(state.sessionId), run);
  }

  async #approveBody(
    state: SessionState,
    generation: number,
    id: ReturnType<typeof parseOperationIdHex>,
    operationIdHex: string,
    rekey: boolean,
  ): Promise<ApproveInfo> {
    if (rekey) {
      await this.reload();
      this.#checkRotation(state, generation);
    }
    const previous = state.current;
    const sessionId = encodeBinary(state.sessionId);
    let committed = false;
    try {
      const c = await this.#taCall("wake/ta/challenge", { operationId: operationIdHex, rekey });
      this.#checkRotation(state, generation);
      const approvalId = decodeBase64urlField(c.approvalId, "bad_request", 16);
      const approvalNonce = decodeBase64urlField(c.approvalNonce, "bad_request", 32);
      const expiresAt = integer(c.expiresAt);
      const webauthn = parseWebAuthn(c.webauthn);
      if ((c.kr === null) === rekey) {
        throw new WakeError("bad_request");
      }
      const ta = await taBinding({
        approvalId: asApprovalId(approvalId),
        operationId: id,
        approvalNonce: asApprovalNonce(approvalNonce),
        sessionId: state.sessionId,
      });
      const deadline = expiresAt - state.offset;
      let prepared: PreparedRotation | undefined;
      let exchangeId: Bytes | undefined;
      let assertion: AuthenticationResponseJSON;
      if (rekey) {
        const start = { ...await parseRekeyKey(object(c.kr), previous.epoch), webauthn };
        exchangeId = start.exchangeId;
        prepared = await this.#prepareRotation(state, generation, previous, start, (th) => taKrChallenge(th, ta));
        await this.#savePending(state, generation, previous, prepared.keys);
        assertion = prepared.assertion;
      } else {
        assertion = await this.#getAssertion({ ...webauthn, challenge: (await taChallenge(ta)).toUint8Array() });
        this.#checkRotation(state, generation);
      }
      const plaintext = new Bytes(utf8ToBytes(JSON.stringify({
        approvalId: encodeBinary(new Bytes(approvalId)),
        operationId: operationIdHex,
        assertion,
        kr: prepared === undefined ? null : {
          exchangeId: encodeBinary(exchangeId!),
          clientPublicKey: encodeBinary(prepared.clientPublicKey),
          clientFinished: encodeBinary(prepared.finished),
        },
      })));
      const completed = await this.#completeRotation(
        state, generation, previous, "wake/ta/approve", plaintext, deadline, prepared?.keys,
        prepared === undefined ? () => state.current : undefined,
      );
      if (completed.recovered) {
        // The old epoch is retired, so the commit happened: adopt the epoch confirmed by wake/session under it.
        await this.#commitRotation(state, generation, previous, prepared!.keys, completed.info);
        committed = true;
        // Resend the same plaintext under the new epoch: the server replays the consumed attempt's stored result.
        const replay = await this.#request("wake/ta/approve", plaintext.toUint8Array());
        const { info, kr } = this.#parseApprove(replay, operationIdHex);
        if (kr === null || kr.result !== "committed") {
          await this.#drop(state);
          throw new WakeError("bad_request");
        }
        const { epoch, serverTime, absoluteExpiresAt, idleTimeoutSec } = completed.info;
        info.kr = { result: "committed", epoch, serverTime, absoluteExpiresAt, idleTimeoutSec };
        return info;
      }
      try {
        const info = await this.#finishApprove(state, generation, previous, operationIdHex, completed.plaintext, prepared);
        if (prepared !== undefined && info.kr?.result === "committed") {
          committed = true;
        }
        return info;
      } catch (e) {
        // After a rekey request the server may have committed: an unreadable answer leaves the epoch unknown.
        if (prepared !== undefined && this.#state === state) {
          await this.#drop(state);
        }
        throw e;
      }
    } catch (e) {
      if (e instanceof WakeError && e.code === "conflict" && this.#state === state) {
        await this.reload();
      }
      throw e;
    } finally {
      if (rekey && !committed) {
        await this.#discardPending(sessionId, previous.epoch);
      }
    }
  }

  async #finishApprove(
    state: SessionState,
    generation: number,
    previous: EpochState,
    operationIdHex: string,
    plaintext: Uint8Array,
    prepared: PreparedRotation | undefined,
  ): Promise<ApproveInfo> {
    const { info, kr: krPart } = this.#parseApprove(plaintext, operationIdHex);
    if (prepared === undefined) {
      if (krPart !== null) {
        throw new WakeError("bad_request");
      }
      return info;
    }
    if (krPart === null) {
      throw new WakeError("bad_request");
    }
    const kr = krPart;
    const result = parseResult(kr.result, ["committed", "conflict", "expired"] as const);
    if (result !== "committed") {
      // The pending generation is discarded by the caller. A conflict also adopts whatever epoch won (§9.6).
      info.kr = { result };
      if (result === "conflict" && this.#state === state) {
        await this.reload();
      }
      return info;
    }
    const rekeyInfo = await this.#verifyRotation(state, prepared, kr);
    await this.#commitRotation(state, generation, previous, prepared.keys, rekeyInfo);
    info.kr = { result, ...rekeyInfo };
    return info;
  }

  /** Parses a wake/ta/approve result into its TA part and the raw kr member (null when absent). */
  #parseApprove(plaintext: Uint8Array, operationIdHex: string): { info: ApproveInfo; kr: Record<string, unknown> | null } {
    const value = parseJsonObject(plaintext, "bad_request");
    if (value.operationId !== operationIdHex) {
      throw new WakeError("bad_request");
    }
    const taPart = object(value.ta);
    if (typeof taPart.status !== "string") {
      throw new WakeError("bad_request");
    }
    const info: ApproveInfo = {
      operationId: operationIdHex,
      ta: { result: parseResult(taPart.result, ["approved", "already_decided", "expired"] as const), status: taPart.status },
    };
    return { info, kr: value.kr === null ? null : object(value.kr) };
  }

  async #taCall(context: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return parseJsonObject(await this.#request(context, utf8ToBytes(JSON.stringify(body))), "bad_request");
  }

  /** Deletes local keys even on failure. Transport failures resolve; protocol errors propagate. */
  async logout(): Promise<void> {
    // A tab that has not adopted the stored session yet can still revoke it.
    if (this.#state === undefined) {
      await this.reload();
    }
    const state = this.#state;
    ++this.#generation;
    try {
      if (!state) {
        return;
      }
      parseJsonObject(await this.#request("wake/logout", EMPTY_JSON, true), "bad_request");
    } finally {
      if (state) {
        await this.#drop(state);
      }
    }
  }
}

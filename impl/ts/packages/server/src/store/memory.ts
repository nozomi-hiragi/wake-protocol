// Spec §7.4–§7.6, §8.1, §8.7–§8.10, §9.4: process-memory atomic stores.
import { base64urlnopad } from "@scure/base";
import { sessionExpired } from "../sm/lifetime.ts";
import type {
  CredentialStore,
  ExchangeRecord,
  LoginCommit,
  RekeyStart,
  RekeyCommit,
  RekeyStartResult,
  RekeyCommitResult,
  SessionRecord,
  SignCountUpdate,
  WakeCredential,
  WakeStore,
} from "./types.ts";

const id = (bytes: Uint8Array) => base64urlnopad.encode(bytes);

function cloneCredential(c: WakeCredential): WakeCredential {
  return {
    ...c,
    credentialId: c.credentialId.slice(),
    userHandle: c.userHandle.slice(),
    publicKey: c.publicKey.slice(),
    ...(c.transports ? { transports: [...c.transports] } : {}),
  };
}

function cloneUpdate(u: SignCountUpdate): SignCountUpdate {
  return { ...u, credentialId: u.credentialId.slice() };
}

function cloneExchange(e: ExchangeRecord): ExchangeRecord {
  return {
    ...e,
    ...(e.signCountUpdate ? { signCountUpdate: cloneUpdate(e.signCountUpdate) } : {}),
    ...(e.reauthenticatedCredentialId ? { reauthenticatedCredentialId: e.reauthenticatedCredentialId.slice() } : {}),
  };
}

function cloneSession(s: SessionRecord): SessionRecord {
  return {
    ...s,
    loginCredentialId: s.loginCredentialId.slice(),
    lastAuthCredentialId: s.lastAuthCredentialId.slice(),
    ...(s.currentKeys ? { currentKeys: { ...s.currentKeys } } : {}),
    ...(s.prevKeys ? { prevKeys: { ...s.prevKeys } } : {}),
  };
}

export class MemoryCredentialStore implements CredentialStore {
  #credentials = new Map<string, WakeCredential>();
  #users = new Map<string, string>();

  constructor(credentials: WakeCredential[] = []) {
    for (const c of credentials) {
      this.setCredential(c);
    }
  }

  /** Throws a plain Error when a credentialId or username would be re-bound to a different user. */
  setCredential(credential: WakeCredential, username?: string): void {
    const key = id(credential.credentialId);
    const existing = this.#credentials.get(key);
    if (existing && existing.userId !== credential.userId) {
      throw new Error("credentialId is already bound to a different user");
    }
    if (username !== undefined) {
      this.#checkUsername(username, credential.userId);
    }
    this.#credentials.set(key, cloneCredential(credential));
    if (username !== undefined) {
      this.#users.set(username, credential.userId);
    }
  }

  /** Throws a plain Error when the username is already bound to a different user. */
  setUser(username: string, userId: string): void {
    this.#checkUsername(username, userId);
    this.#users.set(username, userId);
  }

  #checkUsername(username: string, userId: string): void {
    const bound = this.#users.get(username);
    if (bound !== undefined && bound !== userId) {
      throw new Error("username is already bound to a different user");
    }
  }

  async getCredential(credentialId: Uint8Array): Promise<WakeCredential | null> {
    const c = this.#credentials.get(id(credentialId));
    return c ? cloneCredential(c) : null;
  }

  async findUserCredentials(userId: string): Promise<WakeCredential[]> {
    return [...this.#credentials.values()].filter(c => c.userId === userId).map(cloneCredential);
  }

  async findUserByUsername(username: string): Promise<{ userId: string; credentials: WakeCredential[] } | null> {
    const userId = this.#users.get(username);
    if (userId === undefined) {
      return null;
    }
    return {
      userId,
      credentials: [...this.#credentials.values()].filter(c => c.userId === userId).map(cloneCredential),
    };
  }

  async compareAndSetSignCount(credentialId: Uint8Array, expected: number, next: number): Promise<boolean> {
    const c = this.#credentials.get(id(credentialId));
    if (!c || c.signCount !== expected) {
      return false;
    }
    c.signCount = next;
    return true;
  }

  async updateSignCount(credentialId: Uint8Array, signCount: number): Promise<void> {
    const c = this.#credentials.get(id(credentialId));
    if (!c) {
      throw new Error("credential disappeared during authentication");
    }
    c.signCount = Math.max(c.signCount, signCount);
  }
}

export interface MemoryWakeStoreOptions {
  /** How long a session stays after it became REVOKED or EXPIRED before sweep deletes it. Default 10 minutes. */
  endedSessionRetentionMs?: number;
  /** Minimum time between the opportunistic sweeps run by createExchange. Default 1 minute. */
  sweepIntervalMs?: number;
  /** Clock for opportunistic sweeps and for revocations that carry no time. Default Date.now. */
  now?: () => number;
}

// Test-only access to the session map (DESIGN §2.7). Not exported from the package entry point.
const sessionMaps = new WeakMap<MemoryWakeStore, Map<string, SessionRecord>>();

/** Inserts or replaces a session record, bypassing the login flow. Tests only; re-exported by ./testing. */
export function insertSession(store: MemoryWakeStore, record: SessionRecord): void {
  const sessions = sessionMaps.get(store);
  if (!sessions) {
    throw new TypeError("not a MemoryWakeStore");
  }
  sessions.set(id(record.sessionId.toUint8Array()), cloneSession(record));
}

/**
 * Non-extractable CryptoKeys stay in process memory; persistent implementations must use §8.10 wrapping AAD.
 *
 * Without a timer, abandoned data is dropped opportunistically (§7.4): createExchange runs sweep at most once per
 * sweepIntervalMs, which also deletes the private keys of expired exchanges.
 */
export class MemoryWakeStore implements WakeStore {
  #exchanges = new Map<string, ExchangeRecord>();
  // PENDING exchange keys per session key, so revocation does not scan every exchange.
  #pending = new Map<string, Set<string>>();
  #sessions = new Map<string, SessionRecord>();
  #retention: number;
  #endedRetention: number;
  #sweepInterval: number;
  #clock: () => number;
  #lastSweepAt = Number.NEGATIVE_INFINITY;

  constructor(completedRetentionMs = 600_000, options: MemoryWakeStoreOptions = {}) {
    const endedSessionRetentionMs = options.endedSessionRetentionMs ?? 600_000;
    const sweepIntervalMs = options.sweepIntervalMs ?? 60_000;
    for (const value of [completedRetentionMs, endedSessionRetentionMs, sweepIntervalMs]) {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new RangeError("retention and sweep options must be non-negative safe integers");
      }
    }
    this.#retention = completedRetentionMs;
    this.#endedRetention = endedSessionRetentionMs;
    this.#sweepInterval = sweepIntervalMs;
    this.#clock = options.now ?? Date.now;
    sessionMaps.set(this, this.#sessions);
  }

  async createExchange(record: ExchangeRecord): Promise<void> {
    const key = id(record.exchangeId.toUint8Array());
    if (this.#exchanges.has(key)) {
      throw new Error("duplicate exchangeId");
    }
    this.#opportunisticSweep(this.#clock());
    this.#exchanges.set(key, cloneExchange(record));
    if (record.state === "PENDING") {
      const sessionKey = id(record.sessionId.toUint8Array());
      const keys = this.#pending.get(sessionKey) ?? new Set<string>();
      keys.add(key);
      this.#pending.set(sessionKey, keys);
    }
  }

  /** Leaves PENDING: updates the index and drops the private key. */
  #settle(key: string, ex: ExchangeRecord, state: ExchangeRecord["state"]): void {
    ex.state = state;
    delete ex.serverPrivateKey;
    const sessionKey = id(ex.sessionId.toUint8Array());
    const keys = this.#pending.get(sessionKey);
    keys?.delete(key);
    if (keys?.size === 0) {
      this.#pending.delete(sessionKey);
    }
  }

  #readExchange(key: string, now: number): ExchangeRecord | null {
    const ex = this.#exchanges.get(key);
    if (!ex) {
      return null;
    }
    if (ex.state === "PENDING" && now >= ex.expiresAt) {
      this.#settle(key, ex, "EXPIRED");
    }
    if (ex.state !== "PENDING" && now >= ex.expiresAt + this.#retention) {
      this.#exchanges.delete(key);
      return null;
    }
    return ex;
  }

  async getExchange(exchangeId: Uint8Array, now: number): Promise<ExchangeRecord | null> {
    const ex = this.#readExchange(id(exchangeId), now);
    return ex ? cloneExchange(ex) : null;
  }

  async commitLogin(c: LoginCommit): Promise<boolean> {
    const key = id(c.exchangeId);
    const ex = this.#readExchange(key, c.now);
    if (!ex || ex.state !== "PENDING" || ex.expiresAt <= c.now) {
      return false;
    }
    if (this.#sessions.has(id(c.session.sessionId.toUint8Array()))) {
      return false;
    }
    this.#settle(key, ex, "COMPLETED");
    ex.th = c.th;
    ex.clientFinished = c.clientFinished;
    ex.response = c.response;
    if (c.signCountUpdate) {
      ex.signCountUpdate = cloneUpdate(c.signCountUpdate);
    }
    this.#sessions.set(id(c.session.sessionId.toUint8Array()), cloneSession(c.session));
    return true;
  }

  #opportunisticSweep(now: number): void {
    if (now - this.#lastSweepAt >= this.#sweepInterval) {
      this.#lastSweepAt = now;
      this.#sweepAt(now);
    }
  }

  #activeSession(key: string, now: number): SessionRecord | null {
    const s = this.#sessions.get(key);
    if (!s || s.status !== "ACTIVE") {
      return null;
    }
    if (sessionExpired(s, now)) {
      this.#end(s, "EXPIRED", now);
      this.#deleteKeys(s);
      return null;
    }
    return s;
  }

  async createRekey(c: RekeyStart): Promise<RekeyStartResult> {
    this.#opportunisticSweep(c.now);
    const s = this.#activeSession(id(c.record.sessionId.toUint8Array()), c.now);
    if (!s || !s.currentKeys) {
      return "reauth";
    }
    if (s.currentEpoch !== c.expectedEpoch) {
      return "conflict";
    }
    if (
      c.record.kind !== "rekey" || c.record.state !== "PENDING" ||
      c.record.targetEpoch !== s.currentEpoch + 1 || !c.record.prevTh?.equals(s.currentKeys.th)
    ) {
      throw new TypeError("invalid rekey exchange");
    }
    const key = id(c.record.exchangeId.toUint8Array());
    if (this.#exchanges.has(key)) {
      throw new Error("duplicate exchangeId");
    }
    const sessionKey = id(c.record.sessionId.toUint8Array());
    const pending = [...this.#pending.get(sessionKey) ?? []]
      .map(key => ({ key, ex: this.#readExchange(key, c.now) }))
      .filter((entry): entry is { key: string; ex: ExchangeRecord } =>
        entry.ex?.state === "PENDING" && entry.ex.kind === "rekey")
      .sort((a, b) => (a.ex.createdAt ?? 0) - (b.ex.createdAt ?? 0));
    while (pending.length >= c.maxPendingRekeys) {
      const oldest = pending.shift()!;
      this.#settle(oldest.key, oldest.ex, "SUPERSEDED");
    }
    this.#exchanges.set(key, cloneExchange(c.record));
    const keys = this.#pending.get(sessionKey) ?? new Set<string>();
    keys.add(key);
    this.#pending.set(sessionKey, keys);
    return "created";
  }

  async supersedeExchange(exchangeId: Uint8Array): Promise<void> {
    const key = id(exchangeId);
    const ex = this.#exchanges.get(key);
    if (ex?.state === "PENDING") {
      this.#settle(key, ex, "SUPERSEDED");
    }
  }

  async commitRekey(c: RekeyCommit): Promise<RekeyCommitResult> {
    const key = id(c.exchangeId);
    const ex = this.#readExchange(key, c.now);
    const s = this.#activeSession(id(c.sessionId), c.now);
    if (!s || !s.currentKeys) {
      return "reauth";
    }
    if (!ex || ex.kind !== "rekey" || !ex.sessionId.equals(s.sessionId) || ex.state !== "PENDING") {
      return "expired";
    }
    if (s.currentEpoch !== c.expectedEpoch || ex.targetEpoch !== s.currentEpoch + 1) {
      this.#settle(key, ex, "SUPERSEDED");
      return "conflict";
    }
    if (!ex.prevTh?.equals(s.currentKeys.th)) {
      this.#settle(key, ex, "SUPERSEDED");
      return "conflict";
    }
    this.#settle(key, ex, "COMPLETED");
    ex.th = c.th;
    ex.clientFinished = c.clientFinished;
    ex.response = c.response;
    ex.reauthenticatedCredentialId = c.credentialId.slice();
    if (c.signCountUpdate) {
      ex.signCountUpdate = cloneUpdate(c.signCountUpdate);
    }
    s.prevKeys = s.currentKeys;
    s.prevValidUntil = c.now + c.epochGraceMs;
    s.currentKeys = { ...c.currentKeys };
    s.currentEpoch++;
    s.authTime = c.authTime;
    s.absoluteExpiresAt = Math.min(s.hardCapAt, c.absoluteExpiresAt);
    s.lastAuthCredentialId = c.credentialId.slice();
    return "committed";
  }

  async clearSignCountUpdate(exchangeId: Uint8Array): Promise<boolean> {
    const ex = this.#exchanges.get(id(exchangeId));
    if (!ex?.signCountUpdate) {
      return false;
    }
    delete ex.signCountUpdate;
    return true;
  }

  async getSession(sessionId: Uint8Array): Promise<SessionRecord | null> {
    const s = this.#sessions.get(id(sessionId));
    return s ? cloneSession(s) : null;
  }

  async touchSession(sessionId: Uint8Array, now: number): Promise<void> {
    const s = this.#sessions.get(id(sessionId));
    if (
      s?.status === "ACTIVE" &&
      !sessionExpired(s, now) &&
      now - s.lastActivityAt >= Math.min(s.idleTimeoutSec * 1000 / 8, 900_000)
    ) {
      s.lastActivityAt = now;
    }
  }

  async reserveEncryptions(sessionId: Uint8Array, epoch: number, now: number, limit: number): Promise<boolean> {
    const s = this.#sessions.get(id(sessionId));
    if (!s || s.status !== "ACTIVE" || sessionExpired(s, now)) {
      return false;
    }
    const keys = epoch === s.currentEpoch ? s.currentKeys :
      epoch === s.currentEpoch - 1 && now <= (s.prevValidUntil ?? -1) ? s.prevKeys : undefined;
    if (!keys || keys.c2sCount >= limit || keys.s2cCount >= limit) {
      return false;
    }
    keys.c2sCount++;
    keys.s2cCount++;
    return true;
  }

  #invalidateExchanges(s: SessionRecord): void {
    const keys = this.#pending.get(id(s.sessionId.toUint8Array()));
    for (const key of [...keys ?? []]) {
      const ex = this.#exchanges.get(key);
      if (ex) {
        this.#settle(key, ex, "SUPERSEDED");
      }
    }
  }

  /** Marks the session terminal, remembering when it ended for the retention sweep. */
  #end(s: SessionRecord, status: "REVOKED" | "EXPIRED", now: number): void {
    s.status = status;
    s.endedAt ??= now;
    this.#invalidateExchanges(s);
  }

  #deleteKeys(s: SessionRecord): void {
    delete s.currentKeys;
    delete s.prevKeys;
    delete s.prevValidUntil;
  }

  #revoke(s: SessionRecord): void {
    this.#end(s, "REVOKED", this.#clock());
    this.#deleteKeys(s);
  }

  async revokeForLogout(sessionId: Uint8Array, now: number): Promise<SessionRecord | null> {
    const s = this.#sessions.get(id(sessionId));
    if (!s || s.status !== "ACTIVE" || sessionExpired(s, now)) {
      return null;
    }
    this.#end(s, "REVOKED", now);
    return cloneSession(s);
  }

  async deleteSessionKeys(sessionId: Uint8Array): Promise<void> {
    const s = this.#sessions.get(id(sessionId));
    if (s) {
      this.#deleteKeys(s);
    }
  }

  async expireSession(sessionId: Uint8Array, now: number): Promise<void> {
    const s = this.#sessions.get(id(sessionId));
    if (s?.status === "ACTIVE" && sessionExpired(s, now)) {
      this.#end(s, "EXPIRED", now);
      this.#deleteKeys(s);
    }
  }

  async revokeSession(sessionId: Uint8Array): Promise<void> {
    const s = this.#sessions.get(id(sessionId));
    if (s) {
      this.#revoke(s);
    }
  }

  async revokeSessionsByUser(userId: string): Promise<void> {
    for (const s of this.#sessions.values()) {
      if (s.userId === userId) {
        this.#revoke(s);
      }
    }
  }

  async revokeSessionsByCredential(credentialId: Uint8Array): Promise<void> {
    const key = id(credentialId);
    for (const s of this.#sessions.values()) {
      if (id(s.loginCredentialId) === key || id(s.lastAuthCredentialId) === key) {
        this.#revoke(s);
      }
    }
  }

  async sweep(now: number): Promise<void> {
    this.#sweepAt(now);
  }

  #sweepAt(now: number): void {
    for (const key of [...this.#exchanges.keys()]) {
      this.#readExchange(key, now);
    }
    for (const [key, s] of [...this.#sessions]) {
      if (s.status === "ACTIVE" && sessionExpired(s, now)) {
        this.#end(s, "EXPIRED", now);
        this.#deleteKeys(s);
      }
      if (s.prevKeys && now > (s.prevValidUntil ?? -1)) {
        delete s.prevKeys;
        delete s.prevValidUntil;
      }
      if (s.status !== "ACTIVE" && s.endedAt !== undefined && now - s.endedAt >= this.#endedRetention) {
        this.#sessions.delete(key);
      }
    }
  }
}

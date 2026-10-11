// Spec §7.4–§7.6, §8.1, §8.7–§8.10: process-memory atomic stores.
import { base64urlnopad } from "@scure/base";
import { sessionExpired } from "../sm/lifetime.ts";
import type {
  CredentialStore,
  ExchangeRecord,
  LoginCommit,
  SessionRecord,
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

  setCredential(credential: WakeCredential, username?: string): void {
    this.#credentials.set(id(credential.credentialId), cloneCredential(credential));
    if (username !== undefined) {
      this.setUser(username, credential.userId);
    }
  }

  setUser(username: string, userId: string): void {
    this.#users.set(username, userId);
  }

  async getCredential(credentialId: Uint8Array): Promise<WakeCredential | null> {
    const c = this.#credentials.get(id(credentialId));
    return c ? cloneCredential(c) : null;
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

  async updateSignCount(credentialId: Uint8Array, signCount: number): Promise<void> {
    const c = this.#credentials.get(id(credentialId));
    if (!c) {
      throw new Error("credential disappeared during login");
    }
    c.signCount = Math.max(c.signCount, signCount);
  }
}

/** Non-extractable CryptoKeys stay in process memory; persistent implementations must use §8.10 wrapping AAD. */
export class MemoryWakeStore implements WakeStore {
  #exchanges = new Map<string, ExchangeRecord>();
  #sessions = new Map<string, SessionRecord>();
  #retention: number;

  constructor(completedRetentionMs = 600_000) {
    if (!Number.isSafeInteger(completedRetentionMs) || completedRetentionMs < 0) {
      throw new RangeError("completedRetentionMs");
    }
    this.#retention = completedRetentionMs;
  }

  async createExchange(record: ExchangeRecord): Promise<void> {
    const key = id(record.exchangeId.toUint8Array());
    if (this.#exchanges.has(key)) {
      throw new Error("duplicate exchangeId");
    }
    this.#exchanges.set(key, { ...record });
  }

  async createSession(record: SessionRecord): Promise<void> {
    this.#sessions.set(id(record.sessionId.toUint8Array()), cloneSession(record));
  }

  #readExchange(key: string, now: number): ExchangeRecord | null {
    const ex = this.#exchanges.get(key);
    if (!ex) {
      return null;
    }
    if (ex.state === "PENDING" && now >= ex.expiresAt) {
      ex.state = "EXPIRED";
      delete ex.serverPrivateKey;
    }
    if (ex.state !== "PENDING" && now >= ex.expiresAt + this.#retention) {
      this.#exchanges.delete(key);
      return null;
    }
    return ex;
  }

  async getExchange(exchangeId: Uint8Array, now: number): Promise<ExchangeRecord | null> {
    const ex = this.#readExchange(id(exchangeId), now);
    return ex ? { ...ex } : null;
  }

  async commitLogin(c: LoginCommit): Promise<boolean> {
    const ex = this.#readExchange(id(c.exchangeId), c.now);
    if (!ex || ex.state !== "PENDING" || ex.expiresAt <= c.now) {
      return false;
    }
    if (this.#sessions.has(id(c.session.sessionId.toUint8Array()))) {
      return false;
    }
    ex.state = "COMPLETED";
    ex.th = c.th;
    ex.clientFinished = c.clientFinished;
    ex.response = c.response;
    delete ex.serverPrivateKey;
    this.#sessions.set(id(c.session.sessionId.toUint8Array()), cloneSession(c.session));
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
    for (const ex of this.#exchanges.values()) {
      if (ex.state === "PENDING" && ex.sessionId.equals(s.sessionId)) {
        ex.state = "SUPERSEDED";
        delete ex.serverPrivateKey;
      }
    }
  }

  #deleteKeys(s: SessionRecord): void {
    delete s.currentKeys;
    delete s.prevKeys;
    delete s.prevValidUntil;
  }

  #revoke(s: SessionRecord): void {
    s.status = "REVOKED";
    this.#invalidateExchanges(s);
    this.#deleteKeys(s);
  }

  async revokeForLogout(sessionId: Uint8Array, now: number): Promise<SessionRecord | null> {
    const s = this.#sessions.get(id(sessionId));
    if (!s || s.status !== "ACTIVE" || sessionExpired(s, now)) {
      return null;
    }
    s.status = "REVOKED";
    this.#invalidateExchanges(s);
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
      s.status = "EXPIRED";
      this.#invalidateExchanges(s);
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
    for (const key of this.#exchanges.keys()) {
      this.#readExchange(key, now);
    }
    for (const s of this.#sessions.values()) {
      if (s.status === "ACTIVE" && sessionExpired(s, now)) {
        s.status = "EXPIRED";
        this.#invalidateExchanges(s);
        this.#deleteKeys(s);
      }
      if (s.prevKeys && now > (s.prevValidUntil ?? -1)) {
        delete s.prevKeys;
        delete s.prevValidUntil;
      }
    }
  }
}

// Spec §7.4–§7.6, §8.1, §8.7–§8.10, §9.4: process-memory atomic stores.
import { base64urlnopad } from "@scure/base";
import { sessionExpired } from "../sm/lifetime.ts";
import type {
  ApprovalCommit,
  ApprovalCommitResult,
  ApprovalKrOutcome,
  ApprovalRecord,
  ApprovalStart,
  ApprovalStartResult,
  ApprovalTaOutcome,
  CredentialStore,
  OperationDecision,
  OperationQuery,
  OperationRecord,
  ExchangeRecord,
  EpochKeys,
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

function cloneDecision(d: OperationDecision): OperationDecision {
  switch (d.kind) {
    case "approved":
      return {
        ...d,
        decidedByCredentialId: d.decidedByCredentialId.slice(),
        credentialPublicKey: d.credentialPublicKey.slice(),
        sessionId: d.sessionId.slice(),
        approvalId: d.approvalId.slice(),
        approvalNonce: d.approvalNonce.slice(),
        th: d.th ? d.th.slice() : null,
        authenticatorData: d.authenticatorData.slice(),
        clientDataJSON: d.clientDataJSON.slice(),
        signature: d.signature.slice(),
      };
    case "rejected":
      return { ...d, sessionId: d.sessionId.slice() };
    case "cancelled":
      return { ...d };
  }
}

function cloneOperation(o: OperationRecord): OperationRecord {
  return { ...o, ...(o.decision ? { decision: cloneDecision(o.decision) } : {}) };
}

function cloneApproval(a: ApprovalRecord): ApprovalRecord {
  return { ...a, ...(a.signCountUpdate ? { signCountUpdate: cloneUpdate(a.signCountUpdate) } : {}) };
}

/** Reports a PENDING operation past its expiresAt as EXPIRED without changing the stored record. */
function operationView(o: OperationRecord, now: number): OperationRecord {
  const view = cloneOperation(o);
  if (view.status === "PENDING" && now >= view.expiresAt) {
    view.status = "EXPIRED";
  }
  return view;
}

function cloneEpochKeys(keys: EpochKeys): EpochKeys {
  return { ...keys, credentialId: keys.credentialId.slice() };
}

function cloneSession(s: SessionRecord): SessionRecord {
  return {
    ...s,
    loginCredentialId: s.loginCredentialId.slice(),
    lastAuthCredentialId: s.lastAuthCredentialId.slice(),
    authCredentialIds: s.authCredentialIds.map(credentialId => credentialId.slice()),
    ...(s.currentKeys ? { currentKeys: cloneEpochKeys(s.currentKeys) } : {}),
    ...(s.prevKeys ? { prevKeys: cloneEpochKeys(s.prevKeys) } : {}),
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
  #operations = new Map<string, OperationRecord>();
  // Operation records per approver in (createdAt, operationId) order, so a list never looks at other users' operations.
  // Decided operations stay (audit); the arrays hold the same objects as #operations.
  #operationsByUser = new Map<string, OperationRecord[]>();
  #approvals = new Map<string, ApprovalRecord>();
  // PENDING approval keys per operation and per session.
  #activeByOperation = new Map<string, Set<string>>();
  #activeBySession = new Map<string, Set<string>>();
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
    return this.#createRekey(c);
  }

  #createRekey(c: RekeyStart): RekeyStartResult {
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
    return this.#commitRekey(c);
  }

  #commitRekey(c: RekeyCommit): RekeyCommitResult {
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
    s.currentKeys = cloneEpochKeys(c.currentKeys);
    s.currentEpoch++;
    s.authTime = c.authTime;
    s.absoluteExpiresAt = Math.min(s.hardCapAt, c.absoluteExpiresAt);
    s.lastAuthCredentialId = c.credentialId.slice();
    if (!s.authCredentialIds.some(credentialId => id(credentialId) === id(c.credentialId))) {
      s.authCredentialIds.push(c.credentialId.slice());
    }
    return "committed";
  }

  async clearSignCountUpdate(exchangeId: Uint8Array): Promise<boolean> {
    const holder = this.#exchanges.get(id(exchangeId)) ?? this.#approvals.get(id(exchangeId));
    if (!holder?.signCountUpdate) {
      return false;
    }
    delete holder.signCountUpdate;
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

  /** §8.9 step 3: a terminal session's PENDING approval attempts become unusable. */
  #invalidateApprovals(s: SessionRecord): void {
    for (const key of [...this.#activeBySession.get(id(s.sessionId.toUint8Array())) ?? []]) {
      const att = this.#approvals.get(key);
      if (att) {
        this.#settleApproval(key, att, "EXPIRED");
      }
    }
  }

  /** Marks the session terminal, remembering when it ended for the retention sweep. */
  #end(s: SessionRecord, status: "REVOKED" | "EXPIRED", now: number): void {
    s.status = status;
    s.endedAt ??= now;
    this.#invalidateExchanges(s);
    this.#invalidateApprovals(s);
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
      if (s.authCredentialIds.some(credentialId => id(credentialId) === key)) {
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
    for (const key of [...this.#approvals.keys()]) {
      this.#readApproval(key, now);
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

  async createOperation(record: OperationRecord): Promise<boolean> {
    if (this.#operations.has(record.operationId)) {
      return false;
    }
    const stored = cloneOperation(record);
    this.#operations.set(record.operationId, stored);
    const list = this.#operationsByUser.get(stored.approverUserId) ?? [];
    list.splice(this.#firstAfter(list, stored), 0, stored);
    this.#operationsByUser.set(stored.approverUserId, list);
    return true;
  }

  /** The index of the first record that sorts after the (createdAt, operationId) position, by binary search. */
  #firstAfter(list: OperationRecord[], position: { createdAt: number; operationId: string; }): number {
    let low = 0;
    let high = list.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      const op = list[mid]!;
      if (op.createdAt < position.createdAt || (op.createdAt === position.createdAt && op.operationId <= position.operationId)) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    return low;
  }

  async getOperation(operationId: string, now: number): Promise<OperationRecord | null> {
    const op = this.#operations.get(operationId);
    return op ? operationView(op, now) : null;
  }

  async listOperations(q: OperationQuery): Promise<OperationRecord[]> {
    const list = this.#operationsByUser.get(q.approverUserId) ?? [];
    const found: OperationRecord[] = [];
    for (let i = q.after ? this.#firstAfter(list, q.after) : 0; i < list.length && found.length < q.limit; i++) {
      const view = operationView(list[i]!, q.now);
      if (q.status === undefined || view.status === q.status) {
        found.push(view);
      }
    }
    return found;
  }

  /** Common guard of every decision: PENDING and not past expiresAt (§10.9). */
  #decidable(op: OperationRecord, now: number): "ok" | "already_decided" | "expired" {
    if (op.status !== "PENDING") {
      return "already_decided";
    }
    return now >= op.expiresAt ? "expired" : "ok";
  }

  async cancelOperation(operationId: string, now: number): Promise<"cancelled" | "already_decided" | "expired" | "not_found"> {
    const op = this.#operations.get(operationId);
    if (!op) {
      return "not_found";
    }
    const guard = this.#decidable(op, now);
    if (guard !== "ok") {
      return guard;
    }
    op.status = "CANCELLED";
    op.decision = { kind: "cancelled", decidedAt: now, decidedBy: "server" };
    return "cancelled";
  }

  async rejectOperation(
    operationId: string,
    userId: string,
    sessionId: Uint8Array,
    now: number,
  ): Promise<"rejected" | "already_decided" | "expired" | "not_found"> {
    const op = this.#operations.get(operationId);
    if (!op || op.approverUserId !== userId) {
      return "not_found";
    }
    const guard = this.#decidable(op, now);
    if (guard !== "ok") {
      return guard;
    }
    op.status = "REJECTED";
    op.decision = { kind: "rejected", decidedAt: now, decidedByUserId: userId, sessionId: sessionId.slice() };
    return "rejected";
  }

  /** Leaves PENDING: updates the indexes, and supersedes a still pending bound exchange when the attempt expires. */
  #settleApproval(key: string, att: ApprovalRecord, state: ApprovalRecord["state"]): void {
    att.state = state;
    const owners = [
      [this.#activeByOperation, att.operationId],
      [this.#activeBySession, id(att.sessionId.toUint8Array())],
    ] as const;
    for (const [index, owner] of owners) {
      const keys = index.get(owner);
      keys?.delete(key);
      if (keys?.size === 0) {
        index.delete(owner);
      }
    }
    if (state === "EXPIRED" && att.krExchangeId) {
      this.#supersedeBound(att.krExchangeId.toUint8Array());
    }
  }

  #supersedeBound(exchangeId: Uint8Array): void {
    const key = id(exchangeId);
    const ex = this.#exchanges.get(key);
    if (ex?.state === "PENDING") {
      this.#settle(key, ex, "SUPERSEDED");
    }
  }

  #readApproval(key: string, now: number): ApprovalRecord | null {
    const att = this.#approvals.get(key);
    if (!att) {
      return null;
    }
    if (att.state === "PENDING" && now >= att.expiresAt) {
      this.#settleApproval(key, att, "EXPIRED");
    }
    if (att.state !== "PENDING" && now >= att.expiresAt + this.#retention) {
      this.#approvals.delete(key);
      return null;
    }
    return att;
  }

  async getApproval(approvalId: Uint8Array, now: number): Promise<ApprovalRecord | null> {
    const att = this.#readApproval(id(approvalId), now);
    return att ? cloneApproval(att) : null;
  }

  async createApproval(c: ApprovalStart): Promise<ApprovalStartResult> {
    this.#opportunisticSweep(c.now);
    const att = c.attempt;
    const sessionKey = id(att.sessionId.toUint8Array());
    const key = id(att.approvalId.toUint8Array());
    if (
      att.state !== "PENDING" || this.#approvals.has(key) ||
      (c.rekey !== null) !== (att.krExchangeId !== undefined) ||
      (c.rekey !== null && (
        !c.rekey.record.exchangeId.equals(att.krExchangeId!) || !c.rekey.record.boundApprovalId?.equals(att.approvalId)
      ))
    ) {
      throw new TypeError("invalid approval attempt");
    }
    const s = this.#activeSession(sessionKey, c.now);
    if (!s || !s.currentKeys) {
      return "reauth";
    }
    const op = this.#operations.get(att.operationId);
    if (!op || op.approverUserId !== s.userId) {
      return "not_found";
    }
    const guard = this.#decidable(op, c.now);
    if (guard !== "ok") {
      return guard;
    }
    if (c.rekey) {
      const created = this.#createRekey(c.rekey);
      if (created !== "created") {
        return created;
      }
    }
    const active = [...this.#activeByOperation.get(att.operationId) ?? []]
      .map(k => ({ key: k, att: this.#readApproval(k, c.now) }))
      .filter((entry): entry is { key: string; att: ApprovalRecord } => entry.att?.state === "PENDING")
      .sort((a, b) => a.att.createdAt - b.att.createdAt);
    while (active.length >= c.maxActiveApprovals) {
      const oldest = active.shift()!;
      this.#settleApproval(oldest.key, oldest.att, "EXPIRED");
    }
    this.#approvals.set(key, cloneApproval(att));
    for (const [index, owner] of [[this.#activeByOperation, att.operationId], [this.#activeBySession, sessionKey]] as const) {
      const keys = index.get(owner) ?? new Set<string>();
      keys.add(key);
      index.set(owner, keys);
    }
    return "created";
  }

  #decideOperation(op: OperationRecord, c: ApprovalCommit): ApprovalTaOutcome {
    const guard = this.#decidable(op, c.now);
    if (guard !== "ok") {
      return guard;
    }
    op.status = "APPROVED";
    op.decision = cloneDecision({ kind: "approved", decidedAt: c.now, ...c.record }) as OperationDecision;
    return "approved";
  }

  #applyBoundRekey(c: ApprovalCommit, att: ApprovalRecord): ApprovalKrOutcome | null {
    if (!c.kr) {
      // A TA-only approval on an attempt that offered a rekey: the offered exchange is not used.
      if (att.krExchangeId) {
        this.#supersedeBound(att.krExchangeId.toUint8Array());
      }
      return null;
    }
    const ex = this.#readExchange(id(c.kr.exchangeId), c.now);
    if (!c.kr.rekey || !ex || ex.boundApprovalId === undefined || !ex.boundApprovalId.equals(att.approvalId)) {
      return "expired";
    }
    const result = this.#commitRekey(c.kr.rekey);
    return result === "committed" || result === "conflict" ? result : "expired";
  }

  async commitApproval(c: ApprovalCommit): Promise<ApprovalCommitResult> {
    const sessionKey = id(c.sessionId);
    const s = this.#activeSession(sessionKey, c.now);
    if (!s || !s.currentKeys) {
      return { state: "reauth" };
    }
    const key = id(c.approvalId);
    const att = this.#readApproval(key, c.now);
    if (!att || id(att.sessionId.toUint8Array()) !== sessionKey || att.operationId !== c.operationId) {
      return { state: "expired" };
    }
    if (att.state === "CONSUMED") {
      return { state: "consumed", response: att.result ?? "{}" };
    }
    const op = this.#operations.get(att.operationId);
    if (att.state !== "PENDING" || !op) {
      return { state: "expired" };
    }
    // (1)-(4) of §10.7 run without yielding, so the three parts are decided against one consistent state.
    this.#settleApproval(key, att, "CONSUMED");
    const ta = this.#decideOperation(op, c);
    const kr = this.#applyBoundRekey(c, att);
    att.result = c.result(ta, kr, ta === "expired" ? "EXPIRED" : op.status);
    if (c.signCountUpdate) {
      att.signCountUpdate = cloneUpdate(c.signCountUpdate);
    }
    return { state: "committed", response: att.result };
  }
}

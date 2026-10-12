// Spec §7.4–§7.6, §8.1, §8.10, §9.4: atomic application store contracts.
import type {
  C2sCryptoKey,
  S2cCryptoKey,
  TranscriptHash,
  ExchangeId,
  SessionId,
  ServerNonce,
  EcPublicKey,
  ClientFinishedMac,
  LoginTranscriptHash,
  RekeyTranscriptHash,
  ApprovalId,
  ApprovalNonce,
} from "@wake-protocol/core";

export interface WakeCredential {
  credentialId: Uint8Array;
  userId: string;
  userHandle: Uint8Array;
  /** SPKI DER, rather than the reference COSE_Key representation (§6.5). */
  publicKey: Uint8Array;
  algorithm: number;
  signCount: number;
  backupEligible: boolean;
  status: "active" | "pending" | "suspended" | "deleted";
  transports?: string[];
}

export interface CredentialStore {
  getCredential(credentialId: Uint8Array): Promise<WakeCredential | null>;
  findUserCredentials(userId: string): Promise<WakeCredential[]>;
  findUserByUsername(username: string): Promise<{ userId: string; credentials: WakeCredential[] } | null>;
  /** Atomically advances the counter only if it equals expected, across store instances. */
  compareAndSetSignCount(credentialId: Uint8Array, expected: number, next: number): Promise<boolean>;
  updateSignCount(credentialId: Uint8Array, signCount: number): Promise<void>;
}

export interface EpochKeys {
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
  th: TranscriptHash;
  c2sCount: number;
  s2cCount: number;
  /** When the authentication that established these keys (login or rekey) happened. */
  authTime: number;
  /** The credential that authenticated for these keys. */
  credentialId: Uint8Array;
}

export interface SessionRecord {
  sessionId: SessionId;
  userId: string;
  loginCredentialId: Uint8Array;
  lastAuthCredentialId: Uint8Array;
  /** Unique credentials used by login and every committed rekey. */
  authCredentialIds: Uint8Array[];
  establishedOrigin: string;
  status: "ACTIVE" | "REVOKED" | "EXPIRED";
  currentEpoch: number;
  currentKeys?: EpochKeys;
  prevKeys?: EpochKeys;
  prevValidUntil?: number;
  authTime: number;
  absoluteExpiresAt: number;
  hardCapAt: number;
  idleTimeoutSec: number;
  lastActivityAt: number;
  /** Set when the session became REVOKED or EXPIRED; terminal sessions are swept after a retention period. */
  endedAt?: number;
}

/** Who may complete an exchange. In username mode a null requestedUserId means the username is unknown. */
export type ExchangeUser =
  | { mode: "discoverable"; }
  | { mode: "username"; requestedUserId: string | null; };

/** Counter update that must be applied after the authentication commit; cleared once applied. */
export interface SignCountUpdate {
  credentialId: Uint8Array;
  userId: string;
  signCount: number;
  storedSignCount: number;
  anomaly: boolean;
}

export type ExchangeRecord = ExchangeBase & ExchangeUser;

interface ExchangeBase {
  exchangeId: ExchangeId;
  sessionId: SessionId;
  kind: "login" | "rekey";
  state: "PENDING" | "COMPLETED" | "EXPIRED" | "SUPERSEDED";
  serverNonce: ServerNonce;
  serverPublicKey: EcPublicKey;
  serverPrivateKey?: CryptoKey;
  expiresAt: number;
  th?: TranscriptHash;
  targetEpoch?: number;
  prevTh?: TranscriptHash;
  createdAt?: number;
  boundApprovalId?: ApprovalId;
  reauthenticatedCredentialId?: Uint8Array;
  clientFinished?: ClientFinishedMac;
  response?: string;
  signCountUpdate?: SignCountUpdate;
}

export interface LoginCommit {
  exchangeId: Uint8Array;
  now: number;
  th: LoginTranscriptHash;
  clientFinished: ClientFinishedMac;
  response: string;
  session: SessionRecord;
  signCountUpdate?: SignCountUpdate;
}

export interface RekeyStart {
  record: ExchangeRecord;
  expectedEpoch: number;
  now: number;
  maxPendingRekeys: number;
}

export interface RekeyCommit {
  exchangeId: Uint8Array;
  sessionId: Uint8Array;
  expectedEpoch: number;
  now: number;
  authTime: number;
  th: RekeyTranscriptHash;
  clientFinished: ClientFinishedMac;
  response: string;
  currentKeys: EpochKeys;
  absoluteExpiresAt: number;
  epochGraceMs: number;
  credentialId: Uint8Array;
  signCountUpdate?: SignCountUpdate;
}

export type RekeyStartResult = "created" | "conflict" | "reauth";
export type RekeyCommitResult = "committed" | "conflict" | "expired" | "reauth";

export type OperationStatus = "PENDING" | "APPROVED" | "REJECTED" | "CANCELLED" | "EXPIRED";

/** Authentication record kept for an APPROVED operation (§10.10); byte fields are exactly as received. */
export interface ApprovalDecision {
  kind: "approved";
  decidedAt: number;
  decidedByUserId: string;
  decidedByCredentialId: Uint8Array;
  /** SPKI of the approving credential at decision time, so the record stays verifiable after credential changes. */
  credentialPublicKey: Uint8Array;
  sessionId: Uint8Array;
  approvalId: Uint8Array;
  approvalNonce: Uint8Array;
  /** Only for TA+KR. */
  th: Uint8Array | null;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
}

export interface RejectDecision {
  kind: "rejected";
  decidedAt: number;
  decidedByUserId: string;
  sessionId: Uint8Array;
}

export interface CancelDecision {
  kind: "cancelled";
  decidedAt: number;
  decidedBy: "server";
}

export type OperationDecision = ApprovalDecision | RejectDecision | CancelDecision;

/** content, nonce and approverUserId never change after creation (§10.2). operationId is 64 lowercase hex characters. */
export interface OperationRecord {
  operationId: string;
  content: string;
  /** 32 lowercase hex characters. */
  nonce: string;
  approverUserId: string;
  /** EXPIRED is derived on read from a PENDING record whose expiresAt has passed. */
  status: OperationStatus;
  createdAt: number;
  expiresAt: number;
  decision?: OperationDecision;
}

export interface OperationQuery {
  approverUserId: string;
  status?: OperationStatus;
  limit: number;
  /** Exclusive position in (createdAt, operationId) order. */
  after?: { createdAt: number; operationId: string; };
  now: number;
}

/** A single-use approval attempt (§10.7, Appendix A). The result is the JSON text of the approve response. */
export interface ApprovalRecord {
  approvalId: ApprovalId;
  /** 64 lowercase hex characters. */
  operationId: string;
  sessionId: SessionId;
  approvalNonce: ApprovalNonce;
  krExchangeId?: ExchangeId;
  state: "PENDING" | "CONSUMED" | "EXPIRED";
  result?: string;
  createdAt: number;
  expiresAt: number;
  signCountUpdate?: SignCountUpdate;
}

export interface ApprovalStart {
  attempt: ApprovalRecord;
  /** Creates the bound rekey exchange together with the attempt. */
  rekey: RekeyStart | null;
  maxActiveApprovals: number;
  now: number;
}

export type ApprovalStartResult = "created" | "not_found" | "already_decided" | "expired" | "conflict" | "reauth";

export type ApprovalTaOutcome = "approved" | "already_decided" | "expired";
export type ApprovalKrOutcome = "committed" | "conflict" | "expired";

export interface ApprovalCommit {
  approvalId: Uint8Array;
  operationId: string;
  sessionId: Uint8Array;
  now: number;
  /** Everything of the decision record except decidedAt, which the store sets from now. */
  record: Omit<ApprovalDecision, "kind" | "decidedAt">;
  /** rekey is null when the exchange could no longer be used (not PENDING or expired) at verification time. */
  kr: { exchangeId: Uint8Array; rekey: RekeyCommit | null; } | null;
  /** Builds the response JSON text from the decided outcomes. Must be pure and synchronous. */
  result: (ta: ApprovalTaOutcome, kr: ApprovalKrOutcome | null, status: OperationStatus) => string;
  signCountUpdate?: SignCountUpdate;
}

export type ApprovalCommitResult =
  | { state: "committed" | "consumed"; response: string; }
  | { state: "expired" | "reauth"; };

/**
 * All conditional methods must be atomic across store instances. Persistent stores
 * must protect keys with a separate KEK and AAD (§8.10):
 * LP(ascii("WAKE/1 key-wrap"), sessionId, u32(epoch)) for session keys and
 * LP(ascii("WAKE/1 exchange-key"), exchangeId) for ephemeral private keys.
 */
export interface WakeStore {
  createExchange(record: ExchangeRecord): Promise<void>;
  getExchange(exchangeId: Uint8Array, now: number): Promise<ExchangeRecord | null>;
  /** Checks session state, lifetime and epoch atomically with pending-limit eviction and insertion. */
  createRekey(start: RekeyStart): Promise<RekeyStartResult>;
  /** Checks exchange and session state/lifetime/epoch atomically with both writes. */
  commitRekey(commit: RekeyCommit): Promise<RekeyCommitResult>;
  /** Supersedes only a PENDING exchange and drops its private key. */
  supersedeExchange(exchangeId: Uint8Array): Promise<void>;
  commitLogin(commit: LoginCommit): Promise<boolean>;
  /**
   * Clears the pending counter update of a committed exchange or consumed approval attempt (by its id). Returns true only for the caller
   * that actually cleared it, so the anomaly notification fires at most once.
   */
  clearSignCountUpdate(exchangeId: Uint8Array): Promise<boolean>;
  getSession(sessionId: Uint8Array): Promise<SessionRecord | null>;
  touchSession(sessionId: Uint8Array, now: number): Promise<void>;
  /** Reserve one c2s and one s2c use, only while ACTIVE, unexpired, with keys below limit. */
  reserveEncryptions(sessionId: Uint8Array, epoch: number, now: number, limit: number): Promise<boolean>;
  revokeForLogout(sessionId: Uint8Array, now: number): Promise<SessionRecord | null>;
  deleteSessionKeys(sessionId: Uint8Array): Promise<void>;
  expireSession(sessionId: Uint8Array, now: number): Promise<void>;
  revokeSession(sessionId: Uint8Array): Promise<void>;
  revokeSessionsByUser(userId: string): Promise<void>;
  revokeSessionsByCredential(credentialId: Uint8Array): Promise<void>;
  sweep(now: number): Promise<void>;
  /** Returns false when operationId already exists; the caller then generates a new nonce (§10.2). */
  createOperation(record: OperationRecord): Promise<boolean>;
  /** Reports status EXPIRED for a PENDING operation at or past expiresAt. */
  getOperation(operationId: string, now: number): Promise<OperationRecord | null>;
  /** Ordered by (createdAt, operationId); returns at most query.limit records. */
  listOperations(query: OperationQuery): Promise<OperationRecord[]>;
  /** PENDING and expiresAt > now becomes CANCELLED. */
  cancelOperation(operationId: string, now: number): Promise<"cancelled" | "already_decided" | "expired" | "not_found">;
  /** Only the approver may reject (others get not_found). PENDING and expiresAt > now becomes REJECTED. */
  rejectOperation(
    operationId: string,
    userId: string,
    sessionId: Uint8Array,
    now: number,
  ): Promise<"rejected" | "already_decided" | "expired" | "not_found">;
  /**
   * Atomically checks the session and operation, creates the optional bound rekey exchange, expires the oldest
   * attempts beyond maxActiveApprovals and inserts the attempt.
   */
  createApproval(start: ApprovalStart): Promise<ApprovalStartResult>;
  /** Reports state EXPIRED for a PENDING attempt at or past expiresAt. */
  getApproval(approvalId: Uint8Array, now: number): Promise<ApprovalRecord | null>;
  /**
   * §10.7 steps (1)–(4) in one atomic operation: consumes the attempt, decides the operation, applies the optional
   * rekey independently, and stores the result on the attempt.
   */
  commitApproval(commit: ApprovalCommit): Promise<ApprovalCommitResult>;
}

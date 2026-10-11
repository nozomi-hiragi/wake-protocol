// Spec §7.4–§7.6, §8.1, §8.10: atomic application store contracts.
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
  findUserByUsername(username: string): Promise<{ userId: string; credentials: WakeCredential[] } | null>;
  updateSignCount(credentialId: Uint8Array, signCount: number): Promise<void>;
}

export interface EpochKeys {
  c2s: C2sCryptoKey;
  s2c: S2cCryptoKey;
  th: TranscriptHash;
  c2sCount: number;
  s2cCount: number;
}

export interface SessionRecord {
  sessionId: SessionId;
  userId: string;
  loginCredentialId: Uint8Array;
  lastAuthCredentialId: Uint8Array;
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

/** Counter update that must be applied after the login commit; cleared once applied. */
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
  th?: LoginTranscriptHash;
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
  signCountUpdate: SignCountUpdate;
}

/**
 * All conditional methods must be atomic across store instances. Persistent stores
 * must protect keys with a separate KEK and AAD (§8.10):
 * LP(ascii("WAKE/1 key-wrap"), sessionId, u32(epoch)) for session keys and
 * LP(ascii("WAKE/1 exchange-key"), exchangeId) for ephemeral private keys.
 */
export interface WakeStore {
  createExchange(record: ExchangeRecord): Promise<void>;
  getExchange(exchangeId: Uint8Array, now: number): Promise<ExchangeRecord | null>;
  commitLogin(commit: LoginCommit): Promise<boolean>;
  /**
   * Clears the pending counter update of a committed exchange. Returns true only for the caller
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
}

// Spec §6.3, §13: server configuration and validation.
import { DEFAULT_MAX_PLAINTEXT, ET_BODY_MAX, ET_BODY_MIN, ET_REQUEST_MAX_ENCODED, WakeError } from "@wake-protocol/core";
import { checkRoutes } from "./et/transport.ts";
import type { EtRoute } from "./et/types.ts";
import { MemoryWakeStore } from "./store/memory.ts";
import type { CredentialStore, WakeStore } from "./store/types.ts";

export interface CounterAnomaly {
  credentialId: Uint8Array;
  userId: string;
  storedSignCount: number;
  receivedSignCount: number;
}

export interface WakeServerOptions {
  rpId: string;
  loginOrigins: readonly string[];
  /** Origins accepted for TA and TA+KR ceremonies (§6.3); defaults to loginOrigins. */
  taOrigins?: readonly string[];
  secret: Uint8Array;
  credentials: CredentialStore;
  store?: WakeStore;
  now?: () => number;
  exchangeTtlMs?: number;
  maxPendingRekeys?: number;
  approvalTtlMs?: number;
  maxActiveApprovals?: number;
  maxOperationLifetimeMs?: number;
  webauthnTimeoutMs?: number;
  freshnessWindowMs?: number;
  epochGraceMs?: number;
  authLifetimeMs?: number;
  hardCapMs?: number;
  idleTimeoutSec?: number;
  completedRetentionMs?: number;
  maxPlaintext?: number;
  /** ET body limit (§11.2), at least ET_BODY_MIN bytes. With routes, maxPlaintext must cover the worst-case EtRequest for this limit. */
  etBodyLimit?: number;
  /** In-process WAKE-ET routes (§11.5); none by default. */
  routes?: readonly EtRoute[];
  maxAuthBody?: number;
  /**
   * Set to the maximum number of credentials a user can have. Users above this count and real credential ID length
   * distributions remain distinguishable in username mode.
   */
  fakeCredentialCount?: number;
  fakeCredentialIdLength?: number;
  maxEncryptionsPerKey?: number;
  /** Retry-After value (seconds) sent with every rate_limited response. */
  retryAfterSec?: number;
  onCounterAnomaly?: (event: CounterAnomaly) => void | Promise<void>;
}

export type ServerOptions = Required<Omit<WakeServerOptions, "onCounterAnomaly">> & Pick<WakeServerOptions, "onCounterAnomaly">;

const defaults = {
  exchangeTtlMs: 300_000,
  maxPendingRekeys: 3,
  approvalTtlMs: 300_000,
  maxActiveApprovals: 5,
  maxOperationLifetimeMs: 30 * 86_400_000,
  webauthnTimeoutMs: 270_000,
  freshnessWindowMs: 300_000,
  epochGraceMs: 60_000,
  authLifetimeMs: 7 * 86_400_000,
  hardCapMs: 30 * 86_400_000,
  idleTimeoutSec: 86_400,
  completedRetentionMs: 600_000,
  maxPlaintext: DEFAULT_MAX_PLAINTEXT,
  etBodyLimit: ET_BODY_MAX,
  maxAuthBody: 65_536,
  fakeCredentialCount: 1,
  fakeCredentialIdLength: 32,
  maxEncryptionsPerKey: 2 ** 28,
  retryAfterSec: 1,
};

function invalid(): never {
  throw new WakeError("invalid_option");
}

function hasMethods(value: unknown, names: string[]): boolean {
  return typeof value === "object" && value !== null &&
    names.every(name => typeof (value as Record<string, unknown>)[name] === "function");
}

function checkOrigins(origins: unknown): void {
  if (!Array.isArray(origins) || !origins.length) {
    invalid();
  }
  for (const origin of origins as unknown[]) {
    if (typeof origin !== "string") {
      invalid();
    }
    try {
      const url = new URL(origin);
      if (url.origin !== origin || !["http:", "https:"].includes(url.protocol)) {
        invalid();
      }
    } catch {
      invalid();
    }
  }
}

export function checkOptions(options: WakeServerOptions): ServerOptions {
  if (
    !options || typeof options !== "object" || typeof options.rpId !== "string" ||
    !options.rpId.length || /[\s/:]/u.test(options.rpId)
  ) {
    invalid();
  }
  checkOrigins(options.loginOrigins);
  if (options.taOrigins !== undefined) {
    checkOrigins(options.taOrigins);
  }
  if (!(options.secret instanceof Uint8Array) || options.secret.length < 32) {
    invalid();
  }
  if (!hasMethods(options.credentials, [
    "getCredential", "findUserByUsername", "findUserCredentials", "compareAndSetSignCount", "updateSignCount",
  ])) {
    invalid();
  }
  if (options.now !== undefined && typeof options.now !== "function") {
    invalid();
  }
  if (options.onCounterAnomaly !== undefined && typeof options.onCounterAnomaly !== "function") {
    invalid();
  }
  const values = { ...defaults };
  for (const key of Object.keys(defaults) as (keyof typeof defaults)[]) {
    const value = options[key] === undefined ? defaults[key] : options[key];
    const minimum = key === "completedRetentionMs" || key === "epochGraceMs" || key === "freshnessWindowMs" ? 0 : 1;
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
      invalid();
    }
    values[key] = value;
  }
  if (
    values.webauthnTimeoutMs > values.exchangeTtlMs - 30_000 ||
    values.webauthnTimeoutMs > values.approvalTtlMs - 30_000 ||
    values.epochGraceMs > 300_000 ||
    values.hardCapMs < values.authLifetimeMs ||
    values.idleTimeoutSec > 0xffffffff ||
    values.fakeCredentialIdLength < 16 ||
    values.fakeCredentialIdLength > 64 ||
    values.fakeCredentialCount > 16 ||
    values.maxPendingRekeys > 16 ||
    values.retryAfterSec > 86_400 ||
    values.maxEncryptionsPerKey > 2 ** 28 ||
    values.etBodyLimit < ET_BODY_MIN ||
    values.maxPlaintext > 0xffffffff ||
    values.maxAuthBody > 0xffffffff
  ) {
    invalid();
  }
  const routes = checkRoutes(options.routes);
  // Routes enable ET: any EtRequest within the limits must fit in one message (§11.2, §8.1).
  if (routes.length && values.maxPlaintext < ET_REQUEST_MAX_ENCODED - ET_BODY_MAX + values.etBodyLimit) {
    invalid();
  }
  if (options.store !== undefined && !hasMethods(options.store, [
    "createExchange",
    "getExchange",
    "commitLogin",
    "createRekey",
    "commitRekey",
    "supersedeExchange",
    "clearSignCountUpdate",
    "getSession",
    "touchSession",
    "reserveEncryptions",
    "revokeForLogout",
    "deleteSessionKeys",
    "expireSession",
    "revokeSession",
    "revokeSessionsByUser",
    "revokeSessionsByCredential",
    "sweep",
    "createOperation",
    "getOperation",
    "listOperations",
    "cancelOperation",
    "rejectOperation",
    "createApproval",
    "getApproval",
    "commitApproval",
  ])) {
    invalid();
  }
  return {
    ...options,
    ...values,
    loginOrigins: [...options.loginOrigins],
    taOrigins: [...options.taOrigins ?? options.loginOrigins],
    routes,
    secret: options.secret.slice(),
    store: options.store ?? new MemoryWakeStore(values.completedRetentionMs, { now: options.now ?? Date.now }),
    now: options.now ?? Date.now,
  };
}

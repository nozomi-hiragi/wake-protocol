// Spec §6.3, §13: server configuration and validation.
import { DEFAULT_MAX_PLAINTEXT, WakeError } from "@wake-protocol/core";
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
  secret: Uint8Array;
  credentials: CredentialStore;
  store?: WakeStore;
  now?: () => number;
  exchangeTtlMs?: number;
  webauthnTimeoutMs?: number;
  freshnessWindowMs?: number;
  epochGraceMs?: number;
  authLifetimeMs?: number;
  hardCapMs?: number;
  idleTimeoutSec?: number;
  completedRetentionMs?: number;
  maxPlaintext?: number;
  maxAuthBody?: number;
  fakeCredentialCount?: number;
  fakeCredentialIdLength?: number;
  maxEncryptionsPerKey?: number;
  onCounterAnomaly?: (event: CounterAnomaly) => void | Promise<void>;
}

export type ServerOptions = Required<Omit<WakeServerOptions, "onCounterAnomaly">> & Pick<WakeServerOptions, "onCounterAnomaly">;

const defaults = {
  exchangeTtlMs: 300_000,
  webauthnTimeoutMs: 270_000,
  freshnessWindowMs: 300_000,
  epochGraceMs: 60_000,
  authLifetimeMs: 7 * 86_400_000,
  hardCapMs: 30 * 86_400_000,
  idleTimeoutSec: 86_400,
  completedRetentionMs: 600_000,
  maxPlaintext: DEFAULT_MAX_PLAINTEXT,
  maxAuthBody: 65_536,
  fakeCredentialCount: 1,
  fakeCredentialIdLength: 32,
  maxEncryptionsPerKey: 2 ** 28,
};

function invalid(): never {
  throw new WakeError("invalid_option");
}

function hasMethods(value: unknown, names: string[]): boolean {
  return typeof value === "object" && value !== null &&
    names.every(name => typeof (value as Record<string, unknown>)[name] === "function");
}

export function checkOptions(options: WakeServerOptions): ServerOptions {
  if (
    !options || typeof options !== "object" || typeof options.rpId !== "string" ||
    !options.rpId.length || /[\s/:]/u.test(options.rpId)
  ) {
    invalid();
  }
  if (!Array.isArray(options.loginOrigins) || !options.loginOrigins.length) {
    invalid();
  }
  for (const origin of options.loginOrigins) {
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
  if (!(options.secret instanceof Uint8Array) || options.secret.length < 32) {
    invalid();
  }
  if (!hasMethods(options.credentials, ["getCredential", "findUserByUsername", "updateSignCount"])) {
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
    values.epochGraceMs > 300_000 ||
    values.hardCapMs < values.authLifetimeMs ||
    values.idleTimeoutSec > 0xffffffff ||
    values.fakeCredentialIdLength > 32 ||
    values.fakeCredentialCount > 0xffffffff ||
    values.maxEncryptionsPerKey > 2 ** 28 ||
    values.maxPlaintext > 0xffffffff ||
    values.maxAuthBody > 0xffffffff
  ) {
    invalid();
  }
  if (options.store !== undefined && !hasMethods(options.store, [
    "createExchange",
    "getExchange",
    "commitLogin",
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
  ])) {
    invalid();
  }
  return {
    ...options,
    ...values,
    loginOrigins: [...options.loginOrigins],
    secret: options.secret.slice(),
    store: options.store ?? new MemoryWakeStore(values.completedRetentionMs),
    now: options.now ?? Date.now,
  };
}

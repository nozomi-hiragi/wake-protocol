// Tests for WAKE server behavior (spec §13).
import assert from "node:assert/strict";
import { test } from "node:test";
import { WakeError } from "@wake-protocol/core";
import { createWakeServer, MemoryCredentialStore } from "../src/index.ts";
import type { WakeServerOptions } from "../src/index.ts";
import { ORIGIN, RP } from "./helpers.ts";

const base: WakeServerOptions = {
  rpId: RP,
  loginOrigins: [ORIGIN],
  secret: new Uint8Array(32),
  credentials: new MemoryCredentialStore()
};

const numeric: (keyof WakeServerOptions)[] = [
  "exchangeTtlMs",
  "webauthnTimeoutMs",
  "freshnessWindowMs",
  "epochGraceMs",
  "authLifetimeMs",
  "hardCapMs",
  "idleTimeoutSec",
  "completedRetentionMs",
  "maxPlaintext",
  "maxAuthBody",
  "fakeCredentialCount",
  "fakeCredentialIdLength",
  "maxEncryptionsPerKey"
];

for (const key of numeric) {
  for (const value of [null, "1", NaN, Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    test(
      `options rejects ${key} = ${String(value)}`,
      () => {
        assert.throws(
          () => createWakeServer({ ...base, [key]: value } as WakeServerOptions),
          (error: unknown) => error instanceof WakeError && error.code === "invalid_option"
        );
      }
    );
  }
}

const invalid: [string, Record<string, unknown>][] = [
  ["now wrong type", { now: 1 }],
  ["callback wrong type", { onCounterAnomaly: 1 }],
  ["credentials missing methods", { credentials: {} }],
  ["store missing methods", { store: {} }],
  ["origins wrong type", { loginOrigins: ORIGIN }],
  ["rpId path", { rpId: "example.com/path" }],
  ["empty rpId", { rpId: "" }],
  ["rpId wrong type", { rpId: 3 }],
  ["empty origins", { loginOrigins: [] }],
  ["origin wrong type", { loginOrigins: [3] }],
  ["origin path", { loginOrigins: [`${ORIGIN}/path`] }],
  ["origin trailing slash", { loginOrigins: [`${ORIGIN}/`] }],
  ["opaque origin", { loginOrigins: ["file:///a"] }],
  ["short secret", { secret: new Uint8Array(31) }],
  ["secret wrong type", { secret: [] }],
  ["timeout too close to ttl", { webauthnTimeoutMs: 270001 }],
  ["ttl too short", { exchangeTtlMs: 29999, webauthnTimeoutMs: 1 }],
  ["grace too long", { epochGraceMs: 300001 }],
  ["hard cap shorter than lifetime", { authLifetimeMs: 1001, hardCapMs: 1000 }],
  ["zero idle", { idleTimeoutSec: 0 }],
  ["idle u32 overflow", { idleTimeoutSec: 0x100000000 }],
  ["zero fake count", { fakeCredentialCount: 0 }],
  ["zero fake length", { fakeCredentialIdLength: 0 }],
  ["fake length past digest", { fakeCredentialIdLength: 33 }],
  ["zero encryption count", { maxEncryptionsPerKey: 0 }],
  ["encryption limit past recommended cap", { maxEncryptionsPerKey: 2 ** 28 + 1 }],
];

for (const [name, options] of invalid) {
  test(
    `options rejects ${name}`,
    () => {
      assert.throws(
        () => createWakeServer({ ...base, ...options } as WakeServerOptions),
        (error: unknown) => error instanceof WakeError && error.code === "invalid_option"
      );
    }
  );
}

test(
  "options accepts defaults and exact boundaries",
  () => {
    assert.doesNotThrow(() => createWakeServer(base));
    assert.doesNotThrow(
      () => createWakeServer(
        {
          ...base,
          secret: new Uint8Array(33),
          loginOrigins: ["http://localhost:8787"],
          webauthnTimeoutMs: 270000,
          epochGraceMs: 300000,
          authLifetimeMs: 1,
          hardCapMs: 1,
          idleTimeoutSec: 0xffffffff,
          fakeCredentialCount: 1,
          fakeCredentialIdLength: 32,
          maxEncryptionsPerKey: 2 ** 28
        }
      )
    );
  }
);

for (const key of numeric.filter(key => !["freshnessWindowMs", "epochGraceMs", "completedRetentionMs"].includes(key))) {
  test(
    `positive option rejects zero ${key}`,
    () => {
      assert.throws(
        () => createWakeServer({ ...base, [key]: 0 }),
        (error: unknown) => error instanceof WakeError && error.code === "invalid_option"
      );
    }
  );
}

for (const key of ["maxPlaintext", "maxAuthBody", "fakeCredentialCount"] as const) {
  test(
    `${key} u32 boundary`,
    () => {
      assert.doesNotThrow(() => createWakeServer({ ...base, [key]: 0xffffffff }));
      assert.throws(
        () => createWakeServer({ ...base, [key]: 0x100000000 }),
        (error: unknown) => error instanceof WakeError && error.code === "invalid_option"
      );
    }
  );
}

test(
  "zero accepted windows and minimal positive options",
  () => {
    assert.doesNotThrow(
      () => createWakeServer(
        {
          ...base,
          freshnessWindowMs: 0,
          epochGraceMs: 0,
          completedRetentionMs: 0,
          exchangeTtlMs: 30001,
          webauthnTimeoutMs: 1,
          authLifetimeMs: 1,
          hardCapMs: 1,
          idleTimeoutSec: 1,
          maxPlaintext: 1,
          maxAuthBody: 1,
          fakeCredentialIdLength: 1,
          fakeCredentialCount: 1,
          maxEncryptionsPerKey: 1
        }
      )
    );
  }
);

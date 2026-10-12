// Tests for the in-memory stores (spec §7.4, §8.9; DESIGN §2.7).
import assert from "node:assert/strict";
import { test } from "node:test";
import { generateEphemeral, newExchangeId, newServerNonce, newSessionId } from "@wake-protocol/core";
import type { SessionId } from "@wake-protocol/core";
import { MemoryCredentialStore, MemoryWakeStore } from "../src/index.ts";
import type { ExchangeRecord, SessionRecord } from "../src/index.ts";
import { insertSession, SoftAuthenticator } from "../src/testing.ts";
import { decode, fixture, login, ORIGIN, RP } from "./helpers.ts";

async function exchange(sessionId: SessionId, expiresAt: number, kind: "login" | "rekey" = "login"): Promise<ExchangeRecord> {
  const ephemeral = await generateEphemeral();
  return {
    exchangeId: newExchangeId(),
    sessionId,
    kind,
    state: "PENDING",
    serverNonce: newServerNonce(),
    serverPublicKey: ephemeral.publicKey,
    serverPrivateKey: ephemeral.privateKey,
    expiresAt,
    mode: "discoverable",
  };
}

async function snapshot(store: MemoryWakeStore, e: ExchangeRecord, now: number) {
  return store.getExchange(e.exchangeId.toUint8Array(), now);
}

function sessionRecord(status: SessionRecord["status"] = "ACTIVE", overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    sessionId: newSessionId(),
    userId: "u1",
    loginCredentialId: new Uint8Array([1]),
    lastAuthCredentialId: new Uint8Array([1]),
    establishedOrigin: ORIGIN,
    status,
    currentEpoch: 0,
    authTime: 0,
    absoluteExpiresAt: 1_000_000,
    hardCapAt: 2_000_000,
    idleTimeoutSec: 86_400,
    lastActivityAt: 0,
    ...overrides,
  };
}

test("createExchange sweeps expired exchanges and drops their private keys, at most once per interval", async () => {
  const clock = { now: 0 };
  const store = new MemoryWakeStore(600_000, { now: () => clock.now, sweepIntervalMs: 1000 });
  const abandoned = await exchange(newSessionId(), 5000);
  await store.createExchange(abandoned);
  clock.now = 6000;
  await store.createExchange(await exchange(newSessionId(), 10_000));
  // Read with a time before expiry, so only the sweep at 6000 can have expired it.
  const stored = await snapshot(store, abandoned, 0);
  assert.equal(stored?.state, "EXPIRED");
  assert.equal(stored?.serverPrivateKey, undefined);
});

test("createExchange does not sweep before the interval has passed", async () => {
  const clock = { now: 0 };
  const store = new MemoryWakeStore(600_000, { now: () => clock.now, sweepIntervalMs: 1000 });
  const abandoned = await exchange(newSessionId(), 500);
  await store.createExchange(abandoned);
  clock.now = 999;
  await store.createExchange(await exchange(newSessionId(), 10_000));
  assert.equal((await snapshot(store, abandoned, 0))?.state, "PENDING");
  assert.ok((await snapshot(store, abandoned, 0))?.serverPrivateKey);
  clock.now = 1000;
  await store.createExchange(await exchange(newSessionId(), 10_000));
  assert.equal((await snapshot(store, abandoned, 0))?.state, "EXPIRED");
});

test("terminal sessions are swept exactly after the retention period", async () => {
  const clock = { now: 1000 };
  const store = new MemoryWakeStore(600_000, { now: () => clock.now, endedSessionRetentionMs: 500 });
  const revoked = sessionRecord();
  const expired = sessionRecord("ACTIVE", { absoluteExpiresAt: 1000 });
  const active = sessionRecord();
  for (const s of [revoked, expired, active]) {
    insertSession(store, s);
  }
  await store.revokeSession(revoked.sessionId.toUint8Array());
  await store.expireSession(expired.sessionId.toUint8Array(), 1000);
  assert.equal((await store.getSession(revoked.sessionId.toUint8Array()))?.endedAt, 1000);
  assert.equal((await store.getSession(expired.sessionId.toUint8Array()))?.endedAt, 1000);
  await store.sweep(1499);
  assert.ok(await store.getSession(revoked.sessionId.toUint8Array()));
  assert.ok(await store.getSession(expired.sessionId.toUint8Array()));
  await store.sweep(1500);
  assert.equal(await store.getSession(revoked.sessionId.toUint8Array()), null);
  assert.equal(await store.getSession(expired.sessionId.toUint8Array()), null);
  assert.equal((await store.getSession(active.sessionId.toUint8Array()))?.status, "ACTIVE");
});

test("sweep expires and then deletes a session that nobody touched", async () => {
  const store = new MemoryWakeStore(600_000, { endedSessionRetentionMs: 100 });
  const s = sessionRecord("ACTIVE", { absoluteExpiresAt: 1000 });
  insertSession(store, s);
  await store.sweep(1000);
  assert.equal((await store.getSession(s.sessionId.toUint8Array()))?.status, "EXPIRED");
  await store.sweep(1099);
  assert.ok(await store.getSession(s.sessionId.toUint8Array()));
  await store.sweep(1100);
  assert.equal(await store.getSession(s.sessionId.toUint8Array()), null);
});

test("endedAt keeps the first end time when a session is revoked again", async () => {
  const clock = { now: 10 };
  const store = new MemoryWakeStore(600_000, { now: () => clock.now });
  const s = sessionRecord();
  insertSession(store, s);
  await store.revokeSession(s.sessionId.toUint8Array());
  clock.now = 99;
  await store.revokeSession(s.sessionId.toUint8Array());
  assert.equal((await store.getSession(s.sessionId.toUint8Array()))?.endedAt, 10);
});

test("revoking a session supersedes its PENDING exchanges only", async () => {
  const store = new MemoryWakeStore();
  const s = sessionRecord();
  insertSession(store, s);
  const pendingA = await exchange(s.sessionId, 1_000_000, "rekey");
  const pendingB = await exchange(s.sessionId, 1_000_000, "rekey");
  const expired = await exchange(s.sessionId, 10, "rekey");
  const other = await exchange(newSessionId(), 1_000_000);
  for (const e of [pendingA, pendingB, expired, other]) {
    await store.createExchange(e);
  }
  assert.equal((await snapshot(store, expired, 20))?.state, "EXPIRED");
  await store.revokeSession(s.sessionId.toUint8Array());
  for (const e of [pendingA, pendingB]) {
    const stored = await snapshot(store, e, 20);
    assert.equal(stored?.state, "SUPERSEDED");
    assert.equal(stored?.serverPrivateKey, undefined);
  }
  assert.equal((await snapshot(store, expired, 20))?.state, "EXPIRED");
  assert.equal((await snapshot(store, other, 20))?.state, "PENDING");
});

test("every session end path supersedes pending exchanges via the index", async () => {
  const store = new MemoryWakeStore();
  const byUser = sessionRecord("ACTIVE", { userId: "u9" });
  const byCredential = sessionRecord("ACTIVE", { loginCredentialId: new Uint8Array([7]), lastAuthCredentialId: new Uint8Array([7]) });
  const bySweep = sessionRecord("ACTIVE", { absoluteExpiresAt: 50 });
  const byLogout = sessionRecord();
  const all = [byUser, byCredential, bySweep, byLogout];
  const exchanges: ExchangeRecord[] = [];
  for (const s of all) {
    insertSession(store, s);
    const e = await exchange(s.sessionId, 1_000_000, "rekey");
    exchanges.push(e);
    await store.createExchange(e);
  }
  await store.revokeSessionsByUser("u9");
  await store.revokeSessionsByCredential(new Uint8Array([7]));
  await store.sweep(60);
  await store.revokeForLogout(byLogout.sessionId.toUint8Array(), 60);
  for (const e of exchanges) {
    assert.equal((await snapshot(store, e, 60))?.state, "SUPERSEDED");
  }
});

test("a committed exchange leaves the pending index", async () => {
  const f = await fixture();
  const l = await login(f);
  const exchangeId = decode(l.info.exchangeId);
  assert.equal((await f.store.getExchange(exchangeId, f.clock.now))?.state, "COMPLETED");
  await f.store.revokeSession(l.sessionId.toUint8Array());
  assert.equal((await f.store.getExchange(exchangeId, f.clock.now))?.state, "COMPLETED");
});

test("insertSession is the only way to insert a session, and the class has no createSession", () => {
  assert.equal("createSession" in MemoryWakeStore.prototype, false);
  assert.throws(() => insertSession({} as MemoryWakeStore, sessionRecord()), TypeError);
});

test("MemoryCredentialStore rejects re-binding a credentialId or username to another user", async () => {
  const a = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const b = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
  const store = new MemoryCredentialStore();
  store.setCredential(a.credential, "alice");
  // Same user: updates are allowed.
  store.setCredential({ ...a.credential, signCount: 3 }, "alice");
  store.setUser("alice", "u1");
  assert.throws(() => store.setCredential({ ...a.credential, userId: "u2" }), /different user/u);
  assert.throws(() => store.setCredential(b.credential, "alice"), /different user/u);
  assert.throws(() => store.setUser("alice", "u2"), /different user/u);
  // A rejected call changes nothing.
  assert.equal(await store.getCredential(b.credential.credentialId), null);
  assert.equal((await store.findUserByUsername("alice"))?.userId, "u1");
  assert.equal((await store.getCredential(a.credential.credentialId))?.userId, "u1");
  store.setCredential(b.credential, "bob");
  assert.equal((await store.findUserByUsername("bob"))?.userId, "u2");
});

test("credential counter CAS admits exactly one concurrent update from the same stored value", async () => {
  const auth = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1", signCount: 3 });
  const store = new MemoryCredentialStore([auth.credential]);
  const id = auth.credential.credentialId;
  const results = await Promise.all([
    store.compareAndSetSignCount(id, 3, 4),
    store.compareAndSetSignCount(id, 3, 4)
  ]);
  assert.deepEqual(results, [true, false]);
  assert.equal((await store.getCredential(id))?.signCount, 4);
  assert.equal(await store.compareAndSetSignCount(id, 3, 5), false);
  assert.equal((await store.getCredential(id))?.signCount, 4);
  assert.equal(await store.compareAndSetSignCount(id, 4, 5), true);
  assert.equal((await store.getCredential(id))?.signCount, 5);
  assert.equal(await store.compareAndSetSignCount(new Uint8Array([9]), 0, 1), false);
});

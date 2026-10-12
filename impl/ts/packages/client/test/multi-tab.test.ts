// Spec §8.7, §8.11, §9.6, §9.7: two WakeClient instances on one store behave as two tabs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { utf8ToBytes } from "@wake-protocol/codec";
import { WakeClient, indexedDbSessionStore, memorySessionStore } from "../src/index.ts";
import type { SessionStore, StoredSession } from "../src/index.ts";
import { fixture, hasCode, jsonResponse } from "./fixture.ts";

const login = { mode: "discoverable" } as const;
const data = utf8ToBytes("hello");

function gate() {
  let release!: () => void;
  let reached!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const arrived = new Promise<void>((resolve) => {
    reached = resolve;
  });
  return { release, reached, blocked, arrived };
}

function shared() {
  const store = memorySessionStore();
  return { store };
}

/**
 * The first `load` returns the record it already read, and only after `held.release`.
 * A login or rekey that finishes in between therefore races an older snapshot, not a fresh read.
 */
function delayFirstLoad() {
  const inner = memorySessionStore();
  const held = gate();
  let first = true;
  const store: SessionStore = {
    async load() {
      const record = await inner.load();
      if (first) {
        first = false;
        held.reached();
        await held.blocked;
        return record;
      }
      return inner.load();
    },
    save: (record, expect) => inner.save(record, expect),
    clear: (expect) => inner.clear(expect),
    reserveEncryptions: (sessionId, epoch, count, limit) => inner.reserveEncryptions(sessionId, epoch, count, limit),
    lock: (name, fn) => inner.lock(name, fn),
    subscribe: (listener) => inner.subscribe(listener),
  };
  return { store, held };
}

/** Remembers a pending record so a test can restore a tab that died after kr/complete. */
function capturingStore(): { store: SessionStore; pending: () => StoredSession | undefined } {
  const inner = memorySessionStore();
  let pending: StoredSession | undefined;
  const store: SessionStore = {
    load: () => inner.load(),
    async save(record, expect) {
      const wrote = await inner.save(record, expect);
      if (wrote && record.pending !== undefined) pending = await inner.load();
      return wrote;
    },
    clear: (expect) => inner.clear(expect),
    reserveEncryptions: (sessionId, epoch, count, limit) => inner.reserveEncryptions(sessionId, epoch, count, limit),
    lock: (name, fn) => inner.lock(name, fn),
    subscribe: (listener) => inner.subscribe(listener),
  };
  return { store, pending: () => pending };
}

test("login in one tab is usable in another without a new assertion", async () => {
  const { store } = shared();
  let notices = 0;
  store.subscribe(() => {
    notices += 1;
  });
  const f = await fixture({ store });
  const info = await f.client.login(login);
  assert.equal(notices, 1);
  const b = f.newClient();
  assert.equal(b.loggedIn, false);
  const loaded = await b.reload();
  assert.equal(loaded?.sessionId, info.sessionId);
  assert.equal(loaded?.epoch, 0);
  assert.equal(b.currentSession?.sessionId, info.sessionId);
  const before = f.assertionCalls;
  assert.equal((await b.session()).sessionId, info.sessionId);
  assert.deepEqual(await b.request("custom", data), data);
  assert.equal(f.assertionCalls, before);
});

test("a key rotation moves a stale tab on reload and on epoch_retired", async () => {
  const { store } = shared();
  const f = await fixture({ store });
  await f.client.login(login);
  const b = f.newClient();
  await b.reload();
  await f.client.rekey();
  assert.equal((await b.reload())?.epoch, 1);
  assert.equal((await b.session()).epoch, 1);

  const c = f.newClient();
  await c.reload();
  assert.equal(c.currentSession?.epoch, 1);
  // A second rotation, then a tab that still holds the previous epoch.
  const stale = f.newClient();
  await stale.reload();
  await f.client.rekey();
  assert.equal(stale.currentSession?.epoch, 1);
  f.upAction = () => f.requests.at(-1)!.epoch === 1
    ? jsonResponse({ wakeError: "epoch_retired" }, 401)
    : undefined;
  const before = f.assertionCalls;
  assert.deepEqual(await stale.request("custom", data), data);
  assert.equal(f.assertionCalls, before);
  assert.deepEqual(f.requests.filter((h) => h.context === "custom").map((h) => h.epoch), [1, 2]);
  assert.equal(stale.currentSession?.epoch, 2);
});

test("concurrent rekey on two tabs commits once and conflicts the other", async () => {
  const { store } = shared();
  const f = await fixture({ store });
  await f.client.login(login);
  const b = f.newClient();
  await b.reload();
  const before = f.assertionCalls;
  const results = await Promise.allSettled([f.client.rekey(), b.rekey()]);
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  const ok = fulfilled[0];
  const bad = rejected[0];
  assert.ok(ok?.status === "fulfilled" && ok.value.epoch === 1);
  assert.ok(bad?.status === "rejected" && hasCode("conflict")(bad.reason));
  assert.equal(f.assertionCalls, before + 1);
  assert.equal(f.currentEpoch, 1);
  assert.equal(f.client.loggedIn, true);
  assert.equal(b.loggedIn, true);
});

test("approve with rekey conflicts with a concurrent rekey and calls getAssertion once", async () => {
  const { store } = shared();
  const f = await fixture({ store });
  await f.client.login(login);
  const op = await f.addOperation("Transfer to Alice");
  const b = f.newClient();
  await b.reload();
  const before = f.assertionCalls;
  const results = await Promise.allSettled([
    f.client.approve(op.operationId, { rekey: true }),
    b.rekey(),
  ]);
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  const bad = rejected[0];
  assert.ok(bad?.status === "rejected" && hasCode("conflict")(bad.reason));
  assert.equal(f.assertionCalls, before + 1);
  assert.equal(f.currentEpoch, 1);
  const winner = fulfilled[0];
  assert.equal(winner?.status, "fulfilled");
  if (winner?.status !== "fulfilled") return;
  if ("epoch" in winner.value) {
    assert.equal(winner.value.epoch, 1);
  } else {
    assert.equal(winner.value.kr?.result, "committed");
  }
});

test("encryption reservations are shared across tabs and stop at the limit", async () => {
  const store = memorySessionStore();
  const f = await fixture({ store, maxEncryptionsPerKey: 5, encryptionBlockSize: 2 });
  await f.client.login(login);
  const b = f.newClient();
  await b.reload();
  const clients = [f.client, b];
  for (let i = 0; i < 5; i++) {
    assert.deepEqual(await clients[i % 2]!.request("custom", data), data);
  }
  await assert.rejects(b.request("custom", data), hasCode("reauth"));
  assert.equal(f.requests.filter((h) => h.context === "custom").length, 5);
  assert.equal(b.loggedIn, false);
  // The drop cleared the shared record, so the other tab logs out on reload.
  assert.equal(await f.client.reload(), undefined);
  assert.equal(f.client.loggedIn, false);
});

test("logout clears the shared session and a later login is adopted on reload", async () => {
  const { store } = shared();
  const f = await fixture({ store });
  const info = await f.client.login(login);
  const b = f.newClient();
  assert.equal((await b.reload())?.sessionId, info.sessionId);
  let notices = 0;
  store.subscribe(() => {
    notices += 1;
  });
  await f.client.logout();
  assert.equal(notices, 1);
  assert.equal(await b.reload(), undefined);
  assert.equal(b.loggedIn, false);
  assert.equal(b.currentSession, undefined);
  const again = await f.client.login(login);
  const loaded = await b.reload();
  assert.equal(loaded?.sessionId, again.sessionId);
  assert.equal(b.loggedIn, true);
  assert.equal((await b.session()).sessionId, again.sessionId);
});

test("a dead tab's pending epoch is probed after epoch_retired, and a failed probe logs out", async () => {
  const captured = capturingStore();
  const f = await fixture({ store: captured.store });
  await f.client.login(login);
  const b = f.newClient();
  await b.reload();
  f.krStartMutate = (v) => {
    v.expiresAt = f.serverTime + 1000;
  };
  f.krCompleteResponse = () => {
    throw new TypeError("tab died after the server committed");
  };
  f.upAction = () => f.requests.at(-1)?.context === "wake/session"
    ? jsonResponse({ wakeError: "reauth" }, 401)
    : undefined;
  await assert.rejects(f.client.rekey(), hasCode("reauth"));
  const snapshot = captured.pending();
  assert.equal(snapshot?.current.epoch, 0);
  assert.equal(snapshot?.pending?.epoch, 1);
  assert.equal(f.currentEpoch, 1);
  f.krCompleteResponse = undefined;
  f.krStartMutate = undefined;
  f.upAction = () => {
    const header = f.requests.at(-1)!;
    if (header.context === "custom" && header.epoch === 0) return jsonResponse({ wakeError: "epoch_retired" }, 401);
    return undefined;
  };
  await captured.store.save(snapshot!);
  const before = f.assertionCalls;
  assert.deepEqual(await b.request("custom", data), data);
  assert.equal(f.assertionCalls, before);
  assert.deepEqual(f.requests.filter((h) => h.context === "custom").map((h) => h.epoch), [0, 1]);
  assert.equal(b.currentSession?.epoch, 1);
  assert.equal((await captured.store.load())?.pending, undefined);

  const again = capturingStore();
  const g = await fixture({ store: again.store });
  await g.client.login(login);
  const other = g.newClient();
  await other.reload();
  g.krStartMutate = (v) => {
    v.expiresAt = g.serverTime + 1000;
  };
  g.krCompleteResponse = () => {
    throw new TypeError("tab died after the server committed");
  };
  g.upAction = () => g.requests.at(-1)?.context === "wake/session"
    ? jsonResponse({ wakeError: "reauth" }, 401)
    : undefined;
  await assert.rejects(g.client.rekey(), hasCode("reauth"));
  const pending = again.pending();
  assert.ok(pending?.pending);
  g.krCompleteResponse = undefined;
  g.upAction = () => {
    const header = g.requests.at(-1)!;
    if (header.context === "custom" && header.epoch === 0) return jsonResponse({ wakeError: "epoch_retired" }, 401);
    if (header.context === "wake/session") return jsonResponse({ wakeError: "reauth" }, 401);
    return undefined;
  };
  await again.store.save(pending!);
  await assert.rejects(other.request("custom", data), hasCode("reauth"));
  assert.equal(other.loggedIn, false);
  assert.equal(await again.store.load(), undefined);
});

test("reload during an in-progress login does not abort it", async () => {
  const { store } = shared();
  const f = await fixture({ store });
  await f.client.login(login);
  const held = gate();
  f.onAssertion = async () => {
    held.reached();
    await held.blocked;
  };
  const pending = f.client.login(login);
  await held.arrived;
  // The stored session is still the previous login. Adopting it must not bump the login generation.
  const during = await f.client.reload();
  assert.equal(during?.epoch, 0);
  assert.equal(f.client.loggedIn, true);
  held.release();
  const info = await pending;
  assert.equal(f.client.loggedIn, true);
  assert.equal(f.client.currentSession?.sessionId, info.sessionId);
  assert.equal((await f.client.session()).sessionId, info.sessionId);
});

test("a reload that read an empty store does not undo a login that finished during the read", async () => {
  const { store, held } = delayFirstLoad();
  const f = await fixture({ store });
  const b = f.newClient();
  const pending = b.reload();
  await held.arrived;
  const info = await b.login(login);
  held.release();
  const loaded = await pending;
  assert.equal(b.loggedIn, true);
  assert.equal(loaded?.sessionId, info.sessionId);
  assert.equal(loaded?.epoch, info.epoch);
  assert.equal(b.currentSession?.sessionId, info.sessionId);
  assert.equal((await b.session()).sessionId, info.sessionId);
});

test("a delayed reload does not roll back an epoch committed by rekey meanwhile", async () => {
  const { store, held } = delayFirstLoad();
  const f = await fixture({ store });
  const b = f.newClient();
  const loggedIn = await b.login(login);
  const pending = b.reload();
  await held.arrived;
  const info = await b.rekey();
  held.release();
  const loaded = await pending;
  assert.equal(info.epoch, 1);
  assert.equal(loaded?.sessionId, loggedIn.sessionId);
  assert.equal(loaded?.epoch, 1);
  assert.equal(b.currentSession?.epoch, 1);
  assert.equal(b.loggedIn, true);
  assert.equal((await b.session()).epoch, 1);
});

test("a login in one tab replaces the stored session the other tab reloads", async () => {
  const { store } = shared();
  const f = await fixture({ store });
  const first = await f.client.login(login);
  const b = f.newClient();
  await f.rotateLogin();
  const second = await b.login(login);
  assert.notEqual(second.sessionId, first.sessionId);
  const adopted = await f.client.reload();
  assert.equal(adopted?.sessionId, second.sessionId);
  assert.equal(adopted?.epoch, 0);
  assert.equal((await f.client.session()).sessionId, second.sessionId);
  assert.equal(f.client.currentSession?.sessionId, second.sessionId);
});

test("two clients without a shared store do not see each other's login", async () => {
  const f = await fixture();
  const info = await f.client.login(login);
  const b = f.newClient();
  assert.equal(await b.reload(), undefined);
  assert.equal(b.loggedIn, false);
  assert.equal(b.currentSession, undefined);
  await assert.rejects(b.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, true);
  assert.equal((await f.client.session()).sessionId, info.sessionId);
});

test("indexedDbSessionStore falls back to memory in Node", async () => {
  const store = indexedDbSessionStore({ name: "wake-protocol-test" });
  const f = await fixture({ store });
  const info = await f.client.login(login);
  const loaded = await store.load();
  assert.equal(loaded?.sessionId, info.sessionId);
  assert.equal(loaded?.current.epoch, 0);
  assert.equal(loaded?.current.th.length, 32);
  assert.equal(loaded?.current.c2s.extractable, false);
  const b = f.newClient();
  assert.equal((await b.reload())?.sessionId, info.sessionId);
  const before = f.assertionCalls;
  await b.session();
  assert.equal(f.assertionCalls, before);

  assert.equal(await store.reserveEncryptions(info.sessionId, 99, 3, 5), 3);
  assert.equal(await store.reserveEncryptions(info.sessionId, 99, 10, 5), 2);
  assert.equal(await store.reserveEncryptions(info.sessionId, 99, 1, 5), 0);
  let ran = false;
  await store.lock("demo", async () => {
    ran = true;
  });
  assert.equal(ran, true);
  await assert.rejects(store.lock("demo", async () => store.lock("demo", async () => 1)), hasCode("conflict"));
  assert.equal(await store.save(loaded!, { sessionId: "other-session" }), false);
  assert.equal((await store.load())?.sessionId, info.sessionId);
  assert.equal(await store.clear({ sessionId: info.sessionId }), true);
  assert.equal(await store.load(), undefined);
  assert.equal(await store.reserveEncryptions(info.sessionId, 99, 1, 5), 1);
});

test("encryptionBlockSize rejects values that are not safe integers >= 1", () => {
  for (const encryptionBlockSize of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => new WakeClient({
      baseUrl: "https://example.com",
      getAssertion: async () => {
        throw new Error("unused");
      },
      encryptionBlockSize,
    }), hasCode("invalid_option"));
  }
});

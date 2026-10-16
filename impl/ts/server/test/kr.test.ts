// Spec §6, §8.6, §9: encrypted key rotation and atomic ceremony races.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Bytes, generateEphemeral, newApprovalId, newExchangeId } from "@wake-protocol/core";
import { SoftAuthenticator } from "../src/testing.ts";
import type { AssertionTamper } from "../src/testing.ts";
import { fixture, login, prepare, decode, encode, expectError, sendWire, ORIGIN, RP } from "./helpers.ts";
import type { Fixture } from "./helpers.ts";
import { completeKr, krClient, krError, krOpen, krRequest, krStart, krWire, prepareKr } from "./kr-helpers.ts";
import type { KrClient } from "./kr-helpers.ts";

async function session(f: Fixture, client: KrClient) {
  const state = await f.store.getSession(client.sessionId.toUint8Array());
  assert.ok(state);
  return state;
}

async function exchange(f: Fixture, id: string) {
  const state = await f.store.getExchange(decode(id), f.clock.now);
  assert.ok(state);
  return state;
}

function synchronizeLookups(f: Fixture): number[] {
  const lookup = f.credentials.getCredential.bind(f.credentials);
  const counts: number[] = [];
  let release!: () => void;
  const ready = new Promise<void>(resolve => { release = resolve; });
  f.credentials.getCredential = async id => {
    const credential = await lookup(id);
    if (counts.length < 2) {
      assert.ok(credential);
      counts.push(credential.signCount);
      if (counts.length === 2) {
        release();
      }
      await ready;
    }
    return credential;
  };
  return counts;
}

test("KR verifies Finished, changes keys and authTime, preserves sessionId and other sessions", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const other = krClient(await login(f));
  const before = await session(f, client);
  const info = await krStart(f, client);
  assert.deepEqual(Object.keys(info).sort(), ["epoch", "exchangeId", "expiresAt", "serverNonce", "serverPublicKey", "webauthn"]);
  assert.equal(decode(info.exchangeId).length, 16);
  assert.equal(decode(info.serverNonce).length, 32);
  assert.equal(decode(info.serverPublicKey).length, 65);
  assert.equal(info.expiresAt, f.clock.now + 300000);
  const pending = await exchange(f, info.exchangeId);
  assert.equal(pending.kind, "rekey");
  assert.equal(pending.targetEpoch, 1);
  assert.ok(pending.prevTh?.equals(client.th));
  assert.ok(pending.serverPrivateKey);
  f.clock.now += 100;
  const p = await prepareKr(f, client, {}, f.auth, info);
  const result = await completeKr(f, client, p);
  assert.equal(result.header.epoch, 0);
  const state = await session(f, client);
  assert.equal(state.currentEpoch, 1);
  assert.equal(state.authTime, f.clock.now);
  assert.equal(state.hardCapAt, before.hardCapAt);
  assert.equal(state.absoluteExpiresAt, before.absoluteExpiresAt + 100);
  assert.ok(state.currentKeys?.th.equals(p.th));
  assert.ok(state.prevKeys?.th.equals(client.th));
  assert.equal(state.currentKeys?.c2sCount, 0);
  assert.equal(state.currentKeys?.s2cCount, 0);
  assert.equal(state.currentKeys?.c2s.extractable, false);
  assert.equal(state.currentKeys?.s2c.extractable, false);
  assert.equal(state.prevValidUntil, f.clock.now + 60000);
  const completed = await exchange(f, info.exchangeId);
  assert.equal(completed.state, "COMPLETED");
  assert.equal(completed.serverPrivateKey, undefined);
  assert.ok(completed.th?.equals(p.th));
  assert.ok(completed.clientFinished?.equals(p.finished));
  assert.equal((await krRequest(f, p.next, "wake/session")).json.epoch, 1);
  assert.equal((await krRequest(f, other, "wake/session")).json.epoch, 0);
});

for (const offset of [-1, 0, 1]) {
  test(`real KR old epoch grace boundary ${offset}`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    await completeKr(f, client, p);
    f.clock.now = (await session(f, client)).prevValidUntil! + offset;
    const request = await krWire(f, client, "wake/session");
    const response = await sendWire(f, request);
    if (offset <= 0) {
      assert.equal((await krOpen(client, request, response)).json.epoch, 1);
    } else {
      await expectError(response, 401, "epoch_retired", true);
    }
    await f.store.sweep(f.clock.now);
    assert.equal(Boolean((await session(f, client)).prevKeys), offset <= 0);
    assert.equal((await krRequest(f, p.next, "wake/session")).json.epoch, 1);
  });
}

test("KR lost completion replay reseals identical plaintext with the new requestId and skips assertion verification", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  const a = await completeKr(f, client, p);
  f.clock.now++;
  const b = await krRequest(f, client, "wake/kr/complete", { ...p.body, assertion: { bad: true } });
  assert.equal(a.text, b.text);
  assert.ok(!a.header.requestId.equals(b.header.requestId));
  assert.ok(!a.header.iv.equals(b.header.iv));
  await krError(f, client, "wake/kr/complete", { ...p.body, clientFinished: encode(new Uint8Array(32)) }, "webauthn_failed");
  const different = await generateEphemeral();
  await krError(f, client, "wake/kr/complete", {
    ...p.body, clientPublicKey: encode(different.publicKey.toUint8Array()),
  }, "webauthn_failed");
  assert.equal((await session(f, client)).currentEpoch, 1);
});

test("two KRs retire epoch zero immediately and replay first exchange using its stored transcript", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const first = await prepareKr(f, client);
  const original = await completeKr(f, client, first);
  const second = await prepareKr(f, first.next);
  await completeKr(f, first.next, second);
  await expectError(await sendWire(f, await krWire(f, client, "wake/session")), 401, "epoch_retired", true);
  assert.equal((await krRequest(f, first.next, "wake/session")).json.epoch, 2);
  assert.equal((await krRequest(f, second.next, "wake/session")).json.epoch, 2);
  const replay = await krRequest(f, first.next, "wake/kr/complete", first.body);
  assert.equal(replay.text, original.text);
  assert.equal(replay.header.epoch, 1);
  await expectError(await sendWire(f, await krWire(f, { ...second.next, epoch: 3 }, "wake/session")), 401, "reauth", true);
});

test("competing KR exchange conflicts and loses its private key", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const a = await prepareKr(f, client);
  const b = await prepareKr(f, client);
  await completeKr(f, client, a);
  await krError(f, client, "wake/kr/complete", b.body, "conflict");
  assert.equal((await exchange(f, b.info.exchangeId)).state, "SUPERSEDED");
  assert.equal((await exchange(f, b.info.exchangeId)).serverPrivateKey, undefined);
  await krError(f, client, "wake/kr/complete", b.body, "expired");
});

for (const maxPendingRekeys of [undefined, 1, 16]) {
  test(`KR pending limit ${maxPendingRekeys ?? "default 3"} supersedes the oldest only`, async () => {
    const f = await fixture(maxPendingRekeys === undefined ? {} : { maxPendingRekeys });
    const client = krClient(await login(f));
    const limit = maxPendingRekeys ?? 3;
    const ids: string[] = [];
    for (let i = 0; i <= limit; i++) {
      ids.push((await krStart(f, client)).exchangeId);
      f.clock.now++;
    }
    for (const [index, id] of ids.entries()) {
      const ex = await exchange(f, id);
      assert.equal(ex.state, index === 0 ? "SUPERSEDED" : "PENDING");
      assert.equal(Boolean(ex.serverPrivateKey), index !== 0);
    }
  });
}

test("KR start lists active credentials belonging to session user without transports", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const second = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const suspended = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
  f.credentials.setCredential(second.credential);
  f.credentials.setCredential({ ...suspended.credential, status: "suspended" });
  f.credentials.setCredential(other.credential);
  const info = await krStart(f, client);
  assert.deepEqual(info.webauthn.allowCredentials.map(c => c.id).sort(), [
    encode(f.auth.credential.credentialId), encode(second.credential.credentialId),
  ].sort());
  assert.ok(info.webauthn.allowCredentials.every(c => Object.keys(c).sort().join(",") === "id,type"));
  assert.equal(info.webauthn.rpId, RP);
  assert.equal(info.webauthn.userVerification, "required");
  assert.equal(info.webauthn.timeout, 270000);
});

for (const [name, tamper] of [
  ["origin other allowed login origin", { origin: "https://other.example.com" }],
  ["challenge mismatch", { challenge: new Uint8Array(32) }],
  ["cross origin", { crossOrigin: true }],
  ["RP mismatch", { rpId: "other.example.com" }],
  ["UP absent", { clearFlags: 1 }],
  ["UV absent", { clearFlags: 4 }],
  ["wrong userHandle", { userHandle: new Uint8Array([1]) }],
  ["corrupt signature", { corruptSignature: true }],
] satisfies [string, AssertionTamper][]) {
  test(`KR rejects ${name} without consuming exchange`, async () => {
    const f = await fixture({ loginOrigins: [ORIGIN, "https://other.example.com"] });
    const client = krClient(await login(f));
    const p = await prepareKr(f, client, tamper);
    await krError(f, client, "wake/kr/complete", p.body, "webauthn_failed");
    assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
    assert.ok((await exchange(f, p.info.exchangeId)).serverPrivateKey);
    assert.equal((await session(f, client)).currentEpoch, 0);
  });
}

test("KR rejects a correctly signed credential belonging to another user", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
  f.credentials.setCredential(other.credential);
  const p = await prepareKr(f, client, {}, other);
  await krError(f, client, "wake/kr/complete", p.body, "webauthn_failed");
  assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
});

for (const status of ["pending", "suspended", "deleted"] as const) {
  test(`KR rejects ${status} credential and leaves exchange available`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    const credential = await f.credentials.getCredential(f.auth.credential.credentialId);
    assert.ok(credential);
    f.credentials.setCredential({ ...credential, status });
    await krError(f, client, "wake/kr/complete", p.body, "webauthn_failed");
    assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
  });
}

test("KR wrong Finished does not advance sign counter and correct retry succeeds", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  const before = (await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount;
  await krError(f, client, "wake/kr/complete", { ...p.body, clientFinished: encode(new Uint8Array(32)) }, "webauthn_failed");
  assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, before);
  await completeKr(f, client, p);
});

for (const offset of [-1, 0]) {
  test(`KR exchange expiry boundary ${offset}`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    f.clock.now = p.info.expiresAt + offset;
    if (offset < 0) {
      await completeKr(f, client, p);
    } else {
      await krError(f, client, "wake/kr/complete", p.body, "expired");
      assert.equal((await exchange(f, p.info.exchangeId)).state, "EXPIRED");
      assert.equal((await exchange(f, p.info.exchangeId)).serverPrivateKey, undefined);
    }
  });
}

for (const kind of ["unknown", "other session", "login", "approval bound"] as const) {
  test(`KR exchange ${kind} returns not_found`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    let body = p.body;
    if (kind === "unknown") {
      body = { ...body, exchangeId: encode(newExchangeId().toUint8Array()) };
    } else if (kind === "other session") {
      const other = krClient(await login(f));
      await krError(f, other, "wake/kr/complete", body, "not_found");
      return;
    } else if (kind === "login") {
      body = { ...body, exchangeId: (await prepare(f)).info.exchangeId };
    } else {
      const ex = await exchange(f, p.info.exchangeId);
      const id = newExchangeId();
      await f.store.createExchange({ ...ex, exchangeId: id, boundApprovalId: newApprovalId() });
      body = { ...body, exchangeId: encode(id.toUint8Array()) };
    }
    await krError(f, client, "wake/kr/complete", body, "not_found");
  });
}

for (const delay of [200, 600]) {
  test(`KR extends absolute expiration ${delay < 500 ? "below cap" : "to cap"}`, async () => {
    const f = await fixture({ authLifetimeMs: 1000, hardCapMs: 1500 });
    const client = krClient(await login(f));
    const original = await session(f, client);
    f.clock.now += delay;
    const p = await prepareKr(f, client);
    const result = await completeKr(f, client, p);
    assert.equal(result.json.absoluteExpiresAt, Math.min(original.hardCapAt, f.clock.now + 1000));
    const info = (await krRequest(f, p.next, "wake/session")).json;
    assert.equal(info.authTime, f.clock.now);
    assert.equal(info.hardCapAt, original.hardCapAt);
    assert.equal(info.epoch, 1);
  });
}

for (const context of ["wake/kr/start", "wake/kr/complete"]) {
  for (const plaintext of ["null", "[]", "1", "{", '{"x":1,"x":2}', '{"x":"\\ud800"}', '{"x":9007199254740992}', new Uint8Array([255])]) {
    test(`${context} rejects strict JSON ${String(plaintext)}`, async () => {
      const f = await fixture();
      const client = krClient(await login(f));
      await krError(f, client, context, plaintext, "invalid_request");
    });
  }
}

for (const field of ["exchangeId", "clientPublicKey", "clientFinished"] as const) {
  for (const value of [undefined, null, 1, "AA=", "A", "", encode(new Uint8Array(15))]) {
    test(`KR complete rejects malformed ${field} ${String(value)}`, async () => {
      const f = await fixture();
      const client = krClient(await login(f));
      const p = await prepareKr(f, client);
      await krError(f, client, "wake/kr/complete", { ...p.body, [field]: value }, "invalid_request");
      assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
    });
  }
}

for (const assertion of [undefined, null, 1, [], "x"]) {
  test(`KR complete rejects nonobject assertion ${String(assertion)}`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    await krError(f, client, "wake/kr/complete", { ...p.body, assertion }, "invalid_request");
  });
}

test("KR rejects a correctly sized public key off the P-256 curve", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  const point = new Uint8Array(65);
  point[0] = 4;
  await krError(f, client, "wake/kr/complete", { ...p.body, clientPublicKey: encode(point) }, "invalid_request");
});

test("KR ignores unknown request members", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const info = (await krRequest(f, client, "wake/kr/start", { future: true })).json;
  const p = await prepareKr(f, client, {}, f.auth, info as unknown as Awaited<ReturnType<typeof krStart>>);
  assert.equal((await krRequest(f, client, "wake/kr/complete", { ...p.body, future: { value: 1 } })).json.epoch, 1);
});

test("concurrent BE=0 KRs with the same counter let exactly one commit", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const a = await prepareKr(f, client, { signCount: 2 });
  const b = await prepareKr(f, client, { signCount: 2 });
  const counts = synchronizeLookups(f);
  const requests = await Promise.all([krWire(f, client, "wake/kr/complete", a.body), krWire(f, client, "wake/kr/complete", b.body)]);
  const results = await Promise.all(requests.map(request => sendWire(f, request)));
  let success = 0;
  let retried = 0;
  for (const [index, result] of results.entries()) {
    if (result.status === 503) {
      await expectError(result, 503, "retry", true);
      retried++;
    } else {
      const json = (await krOpen(client, requests[index]!, result)).json;
      if (json.epoch === 1) {
        success++;
      } else {
        assert.deepEqual(json, { error: { code: "conflict" } });
      }
    }
  }
  assert.equal(success, 1);
  assert.deepEqual(counts, [1, 1]);
  assert.ok(retried <= 1);
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 2);
  assert.equal((await session(f, client)).currentEpoch, 1);
  const states = await Promise.all([exchange(f, a.info.exchangeId), exchange(f, b.info.exchangeId)]);
  assert.equal(states.filter(ex => ex.state === "COMPLETED").length, 1);
});

test("KR BE=1 counter anomaly updates max and notifies once across replay", async () => {
  const events: unknown[] = [];
  const f = await fixture({ onCounterAnomaly: event => { events.push(event); } }, {
    rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: true,
  });
  const client = krClient(await login(f));
  const p = await prepareKr(f, client, { signCount: 0 });
  await completeKr(f, client, p);
  await completeKr(f, client, p);
  assert.equal(events.length, 1);
  assert.deepEqual(events[0], {
    credentialId: f.auth.credential.credentialId, userId: "u1", storedSignCount: 1, receivedSignCount: 0,
  });
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 1);
  assert.equal((await exchange(f, p.info.exchangeId)).signCountUpdate, undefined);
});

for (const revoke of ["logout", "session", "user", "credential"] as const) {
  test(`${revoke} supersedes real pending KR exchanges and erases keys`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const a = await krStart(f, client);
    const b = await krStart(f, client);
    if (revoke === "logout") {
      assert.deepEqual((await krRequest(f, client, "wake/logout")).json, {});
    } else if (revoke === "session") {
      await f.server.revokeSession(client.sessionId.toUint8Array());
    } else if (revoke === "user") {
      await f.server.revokeSessionsByUser("u1");
    } else {
      await f.server.revokeSessionsByCredential(f.auth.credential.credentialId);
    }
    for (const id of [a.exchangeId, b.exchangeId]) {
      assert.equal((await exchange(f, id)).state, "SUPERSEDED");
      assert.equal((await exchange(f, id)).serverPrivateKey, undefined);
    }
    const state = await session(f, client);
    assert.equal(state.status, "REVOKED");
    assert.equal(state.currentKeys, undefined);
    assert.equal(state.prevKeys, undefined);
    await expectError(await sendWire(f, await krWire(f, client, "wake/session")), 401, "reauth", true);
  });
}

test("revoking credential B revokes a session logged in with A and rekeyed with B", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential(other.credential);
  const p = await prepareKr(f, client, {}, other);
  await completeKr(f, client, p);
  const state = await session(f, client);
  assert.ok(new Bytes(state.loginCredentialId).equals(new Bytes(f.auth.credential.credentialId)));
  assert.ok(new Bytes(state.lastAuthCredentialId).equals(new Bytes(other.credential.credentialId)));
  await f.server.revokeSessionsByCredential(other.credential.credentialId);
  assert.equal((await session(f, client)).status, "REVOKED");
});

for (const status of ["suspended", "deleted"] as const) {
  test(`KR postcommit ${status} credential B revokes session and returns outer reauth`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
    f.credentials.setCredential(other.credential);
    const p = await prepareKr(f, client, {}, other);
    const commit = f.store.commitRekey.bind(f.store);
    f.store.commitRekey = async value => {
      const result = await commit(value);
      if (result === "committed") {
        const credential = await f.credentials.getCredential(other.credential.credentialId);
        assert.ok(credential);
        f.credentials.setCredential({ ...credential, status });
      }
      return result;
    };
    await expectError(await sendWire(f, await krWire(f, client, "wake/kr/complete", p.body)), 401, "reauth", true);
    assert.equal((await exchange(f, p.info.exchangeId)).state, "COMPLETED");
    assert.equal((await session(f, client)).status, "REVOKED");
    assert.equal((await session(f, client)).currentKeys, undefined);
  });
}

test("concurrent KR starts enforce the pending limit atomically", async () => {
  const f = await fixture({ maxPendingRekeys: 1 });
  const client = krClient(await login(f));
  const starts = await Promise.all(Array.from({ length: 8 }, () => krStart(f, client)));
  const states = await Promise.all(starts.map(info => exchange(f, info.exchangeId)));
  assert.equal(states.filter(ex => ex.state === "PENDING").length, 1);
  assert.equal(states.filter(ex => ex.state === "SUPERSEDED").length, 7);
  assert.equal(states.filter(ex => ex.serverPrivateKey !== undefined).length, 1);
});

for (const event of ["logout", "epoch change"] as const) {
  test(`KR start handles ${event} during asynchronous credential lookup`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = event === "epoch change" ? await prepareKr(f, client) : undefined;
    const find = f.credentials.findUserCredentials.bind(f.credentials);
    f.credentials.findUserCredentials = async userId => {
      const result = await find(userId);
      if (p) {
        await completeKr(f, client, p);
      } else {
        await f.store.revokeSession(client.sessionId.toUint8Array());
      }
      return result;
    };
    const request = await krWire(f, client, "wake/kr/start");
    const response = await sendWire(f, request);
    if (p) {
      assert.deepEqual((await krOpen(client, request, response)).json, { error: { code: "conflict" } });
    } else {
      await expectError(response, 401, "reauth", true);
    }
  });
}

test("KR exchange expiring during counter CAS cannot commit", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
  f.credentials.compareAndSetSignCount = async (...args) => {
    const result = await compare(...args);
    f.clock.now = p.info.expiresAt;
    return result;
  };
  await krError(f, client, "wake/kr/complete", p.body, "expired");
  assert.equal((await exchange(f, p.info.exchangeId)).state, "EXPIRED");
  assert.equal((await session(f, client)).currentEpoch, 0);
});

test("KR logout during counter CAS prevents atomic commit", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
  f.credentials.compareAndSetSignCount = async (...args) => {
    const result = await compare(...args);
    await f.store.revokeSession(client.sessionId.toUint8Array());
    return result;
  };
  await expectError(await sendWire(f, await krWire(f, client, "wake/kr/complete", p.body)), 401, "reauth", true);
  assert.equal((await exchange(f, p.info.exchangeId)).state, "SUPERSEDED");
  assert.equal((await session(f, client)).currentEpoch, 0);
});

test("BE=0 KR CAS loser returns outer retry while winning exchange is still pending", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const a = await prepareKr(f, client, { signCount: 2 });
  const b = await prepareKr(f, client, { signCount: 2 });
  const counts = synchronizeLookups(f);
  let signalBeforeCommit!: () => void;
  const beforeCommit = new Promise<void>(resolve => { signalBeforeCommit = resolve; });
  let releaseCommit!: () => void;
  const commitAllowed = new Promise<void>(resolve => { releaseCommit = resolve; });
  const commit = f.store.commitRekey.bind(f.store);
  f.store.commitRekey = async value => {
    signalBeforeCommit();
    await commitAllowed;
    return commit(value);
  };
  const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
  let comparisons = 0;
  f.credentials.compareAndSetSignCount = async (...args) => {
    if (++comparisons === 2) {
      await beforeCommit;
    }
    return compare(...args);
  };
  const wires = await Promise.all([krWire(f, client, "wake/kr/complete", a.body), krWire(f, client, "wake/kr/complete", b.body)]);
  const responses = wires.map(request => sendWire(f, request));
  try {
    const loser = await Promise.race(responses);
    await expectError(loser.clone(), 503, "retry", true);
    assert.equal((await exchange(f, a.info.exchangeId)).state, "PENDING");
    assert.equal((await exchange(f, b.info.exchangeId)).state, "PENDING");
  } finally {
    releaseCommit();
  }
  const all = await Promise.all(responses);
  assert.deepEqual(all.map(result => result.status).sort(), [200, 503]);
  assert.deepEqual(counts, [1, 1]);
  const losingBody = all[0]!.status === 503 ? a.body : b.body;
  await krError(f, client, "wake/kr/complete", losingBody, "conflict");
});

for (const backupEligible of [false, true]) {
  test(`identical concurrent KR completions replay one commit (BE=${backupEligible})`, async () => {
    const f = await fixture({}, { rpId: RP, origin: ORIGIN, userId: "u1", backupEligible });
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    const counts = synchronizeLookups(f);
    let signalCommitted!: () => void;
    const committed = new Promise<void>(resolve => { signalCommitted = resolve; });
    let successes = 0;
    const commit = f.store.commitRekey.bind(f.store);
    f.store.commitRekey = async value => {
      const result = await commit(value);
      if (result === "committed") {
        successes++;
        signalCommitted();
      }
      return result;
    };
    const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
    let comparisons = 0;
    f.credentials.compareAndSetSignCount = async (...args) => {
      if (++comparisons === 2) {
        await committed;
      }
      return compare(...args);
    };
    const [a, b] = await Promise.all([
      krRequest(f, client, "wake/kr/complete", p.body), krRequest(f, client, "wake/kr/complete", p.body),
    ]);
    assert.equal(a.text, b.text);
    assert.equal(a.json.epoch, 1);
    assert.equal(successes, 1);
    assert.deepEqual(counts, [1, 1]);
    assert.equal(comparisons, backupEligible ? 0 : 2);
  });
}

for (const anomaly of [false, true]) {
  test(`KR deferred counter update failure retries on replay (anomaly=${anomaly})`, async () => {
    let notifications = 0;
    const f = await fixture({ onCounterAnomaly: () => { notifications++; } }, {
      rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: true,
    });
    const client = krClient(await login(f));
    const p = await prepareKr(f, client, { signCount: anomaly ? 0 : 3 });
    const update = f.credentials.updateSignCount.bind(f.credentials);
    let attempts = 0;
    f.credentials.updateSignCount = async (...args) => {
      if (++attempts === 1) {
        throw new Error("transient credential store failure");
      }
      await update(...args);
    };
    await krError(f, client, "wake/kr/complete", p.body, "internal");
    assert.equal((await exchange(f, p.info.exchangeId)).state, "COMPLETED");
    assert.ok((await exchange(f, p.info.exchangeId)).signCountUpdate);
    assert.equal(notifications, 0);
    await completeKr(f, client, p);
    await completeKr(f, client, p);
    assert.equal(attempts, 2);
    assert.equal(notifications, anomaly ? 1 : 0);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, anomaly ? 1 : 3);
    assert.equal((await exchange(f, p.info.exchangeId)).signCountUpdate, undefined);
  });
}

test("KR failed anomaly callback preserves commit and never notifies twice on replay", async () => {
  let notifications = 0;
  const f = await fixture({ onCounterAnomaly: () => {
    notifications++;
    throw new Error("audit unavailable");
  } }, { rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: true });
  const client = krClient(await login(f));
  const p = await prepareKr(f, client, { signCount: 0 });
  await expectError(await sendWire(f, await krWire(f, client, "wake/kr/complete", p.body)), 503, "retry", true);
  assert.equal((await exchange(f, p.info.exchangeId)).state, "COMPLETED");
  await completeKr(f, client, p);
  await completeKr(f, client, p);
  assert.equal(notifications, 1);
});

test("replay checks the credential used by its KR even after another KR changes lastAuthCredentialId", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const b = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const c = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential(b.credential);
  f.credentials.setCredential(c.credential);
  const first = await prepareKr(f, client, {}, b);
  await completeKr(f, client, first);
  const second = await prepareKr(f, first.next, {}, c);
  await completeKr(f, first.next, second);
  const credential = await f.credentials.getCredential(b.credential.credentialId);
  assert.ok(credential);
  f.credentials.setCredential({ ...credential, status: "suspended" });
  await expectError(await sendWire(f, await krWire(f, first.next, "wake/kr/complete", first.body)), 401, "reauth", true);
  assert.equal((await session(f, client)).status, "REVOKED");
});

test("logout using real KR previous epoch seals its response before deleting both epochs", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  await completeKr(f, client, p);
  const pending = await krStart(f, p.next);
  const result = await krRequest(f, client, "wake/logout");
  assert.equal(result.header.epoch, 0);
  assert.deepEqual(result.json, {});
  const state = await session(f, client);
  assert.equal(state.status, "REVOKED");
  assert.equal(state.currentKeys, undefined);
  assert.equal(state.prevKeys, undefined);
  assert.equal((await exchange(f, pending.exchangeId)).state, "SUPERSEDED");
  await expectError(await sendWire(f, await krWire(f, p.next, "wake/session")), 401, "reauth", true);
});

for (const outcome of ["expired", "conflict"] as const) {
  test(`KR pending ${outcome} check precedes malformed public key`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    if (outcome === "expired") {
      f.clock.now = p.info.expiresAt;
    } else {
      await completeKr(f, client, await prepareKr(f, client));
    }
    await krError(f, client, "wake/kr/complete", { ...p.body, clientPublicKey: "bad=" }, outcome);
  });
}

for (const field of ["exchangeId", "clientFinished", "clientPublicKey"] as const) {
  test(`KR rejects nonzero unused Base64url bits in ${field}`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const value = p.body[field];
    const last = alphabet.indexOf(value.at(-1)!);
    const mask = field === "exchangeId" ? 15 : 3;
    assert.equal(last & mask, 0);
    const noncanonical = value.slice(0, -1) + alphabet[last | 1]!;
    await krError(f, client, "wake/kr/complete", { ...p.body, [field]: noncanonical }, "invalid_request");
  });
}

for (const row of [
  { stored: 0, received: 0, backupEligible: false, flags: 5, accepted: true },
  { stored: 1, received: 2, backupEligible: false, flags: 5, accepted: true },
  { stored: 2, received: 2, backupEligible: false, flags: 13, accepted: false },
  { stored: 2, received: 1, backupEligible: false, flags: 13, accepted: false },
  { stored: 2, received: 2, backupEligible: true, flags: 5, accepted: true },
  { stored: 2, received: 1, backupEligible: true, flags: 5, accepted: true },
]) {
  test(`KR registered BE counter rule ${JSON.stringify(row)}`, async () => {
    const f = await fixture({}, { rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: row.backupEligible });
    const client = krClient(await login(f, { signCount: row.stored }));
    const p = await prepareKr(f, client, { signCount: row.received, flags: row.flags });
    if (row.accepted) {
      await completeKr(f, client, p);
      assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, Math.max(row.stored, row.received));
    } else {
      await krError(f, client, "wake/kr/complete", p.body, "webauthn_failed");
      assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
    }
  });
}

test("MemoryCredentialStore user lookup returns isolated copies of only that user's credentials", async () => {
  const f = await fixture();
  const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
  f.credentials.setCredential(other.credential);
  const found = await f.credentials.findUserCredentials("u1");
  assert.equal(found.length, 1);
  assert.ok(new Bytes(found[0]!.credentialId).equals(new Bytes(f.auth.credential.credentialId)));
  found[0]!.credentialId.fill(0);
  found[0]!.publicKey.fill(0);
  found[0]!.userHandle.fill(0);
  found[0]!.status = "deleted";
  assert.deepEqual(await f.credentials.findUserCredentials("missing"), []);
  const fresh = (await f.credentials.findUserCredentials("u1"))[0]!;
  assert.equal(fresh.status, "active");
  assert.ok(new Bytes(fresh.credentialId).equals(new Bytes(f.auth.credential.credentialId)));
  assert.ok(new Bytes(fresh.publicKey).equals(new Bytes(f.auth.credential.publicKey)));
  assert.ok(new Bytes(fresh.userHandle).equals(new Bytes(f.auth.credential.userHandle)));
});

test("distinct concurrent BE=1 KRs atomically commit only one epoch", async () => {
  const f = await fixture({}, { rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: true });
  const client = krClient(await login(f));
  const a = await prepareKr(f, client);
  const b = await prepareKr(f, client);
  const counts = synchronizeLookups(f);
  f.credentials.compareAndSetSignCount = async () => { throw new Error("BE=1 must not use counter CAS"); };
  const results = await Promise.all([
    krRequest(f, client, "wake/kr/complete", a.body),
    krRequest(f, client, "wake/kr/complete", b.body),
  ]);
  assert.equal(results.filter(result => result.json.epoch === 1).length, 1);
  const losing = results.find(result => result.json.epoch !== 1);
  assert.deepEqual(losing?.json, { error: { code: "conflict" } });
  assert.deepEqual(counts, [1, 1]);
  assert.equal((await session(f, client)).currentEpoch, 1);
  const states = await Promise.all([exchange(f, a.info.exchangeId), exchange(f, b.info.exchangeId)]);
  assert.deepEqual(states.map(ex => ex.state).sort(), ["COMPLETED", "SUPERSEDED"]);
  assert.ok(states.every(ex => ex.serverPrivateKey === undefined));
});

test("session expiring during awaited KR counter CAS cannot update its epoch", async () => {
  const f = await fixture({ authLifetimeMs: 1000, hardCapMs: 1500 });
  const client = krClient(await login(f));
  const p = await prepareKr(f, client);
  const before = await session(f, client);
  const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
  f.credentials.compareAndSetSignCount = async (...args) => {
    const result = await compare(...args);
    f.clock.now = before.absoluteExpiresAt;
    return result;
  };
  await expectError(await sendWire(f, await krWire(f, client, "wake/kr/complete", p.body)), 401, "reauth", true);
  const expired = await session(f, client);
  assert.equal(expired.currentEpoch, 0);
  assert.equal(expired.absoluteExpiresAt, before.absoluteExpiresAt);
  assert.equal(expired.status, "EXPIRED");
  assert.equal(expired.currentKeys, undefined);
  assert.equal(expired.prevKeys, undefined);
  const superseded = await exchange(f, p.info.exchangeId);
  assert.equal(superseded.state, "SUPERSEDED");
  assert.equal(superseded.serverPrivateKey, undefined);
});

test("KR start expiring during credential lookup deletes both epochs before the next sweep", async () => {
  const f = await fixture({ authLifetimeMs: 1000, hardCapMs: 1500 });
  const client = krClient(await login(f));
  f.clock.now += 100;
  const p = await prepareKr(f, client);
  await completeKr(f, client, p);
  const pending = await krStart(f, p.next);
  const before = await session(f, p.next);
  assert.ok(before.currentKeys);
  assert.ok(before.prevKeys);
  const find = f.credentials.findUserCredentials.bind(f.credentials);
  f.credentials.findUserCredentials = async userId => {
    const credentials = await find(userId);
    f.clock.now = before.absoluteExpiresAt;
    return credentials;
  };
  await expectError(await sendWire(f, await krWire(f, p.next, "wake/kr/start")), 401, "reauth", true);
  const expired = await session(f, p.next);
  assert.equal(expired.currentEpoch, 1);
  assert.equal(expired.absoluteExpiresAt, before.absoluteExpiresAt);
  assert.equal(expired.status, "EXPIRED");
  assert.equal(expired.currentKeys, undefined);
  assert.equal(expired.prevKeys, undefined);
  const superseded = await exchange(f, pending.exchangeId);
  assert.equal(superseded.state, "SUPERSEDED");
  assert.equal(superseded.serverPrivateKey, undefined);
});

for (const [field, length] of [
  ["exchangeId", 15], ["exchangeId", 17],
  ["clientFinished", 31], ["clientFinished", 33],
  ["clientPublicKey", 64], ["clientPublicKey", 66],
] as const) {
  test(`KR complete rejects ${field} length ${length} beside its exact accepted boundary`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const p = await prepareKr(f, client);
    await krError(f, client, "wake/kr/complete", { ...p.body, [field]: encode(new Uint8Array(length)) }, "invalid_request");
    assert.equal((await exchange(f, p.info.exchangeId)).state, "PENDING");
    await completeKr(f, client, p);
  });
}

test("revoking an intermediate KR credential revokes the session after later rekeys", async () => {
  const f = await fixture();
  const client = krClient(await login(f));
  const b = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const c = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential(b.credential);
  f.credentials.setCredential(c.credential);
  const middle = await prepareKr(f, client, {}, b);
  await completeKr(f, client, middle);
  const latest = await prepareKr(f, middle.next, {}, c);
  await completeKr(f, middle.next, latest);
  const repeated = await prepareKr(f, latest.next, {}, c);
  await completeKr(f, latest.next, repeated);
  assert.deepEqual((await session(f, repeated.next)).authCredentialIds, [
    f.auth.credential.credentialId, b.credential.credentialId, c.credential.credentialId,
  ]);
  await f.server.revokeSessionsByCredential(new Uint8Array([0]));
  assert.equal((await session(f, repeated.next)).status, "ACTIVE");
  await f.server.revokeSessionsByCredential(b.credential.credentialId);
  assert.equal((await session(f, repeated.next)).status, "REVOKED");
  await expectError(await sendWire(f, await krWire(f, repeated.next, "wake/session")), 401, "reauth", true);
});

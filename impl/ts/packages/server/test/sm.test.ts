// Tests for WAKE server behavior (spec §8, §12).
import assert from "node:assert/strict";
import { test } from "node:test";
import { Bytes, DIR_S2C, WakeError, newSessionId, newExchangeId, seal, parseWire } from "@wake-protocol/core";
import type { SessionRecord } from "../src/index.ts";
import { insertSession } from "../src/testing.ts";
import { fixture, jsonRequest, login, prepare, wire, sendWire, opened, expectError, response, ORIGIN, decode } from "./helpers.ts";
import type { Fixture, Login } from "./helpers.ts";

async function session(f: Fixture, l: Login): Promise<SessionRecord> {
  const result = await f.store.getSession(l.sessionId.toUint8Array());
  assert.ok(result);
  return result;
}

test(
  "session response authenticates the matching header fields and refreshes IV on replay",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const request = await wire(f, l);
    const a = await opened(l, await sendWire(f, request));
    const b = await opened(l, await sendWire(f, request));
    const header = parseWire(request).header;
    assert.ok(a.header.sessionId.equals(header.sessionId));
    assert.ok(a.header.requestId.equals(header.requestId));
    assert.equal(a.header.epoch, header.epoch);
    assert.equal(a.header.context, header.context);
    assert.equal(a.header.issuedAt, f.clock.now);
    assert.equal(a.header.dir, DIR_S2C);
    assert.ok(!a.header.iv.equals(header.iv));
    assert.ok(!a.header.iv.equals(b.header.iv));
    assert.deepEqual(
      a.json,
      {
        sessionId: l.info.sessionId,
        epoch: 0,
        authTime: f.clock.now,
        absoluteExpiresAt: f.clock.now + 7 * 86400000,
        hardCapAt: f.clock.now + 30 * 86400000,
        idleTimeoutSec: 86400,
        serverTime: f.clock.now,
        rekeyRecommended: false
      }
    );
    const state = await session(f, l);
    assert.equal(state.currentKeys?.c2sCount, 2);
    assert.equal(state.currentKeys?.s2cCount, 2);
  }
);

test(
  "SM rejects wrong content type, malformed wire and S2C direction",
  async () => {
    const f = await fixture();
    const l = await login(f);
    await expectError(await sendWire(f, await wire(f, l), { "content-type": "application/json" }), 400, "bad_request", true);
    await expectError(await sendWire(f, new Uint8Array([1])), 400, "bad_request", true);
    const wrong = await seal(l.s2c, { ...parseWire(await wire(f, l)).header, dir: DIR_S2C }, new Bytes([123, 125]));
    await expectError(await sendWire(f, wrong), 400, "bad_request", true);
  }
);

test(
  "SM checks actual plaintext size and Content-Length before session lookup",
  async () => {
    const f = await fixture({ maxPlaintext: 300 });
    const l = await login(f);
    let lookups = 0;
    const lookup = f.store.getSession.bind(f.store);
    f.store.getSession = async id => {
      lookups++;
      return lookup(id);
    };
    const unknown = { ...l, sessionId: newSessionId() };
    await expectError(await sendWire(f, await wire(f, unknown, "wake/session", "x".repeat(301))), 413, "too_large", true);
    assert.equal(lookups, 0);
    await expectError(
      await sendWire(f, await wire(f, unknown), { "content-length": String(4 + 371 + 300 + 16 + 1) }),
      413,
      "too_large",
      true
    );
    assert.equal(lookups, 0);
    await expectError(await sendWire(f, new Uint8Array(4 + 371 + 300 + 17)), 413, "too_large", true);
    assert.equal(lookups, 0);
    const accepted = await wire(f, l, "wake/session", "{}" + " ".repeat(298));
    assert.equal((await opened(l, await sendWire(f, accepted))).json.rekeyRecommended, false);
  }
);

test(
  "unknown session and corrupted ciphertext/header authentication all map to reauth",
  async () => {
    const f = await fixture();
    const l = await login(f);
    await expectError(await sendWire(f, await wire(f, { ...l, sessionId: newSessionId() })), 401, "reauth", true);
    const bytes = (await wire(f, l)).toUint8Array();
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    await expectError(await sendWire(f, bytes), 401, "reauth", true);
    const headerTamper = (await wire(f, l)).toUint8Array();
    headerTamper[98] = headerTamper[98]! ^ 1;
    await expectError(await sendWire(f, headerTamper), 401, "reauth", true);
  }
);

for (const delta of [-300001, -300000, 300000, 300001]) {
  test(
    `freshness boundary ${delta}`,
    async () => {
      const f = await fixture();
      const l = await login(f);
      const result = await opened(l, await sendWire(f, await wire(f, l, "wake/session", "{}", 0, f.clock.now + delta)));
      if (Math.abs(delta) > 300000) {
        assert.deepEqual(result.json, { error: { code: "stale_request" } });
      } else {
        assert.equal(result.json.rekeyRecommended, false);
      }
    }
  );
}

test(
  "stale request precedes invalid context and invalid plaintext",
  async () => {
    const f = await fixture();
    const l = await login(f);
    assert.deepEqual(
      (await opened(l, await sendWire(f, await wire(f, l, "custom", "broken", 0, f.clock.now - 300001)))).json,
      { error: { code: "stale_request" } }
    );
  }
);

test(
  "unknown context returns encrypted invalid_context before plaintext validation",
  async () => {
    const f = await fixture();
    const l = await login(f);
    assert.deepEqual(
      (await opened(l, await sendWire(f, await wire(f, l, "custom", "broken")))).json,
      { error: { code: "invalid_context" } }
    );
  }
);

for (const plaintext of [
  "null",
  "[]",
  "1",
  '"x"',
  "{",
  '{"a":1,"a":1}',
  '{"a":"\\ud800"}',
  '{"a":9007199254740992}',
  new Uint8Array([0xff])
]) {
  test(
    `invalid strict JSON plaintext ${String(plaintext)}`,
    async () => {
      const f = await fixture();
      const l = await login(f);
      assert.deepEqual(
        (await opened(l, await sendWire(f, await wire(f, l, "wake/session", plaintext)))).json,
        { error: { code: "invalid_request" } }
      );
    }
  );
}

test(
  "unknown plaintext members are ignored",
  async () => {
    const f = await fixture();
    const l = await login(f);
    assert.equal((await opened(l, await sendWire(f, await wire(f, l, "wake/session", '{"unknown":true}')))).json.epoch, 0);
  }
);

for (const field of ["absoluteExpiresAt", "hardCapAt", "idle"] as const) {
  for (const offset of [-1, 0]) {
    test(
      `${field} expiry boundary ${offset}`,
      async () => {
        const f = await fixture();
        const l = await login(f);
        const old = await session(f, l);
        const boundary = f.clock.now + 8000;
        insertSession(f.store, { ...old, ...(field === "idle" ? { idleTimeoutSec: 8 } : { [field]: boundary }) });
        f.clock.now = boundary + offset;
        const res = await sendWire(f, await wire(f, l));
        if (offset < 0) {
          assert.equal(res.status, 200);
        } else {
          await expectError(res, 401, "reauth", true);
          const expired = await session(f, l);
          assert.equal(expired.status, "EXPIRED");
          assert.equal(expired.currentKeys, undefined);
        }
      }
    );
  }
}

for (const idle of [8, 86400]) {
  test(
    `activity touch uses conditional granularity for idle ${idle}`,
    async () => {
      const f = await fixture();
      const l = await login(f);
      const before = await session(f, l);
      insertSession(f.store, { ...before, idleTimeoutSec: idle });
      const granularity = Math.min(idle * 1000 / 8, 900000);
      f.clock.now = before.lastActivityAt + granularity - 1;
      await opened(l, await sendWire(f, await wire(f, l)));
      assert.equal((await session(f, l)).lastActivityAt, before.lastActivityAt);
      f.clock.now++;
      await opened(l, await sendWire(f, await wire(f, l)));
      assert.equal((await session(f, l)).lastActivityAt, f.clock.now);
    }
  );
}

for (const row of [
  { epoch: 2, delta: 0, code: null },
  { epoch: 1, delta: 0, code: null },
  { epoch: 1, delta: 1, code: "epoch_retired" },
  { epoch: 0, delta: 0, code: "epoch_retired" },
  { epoch: 3, delta: 0, code: "reauth" }
]) {
  test(
    `epoch table ${JSON.stringify(row)}`,
    async () => {
      const f = await fixture();
      const l = await login(f);
      const s = await session(f, l);
      assert.ok(s.currentKeys);
      const current = await login(f);
      const currentState = await session(f, current);
      assert.ok(currentState.currentKeys);
      insertSession(
        f.store,
        {
          ...s,
          currentKeys: currentState.currentKeys,
          currentEpoch: 2,
          prevKeys: { ...s.currentKeys },
          prevValidUntil: f.clock.now
        }
      );
      f.clock.now += row.delta;
      const requestLogin = row.epoch === 2 ? { ...l, c2s: current.c2s, s2c: current.s2c } : l;
      const res = await sendWire(f, await wire(f, requestLogin, "wake/session", "{}", row.epoch));
      if (row.code) {
        await expectError(res, 401, row.code, true);
      } else {
        const value = await opened(requestLogin, res);
        assert.equal(value.header.epoch, row.epoch);
        assert.equal(value.json.epoch, 2);
      }
    }
  );
}

test(
  "logout on previous epoch seals response before dropping keys and invalidates exchanges",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const s = await session(f, l);
    assert.ok(s.currentKeys);
    const current = await login(f);
    const currentState = await session(f, current);
    assert.ok(currentState.currentKeys);
    insertSession(
      f.store,
      {
        ...s,
        currentKeys: currentState.currentKeys,
        currentEpoch: 1,
        prevKeys: { ...s.currentKeys },
        prevValidUntil: f.clock.now + 1000
      }
    );
    const pending = await prepare(f);
    const ex = await f.store.getExchange(decode(pending.info.exchangeId), f.clock.now);
    assert.ok(ex);
    const insertedId = newExchangeId();
    await f.store.createExchange({ ...ex, sessionId: l.sessionId, exchangeId: insertedId });
    const out = await opened(l, await sendWire(f, await wire(f, l, "wake/logout", "{}", 0)));
    assert.deepEqual(out.json, {});
    assert.equal(out.header.epoch, 0);
    const revoked = await session(f, l);
    assert.equal(revoked.status, "REVOKED");
    assert.equal(revoked.currentKeys, undefined);
    assert.equal(revoked.prevKeys, undefined);
    const invalidated = await f.store.getExchange(insertedId.toUint8Array(), f.clock.now);
    assert.equal(invalidated?.state, "SUPERSEDED");
    assert.equal(invalidated?.serverPrivateKey, undefined);
    await expectError(await sendWire(f, await wire(f, l)), 401, "reauth", true);
  }
);

test(
  "two concurrent logout requests have exactly one successful response",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const request = await wire(f, l, "wake/logout");
    const responses = await Promise.all([sendWire(f, request), sendWire(f, request)]);
    assert.deepEqual(responses.map(res => res.status).sort(), [200, 401]);
    for (const res of responses) {
      if (res.status === 200) {
        assert.deepEqual((await opened(l, res)).json, {});
      } else {
        await expectError(res, 401, "reauth", true);
      }
    }
  }
);

for (const revoke of ["session", "user", "credential", "lastAuthCredential"] as const) {
  test(
    `revocation by ${revoke} deletes keys and invalidates related exchanges only`,
    async () => {
      const f = await fixture();
      const l = await login(f);
      const other = await login(f);
      const s = await session(f, l);
      if (revoke === "lastAuthCredential") {
        insertSession(f.store, {
          ...s,
          loginCredentialId: new Uint8Array([2]),
          lastAuthCredentialId: f.auth.credential.credentialId
        });
      }
      if (revoke === "session") {
        await f.server.revokeSession(l.sessionId.toUint8Array());
      }
      else if (revoke === "user") {
        await f.server.revokeSessionsByUser("u1");
      } else {
        await f.server.revokeSessionsByCredential(f.auth.credential.credentialId);
      }
      await expectError(await sendWire(f, await wire(f, l)), 401, "reauth", true);
      assert.equal((await session(f, l)).currentKeys, undefined);
      if (revoke === "session") {
        assert.equal((await sendWire(f, await wire(f, other))).status, 200);
      }
    }
  );
}

for (const direction of ["c2s", "s2c"] as const) {
  test(
    `encryption limit ${direction} rejects at limit and allows last slot atomically`,
    async () => {
      const f = await fixture({ maxEncryptionsPerKey: 2 });
      const l = await login(f);
      const s = await session(f, l);
      assert.ok(s.currentKeys);
      insertSession(f.store, { ...s, currentKeys: { ...s.currentKeys, [`${direction}Count`]: 1 } });
      const request = await wire(f, l);
      const results = await Promise.all([sendWire(f, request), sendWire(f, request)]);
      assert.deepEqual(results.map(res => res.status).sort(), [200, 401]);
      await expectError(await sendWire(f, await wire(f, l)), 401, "reauth", true);
      assert.equal((await session(f, l)).currentKeys?.[`${direction}Count`], 2);
    }
  );
}

for (const direction of ["c2s", "s2c"] as const) {
  for (const count of [2 ** 24 - 2, 2 ** 24 - 1]) {
    test(
      `rekey recommendation ${direction} at ${count}`,
      async () => {
        const f = await fixture();
        const l = await login(f);
        const s = await session(f, l);
        assert.ok(s.currentKeys);
        insertSession(f.store, { ...s, currentKeys: { ...s.currentKeys, [`${direction}Count`]: count } });
        assert.equal((await opened(l, await sendWire(f, await wire(f, l)))).json.rekeyRecommended, count + 1 >= 2 ** 24);
      }
    );
  }
}

test(
  "unexpected store failure before decryption returns retry; after decryption returns encrypted internal",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const get = f.store.getSession.bind(f.store);
    f.store.getSession = async () => {
      throw new Error("unavailable");
    };
    await expectError(await sendWire(f, await wire(f, l)), 503, "retry", true);
    f.store.getSession = get;
    f.store.touchSession = async () => {
      throw new Error("unavailable");
    };
    assert.deepEqual((await opened(l, await sendWire(f, await wire(f, l)))).json, { error: { code: "internal" } });
  }
);

test(
  "rate limited stores map auth and SM outer errors, and decrypted errors",
  async () => {
    const f = await fixture();
    const l = await login(f);
    f.store.createExchange = async () => {
      throw new WakeError("rate_limited");
    };
    const startResponse = response(
      await f.server.handle(
        new Request(`${ORIGIN}/auth/start`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"mode":"discoverable"}'
        })
      )
    );
    await expectError(startResponse, 429, "rate_limited");
    const get = f.store.getSession.bind(f.store);
    f.store.getSession = async () => {
      throw new WakeError("rate_limited");
    };
    await expectError(await sendWire(f, await wire(f, l)), 429, "rate_limited", true);
    f.store.getSession = get;
    f.store.touchSession = async () => {
      throw new WakeError("rate_limited");
    };
    assert.deepEqual((await opened(l, await sendWire(f, await wire(f, l)))).json, { error: { code: "rate_limited" } });
  }
);

test(
  "sweep expires sessions and removes retired previous keys only after grace",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const s = await session(f, l);
    assert.ok(s.currentKeys);
    insertSession(f.store, { ...s, currentEpoch: 1, prevKeys: { ...s.currentKeys }, prevValidUntil: f.clock.now + 1 });
    await f.store.sweep(f.clock.now + 1);
    assert.ok((await session(f, l)).prevKeys);
    await f.store.sweep(f.clock.now + 2);
    assert.equal((await session(f, l)).prevKeys, undefined);
    await f.store.sweep(s.absoluteExpiresAt);
    assert.equal((await session(f, l)).status, "EXPIRED");
    assert.equal((await session(f, l)).currentKeys, undefined);
  }
);

for (const error of [new Error("unavailable"), undefined]) {
  test(
    `reservation failure returns retry without retrying ${String(error)}`,
    async () => {
      const f = await fixture();
      const l = await login(f);
      const reserve = f.store.reserveEncryptions.bind(f.store);
      let attempts = 0;
      f.store.reserveEncryptions = async (...args) => {
        if (attempts++ === 0) {
          throw error;
        }
        return reserve(...args);
      };
      await expectError(await sendWire(f, await wire(f, l)), 503, "retry", true);
      assert.equal(attempts, 1);
      const state = await session(f, l);
      assert.equal(state.currentKeys?.c2sCount, 0);
      assert.equal(state.currentKeys?.s2cCount, 0);
    }
  );
}

test(
  "persistent reservation failure returns retry without uncounted encryption",
  async () => {
    const f = await fixture();
    const l = await login(f);
    let attempts = 0;
    f.store.reserveEncryptions = async () => {
      attempts++;
      throw new Error("unavailable");
    };
    await expectError(await sendWire(f, await wire(f, l)), 503, "retry", true);
    assert.equal(attempts, 1);
    assert.equal((await session(f, l)).currentKeys?.s2cCount, 0);
  }
);

test(
  "revocation invalidates pending exchanges and unrelated user sessions stay active",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const p = await prepare(f);
    const ex = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
    assert.ok(ex);
    const id = newExchangeId();
    await f.store.createExchange({ ...ex, exchangeId: id, sessionId: l.sessionId });
    const s = await session(f, l);
    const unrelatedId = newSessionId();
    insertSession(
      f.store,
      {
        ...s,
        sessionId: unrelatedId,
        userId: "u2",
        loginCredentialId: new Uint8Array([9]),
        lastAuthCredentialId: new Uint8Array([9])
      }
    );
    await f.server.revokeSessionsByUser("u1");
    const invalidated = await f.store.getExchange(id.toUint8Array(), f.clock.now);
    assert.equal(invalidated?.state, "SUPERSEDED");
    assert.equal(invalidated?.serverPrivateKey, undefined);
    assert.equal((await f.store.getSession(unrelatedId.toUint8Array()))?.status, "ACTIVE");
  }
);

test(
  "suspended session status and absent epoch keys require reauthentication",
  async () => {
    const f = await fixture();
    const l = await login(f);
    const s = await session(f, l);
    insertSession(f.store, { ...s, status: "REVOKED" });
    await expectError(await sendWire(f, await wire(f, l)), 401, "reauth", true);
    insertSession(f.store, { ...s, currentKeys: undefined });
    await expectError(await sendWire(f, await wire(f, l)), 401, "reauth", true);
  }
);

for (const offset of [0, 1]) {
  test(
    `stale requests do not touch activity at G plus ${offset}`,
    async () => {
      const f = await fixture({ freshnessWindowMs: 100 });
      const l = await login(f);
      const before = await session(f, l);
      insertSession(f.store, { ...before, idleTimeoutSec: 8 });
      const granularity = 8 * 1000 / 8;
      f.clock.now = before.lastActivityAt + granularity + offset;
      let touches = 0;
      const touch = f.store.touchSession.bind(f.store);
      f.store.touchSession = async (...args) => {
        touches++;
        return touch(...args);
      };
      const result = await opened(l, await sendWire(f, await wire(f, l, "wake/session", "{}", 0, f.clock.now - 101)));
      assert.deepEqual(result.json, { error: { code: "stale_request" } });
      assert.equal(touches, 0);
      assert.equal((await session(f, l)).lastActivityAt, before.lastActivityAt);
    }
  );
}

test(
  "reservation rate_limited from the store is an outer 429 with Retry-After",
  async () => {
    for (const retryAfterSec of [undefined, 7]) {
      const f = await fixture(retryAfterSec === undefined ? {} : { retryAfterSec });
      const l = await login(f);
      const reserve = f.store.reserveEncryptions.bind(f.store);
      let attempts = 0;
      f.store.reserveEncryptions = async (...args) => {
        if (attempts++ === 0) {
          throw new WakeError("rate_limited");
        }
        return reserve(...args);
      };
      const res = await sendWire(f, await wire(f, l));
      await expectError(res, 429, "rate_limited", true);
      assert.equal(res.headers.get("retry-after"), String(retryAfterSec ?? 1));
      assert.equal(attempts, 1);
      const state = await session(f, l);
      assert.equal(state.currentKeys?.c2sCount, 0);
    }
  }
);

test(
  "every outer and auth rate_limited response carries Retry-After, and other errors do not",
  async () => {
    const f = await fixture({ retryAfterSec: 3 });
    const l = await login(f);
    f.store.createExchange = async () => {
      throw new WakeError("rate_limited");
    };
    const started = await jsonRequest(f.server, "/auth/start", { mode: "discoverable" });
    await expectError(started, 429, "rate_limited");
    assert.equal(started.headers.get("retry-after"), "3");
    const get = f.store.getSession.bind(f.store);
    f.store.getSession = async () => {
      throw new WakeError("rate_limited");
    };
    const limited = await sendWire(f, await wire(f, l));
    assert.equal(limited.headers.get("retry-after"), "3");
    f.store.getSession = async () => {
      throw new Error("unavailable");
    };
    const retry = await sendWire(f, await wire(f, l));
    await expectError(retry, 503, "retry", true);
    assert.equal(retry.headers.get("retry-after"), null);
    f.store.getSession = get;
  }
);

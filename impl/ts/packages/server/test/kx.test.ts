// Tests for WAKE server behavior (spec §7.5–§7.8).
import assert from "node:assert/strict";
import { test } from "node:test";
import { asClientFinishedMac, generateEphemeral } from "@wake-protocol/core";
import { fixture, prepare, login, jsonRequest, expectError, decode, encode } from "./helpers.ts";
import type { Fixture } from "./helpers.ts";
import type { LoginCommit } from "../src/index.ts";

function synchronizeCredentialLookups(f: Fixture): number[] {
  const lookup = f.credentials.getCredential.bind(f.credentials);
  const counts: number[] = [];
  let release!: () => void;
  const ready = new Promise<void>(resolve => {
    release = resolve;
  });
  f.credentials.getCredential = async id => {
    const credential = await lookup(id);
    if (counts.length < 2) {
      counts.push(credential!.signCount);
      if (counts.length === 2) {
        release();
      }
      await ready;
    }
    return credential;
  };
  return counts;
}

test(
  "KX verifies serverFinished, establishes session and erases ephemeral private key",
  async () => {
    const f = await fixture();
    const p = await login(f);
    const session = await f.store.getSession(p.sessionId.toUint8Array());
    assert.equal(session?.status, "ACTIVE");
    assert.equal(session?.userId, "u1");
    assert.equal(session?.establishedOrigin, "https://example.com");
    assert.equal(session?.currentEpoch, 0);
    assert.equal(session?.authTime, f.clock.now);
    assert.equal(session?.absoluteExpiresAt, f.clock.now + 7 * 86400000);
    assert.equal(session?.hardCapAt, f.clock.now + 30 * 86400000);
    assert.equal(session?.currentKeys?.c2s.extractable, false);
    assert.equal(session?.currentKeys?.s2c.extractable, false);
    assert.ok(session?.currentKeys?.th.equals(p.th));
    const exchange = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
    assert.equal(exchange?.state, "COMPLETED");
    assert.equal(exchange?.serverPrivateKey, undefined);
  }
);

test(
  "failed Finished leaves exchange available for a correct retry",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    let counterComparisons = 0;
    const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
    f.credentials.compareAndSetSignCount = async (...args) => {
      counterComparisons++;
      return compare(...args);
    };
    await expectError(
      await jsonRequest(f.server, "/auth/complete", { ...p.body, clientFinished: encode(new Uint8Array(32)) }),
      401,
      "auth_failed"
    );
    assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "PENDING");
    assert.equal(counterComparisons, 0);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 0);
    assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
    assert.equal(counterComparisons, 1);
  }
);

test(
  "completed replay is byte-identical and skips all assertion revalidation",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    let counterComparisons = 0;
    const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
    f.credentials.compareAndSetSignCount = async (...args) => {
      counterComparisons++;
      return compare(...args);
    };
    f.credentials.updateSignCount = async () => {
      throw new Error("CAS logins need no post-commit update");
    };
    const first = await jsonRequest(f.server, "/auth/complete", p.body);
    assert.equal(first.status, 200);
    assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.signCountUpdate, undefined);
    const text = await first.text();
    f.credentials.setCredential({ ...f.auth.credential, status: "suspended" }, "alice");
    f.clock.now++;
    const replay = await jsonRequest(f.server, "/auth/complete", { ...p.body, assertion: { bad: true } });
    assert.equal(replay.status, 200);
    assert.equal(await replay.text(), text);
    assert.equal(counterComparisons, 1);
    await expectError(
      await jsonRequest(f.server, "/auth/complete", { ...p.body, clientFinished: encode(new Uint8Array(32)) }),
      401,
      "auth_failed"
    );
    const different = await generateEphemeral();
    await expectError(
      await jsonRequest(f.server, "/auth/complete", { ...p.body, clientPublicKey: encode(different.publicKey.toUint8Array()) }),
      401,
      "auth_failed"
    );
  }
);

for (const backupEligible of [false, true]) {
  for (const status of ["suspended", "deleted"] as const) {
    test(`KX revokes a session when the credential becomes ${status} before commit (BE=${backupEligible})`, async () => {
      const f = await fixture({}, { rpId: "example.com", origin: "https://example.com", userId: "u1", backupEligible });
      const p = await prepare(f, { signCount: 1 });
      const credentialId = f.auth.credential.credentialId;
      const lookup = f.credentials.getCredential.bind(f.credentials);
      let deleted = false;
      let nullLookups = 0;
      f.credentials.getCredential = async id => {
        if (deleted) {
          nullLookups++;
          return null;
        }
        return lookup(id);
      };
      let counterUpdates = 0;
      f.credentials.updateSignCount = async () => {
        counterUpdates++;
        throw new Error("revocation must precede deferred counter updates");
      };
      const commit = f.store.commitLogin.bind(f.store);
      f.store.commitLogin = async value => {
        const credential = await lookup(credentialId);
        assert.ok(credential);
        assert.equal(credential.status, "active");
        assert.equal(credential.signCount, backupEligible ? 0 : 1);
        f.credentials.setCredential({ ...credential, status }, "alice");
        deleted = status === "deleted";
        await f.store.revokeSessionsByCredential(credentialId);
        assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
        const committed = await commit(value);
        assert.equal(committed, true);
        assert.equal((await f.store.getSession(p.sessionId.toUint8Array()))?.status, "ACTIVE");
        return committed;
      };
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
      assert.equal((await f.store.getSession(p.sessionId.toUint8Array()))?.status, "REVOKED");
      assert.equal(nullLookups, status === "deleted" ? 1 : 0);
      assert.equal(counterUpdates, 0);
    });
  }
}

for (const backupEligible of [false, true]) {
  test(
    `concurrent completions return identical cached bytes for ${backupEligible ? "BE=true" : "0/0 counters"}`,
    async () => {
      const f = await fixture({}, { rpId: "example.com", origin: "https://example.com", userId: "u1", backupEligible });
      const p = await prepare(f, { signCount: backupEligible ? 1 : 0 });
      const counts = synchronizeCredentialLookups(f);
      f.credentials.compareAndSetSignCount = async () => {
        throw new Error("BE=true and 0/0 counters do not require CAS");
      };
      let successfulCommits = 0;
      const commit = f.store.commitLogin.bind(f.store);
      f.store.commitLogin = async (value: LoginCommit) => {
        const result = await commit(value);
        if (result) {
          successfulCommits++;
        }
        return result;
      };
      const [a, b] = await Promise.all([
        jsonRequest(f.server, "/auth/complete", p.body),
        jsonRequest(f.server, "/auth/complete", p.body)
      ]);
      assert.equal(a.status, 200);
      assert.equal(b.status, 200);
      assert.equal(await a.text(), await b.text());
      assert.equal(successfulCommits, 1);
      assert.deepEqual(counts, [0, 0]);
      assert.ok(await f.store.getSession(p.sessionId.toUint8Array()));
    }
  );
}

test("concurrent BE=false completions replay identical bytes after a counter CAS failure", async () => {
  const f = await fixture();
  const p = await prepare(f, { signCount: 1 });
  const counts = synchronizeCredentialLookups(f);
  let release!: () => void;
  const committed = new Promise<void>(resolve => {
    release = resolve;
  });
  let comparisons = 0;
  let failedComparisons = 0;
  const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
  f.credentials.compareAndSetSignCount = async (id, expected, next) => {
    comparisons++;
    assert.equal(expected, 0);
    assert.equal(next, 1);
    if (comparisons === 2) {
      await committed;
    }
    const result = await compare(id, expected, next);
    if (!result) {
      failedComparisons++;
      assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "COMPLETED");
    }
    return result;
  };
  let successfulCommits = 0;
  const commit = f.store.commitLogin.bind(f.store);
  f.store.commitLogin = async (value: LoginCommit) => {
    const result = await commit(value);
    if (result) {
      successfulCommits++;
      release();
    }
    return result;
  };
  const [a, b] = await Promise.all([
    jsonRequest(f.server, "/auth/complete", p.body),
    jsonRequest(f.server, "/auth/complete", p.body)
  ]);
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  assert.equal(await a.text(), await b.text());
  assert.deepEqual(counts, [0, 0]);
  assert.equal(comparisons, 2);
  assert.equal(failedComparisons, 1);
  assert.equal(successfulCommits, 1);
  assert.equal((await f.store.getSession(p.sessionId.toUint8Array()))?.status, "ACTIVE");
});

test("a counter CAS loser retries identical bytes while the winner is waiting to commit", async () => {
  const f = await fixture();
  const p = await prepare(f, { signCount: 1 });
  const counts = synchronizeCredentialLookups(f);
  let signalBeforeCommit!: () => void;
  const beforeCommit = new Promise<void>(resolve => {
    signalBeforeCommit = resolve;
  });
  let releaseCommit!: () => void;
  const commitAllowed = new Promise<void>(resolve => {
    releaseCommit = resolve;
  });
  let comparisons = 0;
  let failedComparisons = 0;
  const compare = f.credentials.compareAndSetSignCount.bind(f.credentials);
  f.credentials.compareAndSetSignCount = async (id, expected, next) => {
    comparisons++;
    assert.equal(expected, 0);
    assert.equal(next, 1);
    if (comparisons === 2) {
      await beforeCommit;
    }
    const result = await compare(id, expected, next);
    if (!result) {
      failedComparisons++;
      assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "PENDING");
    }
    return result;
  };
  let successfulCommits = 0;
  const commit = f.store.commitLogin.bind(f.store);
  f.store.commitLogin = async (value: LoginCommit) => {
    signalBeforeCommit();
    await commitAllowed;
    const result = await commit(value);
    if (result) {
      successfulCommits++;
    }
    return result;
  };
  const requests = [
    jsonRequest(f.server, "/auth/complete", p.body),
    jsonRequest(f.server, "/auth/complete", p.body)
  ];
  try {
    const loser = await Promise.race(requests);
    await expectError(loser, 503, "retry");
    assert.deepEqual(counts, [0, 0]);
    assert.equal(comparisons, 2);
    assert.equal(failedComparisons, 1);
    assert.equal(successfulCommits, 0);
    assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "PENDING");
    assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 1);
    releaseCommit();
    const replies = await Promise.all(requests);
    const winner = replies.find(reply => reply.status === 200);
    assert.ok(winner);
    const replay = await jsonRequest(f.server, "/auth/complete", p.body);
    assert.equal(replay.status, 200);
    assert.equal(await replay.text(), await winner.text());
    assert.equal(successfulCommits, 1);
    assert.equal(comparisons, 2);
    assert.equal((await f.store.getSession(p.sessionId.toUint8Array()))?.status, "ACTIVE");
  } finally {
    signalBeforeCommit();
    releaseCommit();
    await Promise.allSettled(requests);
  }
});

test("cloned BE=false credentials with the same next counter cannot complete separate exchanges", async () => {
  const f = await fixture();
  const pending = await Promise.all([prepare(f, { signCount: 1 }), prepare(f, { signCount: 1 })]);
  const counts = synchronizeCredentialLookups(f);
  const replies = await Promise.all(pending.map(p => jsonRequest(f.server, "/auth/complete", p.body)));
  assert.deepEqual(counts, [0, 0]);
  assert.deepEqual(replies.map(reply => reply.status).sort(), [200, 503]);
  for (let i = 0; i < replies.length; i++) {
    const reply = replies[i]!;
    const p = pending[i]!;
    const ex = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
    const session = await f.store.getSession(p.sessionId.toUint8Array());
    if (reply.status === 503) {
      await expectError(reply, 503, "retry");
      assert.equal(ex?.state, "PENDING");
      assert.ok(ex?.serverPrivateKey);
      assert.equal(session, null);
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
      const retried = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
      assert.equal(retried?.state, "PENDING");
      assert.ok(retried?.serverPrivateKey);
      assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
      assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 1);
    } else {
      assert.equal(ex?.state, "COMPLETED");
      assert.equal(ex?.signCountUpdate, undefined);
      assert.equal(session?.status, "ACTIVE");
    }
  }
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 1);
});

test("a failed counter CAS leaves the exchange PENDING without a session", async () => {
  const f = await fixture();
  const p = await prepare(f, { signCount: 4 });
  let comparisons = 0;
  f.credentials.compareAndSetSignCount = async (id, expected, next) => {
    comparisons++;
    assert.deepEqual(id, f.auth.credential.credentialId);
    assert.equal(expected, 0);
    assert.equal(next, 4);
    return false;
  };
  f.store.commitLogin = async () => {
    throw new Error("must not commit after failed CAS");
  };
  await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 503, "retry");
  assert.equal(comparisons, 1);
  const ex = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
  assert.equal(ex?.state, "PENDING");
  assert.ok(ex?.serverPrivateKey);
  assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 0);
});

for (const state of ["expired", "missing", "completed mismatch"] as const) {
  test(`a failed counter CAS still rejects the ${state} exchange`, async () => {
    const f = await fixture({ completedRetentionMs: 10 });
    const p = await prepare(f, { signCount: 1 });
    const read = f.store.getExchange.bind(f.store);
    let casFailed = false;
    let comparisons = 0;
    f.credentials.compareAndSetSignCount = async () => {
      comparisons++;
      casFailed = true;
      if (state !== "completed mismatch") {
        f.clock.now = p.info.expiresAt + (state === "missing" ? 10 : 0);
        if (state === "missing") {
          await f.store.sweep(f.clock.now);
        }
      }
      return false;
    };
    f.store.getExchange = async (...args) => {
      const ex = await read(...args);
      if (casFailed && state === "completed mismatch" && ex) {
        assert.notEqual(p.body.clientFinished, encode(new Uint8Array(32)));
        return {
          ...ex,
          state: "COMPLETED",
          th: p.th,
          clientFinished: asClientFinishedMac(new Uint8Array(32)),
          response: "{}"
        };
      }
      return ex;
    };
    f.store.commitLogin = async () => {
      throw new Error("must not commit after failed CAS");
    };
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
    assert.equal(comparisons, 1);
    const ex = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
    assert.equal(ex?.state, state === "expired" ? "EXPIRED" : state === "missing" ? undefined : "COMPLETED");
    assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 0);
  });
}

test("a rejected login commit safely leaves the counter advanced after successful CAS", async () => {
  const f = await fixture();
  const p = await prepare(f, { signCount: 4 });
  f.store.commitLogin = async value => {
    assert.equal(value.signCountUpdate, undefined);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 4);
    return false;
  };
  await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "PENDING");
  assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 4);
});

test("concurrent BE=true anomalies in separate exchanges both commit and notify once per exchange", async () => {
  const events: unknown[] = [];
  const f = await fixture(
    {
      onCounterAnomaly: event => {
        events.push(event);
      }
    },
    { rpId: "example.com", origin: "https://example.com", userId: "u1", signCount: 2, backupEligible: true }
  );
  const pending = await Promise.all([prepare(f, { signCount: 1 }), prepare(f, { signCount: 1 })]);
  const counts = synchronizeCredentialLookups(f);
  f.credentials.compareAndSetSignCount = async () => {
    throw new Error("BE=true does not require CAS");
  };
  const replies = await Promise.all(pending.map(p => jsonRequest(f.server, "/auth/complete", p.body)));
  assert.deepEqual(counts, [2, 2]);
  assert.equal(events.length, 2);
  for (let i = 0; i < replies.length; i++) {
    assert.equal(replies[i]!.status, 200);
    const p = pending[i]!;
    assert.equal((await f.store.getSession(p.sessionId.toUint8Array()))?.status, "ACTIVE");
    assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
  }
  assert.equal(events.length, 2);
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 2);
});

for (const offset of [-1, 0]) {
  test(
    `exchange expiry boundary offset ${offset}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      f.clock.now = p.info.expiresAt + offset;
      const res = await jsonRequest(f.server, "/auth/complete", p.body);
      if (offset < 0) {
        assert.equal(res.status, 200);
      } else {
        await expectError(res, 401, "auth_failed");
        const ex = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
        assert.equal(ex?.state, "EXPIRED");
        assert.equal(ex?.serverPrivateKey, undefined);
      }
    }
  );
}

test(
  "exchange expiry during awaited verification is checked at atomic commit",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    const lookup = f.credentials.getCredential.bind(f.credentials);
    f.credentials.getCredential = async id => {
      const credential = await lookup(id);
      f.clock.now = p.info.expiresAt;
      return credential;
    };
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
    assert.equal(await f.store.getSession(p.sessionId.toUint8Array()), null);
  }
);

test(
  "exchange is looked up before public-key parsing",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    await expectError(
      await jsonRequest(f.server, "/auth/complete", { ...p.body, exchangeId: encode(new Uint8Array(16)), clientPublicKey: "broken" }),
      401,
      "auth_failed"
    );
  }
);

for (const kind of ["rekey", "expired", "superseded"] as const) {
  test(
    `KX rejects ${kind} exchange before credential lookup`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      const read = f.store.getExchange.bind(f.store);
      let credentialLookups = 0;
      f.store.getExchange = async (...args) => {
        const ex = await read(...args);
        return ex ?
          {
            ...ex,
            kind: kind === "rekey" ? "rekey" : "login",
            state: kind === "expired" ? "EXPIRED" : kind === "superseded" ? "SUPERSEDED" : "PENDING"
          } :
          null;
      };
      f.credentials.getCredential = async () => {
        credentialLookups++;
        throw new Error("must not lookup");
      };
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
      assert.equal(credentialLookups, 0);
    }
  );
}

for (const key of [
  new Uint8Array(33).fill(2),
  new Uint8Array([4, ...new Uint8Array(64)]),
  new Uint8Array(65).fill(6)
]) {
  test(
    `KX rejects public key ${key.length}/${key[0]}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      await expectError(await jsonRequest(f.server, "/auth/complete", { ...p.body, clientPublicKey: encode(key) }), 400, "bad_request");
    }
  );
}

for (const change of [
  { exchangeId: "AA=" },
  { exchangeId: encode(new Uint8Array(15)) },
  { clientFinished: "AA=" },
  { clientFinished: encode(new Uint8Array(31)) },
  { assertion: null },
  { assertion: [] }
]) {
  test(
    `KX rejects malformed outer body ${JSON.stringify(change)}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      await expectError(await jsonRequest(f.server, "/auth/complete", { ...p.body, ...change }), 400, "bad_request");
    }
  );
}

test(
  "sweep retains completed replay until retention then removes it",
  async () => {
    const f = await fixture({ completedRetentionMs: 10 });
    const p = await prepare(f);
    const first = await jsonRequest(f.server, "/auth/complete", p.body);
    assert.equal(first.status, 200);
    const text = await first.text();
    f.clock.now = p.info.expiresAt + 9;
    await f.store.sweep(f.clock.now);
    const replay = await jsonRequest(f.server, "/auth/complete", p.body);
    assert.equal(replay.status, 200);
    assert.equal(await replay.text(), text);
    f.clock.now++;
    await f.store.sweep(f.clock.now);
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

test(
  "sweep expires pending exchange, drops key and deletes after retention",
  async () => {
    const f = await fixture({ completedRetentionMs: 10 });
    const p = await prepare(f);
    await f.store.sweep(p.info.expiresAt - 1);
    assert.ok((await f.store.getExchange(decode(p.info.exchangeId), p.info.expiresAt - 1))?.serverPrivateKey);
    await f.store.sweep(p.info.expiresAt);
    const ex = await f.store.getExchange(decode(p.info.exchangeId), p.info.expiresAt);
    assert.equal(ex?.state, "EXPIRED");
    assert.equal(ex?.serverPrivateKey, undefined);
    await f.store.sweep(p.info.expiresAt + 10);
    assert.equal(await f.store.getExchange(decode(p.info.exchangeId), p.info.expiresAt + 10), null);
  }
);

for (const body of ["null", "[]", "{}", '{"a":1,"a":1}', '{"a":"\\ud800"}', '{"a":9007199254740992}']) {
  test(
    `complete rejects strict outer JSON ${body}`,
    async () => {
      const f = await fixture();
      const res = await f.server.handle(
        new Request("https://example.com/auth/complete", { method: "POST", headers: { "content-type": "application/json" }, body })
      );
      assert.ok(res);
      await expectError(res, 400, "bad_request");
    }
  );
}

test(
  "complete enforces content type and body length before exchange lookup",
  async () => {
    const f = await fixture({ maxAuthBody: 32 });
    let lookups = 0;
    f.store.getExchange = async () => {
      lookups++;
      throw new Error("must not lookup");
    };
    await expectError(await jsonRequest(f.server, "/auth/complete", {}, { "content-type": "text/plain" }), 400, "bad_request");
    await expectError(await jsonRequest(f.server, "/auth/complete", { padding: "x".repeat(32) }), 400, "bad_request");
    assert.equal(lookups, 0);
  }
);

test(
  "auth unexpected store failures map to retry and rate limit to 429",
  async () => {
    const { WakeError } = await import("@wake-protocol/core");
    const f = await fixture();
    const p = await prepare(f);
    f.store.getExchange = async () => {
      throw new Error("unavailable");
    };
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 503, "retry");
    f.store.getExchange = async () => {
      throw new WakeError("rate_limited");
    };
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 429, "rate_limited");
  }
);

test(
  "counter max is preserved for concurrent independently valid logins",
  async () => {
    const f = await fixture({}, { rpId: "example.com", origin: "https://example.com", userId: "u1", backupEligible: true });
    const [high, low] = await Promise.all([prepare(f, { signCount: 8 }), prepare(f, { signCount: 3 })]);
    const results = await Promise.all([
      jsonRequest(f.server, "/auth/complete", high.body),
      jsonRequest(f.server, "/auth/complete", low.body)
    ]);
    for (const res of results) {
      assert.equal(res.status, 200);
    }
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 8);
  }
);

test(
  "outer exchangeId rejects nonzero unused low four bits as bad_request",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const value = p.body.exchangeId;
    const last = alphabet.indexOf(value.at(-1)!);
    assert.equal(last & 15, 0);
    const noncanonical = value.slice(0, -1) + alphabet[last | 1]!;
    await expectError(await jsonRequest(f.server, "/auth/complete", { ...p.body, exchangeId: noncanonical }), 400, "bad_request");
  }
);

// Spec §8.6–8.7, §9: independent-peer rotation and recovery boundaries.
import assert from "node:assert/strict";
import { test } from "node:test";
import { base64urlnopad } from "@scure/base";
import { bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import { parseWire } from "@wake-protocol/core";
import { fixture, hasCode, jsonResponse, readJson, TTL } from "./fixture.ts";

const login = { mode: "discoverable" } as const;
const data = utf8ToBytes("hello");

function gate() {
  let release!: () => void;
  let reached!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const arrived = new Promise<void>(resolve => { reached = resolve; });
  return { release, reached, blocked, arrived };
}

function loseThenRetire(f: Awaited<ReturnType<typeof fixture>>) {
  f.krCompleteResponse = attempt => {
    if (attempt === 1) {
      throw new TypeError("lost committed response");
    }
    return jsonResponse({ wakeError: "epoch_retired" }, 401);
  };
}

function brokenBody() {
  return new Response(new ReadableStream({ start(controller) {
    controller.error(new TypeError("connection lost"));
  } }), { headers: { "Content-Type": "application/wake" } });
}

test("KR authenticates its challenge and Finished, switches epochs and keeps the session ID", async () => {
  const f = await fixture();
  const initial = await f.client.login(login);
  const info = await f.client.rekey();
  assert.equal(info.epoch, 1);
  assert.equal(info.serverTime, f.serverTime);
  assert.equal(info.absoluteExpiresAt, 3_500_000);
  assert.equal(info.idleTimeoutSec, 60);
  assert.equal(f.assertionCalls, 2);
  assert.deepEqual(f.assertionOptions!.allowCredentials, [{ type: "public-key", id: "AQ" }]);
  assert.equal((await f.client.session()).sessionId, initial.sessionId);
  assert.deepEqual(f.requests.map(h => h.epoch), [0, 0, 1]);
  assert.equal((await f.client.rekey()).epoch, 2);
  assert.equal((await f.client.session()).epoch, 2);
  const ids = f.requests.map(h => base64urlnopad.encode(h.requestId.toUint8Array()));
  const ivs = f.wires.map(w => base64urlnopad.encode(parseWire(w).header.iv.toUint8Array()));
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(new Set(ivs).size, ivs.length);
});

for (const kind of ["network", "body", "502", "retry"] as const) {
  test(`KR lost ${kind} completion resends identical plaintext with fresh requestId and IV`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.krCompleteResponse = (attempt, response) => {
      if (attempt > 1) {
        return response;
      }
      if (kind === "network") {
        throw new TypeError("offline");
      }
      if (kind === "body") {
        return brokenBody();
      }
      return kind === "502" ? new Response("gateway", { status: 502 }) : jsonResponse({ wakeError: "retry" }, 503);
    };
    assert.equal((await f.client.rekey()).epoch, 1);
    assert.equal(f.krCompleteBodies.length, 2);
    assert.equal(f.krCompleteBodies[0], f.krCompleteBodies[1]);
    assert.equal(f.assertionCalls, 2);
    const requests = f.requests.filter(h => h.context === "wake/kr/complete");
    assert.equal(requests[0]!.requestId.equals(requests[1]!.requestId), false);
    assert.equal(requests[0]!.iv.equals(requests[1]!.iv), false);
    assert.deepEqual(requests.map(h => h.epoch), [0, 0]);
    assert.deepEqual(f.sleeps, [100]);
    assert.equal((await f.client.session()).epoch, 1);
  });
}

test("retired completion recovers pending keys without switching before session confirmation", async () => {
  const f = await fixture();
  await f.client.login(login);
  loseThenRetire(f);
  const g = gate();
  f.upResponse = async (h, response) => {
    if (h.context === "wake/session" && h.epoch === 1) {
      g.reached();
      await g.blocked;
    }
    return response;
  };
  const rotation = f.client.rekey();
  await g.arrived;
  assert.deepEqual(await f.client.request("custom", data), data);
  assert.equal(f.requests.at(-1)!.epoch, 0);
  g.release();
  const info = await rotation;
  assert.equal(info.epoch, 1);
  assert.equal(info.absoluteExpiresAt, 3_500_000);
  f.upResponse = undefined;
  assert.equal((await f.client.session()).epoch, 1);
});

for (const failure of ["reauth", "network", "wrong epoch", "encrypted error"] as const) {
  test(`pending-key recovery ${failure} drops the failed session`, async () => {
    const f = await fixture();
    await f.client.login(login);
    loseThenRetire(f);
    f.upAction = () => {
      const h = f.requests.at(-1)!;
      if (h.context === "wake/session" && h.epoch === 1) {
        if (failure === "network") {
          throw new TypeError("offline");
        }
        if (failure === "reauth") {
          return jsonResponse({ wakeError: "reauth" }, 401);
        }
      }
    };
    f.upPlaintext = (h, plaintext) => {
      if (h.context !== "wake/session") {
        return plaintext;
      }
      if (failure === "encrypted error") {
        return utf8ToBytes('{"error":{"code":"expired"},"future":1}');
      }
      const value = readJson(bytesToUtf8(plaintext));
      if (failure === "wrong epoch") {
        value.epoch = 0;
      }
      return utf8ToBytes(JSON.stringify(value));
    };
    await assert.rejects(f.client.rekey());
    assert.equal(f.client.loggedIn, false);
    await assert.rejects(f.client.session(), hasCode("reauth"));
  });
}

for (const field of ["serverFinished", "epoch", "serverTime", "absoluteExpiresAt", "idleTimeoutSec"]) {
  test(`KR mismatching ${field} requires reauthentication without retry`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.krCompleteMutate = value => {
      value[field] = field === "serverFinished" ? base64urlnopad.encode(new Uint8Array(32)) : (value[field] as number) + 1;
    };
    await assert.rejects(f.client.rekey(), hasCode("auth_failed"));
    assert.equal(f.client.loggedIn, false);
    assert.equal(f.sleeps.length, 0);
  });
}

for (const [field, value] of [
  ["epoch", 2 ** 32], ["serverTime", -1], ["serverTime", 1.5], ["serverTime", 2 ** 53],
  ["absoluteExpiresAt", null], ["idleTimeoutSec", 2 ** 32], ["serverFinished", "AQ"], ["serverFinished", "AQ="],
] as const) {
  test(`KR malformed completion ${field}=${value} drops the session`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.krCompleteMutate = v => { v[field] = value; };
    await assert.rejects(f.client.rekey(), hasCode("auth_failed"));
    assert.equal(f.client.loggedIn, false);
  });
}

for (const code of ["conflict", "expired", "webauthn_failed", "retry", "epoch_retired"]) {
  for (const future of [false, true]) {
    test(`encrypted KR ${code}, future member=${future}, preserves current epoch without retry`, async () => {
      const f = await fixture();
      await f.client.login(login);
      f.krCompleteError = code;
      if (future) {
        f.krCompleteMutate = v => { v.future = 1; };
      }
      await assert.rejects(f.client.rekey(), hasCode(code));
      assert.equal((await f.client.session()).epoch, 0);
      assert.equal(f.sleeps.length, 0);
      f.krCompleteError = undefined;
      f.krCompleteMutate = undefined;
      assert.equal((await f.client.rekey()).epoch, 1);
    });
  }
}

for (const [field, value] of [
  ["epoch", 0], ["epoch", 2], ["epoch", 2 ** 32], ["exchangeId", "AQ"], ["serverNonce", "AQ"],
  ["serverPublicKey", "AQ"], ["exchangeId", "AAAAAAAAAAAAAAAAAAAAAB"], ["expiresAt", 1.5],
  ["expiresAt", -1], ["expiresAt", 2 ** 53], ["webauthn", []],
  ["webauthn", { rpId: 1, userVerification: "required", allowCredentials: [], timeout: 1 }],
  ["webauthn", { rpId: "example.com", userVerification: "preferred", allowCredentials: [], timeout: 1 }],
  ["webauthn", { rpId: "example.com", userVerification: "required", allowCredentials: [], timeout: 2 ** 32 }],
  ["webauthn", { rpId: "example.com", userVerification: "required", allowCredentials: [{ type: "public-key", id: "AQ=" }],
    timeout: 1 }],
] as const) {
  test(`KR malformed start ${field}=${JSON.stringify(value)} keeps current keys`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.krStartMutate = v => { v[field] = value; };
    await assert.rejects(f.client.rekey(), hasCode("bad_request"));
    assert.equal(f.krCompleteBodies.length, 0);
    assert.equal((await f.client.session()).epoch, 0);
  });
}

for (const text of ['{"epoch":1,"epoch":1}', '[]', '{"epoch":9007199254740992}', '{']) {
  for (const phase of ["start", "complete"] as const) {
    test(`strict KR ${phase} JSON rejects ${text}`, async () => {
      const f = await fixture();
      await f.client.login(login);
      f.upPlaintext = (h, plaintext) => h.context === `wake/kr/${phase}` ? utf8ToBytes(text) : plaintext;
      await assert.rejects(f.client.rekey(), hasCode(phase === "start" ? "bad_request" : "auth_failed"));
      assert.equal(f.client.loggedIn, phase === "start");
    });
  }
}

for (const gap of [99, 100, 101]) {
  test(`KR offset-corrected retry deadline minus ${gap}ms`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.krStartMutate = v => { v.expiresAt = f.serverTime + 1000; };
    const deadline = f.localTime + 1000;
    f.krCompleteResponse = (attempt, response) => {
      if (attempt > 1) {
        return response;
      }
      f.localTime = deadline - gap;
      throw new TypeError("lost response");
    };
    if (gap > 100) {
      assert.equal((await f.client.rekey()).epoch, 1);
      assert.equal(f.krCompleteBodies.length, 2);
    } else {
      await assert.rejects(f.client.rekey(), hasCode("expired"));
      assert.equal(f.client.loggedIn, true);
      assert.equal(f.krCompleteBodies.length, 1);
      assert.equal(f.localTime, deadline);
    }
  });
}

test("WebAuthn reaching the authenticated exchange deadline sends no completion", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.onAssertion = () => { f.localTime += TTL; };
  await assert.rejects(f.client.rekey(), hasCode("expired"));
  assert.equal(f.krCompleteBodies.length, 0);
  assert.equal((await f.client.session()).epoch, 0);
});

for (const stale of [false, true]) {
  test(`old-key application response survives KR; stale retry=${stale} uses current keys`, async () => {
    const f = await fixture();
    await f.client.login(login);
    const g = gate();
    let first = true;
    f.upPlaintext = (h, plaintext) => h.context === "custom" && first && stale
      ? utf8ToBytes('{"error":{"code":"stale_request"}}') : plaintext;
    f.upResponse = async (h, response) => {
      if (h.context === "custom" && first) {
        g.reached();
        await g.blocked;
        first = false;
      }
      return response;
    };
    const request = f.client.request("custom", data);
    await g.arrived;
    await f.client.rekey();
    g.release();
    assert.deepEqual(await request, data);
    assert.deepEqual(f.requests.filter(h => h.context === "custom").map(h => h.epoch), stale ? [0, 1] : [0]);
    assert.equal((await f.client.session()).epoch, 1);
  });
}

for (const reportedEpoch of [0, 1]) {
  test(`old-key session response epoch ${reportedEpoch} is compared with current at acceptance`, async () => {
    const f = await fixture();
    await f.client.login(login);
    const g = gate();
    f.upPlaintext = (h, plaintext) => h.context === "wake/session"
      ? utf8ToBytes(JSON.stringify({ ...readJson(bytesToUtf8(plaintext)), epoch: reportedEpoch })) : plaintext;
    f.upResponse = async (h, response) => {
      if (h.context === "wake/session" && h.epoch === 0) {
        g.reached();
        await g.blocked;
      }
      return response;
    };
    const session = f.client.session();
    await g.arrived;
    await f.client.rekey();
    g.release();
    if (reportedEpoch === 1) {
      assert.equal((await session).epoch, 1);
    } else {
      await assert.rejects(session, hasCode("bad_request"));
    }
  });
}

test("concurrent KR is conflict; the reservation is released after finishing", async () => {
  const f = await fixture();
  await f.client.login(login);
  const g = gate();
  f.krCompleteResponse = async (_attempt, response) => {
    g.reached();
    await g.blocked;
    return response;
  };
  const first = f.client.rekey();
  await g.arrived;
  await assert.rejects(f.client.rekey(), hasCode("conflict"));
  g.release();
  await first;
  f.krCompleteResponse = undefined;
  assert.equal((await f.client.rekey()).epoch, 2);
});

for (const action of ["logout", "login", "login during recovery"] as const) {
  test(`${action} cancels KR without resurrecting or deleting a replacement session`, async () => {
    const f = await fixture();
    await f.client.login(login);
    const g = gate();
    if (action === "login during recovery") {
      loseThenRetire(f);
      f.upResponse = async (h, response) => {
        if (h.context === "wake/session" && h.epoch === 1) {
          g.reached();
          await g.blocked;
        }
        return response;
      };
    } else {
      f.krCompleteResponse = async (_attempt, response) => {
        g.reached();
        await g.blocked;
        return response;
      };
    }
    const rotation = f.client.rekey();
    await g.arrived;
    if (action === "logout") {
      await f.client.logout();
    } else {
      await f.client.login(login);
    }
    g.release();
    await assert.rejects(rotation);
    assert.equal(f.client.loggedIn, action !== "logout");
    if (action !== "logout") {
      assert.equal((await f.client.session()).epoch, 0);
    }
  });
}

test("per-epoch encryption reservations restart after KR", async () => {
  const f = await fixture({ maxEncryptionsPerKey: 2 });
  await f.client.login(login);
  await f.client.rekey();
  assert.equal((await f.client.session()).epoch, 1);
  assert.equal((await f.client.session()).epoch, 1);
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.deepEqual(f.requests.map(h => h.epoch), [0, 0, 1, 1]);
});

test("old-epoch retries still consume the old key's encryption budget", async () => {
  const f = await fixture({ maxEncryptionsPerKey: 2 });
  await f.client.login(login);
  f.krCompleteResponse = () => { throw new TypeError("lost response"); };
  await assert.rejects(f.client.rekey(), hasCode("reauth"));
  assert.equal(f.krCompleteBodies.length, 1);
  assert.equal(f.client.loggedIn, false);
});

test("non-retry outer errors and malformed JSON do not trigger transport retries", async () => {
  for (const response of [
    jsonResponse({ wakeError: "bad_request" }, 400),
    jsonResponse({ wakeError: "rate_limited" }, 429),
    new Response('{"wakeError":"retry","wakeError":"retry"}', { status: 503,
      headers: { "Content-Type": "application/json" } }),
  ]) {
    const f = await fixture();
    await f.client.login(login);
    f.krCompleteResponse = () => response;
    await assert.rejects(f.client.rekey());
    assert.equal(f.krCompleteBodies.length, 1);
    assert.equal(f.sleeps.length, 0);
  }
});

for (const method of ["encrypt", "decrypt", "verify"] as const) {
  for (const exception of ["TypeError", "DOMException"] as const) {
    test(`KR propagates Web Crypto ${method} ${exception} without transport retry`, async () => {
      const f = await fixture();
      await f.client.login(login);
      const failure = exception === "TypeError" ? new TypeError("programming failure")
        : new DOMException("cryptographic programming failure", "InvalidAccessError");
      const original = Object.getOwnPropertyDescriptor(crypto.subtle, method);
      const inject = () => {
        Object.defineProperty(crypto.subtle, method, {
          configurable: true,
          value: async () => { throw failure; },
        });
      };
      if (method === "encrypt") {
        f.upResponse = (h, response) => {
          if (h.context === "wake/kr/start") {
            inject();
          }
          return response;
        };
      } else {
        f.krCompleteResponse = (_attempt, response) => {
          inject();
          return response;
        };
      }
      try {
        await assert.rejects(f.client.rekey(), error => error === failure);
        assert.equal(f.sleeps.length, 0);
        assert.equal(f.krCompleteBodies.length, method === "encrypt" ? 0 : 1);
      } finally {
        if (original) {
          Object.defineProperty(crypto.subtle, method, original);
        } else {
          Reflect.deleteProperty(crypto.subtle, method);
        }
      }
    });
  }
}

for (const timeout of [0, 0xffffffff]) {
  test(`KR accepts maximum safe expiresAt and timeout boundary ${timeout}`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.krStartMutate = v => {
      v.expiresAt = Number.MAX_SAFE_INTEGER;
      v.future = 1;
      (v.webauthn as Record<string, unknown>).timeout = timeout;
    };
    assert.equal((await f.client.rekey()).epoch, 1);
    assert.equal(f.assertionOptions!.timeout, timeout);
  });
}

test("KR start's unknown encrypted error members are ignored", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.upPlaintext = (h, plaintext) => h.context === "wake/kr/start"
    ? utf8ToBytes('{"error":{"code":"conflict","future":1},"future":1}') : plaintext;
  await assert.rejects(f.client.rekey(), hasCode("conflict"));
  assert.equal((await f.client.session()).epoch, 0);
});

test("authenticated KR completion extends the local absolute lifetime", async () => {
  const f = await fixture();
  await f.client.login(login);
  await f.client.rekey();
  f.localTime += 1_000_000;
  f.serverTime += 1_000_000;
  assert.equal((await f.client.session()).epoch, 1);
  f.localTime += 500_000;
  await assert.rejects(f.client.session(), hasCode("reauth"));
});

test("KR start rejects an off-curve server public key", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.krStartMutate = v => {
    const key = new Uint8Array(65);
    key[0] = 4;
    v.serverPublicKey = base64urlnopad.encode(key);
  };
  await assert.rejects(f.client.rekey(), hasCode("bad_request"));
  assert.equal(f.krCompleteBodies.length, 0);
  assert.equal((await f.client.session()).epoch, 0);
});

test("recovery probe remains counted under the pending generation's encryption limit", async () => {
  const f = await fixture({ maxEncryptionsPerKey: 3 });
  await f.client.login(login);
  loseThenRetire(f);
  await f.client.rekey();
  await f.client.session();
  await f.client.session();
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.deepEqual(f.requests.map(h => h.epoch), [0, 0, 0, 1, 1, 1]);
});

test("KR without an active session requires login", async () => {
  const f = await fixture();
  await assert.rejects(f.client.rekey(), hasCode("reauth"));
  assert.equal(f.requests.length, 0);
});

test("cancelled KR WebAuthn retains current keys and releases the concurrency guard", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.onAssertion = () => {
    throw new DOMException("cancelled", "NotAllowedError");
  };
  await assert.rejects(f.client.rekey(), { name: "NotAllowedError" });
  assert.equal(f.krCompleteBodies.length, 0);
  assert.equal((await f.client.session()).epoch, 0);
  f.onAssertion = undefined;
  assert.equal((await f.client.rekey()).epoch, 1);
});

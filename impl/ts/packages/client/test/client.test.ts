// Spec §4, §7, §8, §12: client boundary and end-to-end tests.
import assert from "node:assert/strict";
import { test } from "node:test";
import { base64urlnopad } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { DIR_C2S, newRequestId, newSessionId } from "@wake-protocol/core";
import { WakeClient } from "../src/index.ts";
import { TTL, fixture, hasCode, jsonResponse, readJson } from "./fixture.ts";

const login = { mode: "discoverable" } as const;

const data = utf8ToBytes("{}");

test("real KX challenge, Finished and SM session/logout", async () => {
  const f = await fixture();
  assert.equal(f.client.loggedIn, false);
  const info = await f.client.login(login);
  assert.equal(f.client.loggedIn, true);
  assert.equal(info.sessionId, f.start.sessionId);
  assert.equal(info.epoch, 0);
  assert.equal(f.assertionOptions!.challenge.length, 32);
  assert.equal(f.assertionOptions!.userVerification, "required");
  assert.equal(f.assertionOptions!.rpId, "example.com");
  assert.equal(f.assertionOptions!.timeout, TTL - 30_000);
  const session = await f.client.session();
  assert.equal(session.sessionId, info.sessionId);
  assert.equal(session.authTime, 2_000_000);
  assert.equal(session.hardCapAt, 4_000_000);
  assert.equal(session.rekeyRecommended, false);
  await f.client.logout();
  assert.equal(f.revoked, true);
  assert.equal(f.client.loggedIn, false);
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.requests.length, 2);
});

test("username request and credential descriptors reach assertion adapter", async () => {
  const f = await fixture();
  const w = f.start.webauthn as Record<string, unknown>;
  w.allowCredentials = [
    {
      type: "public-key",
      id: "AQ",
      transports: ["internal", "hybrid"],
      extra: 1,
    },
  ];
  await f.client.login({
    mode: "username",
    username: "test",
  });
  assert.deepEqual(readJson(f.startBodies[0]!), {
    mode: "username",
    username: "test",
  });
  assert.deepEqual(f.assertionOptions!.allowCredentials, [
    {
      type: "public-key",
      id: "AQ",
      transports: ["internal", "hybrid"],
    },
  ]);
});

for (const kind of ["network", "503", "retry-body"] as const) {
  test(`auth complete ${kind} retries byte-identical body`, async () => {
    const f = await fixture();
    f.completeAction = (attempt) => {
      if (attempt > 1) {
        return;
      }
      if (kind === "network") {
        throw new TypeError("network unavailable");
      }
      return kind === "503" ? new Response("unavailable", { status: 503 }) : jsonResponse({ error: "retry" });
    };
    await f.client.login(login);
    assert.equal(f.completeBodies.length, 2);
    assert.equal(f.completeBodies[0], f.completeBodies[1]);
    assert.equal(f.assertionCalls, 1);
    assert.deepEqual(f.sleeps, [100]);
  });
}

// The test deadline is startArrivedAt + (expiresAt - serverTime) = localTime + 30 s.
function setShortTtl(f: Awaited<ReturnType<typeof fixture>>) {
  f.start.expiresAt = (f.start.serverTime as number) + 30_000;
}

test("retries stop exactly at the local deadline (start arrival + expiresAt - serverTime)", async () => {
  const f = await fixture();
  setShortTtl(f);
  const arrived = f.localTime;
  f.completeAction = () => {
    throw new TypeError("offline");
  };
  await assert.rejects(f.client.login(login), hasCode("auth_failed"));
  assert.equal(f.sleeps.reduce((a, b) => a + b, 0), 30_000);
  // The last sleep ends exactly at the deadline, where no further attempt is sent.
  assert.equal(f.completeBodies.length, f.sleeps.length);
  assert.equal(f.localTime, arrived + 30_000);
  assert.equal(new Set(f.completeBodies).size, 1);
  assert.equal(f.client.loggedIn, false);
});

test("an attempt just before the local deadline is sent", async () => {
  const f = await fixture();
  setShortTtl(f);
  const deadline = f.localTime + 30_000;
  f.completeAction = (attempt) => {
    if (attempt === 1) {
      f.localTime = deadline - 200;
      throw new TypeError("offline");
    }
    return undefined;
  };
  await f.client.login(login);
  assert.equal(f.completeBodies.length, 2);
  assert.deepEqual(f.sleeps, [100]);
});

test("no attempt is sent once the local deadline is reached", async () => {
  const f = await fixture();
  setShortTtl(f);
  const deadline = f.localTime + 30_000;
  f.completeAction = () => {
    f.localTime = deadline - 100;
    throw new TypeError("offline");
  };
  await assert.rejects(f.client.login(login), hasCode("auth_failed"));
  assert.equal(f.completeBodies.length, 1);
  assert.deepEqual(f.sleeps, [100]);
  assert.equal(f.localTime, deadline);
});

test("a failure after the deadline stops without sleeping", async () => {
  const f = await fixture();
  setShortTtl(f);
  f.completeAction = () => {
    f.localTime += 30_001;
    throw new TypeError("offline");
  };
  await assert.rejects(f.client.login(login), hasCode("auth_failed"));
  assert.equal(f.completeBodies.length, 1);
  assert.equal(f.sleeps.length, 0);
});

test("the first completion is sent even if the deadline passed during WebAuthn", async () => {
  const f = await fixture();
  setShortTtl(f);
  f.onAssertion = () => {
    f.localTime += 10 * TTL;
  };
  await f.client.login(login);
  assert.equal(f.completeBodies.length, 1);
});

for (const [name, skew] of [
  ["ahead of", 10 * TTL],
  ["behind", -10 * TTL],
  ["10 minutes ahead of", 600_000],
  ["10 minutes behind", -600_000],
] as const) {
  test(`login works with a device clock ${name} the server by more than the TTL`, async () => {
    const f = await fixture();
    f.localTime = f.serverTime + skew;
    const info = await f.client.login(login);
    assert.equal(f.completeBodies.length, 1);
    assert.equal(info.serverTime, f.serverTime);
    await f.client.session();
    assert.equal(f.requests[0]!.issuedAt, f.serverTime);
  });
}

for (const kind of ["body-stream", "502", "504", "json-500-retry"] as const) {
  test(`auth complete ${kind} is resent with the same body`, async () => {
    const f = await fixture();
    f.completeAction = (attempt) => {
      if (attempt > 1) {
        return;
      }
      if (kind === "body-stream") {
        let sent = false;
        return new Response(new ReadableStream({
          pull(c) {
            if (sent) {
              c.error(new TypeError("connection lost"));
              return;
            }
            sent = true;
            c.enqueue(utf8ToBytes('{"serverTi'));
          },
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (kind === "json-500-retry") {
        return jsonResponse({ error: "retry" }, 500);
      }
      return new Response(`<html>${kind} gateway</html>`, {
        status: Number(kind),
        headers: { "Content-Type": "text/html" },
      });
    };
    await f.client.login(login);
    assert.equal(f.completeBodies.length, 2);
    assert.equal(f.completeBodies[0], f.completeBodies[1]);
    assert.equal(f.assertionCalls, 1);
  });
}

test("a JSON 500 with another error is final", async () => {
  const f = await fixture();
  f.completeAction = () => jsonResponse({ error: "auth_failed" }, 500);
  await assert.rejects(f.client.login(login), hasCode("auth_failed"));
  assert.equal(f.completeBodies.length, 1);
});

test("reserved wake/ and wake- contexts are rejected locally and keep the keys", async () => {
  const f = await fixture();
  await f.client.login(login);
  for (const context of ["wake/logout", "wake/session", "wake-x", "wake/"]) {
    await assert.rejects(f.client.request(context, data), hasCode("bad_request"));
  }
  assert.equal(f.requests.length, 0);
  assert.equal(f.client.loggedIn, true);
  await f.client.session();
  assert.equal(f.requests.length, 1);
});

for (const [name, mutate] of [
  ["missing serverTime", (v: Record<string, unknown>) => {
    delete v.serverTime;
  }],
  ["fractional serverTime", (v: Record<string, unknown>) => {
    v.serverTime = 1.5;
  }],
  ["negative serverTime", (v: Record<string, unknown>) => {
    v.serverTime = -1;
  }],
  ["string serverTime", (v: Record<string, unknown>) => {
    v.serverTime = "2000000";
  }],
  ["expiresAt equal to serverTime", (v: Record<string, unknown>) => {
    v.expiresAt = v.serverTime;
  }],
  ["expiresAt before serverTime", (v: Record<string, unknown>) => {
    v.expiresAt = (v.serverTime as number) - 1;
  }],
] as const) {
  test(`start with ${name} is bad_request and sends no completion`, async () => {
    const f = await fixture();
    mutate(f.start);
    await assert.rejects(f.client.login(login), hasCode("bad_request"));
    assert.equal(f.completeBodies.length, 0);
  });
}

test("non-canonical base64url trailing bits are rejected as bad_request", async () => {
  // "AQ" is canonical for [1]; "AR" decodes to the same byte with nonzero trailing bits.
  const f = await fixture();
  f.start.sessionId = "A".repeat(42) + "R";
  await assert.rejects(f.client.login(login), hasCode("bad_request"));
  const g = await fixture();
  g.start.serverNonce = (g.start.serverNonce as string).slice(0, -1) + "B";
  await assert.rejects(g.client.login(login), hasCode("bad_request"));
});

for (const field of ["serverTime", "absoluteExpiresAt", "idleTimeoutSec", "serverFinished", "sessionId", "epoch"]) {
  test(`tampered completion ${field} is auth_failed`, async () => {
    const f = await fixture();
    f.completeMutate = (v) => {
      if (field === "serverFinished") {
        v[field] = base64urlnopad.encode(new Uint8Array(32));
      } else if (field === "sessionId") {
        v[field] = base64urlnopad.encode(new Uint8Array(32));
      } else {
        v[field] = (v[field] as number) + 1;
      }
    };
    await assert.rejects(f.client.login(login), hasCode("auth_failed"));
    assert.equal(f.client.loggedIn, false);
  });
}

const invalidStart: [string, (v: Record<string, unknown>) => void][] = [
  ["version", v => {
    v.version = "WAKE/2";
  }],
  ["epoch", v => {
    v.epoch = 1;
  }],
  ["exchangeId length", v => {
    v.exchangeId = "AQ";
  }],
  ["sessionId length", v => {
    v.sessionId = "AQ";
  }],
  ["nonce length", v => {
    v.serverNonce = "AQ";
  }],
  ["binary type", v => {
    v.sessionId = 42;
  }],
  ["padded b64", v => {
    v.sessionId = String(v.sessionId) + "=";
  }],
  ["noncanonical unused bits", v => {
    v.exchangeId = "AAAAAAAAAAAAAAAAAAAAAB";
  }],
  ["invalid alphabet", v => {
    v.serverNonce = "+";
  }],
  ["public key length", v => {
    v.serverPublicKey = "AQ";
  }],
  ["public key prefix", v => {
    v.serverPublicKey = base64urlnopad.encode(new Uint8Array(65));
  }],
  ["off curve", v => {
    const b = new Uint8Array(65);
    b[0] = 4;
    v.serverPublicKey = base64urlnopad.encode(b);
  }],
  ["negative expiresAt", v => {
    v.expiresAt = -1;
  }],
  ["fractional expiresAt", v => {
    v.expiresAt = 1.5;
  }],
  ["unsafe expiresAt", v => {
    v.expiresAt = 2 ** 53;
  }],
  ["webauthn object", v => {
    v.webauthn = [];
  }],
  ["rpId", v => {
    (v.webauthn as Record<string, unknown>).rpId = 1;
  }],
  ["UV", v => {
    (v.webauthn as Record<string, unknown>).userVerification = "preferred";
  }],
  ["allowCredentials", v => {
    (v.webauthn as Record<string, unknown>).allowCredentials = {};
  }],
  ["descriptor object", v => {
    (v.webauthn as Record<string, unknown>).allowCredentials = [null];
  }],
  ["descriptor type", v => {
    (v.webauthn as Record<string, unknown>).allowCredentials = [
      {
        type: "wrong",
        id: "AQ",
      },
    ];
  }],
  ["descriptor id", v => {
    (v.webauthn as Record<string, unknown>).allowCredentials = [
      {
        type: "public-key",
        id: "AQ=",
      },
    ];
  }],
  ["descriptor transports", v => {
    (v.webauthn as Record<string, unknown>).allowCredentials = [
      {
        type: "public-key",
        id: "AQ",
        transports: [1],
      },
    ];
  }],
  ["negative timeout", v => {
    (v.webauthn as Record<string, unknown>).timeout = -1;
  }],
  ["u32 timeout overflow", v => {
    (v.webauthn as Record<string, unknown>).timeout = 2 ** 32;
  }],
];

for (const [name, mutate] of invalidStart) {
  test(`reject start: ${name}`, async () => {
    const f = await fixture();
    mutate(f.start);
    await assert.rejects(f.client.login(login), hasCode("bad_request"));
    assert.equal(f.assertionCalls, 0);
    assert.equal(f.completeBodies.length, 0);
  });
}

for (const text of ['{"version":"WAKE/1","version":"WAKE/1"}', '{"x":"\\ud800"}', '{"x":9007199254740992}', '[]', '{']) {
  test(`reject non-I-JSON start ${text}`, async () => {
    const f = await fixture();
    f.startResponse = new Response(text);
    await assert.rejects(f.client.login(login), hasCode("bad_request"));
  });
}

test("fatal UTF-8 decoding on start", async () => {
  const f = await fixture();
  f.startResponse = new Response(new Uint8Array([0xff]));
  await assert.rejects(f.client.login(login), hasCode("bad_request"));
});

test("unknown fields ignored; exact upper integer boundaries accepted", async () => {
  const f = await fixture();
  f.start.extra = { value: true };
  f.start.expiresAt = Number.MAX_SAFE_INTEGER;
  (f.start.webauthn as Record<string, unknown>).timeout = 0xffffffff;
  await f.client.login(login);
  assert.equal(f.assertionOptions!.timeout, 0xffffffff);
});

for (const field of ["dir", "sessionId", "epoch", "requestId", "context"] as const) {
  test(`wrong s2c ${field} rejected before decryption`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.headerMutate = h => {
      if (field === "dir") {
        h.dir = DIR_C2S;
      }
      if (field === "sessionId") {
        h.sessionId = newSessionId();
      }
      if (field === "epoch") {
        h.epoch = 1;
      }
      if (field === "requestId") {
        h.requestId = newRequestId();
      }
      if (field === "context") {
        h.context = "other";
      }
    };
    // Even unauthentic ciphertext yields bad_request, proving header checks precede open.
    f.tamper = true;
    await assert.rejects(f.client.session(), hasCode("bad_request"));
    assert.equal(f.client.loggedIn, true);
  });
}

test("tampered s2c ciphertext is reauth but retains the session", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.tamper = true;
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, true);
  f.tamper = false;
  await f.client.session();
});

test("decryption failure does not advance the offset from an unauthenticated response", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.localTime += 25;
  f.serverTime += 100_000;
  f.tamper = true;
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, true);
  assert.equal(f.requests[0]!.issuedAt, 2_000_025);

  f.tamper = false;
  f.localTime += 25;
  await f.client.session();
  assert.equal(f.requests[1]!.issuedAt, 2_000_050);

  // Only the successfully decrypted response can correct the next request's time.
  await f.client.session();
  assert.equal(f.requests[2]!.issuedAt, 2_100_000);
  assert.equal(f.requests.length, 3);
});

test("stale_request corrects offset and retries once with fresh requestId and IV", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.serverTime += 100_000;
  f.plaintext = utf8ToBytes('{"error":{"code":"stale_request"}}');
  f.upAction = () => {
    if (f.requests.length === 2) {
      f.plaintext = undefined;
    }
    return undefined;
  };
  await f.client.session();
  assert.equal(f.requests.length, 2);
  assert.equal(f.requests[0]!.issuedAt, 2_000_000);
  assert.equal(f.requests[1]!.issuedAt, 2_100_000);
  assert.equal(f.requests[0]!.requestId.equals(f.requests[1]!.requestId), false);
  assert.equal(f.requests[0]!.iv.equals(f.requests[1]!.iv), false);
});

test("a second stale_request stops instead of looping", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.plaintext = utf8ToBytes('{"error":{"code":"stale_request"}}');
  await assert.rejects(f.client.session(), hasCode("stale_request"));
  assert.equal(f.requests.length, 2);
});

for (const code of ["bad_request", "too_large", "reauth", "epoch_retired", "rate_limited", "retry"]) {
  test(`outer ${code} maps to WakeError`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.upAction = () => jsonResponse({ wakeError: code }, 401);
    // epoch_retired for the current epoch means the server moved on: nothing to fall back to, so reauth.
    const retired = code === "epoch_retired";
    await assert.rejects(f.client.session(), hasCode(retired ? "reauth" : code));
    assert.equal(f.client.loggedIn, code !== "reauth" && !retired);
  });
}

for (const value of [{ wakeError: "unknown" }, { wakeError: 4 }, {}, []]) {
  test(`malformed outer ${JSON.stringify(value)} is bad_request`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.upAction = () => jsonResponse(value, 400);
    await assert.rejects(f.client.session(), hasCode("bad_request"));
  });
}

test("HTTP 200 JSON is still an outer error", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.upAction = () => jsonResponse({ wakeError: "reauth" });
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, false);
});

test("logout resolves offline and always deletes local keys", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.upAction = () => {
    throw new TypeError("offline");
  };
  await f.client.logout();
  assert.equal(f.client.loggedIn, false);
  await f.client.logout();
  await assert.rejects(f.client.request("custom", data), hasCode("reauth"));
  assert.equal(f.requests.length, 1);
});

test("logout surfaces protocol errors after deleting keys", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.plaintext = utf8ToBytes('{"error":{"code":"internal"}}');
  await assert.rejects(f.client.logout(), hasCode("internal"));
  assert.equal(f.client.loggedIn, false);
});

test("unique requestIds/IVs and authenticated time offset across calls", async () => {
  const f = await fixture();
  await f.client.login(login);
  await Promise.all([f.client.session(), f.client.session(), f.client.session()]);
  assert.equal(new Set(f.requests.map(h => base64urlnopad.encode(h.requestId.toUint8Array()))).size, 3);
  assert.equal(new Set(f.requests.map(h => base64urlnopad.encode(h.iv.toUint8Array()))).size, 3);
  assert.equal(f.requests[0]!.issuedAt, f.serverTime);
  f.localTime += 50;
  await f.client.session();
  assert.equal(f.requests[3]!.issuedAt, f.serverTime + 50);
  await f.client.session();
  assert.equal(f.requests[4]!.issuedAt, f.serverTime);
});

test("generic request preserves binary plaintext and ignores error with other members", async () => {
  const f = await fixture();
  await f.client.login(login);
  const binary = new Uint8Array([0xff, 0, 1]);
  assert.deepEqual(await f.client.request("custom", binary), binary);
  const value = utf8ToBytes('{"error":{"code":"stale_request"},"data":1}');
  assert.deepEqual(await f.client.request("custom", value), value);
  assert.equal(f.requests.length, 2);
});

test("encrypted application error maps its string code", async () => {
  const f = await fixture();
  await f.client.login(login);
  await assert.rejects(f.client.request("custom", utf8ToBytes('{"error":{"code":"not_found"}}')), hasCode("not_found"));
});

for (const text of ['{"x":1,"x":2}', '{"x":"\\ud800"}', '[]', '{', '{"x":9007199254740992}']) {
  test(`JSON helper rejects malformed session ${text}`, async () => {
    const f = await fixture();
    await f.client.login(login);
    f.plaintext = utf8ToBytes(text);
    await assert.rejects(f.client.session(), hasCode("bad_request"));
  });
}

for (const limit of [0, -1, 1.5, NaN, Infinity, 2 ** 28 + 1]) {
  test(`reject invalid encryption limit ${limit}`, () => {
    assert.throws(() => new WakeClient({
      baseUrl: "",
      getAssertion: async () => {
        throw new Error();
      },
      maxEncryptionsPerKey: limit,
    }), hasCode("invalid_option"));
  });
}

test("encryption counter boundary counts failed sends and stale retries", async () => {
  const f = await fixture({ maxEncryptionsPerKey: 2 });
  await f.client.login(login);
  f.upAction = () => {
    throw new TypeError("offline");
  };
  await assert.rejects(f.client.session(), TypeError);
  f.upAction = undefined;
  await f.client.session();
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.requests.length, 2);
  assert.equal(f.client.loggedIn, false);
});

test("stale retry cannot exceed encryption budget", async () => {
  const f = await fixture({ maxEncryptionsPerKey: 1 });
  await f.client.login(login);
  f.plaintext = utf8ToBytes('{"error":{"code":"stale_request"}}');
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.requests.length, 1);
  assert.equal(f.client.loggedIn, false);
});

test("absolute lifetime is enforced at the authenticated deadline", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.localTime = 1_999_999;
  await f.client.session();
  // The authenticated response updates offset to 1ms.
  f.localTime = 2_999_999;
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, false);
});

for (const code of ["bad_request", "auth_failed", "rate_limited", "custom_auth_error"]) {
  for (const phase of ["start", "complete"] as const) {
    test(`auth ${phase} preserves error ${code} without retry`, async () => {
      const f = await fixture();
      if (phase === "start") {
        f.startResponse = jsonResponse({ error: code }, 401);
      } else {
        f.completeAction = () => jsonResponse({ error: code }, 401);
      }
      await assert.rejects(f.client.login(login), hasCode(code));
      assert.equal(f.sleeps.length, 0);
      assert.equal(f.client.loggedIn, false);
    });
  }
}

for (const [field, value] of [
  ["serverTime", -1], ["serverTime", 1.5], ["serverTime", 2 ** 53],
  ["absoluteExpiresAt", -1], ["idleTimeoutSec", -1], ["idleTimeoutSec", 2 ** 32],
  ["serverFinished", "AQ"], ["serverFinished", "AQ="], ["serverFinished", null],
] as const) {
  test(`invalid completion ${field}=${value}`, async () => {
    const f = await fixture();
    f.completeMutate = v => {
      v[field] = value;
    };
    await assert.rejects(f.client.login(login), hasCode("auth_failed"));
    assert.equal(f.client.loggedIn, false);
  });
}

test("completion rejects duplicate keys and malformed error responses", async () => {
  for (const text of ['{"serverTime":1,"serverTime":1}', '[]', '{}', '{"error":4}', '{']) {
    const f = await fixture();
    f.completeAction = () => new Response(text, { status: 401 });
    await assert.rejects(f.client.login(login), hasCode("auth_failed"));
  }
});

test("maximum Finished integers authenticate successfully", async () => {
  const f = await fixture();
  f.serverTime = Number.MAX_SAFE_INTEGER;
  // Recompute the Finished using independent peer logic via the fixture's completion path.
  // serverTime itself is an exact boundary; a larger value was rejected above.
  await f.client.login(login);
  assert.equal(f.client.loggedIn, true);
});

const invalidSession: [
  string,
  unknown
][] = [
  ["sessionId", "AQ"], ["sessionId", base64urlnopad.encode(new Uint8Array(32))],
  ["epoch", 1], ["epoch", -1], ["epoch", 2 ** 32], ["authTime", -1],
  ["authTime", 1.5], ["authTime", 2 ** 53], ["absoluteExpiresAt", "3000000"],
  ["hardCapAt", null], ["idleTimeoutSec", -1], ["idleTimeoutSec", 2 ** 32],
  ["serverTime", true], ["rekeyRecommended", 0],
];

for (const [field, value] of invalidSession) {
  test(`invalid session ${field}=${value}`, async () => {
    const f = await fixture();
    const info = await f.client.login(login);
    f.plaintext = utf8ToBytes(JSON.stringify({
      ...info,
      authTime: 2_000_000,
      hardCapAt: 4_000_000,
      rekeyRecommended: false,
      [field]: value,
    }));
    await assert.rejects(f.client.session(), hasCode("bad_request"));
  });
}

test("session accepts unknown members and exact integer limits", async () => {
  const f = await fixture();
  const info = await f.client.login(login);
  f.plaintext = utf8ToBytes(JSON.stringify({
    ...info,
    authTime: 0,
    hardCapAt: Number.MAX_SAFE_INTEGER,
    absoluteExpiresAt: Number.MAX_SAFE_INTEGER,
    idleTimeoutSec: 0xffffffff,
    rekeyRecommended: true,
    future: "ignored",
  }));
  const value = await f.client.session();
  assert.equal(value.authTime, 0);
  assert.equal(value.hardCapAt, Number.MAX_SAFE_INTEGER);
  assert.equal(value.idleTimeoutSec, 0xffffffff);
  assert.equal(value.rekeyRecommended, true);
});

test("session and logout reject invalid UTF-8 after authentication", async () => {
  for (const operation of ["session", "logout"] as const) {
    const f = await fixture();
    await f.client.login(login);
    f.plaintext = new Uint8Array([0xff]);
    await assert.rejects(f.client[operation](), hasCode("bad_request"));
    assert.equal(f.client.loggedIn, operation === "session");
  }
});

test("logout validates JSON object, ignoring unknown members", async () => {
  for (const text of ['[]', '{"x":1,"x":2}', '{"future":1}']) {
    const f = await fixture();
    await f.client.login(login);
    f.plaintext = utf8ToBytes(text);
    if (text === '{"future":1}') {
      await f.client.logout();
    } else {
      await assert.rejects(f.client.logout(), hasCode("bad_request"));
    }
    assert.equal(f.client.loggedIn, false);
  }
});

test("logout tolerates network failure while reading the response body", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.upAction = () => new Response(new ReadableStream({ start(c) {
      c.error(new TypeError("connection lost"));
    } }));
  await f.client.logout();
  assert.equal(f.client.loggedIn, false);
});

test("malformed outer JSON and wire are rejected", async () => {
  for (const response of [
    new Response('{"wakeError":"retry","wakeError":"retry"}', { status: 503 }),
    new Response(new Uint8Array([0xff]), { status: 401 }),
    new Response(new Uint8Array([1, 2, 3]), { headers: { "Content-Type": "application/wake" } }),
  ]) {
    const f = await fixture();
    await f.client.login(login);
    f.upAction = () => response;
    await assert.rejects(f.client.session(), hasCode("bad_request"));
  }
});

test("issuedAt floors fractional clock and clamps negative time", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.localTime = -1_000_000.5;
  await f.client.session();
  assert.equal(f.requests[0]!.issuedAt, 0);
  f.localTime += 0.75;
  await f.client.session();
  assert.equal(f.requests[1]!.issuedAt, 2_000_000);
});

test("new login clears existing session even if WebAuthn fails", async () => {
  let rejectAssertion = false;
  const f = await fixture({ getAssertion: async (opts) => {
      if (rejectAssertion) {
        throw new DOMException("cancelled", "NotAllowedError");
      }
      return {
        id: "AQ",
        rawId: "AQ",
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: base64urlnopad.encode(utf8ToBytes(JSON.stringify({ challenge: base64urlnopad.encode(opts.challenge) }))),
          authenticatorData: "AQ",
          signature: "AQ",
        },
      };
    } });
  await f.client.login(login);
  rejectAssertion = true;
  await assert.rejects(f.client.login(login), { name: "NotAllowedError" });
  assert.equal(f.client.loggedIn, false);
});

test("logout invalidates an in-flight login instead of resurrecting keys", async () => {
  let release!: () => void;
  let reached!: () => void;
  const blocked = new Promise<void>(resolve => {
    release = resolve;
  });
  const assertionReached = new Promise<void>(resolve => {
    reached = resolve;
  });
  const f = await fixture({ getAssertion: async () => {
      reached();
      await blocked;
      return {
        id: "AQ",
        rawId: "AQ",
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: "AQ",
          authenticatorData: "AQ",
          signature: "AQ",
        },
      };
    } });
  const pending = f.client.login(login);
  await assertionReached;
  await f.client.logout();
  release();
  await assert.rejects(pending, hasCode("auth_failed"));
  assert.equal(f.client.loggedIn, false);
  assert.equal(f.completeBodies.length, 0);
});

test("hard encryption maximum itself is accepted", async () => {
  const f = await fixture({ maxEncryptionsPerKey: 2 ** 28 });
  await f.client.login(login);
  await f.client.session();
});

test("JSON 503 responses are checked with strict I-JSON before retry", async () => {
  const f = await fixture();
  f.completeAction = () => new Response('{"error":"retry","error":"retry"}', {
    status: 503,
    headers: { "Content-Type": "application/json" },
  });
  await assert.rejects(f.client.login(login), hasCode("auth_failed"));
  assert.equal(f.completeBodies.length, 1);
  assert.equal(f.sleeps.length, 0);
});

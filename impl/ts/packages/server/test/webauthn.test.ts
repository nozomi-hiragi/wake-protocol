// Tests for WAKE server behavior (spec §6.2–§6.4).
import assert from "node:assert/strict";
import { test } from "node:test";
import { fixture, prepare, jsonRequest, expectError, ORIGIN, RP, encode, decode } from "./helpers.ts";
import type { AssertionTamper } from "../src/testing.ts";
import { SoftAuthenticator } from "../src/testing.ts";

const tamperCases: [string, AssertionTamper][] = [
  ["assertion type", { type: "other" }],
  ["client data type", { clientDataType: "webauthn.create" }],
  ["challenge mismatch", { challenge: new Uint8Array(32) }],
  ["challenge short", { challenge: new Uint8Array(31) }],
  ["challenge noncanonical", { challenge: "AA=" }],
  ["origin exact mismatch", { origin: `${ORIGIN}/` }],
  ["unlisted origin", { origin: "https://evil.example.com" }],
  ["cross origin", { crossOrigin: true }],
  ["nonboolean cross origin", { crossOrigin: "false" }],
  ["top origin", { topOrigin: ORIGIN }],
  ["RP hash", { rpIdHash: new Uint8Array(32) }],
  ["RP name", { rpId: "other.example.com" }],
  ["UP absent", { clearFlags: 0x01 }],
  ["UV absent", { clearFlags: 0x04 }],
  ["AT set", { setFlags: 0x40 }],
  ["BS without BE", { flags: 0x15 }],
  ["ED set without extension data", { setFlags: 0x80 }],
  ["extensions without ED", { extraAuthData: new Uint8Array([0xa0]) }],
  ["short auth data", { authenticatorData: new Uint8Array(36) }],
  ["user handle mismatch", { userHandle: new Uint8Array([1]) }],
  ["unknown credential", { credentialId: new Uint8Array(32), rawId: new Uint8Array(32) }],
  ["id mismatch", { credentialId: new Uint8Array([9]) }],
  ["rawId mismatch", { rawId: new Uint8Array([9]) }],
  ["id noncanonical", { credentialId: "AA=" }],
  ["rawId noncanonical", { rawId: "AA=" }],
  ["corrupt signature", { corruptSignature: true }],
  ["raw signature bytes", { signature: new Uint8Array(64) }],
  [
    "duplicate JSON keys",
    { clientDataJSON: '{"type":"webauthn.get","type":"webauthn.get"}' }
  ],
  ["invalid client data UTF-8", { clientDataJSON: new Uint8Array([0xff]) }],
  ["nonobject client data", { clientDataJSON: "[]" }],
  ["malformed client data", { clientDataJSON: "{" }],
  ["lone surrogate client data", { clientDataJSON: '{"x":"\\ud800"}' }],
  ["unsafe integer client data", { clientDataJSON: '{"x":9007199254740992}' }],
];

for (const variant of ["non-minimal", "trailing", "wrong-tag", "negative", "long-form"] as const) {
  tamperCases.push([`DER ${variant}`, { signatureDer: variant }]);
}

for (const [name, tamper] of tamperCases) {
  test(
    `WebAuthn rejects ${name} without consuming exchange`,
    async () => {
      const f = await fixture();
      const strictExtension = ["duplicate JSON keys", "lone surrogate client data", "unsafe integer client data"].includes(name);
      const p = await prepare(f, strictExtension ? {} : tamper);
      if (strictExtension) {
        const received = JSON.parse(new TextDecoder().decode(decode(p.body.assertion.response.clientDataJSON))) as { challenge: string; };
        const base = new TextDecoder().decode(decode(p.body.assertion.response.clientDataJSON)).slice(0, -1);
        const extension = name === "duplicate JSON keys" ?
          ',"x":1,"x":2}' :
          name === "lone surrogate client data" ? ',"x":"\\ud800"}' : ',"x":9007199254740992}';
        p.body.assertion = await f.auth.getAssertion(
          { ...p.info.webauthn, challenge: decode(received.challenge) },
          { clientDataJSON: base + extension },
        );
      }
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
      const exchange = await f.store.getExchange(decode(p.info.exchangeId), f.clock.now);
      assert.equal(exchange?.state, "PENDING");
      assert.ok(exchange?.serverPrivateKey);
    }
  );
}

for (const field of ["clientDataJSON", "authenticatorData", "signature"] as const) {
  test(
    `WebAuthn rejects noncanonical ${field}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      p.body.assertion.response[field] += "=";
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
    }
  );
}

for (const status of ["pending", "suspended", "deleted"] as const) {
  test(
    `WebAuthn rejects ${status} credentials`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      f.credentials.setCredential({ ...f.auth.credential, status }, "alice");
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
    }
  );
}

for (const change of [{ algorithm: -257 }, { publicKey: new Uint8Array(1) }]) {
  test(
    `WebAuthn rejects unsupported algorithm or invalid SPKI ${Object.keys(change)}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      f.credentials.setCredential({ ...f.auth.credential, ...change }, "alice");
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
    }
  );
}

for (const tamper of [
  { userHandle: "omit" },
  { userHandle: null },
  { crossOrigin: false },
  { setFlags: 0x80, extraAuthData: new Uint8Array([0xa0]) },
  { flags: 0x1d }
] as AssertionTamper[]) {
  test(
    `WebAuthn accepts optional handles, same origin and valid flags ${JSON.stringify(tamper)}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f, tamper);
      assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
    }
  );
}

test(
  "username check rejects another user's otherwise valid credential",
  async () => {
    const f = await fixture();
    const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
    f.credentials.setCredential(other.credential, "bob");
    const p = await prepare(f, {}, { mode: "username", username: "bob" }, true);
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

test(
  "unknown username cannot authenticate a real credential even when allowCredentials is bypassed",
  async () => {
    const f = await fixture();
    const p = await prepare(f, {}, { mode: "username", username: "missing" }, true);
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

test(
  "SoftAuthenticator respects RP and allowCredentials and keeps counters independently",
  async () => {
    const auth = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1", signCount: 9, credentialIdLength: 16 });
    assert.equal(auth.credential.credentialId.length, 16);
    assert.equal(auth.credential.signCount, 9);
    const options = {
      rpId: RP,
      challenge: new Uint8Array(32),
      allowCredentials: [],
      userVerification: "required" as const,
      timeout: 1
    };
    await assert.rejects(
      auth.getAssertion({
        ...options,
        allowCredentials: [{ type: "public-key", id: encode(new Uint8Array([9])) }]
      }),
      { name: "NotAllowedError" }
    );
    await assert.rejects(auth.getAssertion({ ...options, rpId: "other.com" }), { name: "NotAllowedError" });
    await auth.getAssertion(options, { counter: "fixed" });
    assert.equal(auth.signCount, 9);
    await auth.getAssertion(options);
    assert.equal(auth.signCount, 10);
    assert.equal(auth.credential.signCount, 9);
  }
);

const counterRows = [
  { stored: 0, received: 0, backup: false, flags: 5, accepted: true },
  { stored: 1, received: 2, backup: false, flags: 5, accepted: true },
  { stored: 2, received: 2, backup: false, flags: 13, accepted: false },
  { stored: 2, received: 1, backup: false, flags: 13, accepted: false },
  { stored: 2, received: 2, backup: true, flags: 5, accepted: true },
  { stored: 2, received: 1, backup: true, flags: 5, accepted: true },
];

for (const row of counterRows) {
  test(
    `signature counter policy ${JSON.stringify(row)}`,
    async () => {
      const events: unknown[] = [];
      const f = await fixture(
        {
          onCounterAnomaly: event => {
            events.push(event);
          }
        },
        {
          rpId: RP,
          origin: ORIGIN,
          userId: "u1",
          signCount: row.stored,
          backupEligible: row.backup
        }
      );
      const p = await prepare(f, { signCount: row.received, counter: "fixed", flags: row.flags });
      const result = await jsonRequest(f.server, "/auth/complete", p.body);
      if (row.accepted) {
        assert.equal(result.status, 200);
        assert.equal(
          (await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount,
          Math.max(row.stored, row.received)
        );
        assert.equal(events.length, row.stored > 0 && row.received <= row.stored ? 1 : 0);
        if (events.length) {
          assert.deepEqual(
            events[0],
            {
              credentialId: f.auth.credential.credentialId,
              userId: "u1",
              storedSignCount: row.stored,
              receivedSignCount: row.received
            }
          );
        }
      } else {
        await expectError(result, 401, "auth_failed");
        assert.equal(events.length, 0);
      }
    }
  );
}

test(
  "credential counter updates use max for concurrent and older values",
  async () => {
    const f = await fixture();
    await Promise.all(
      [
        f.credentials.updateSignCount(f.auth.credential.credentialId, 7),
        f.credentials.updateSignCount(f.auth.credential.credentialId, 3)
      ]
    );
    await f.credentials.updateSignCount(f.auth.credential.credentialId, 1);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 7);
  }
);

test(
  "assertion signature must match stored credential public key",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
    f.credentials.setCredential({ ...f.auth.credential, publicKey: other.credential.publicKey }, "alice");
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

for (const field of ["id", "rawId", "type", "response"] as const) {
  test(
    `assertion rejects incorrect JSON field type ${field}`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      await expectError(
        await jsonRequest(f.server, "/auth/complete", { ...p.body, assertion: { ...p.body.assertion, [field]: 1 } }),
        401,
        "auth_failed"
      );
    }
  );
}

test(
  "assertion rejects noncanonical userHandle",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    p.body.assertion.response.userHandle += "=";
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

for (const field of ["id", "rawId"] as const) {
  test(
    `canonical ${field} encoding enforced even when decoded ID matches`,
    async () => {
      const f = await fixture();
      const p = await prepare(f);
      p.body.assertion[field] += "=";
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
    }
  );
}

test(
  "DER tamper variants preserve valid signed integer values",
  async () => {
    const { ecdsaDerToRaw, importP256SpkiPublicKey, p256EcdsaVerify, sha256 } = await import("@wake-protocol/crypto");
    const f = await fixture();
    const key = await importP256SpkiPublicKey(f.auth.credential.publicKey);
    for (const variant of ["non-minimal", "trailing", "wrong-tag", "negative", "long-form"] as const) {
      const assertion = await f.auth.getAssertion(
        {
          rpId: RP,
          challenge: new Uint8Array(32),
          allowCredentials: [],
          userVerification: "required",
          timeout: 1
        },
        { signatureDer: variant }
      );
      const der = decode(assertion.response.signature);
      let offset = variant === "long-form" ? 3 : 2;
      const raw = new Uint8Array(64);
      for (let part = 0; part < 2; part++) {
        assert.equal(der[offset++], 2);
        const length = der[offset++]!;
        let integer = der.slice(offset, offset + length);
        offset += length;
        while (integer.length > 1 && integer[0] === 0) {
          integer = integer.subarray(1);
        }
        assert.ok(integer.length <= 32);
        raw.set(integer, (part + 1) * 32 - integer.length);
      }
      const authData = decode(assertion.response.authenticatorData);
      const clientHash = await sha256(decode(assertion.response.clientDataJSON));
      const signed = new Uint8Array(authData.length + 32);
      signed.set(authData);
      signed.set(clientHash, authData.length);
      assert.equal(await p256EcdsaVerify(key, raw, signed), true, variant);
      if (variant === "non-minimal") {
        assert.equal(der[4], 0);
        assert.ok(der[5]! > 0 && der[5]! < 0x80);
        const repaired = new Uint8Array([...der.slice(0, 4), ...der.slice(5)]);
        repaired[1] = repaired[1]! - 1;
        repaired[3] = repaired[3]! - 1;
        assert.equal(await p256EcdsaVerify(key, ecdsaDerToRaw(repaired, 32), signed), true);
      }
    }
  }
);

for (const userHandle of ["omit", null] as const) {
  test(
    `username completes with ${String(userHandle)} userHandle`,
    async () => {
      const f = await fixture();
      const p = await prepare(f, { userHandle }, { mode: "username", username: "alice" });
      assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
    }
  );
}

test(
  "canonical challenge check rejects padded encoding of otherwise correct 32-byte challenge",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    const original = JSON.parse(new TextDecoder().decode(decode(p.body.assertion.response.clientDataJSON))) as { challenge: string; };
    p.body.assertion = await f.auth.getAssertion(
      { ...p.info.webauthn, challenge: decode(original.challenge) },
      { challenge: original.challenge + "=" },
    );
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

test(
  "counter anomaly callback failure preserves committed login and replay never notifies twice",
  async () => {
    let notifications = 0;
    const f = await fixture(
      {
        onCounterAnomaly: async () => {
          notifications++;
          throw new Error("audit unavailable");
        }
      },
      { rpId: RP, origin: ORIGIN, userId: "u1", signCount: 2, backupEligible: true }
    );
    const p = await prepare(f, { signCount: 1 });
    let counterUpdates = 0;
    const update = f.credentials.updateSignCount.bind(f.credentials);
    f.credentials.updateSignCount = async (...args) => {
      counterUpdates++;
      await update(...args);
    };
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 503, "retry");
    assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "COMPLETED");
    assert.equal((await f.store.getSession(p.sessionId.toUint8Array()))?.status, "ACTIVE");
    assert.equal(counterUpdates, 1);
    assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, 2);
    assert.equal(notifications, 1);
    assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
    assert.equal(notifications, 1);
    assert.equal(counterUpdates, 1);
  }
);

test(
  "counter anomaly with later Finished failure does not notify",
  async () => {
    let notifications = 0;
    const f = await fixture(
      {
        onCounterAnomaly: () => {
          notifications++;
        }
      },
      { rpId: RP, origin: ORIGIN, userId: "u1", signCount: 2, backupEligible: true }
    );
    const p = await prepare(f, { signCount: 1 });
    await expectError(
      await jsonRequest(f.server, "/auth/complete", { ...p.body, clientFinished: encode(new Uint8Array(32)) }),
      401,
      "auth_failed"
    );
    assert.equal(notifications, 0);
    assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "PENDING");
    assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
    assert.equal(notifications, 1);
  }
);

test(
  "concurrent anomaly completions notify only the successful commit",
  async () => {
    const events: unknown[] = [];
    const f = await fixture(
      {
        onCounterAnomaly: event => {
          events.push(event);
        }
      },
      { rpId: RP, origin: ORIGIN, userId: "u1", signCount: 2, backupEligible: true }
    );
    const p = await prepare(f, { signCount: 1 });
    const replies = await Promise.all([
      jsonRequest(f.server, "/auth/complete", p.body),
      jsonRequest(f.server, "/auth/complete", p.body)
    ]);
    for (const reply of replies) {
      assert.equal(reply.status, 200);
    }
    assert.equal(await replies[0]!.text(), await replies[1]!.text());
    assert.deepEqual(
      events,
      [
        {
          credentialId: f.auth.credential.credentialId,
          userId: "u1",
          storedSignCount: 2,
          receivedSignCount: 1
        }
      ]
    );
  }
);

test(
  "signed correct challenge rejects nonzero unused low two bits as auth_failed",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    const original = JSON.parse(new TextDecoder().decode(decode(p.body.assertion.response.clientDataJSON))) as { challenge: string; };
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(original.challenge.at(-1)!);
    assert.equal(last & 3, 0);
    const noncanonical = original.challenge.slice(0, -1) + alphabet[last | 1]!;
    p.body.assertion = await f.auth.getAssertion(
      { ...p.info.webauthn, challenge: decode(original.challenge) },
      { challenge: noncanonical },
    );
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

test(
  "rawId length modulo four equal to one maps to auth_failed",
  async () => {
    const f = await fixture();
    const p = await prepare(f);
    p.body.assertion.rawId += "AA";
    assert.equal(p.body.assertion.rawId.length % 4, 1);
    await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 401, "auth_failed");
  }
);

for (const anomaly of [false, true]) {
  test(
    `a counter update that fails after the commit is applied on replay (anomaly ${anomaly})`,
    async () => {
      let notifications = 0;
      const f = await fixture(
        {
          onCounterAnomaly: () => {
            notifications++;
          }
        },
        { rpId: RP, origin: ORIGIN, userId: "u1", signCount: anomaly ? 5 : 0, backupEligible: true }
      );
      const p = await prepare(f, { signCount: anomaly ? 3 : 4 });
      const update = f.credentials.updateSignCount.bind(f.credentials);
      let attempts = 0;
      f.credentials.updateSignCount = async (...args) => {
        if (attempts++ === 0) {
          throw new Error("credential store unavailable");
        }
        await update(...args);
      };
      await expectError(await jsonRequest(f.server, "/auth/complete", p.body), 503, "retry");
      assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.state, "COMPLETED");
      assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, anomaly ? 5 : 0);
      assert.equal(notifications, 0);
      const replayed = await jsonRequest(f.server, "/auth/complete", p.body);
      assert.equal(replayed.status, 200);
      assert.equal(attempts, 2);
      assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))?.signCount, anomaly ? 5 : 4);
      assert.equal(notifications, anomaly ? 1 : 0);
      assert.equal((await jsonRequest(f.server, "/auth/complete", p.body)).status, 200);
      assert.equal(attempts, 2);
      assert.equal(notifications, anomaly ? 1 : 0);
      assert.equal((await f.store.getExchange(decode(p.info.exchangeId), f.clock.now))?.signCountUpdate, undefined);
    }
  );
}

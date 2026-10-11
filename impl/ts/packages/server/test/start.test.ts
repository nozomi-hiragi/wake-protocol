// Tests for WAKE server behavior (spec §6.6, §7.2).
import assert from "node:assert/strict";
import { test } from "node:test";
import { fixture, start, jsonRequest, expectError, decode, encode, ORIGIN, response } from "./helpers.ts";
import { SoftAuthenticator } from "../src/testing.ts";

test(
  "start exposes fresh exchange values and required WebAuthn options",
  async () => {
    const f = await fixture();
    const a = await start(f);
    const b = await start(f);
    assert.equal(a.version, "WAKE/1");
    assert.equal(a.epoch, 0);
    assert.equal(a.expiresAt, f.clock.now + 300000);
    assert.equal(decode(a.exchangeId).length, 16);
    assert.equal(decode(a.sessionId).length, 32);
    assert.equal(decode(a.serverNonce).length, 32);
    assert.equal(decode(a.serverPublicKey).length, 65);
    assert.equal(decode(a.serverPublicKey)[0], 4);
    assert.notEqual(a.exchangeId, b.exchangeId);
    assert.notEqual(a.sessionId, b.sessionId);
    assert.notEqual(a.serverNonce, b.serverNonce);
    assert.notEqual(a.serverPublicKey, b.serverPublicKey);
    assert.deepEqual(a.webauthn, {
      rpId: "example.com",
      allowCredentials: [],
      userVerification: "required",
      timeout: 270000
    });
    const exchange = await f.store.getExchange(decode(a.exchangeId), f.clock.now);
    assert.equal(exchange?.state, "PENDING");
    assert.equal(exchange?.serverPrivateKey?.extractable, false);
    assert.equal(await f.store.getSession(decode(a.sessionId)), null);
  }
);

test(
  "username start filters inactive credentials and forwards transports",
  async () => {
    const f = await fixture();
    const inactive = await SoftAuthenticator.create({ rpId: "example.com", origin: ORIGIN, userId: "u1" });
    f.credentials.setCredential({ ...inactive.credential, status: "suspended" }, "alice");
    const result = await start(f, { mode: "username", username: "alice", extra: true });
    assert.deepEqual(
      result.webauthn.allowCredentials,
      [
        {
          type: "public-key",
          id: encode(f.auth.credential.credentialId),
          transports: ["internal", "hybrid"]
        }
      ]
    );
  }
);

test(
  "unknown and credentialless users get deterministic distinct fake IDs with the same shape",
  async () => {
    const f = await fixture({ fakeCredentialCount: 3, fakeCredentialIdLength: 16 });
    f.credentials.setUser("empty", "u2");
    const [a, b, c, empty] = await Promise.all(
      [
        start(f, { mode: "username", username: "missing" }),
        start(f, { mode: "username", username: "missing" }),
        start(f, { mode: "username", username: "other" }),
        start(f, { mode: "username", username: "empty" })
      ]
    );
    assert.deepEqual(a.webauthn.allowCredentials, b.webauthn.allowCredentials);
    assert.notDeepEqual(a.webauthn.allowCredentials, c.webauthn.allowCredentials);
    assert.equal(a.webauthn.allowCredentials.length, 3);
    assert.equal(empty.webauthn.allowCredentials.length, 3);
    for (const item of a.webauthn.allowCredentials) {
      assert.equal(decode(item.id).length, 16);
      assert.deepEqual(item.transports, ["internal", "hybrid"]);
    }
    assert.equal(new Set(a.webauthn.allowCredentials.map(item => item.id)).size, 3);
    assert.deepEqual(Object.keys(a).sort(), Object.keys(await start(f, { mode: "username", username: "alice" })).sort());
  }
);

for (const body of [
  null,
  [],
  "discoverable",
  {},
  { mode: "other" },
  { mode: "username" },
  { mode: "username", username: "" },
  { mode: "username", username: 1 },
  { mode: "username", username: "x".repeat(257) }
]) {
  test(
    `start rejects invalid shape ${JSON.stringify(body)}`,
    async () => {
      const f = await fixture();
      await expectError(await jsonRequest(f.server, "/auth/start", body), 400, "bad_request");
    }
  );
}

test(
  "username length accepts 256 UTF-16 code units and rejects 257",
  async () => {
    const f = await fixture();
    assert.equal((await jsonRequest(f.server, "/auth/start", { mode: "username", username: "x".repeat(256) })).status, 200);
    await expectError(await jsonRequest(f.server, "/auth/start", { mode: "username", username: "x".repeat(257) }), 400, "bad_request");
  }
);

for (const path of ["/auth/start", "/auth/complete", "/wake/up"]) {
  test(
    `${path} rejects other methods and advertises POST`,
    async () => {
      const f = await fixture();
      const res = response(await f.server.handle(new Request(`${ORIGIN}${path}`, { method: "GET" })));
      assert.equal(res.headers.get("allow"), "POST");
      await expectError(res, 405, "bad_request", path === "/wake/up");
    }
  );
}

for (const body of [
  '{"mode":"discoverable","mode":"discoverable"}',
  '{"mode":"discoverable","x":"\\ud800"}',
  '{"mode":"discoverable","x":9007199254740992}',
  '{',
  '[]'
]) {
  test(
    `start rejects strict JSON ${body}`,
    async () => {
      const f = await fixture();
      await expectError(
        response(
          await f.server.handle(
            new Request(`${ORIGIN}/auth/start`, { method: "POST", headers: { "content-type": "application/json" }, body })
          )
        ),
        400,
        "bad_request"
      );
    }
  );
}

test(
  "auth content type parameters accepted; mismatched type and invalid UTF-8 rejected",
  async () => {
    const f = await fixture();
    assert.equal(
      (await jsonRequest(f.server, "/auth/start", { mode: "discoverable" }, { "content-type": "application/json; charset=utf-8" })).status,
      200
    );
    await expectError(
      await jsonRequest(f.server, "/auth/start", { mode: "discoverable" }, { "content-type": "text/plain" }),
      400,
      "bad_request"
    );
    await expectError(
      response(
        await f.server.handle(
          new Request(`${ORIGIN}/auth/start`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: new Uint8Array([0xff])
          })
        )
      ),
      400,
      "bad_request"
    );
  }
);

test(
  "auth body size checks actual size and Content-Length",
  async () => {
    const text = '{"mode":"discoverable"}';
    const f = await fixture({ maxAuthBody: text.length });
    assert.equal((await jsonRequest(f.server, "/auth/start", { mode: "discoverable" })).status, 200);
    await expectError(
      response(
        await f.server.handle(
          new Request(`${ORIGIN}/auth/start`, { method: "POST", headers: { "content-type": "application/json" }, body: text + " " })
        )
      ),
      400,
      "bad_request"
    );
    await expectError(
      await jsonRequest(f.server, "/auth/start", { mode: "discoverable" }, { "content-length": String(text.length + 1) }),
      400,
      "bad_request"
    );
  }
);

test(
  "unrecognized paths are left to the host app",
  async () => {
    const f = await fixture();
    assert.equal(await f.server.handle(new Request(`${ORIGIN}/api/custom`)), null);
  }
);

test(
  "fake IDs match independently constructed domain-separated HMAC inputs",
  async () => {
    const { createHmac } = await import("node:crypto");
    const f = await fixture({ fakeCredentialCount: 2, fakeCredentialIdLength: 16 });
    const result = await start(f, { mode: "username", username: "missing" });
    for (let index = 0; index < 2; index++) {
      const fields = [
        Buffer.from("wake-server fake-credential", "ascii"),
        Buffer.from("missing", "utf8"),
        Buffer.alloc(4)
      ];
      fields[2]!.writeUInt32BE(index);
      const pieces = fields.flatMap(field => {
        const length = Buffer.alloc(4);
        length.writeUInt32BE(field.length);
        return [length, field];
      });
      const expected = createHmac("sha256", Buffer.alloc(32, 7))
        .update(Buffer.concat(pieces))
        .digest()
        .subarray(0, 16)
        .toString("base64url");
      assert.equal(result.webauthn.allowCredentials[index]!.id, expected);
    }
  }
);

test(
  "streamed size violation returns size error even when cancellation rejects",
  async () => {
    const f = await fixture({ maxAuthBody: 32 });
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"mode":"discoverable"}'));
        controller.enqueue(new Uint8Array(33));
      },
      cancel() {
        cancelled = true;
        throw new Error("cancel failed");
      }
    });
    const req = new Request(`${ORIGIN}/auth/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      duplex: "half"
    } as RequestInit);
    await expectError(response(await f.server.handle(req)), 400, "bad_request");
    assert.equal(cancelled, true);
  }
);

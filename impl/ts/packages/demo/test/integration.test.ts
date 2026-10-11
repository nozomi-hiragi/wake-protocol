// Real WakeClient against a real WAKE server in process (spec §7, §8, §12).
import assert from "node:assert/strict";
import { test } from "node:test";
import { WakeClient } from "@wake-protocol/client";
import type { GetAssertionOptions } from "@wake-protocol/client";
import { createWakeServer, MemoryCredentialStore, MemoryWakeStore } from "@wake-protocol/server";
import { SoftAuthenticator } from "@wake-protocol/server/testing";
import { createDemoApp } from "../src/app.ts";
import { assertionFor } from "./helpers.ts";

const RP = "example.com";
const ORIGIN = "https://example.com";
const W = 300_000;

const hasCode = (code: string) => (e: unknown) => e instanceof Error && "code" in e && e.code === code;

interface Clock {
  client: number;
  server: number;
}

type Handler = (req: Request) => Promise<Response | null>;

async function setup(wrap?: (handle: Handler) => Handler, clientOffsetMs = 0) {
  const auth = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const credentials = new MemoryCredentialStore();
  credentials.setCredential(auth.credential, "alice");
  const clock: Clock = { client: 1_000_000 + clientOffsetMs, server: 1_000_000 };
  const server = createWakeServer({
    rpId: RP,
    loginOrigins: [ORIGIN],
    secret: new Uint8Array(32).fill(9),
    credentials,
    store: new MemoryWakeStore(),
    now: () => clock.server,
  });
  const f = {
    auth,
    clock,
    server,
    calls: [] as string[],
    wrap: wrap ?? ((handle: Handler) => handle),
  };
  const handle = f.wrap((req) => server.handle(req));
  const fetchImpl: typeof fetch = async (url, init) => {
    const request = new Request(new URL(String(url), ORIGIN), init);
    f.calls.push(new URL(request.url).pathname);
    const response = await handle(request);
    assert.ok(response);
    return response;
  };
  const getAssertion = assertionFor(auth);
  const client = new WakeClient({
    baseUrl: ORIGIN,
    getAssertion,
    fetch: fetchImpl,
    now: () => clock.client,
    sleep: async () => {},
  });
  return { ...f, client, fetchImpl, getAssertion, credentials };
}

test("discoverable login, session, logout, session rejects with reauth", async () => {
  const f = await setup();
  const login = await f.client.login({ mode: "discoverable" });
  assert.equal(login.epoch, 0);
  assert.equal(f.client.loggedIn, true);
  const session = await f.client.session();
  assert.equal(session.sessionId, login.sessionId);
  assert.equal(session.epoch, 0);
  assert.equal(session.absoluteExpiresAt, login.absoluteExpiresAt);
  assert.equal(session.idleTimeoutSec, login.idleTimeoutSec);
  assert.equal(session.serverTime, f.clock.server);
  assert.equal(session.authTime, f.clock.server);
  assert.equal(session.rekeyRecommended, false);
  assert.ok(session.hardCapAt >= session.absoluteExpiresAt);
  await f.client.logout();
  assert.equal(f.client.loggedIn, false);
  await assert.rejects(f.client.session(), hasCode("reauth"));
});

test("a new login after logout gets a fresh session", async () => {
  const f = await setup();
  const login = await f.client.login({ mode: "discoverable" });
  await f.client.logout();
  const second = await f.client.login({ mode: "discoverable" });
  assert.notEqual(second.sessionId, login.sessionId);
  assert.equal((await f.client.session()).sessionId, second.sessionId);
});

test("username login works and an unknown username fails with auth_failed", async () => {
  const f = await setup();
  const login = await f.client.login({ mode: "username", username: "alice" });
  assert.equal((await f.client.session()).sessionId, login.sessionId);
  // The server answers an unknown username with a fake allow list. A real authenticator cannot use it ...
  const other = await setup();
  await assert.rejects(
    other.client.login({ mode: "username", username: "nobody" }),
    (e: unknown) => e instanceof Error && e.name === "NotAllowedError",
  );
  // ... and one that ignores the list (a resident key picked by the user) still fails at /auth/complete.
  const ignoring = new WakeClient({
    baseUrl: ORIGIN,
    getAssertion: (options: GetAssertionOptions) => other.getAssertion({ ...options, allowCredentials: [] }),
    fetch: other.fetchImpl,
    now: () => other.clock.client,
    sleep: async () => {},
  });
  await assert.rejects(ignoring.login({ mode: "username", username: "nobody" }), hasCode("auth_failed"));
  assert.equal(ignoring.loggedIn, false);
});

test("a lost /auth/complete response is recovered by resending the same body", async () => {
  let dropped = false;
  const bodies: string[] = [];
  const f = await setup(handle => async (req) => {
    if (new URL(req.url).pathname !== "/auth/complete") {
      return handle(req);
    }
    bodies.push(await req.clone().text());
    const response = await handle(req);
    if (!dropped) {
      dropped = true;
      throw new TypeError("network error");
    }
    return response;
  });
  const login = await f.client.login({ mode: "discoverable" });
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0], bodies[1]);
  assert.equal(f.calls.filter(path => path === "/auth/complete").length, 2);
  assert.equal(f.calls.filter(path => path === "/auth/start").length, 1);
  assert.equal((await f.client.session()).sessionId, login.sessionId);
  // The authenticator was used once and the credential counter advanced once.
  assert.equal(f.auth.signCount, 1);
});

test("a stale_request response corrects the clock offset and succeeds with one resend", async () => {
  const f = await setup();
  await f.client.login({ mode: "discoverable" });
  const before = f.calls.length;
  f.clock.server += W + 1;
  const session = await f.client.session();
  assert.equal(session.serverTime, f.clock.server);
  assert.equal(f.calls.slice(before).filter(path => path === "/wake/up").length, 2);
  // The corrected offset keeps later requests to a single transmission.
  const after = f.calls.length;
  await f.client.session();
  assert.equal(f.calls.slice(after).filter(path => path === "/wake/up").length, 1);
});

test("the freshness window boundary: exactly W is accepted without a resend", async () => {
  const f = await setup();
  await f.client.login({ mode: "discoverable" });
  const before = f.calls.length;
  f.clock.server += W;
  await f.client.session();
  assert.equal(f.calls.slice(before).filter(path => path === "/wake/up").length, 1);
});

test("idle timeout leads to reauth", async () => {
  const f = await setup();
  const login = await f.client.login({ mode: "discoverable" });
  f.clock.server += login.idleTimeoutSec * 1000;
  f.clock.client += login.idleTimeoutSec * 1000;
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, false);
});

test("just before the idle timeout the session still works", async () => {
  const f = await setup();
  const login = await f.client.login({ mode: "discoverable" });
  f.clock.server += login.idleTimeoutSec * 1000 - 1;
  f.clock.client += login.idleTimeoutSec * 1000 - 1;
  assert.equal((await f.client.session()).sessionId, login.sessionId);
});

test("revokeSessionsByUser leads to reauth", async () => {
  const f = await setup();
  await f.client.login({ mode: "discoverable" });
  await f.client.session();
  await f.server.revokeSessionsByUser("u1");
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, false);
});

test("revokeSessionsByCredential leads to reauth", async () => {
  const f = await setup();
  await f.client.login({ mode: "discoverable" });
  await f.server.revokeSessionsByCredential(f.auth.credential.credentialId);
  await assert.rejects(f.client.session(), hasCode("reauth"));
});

test("a tampered s2c response is rejected with reauth", async () => {
  let tamper = false;
  const f = await setup(handle => async (req) => {
    const response = await handle(req);
    if (!tamper || !response || new URL(req.url).pathname !== "/wake/up") {
      return response;
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    return new Response(bytes, { status: response.status, headers: response.headers });
  });
  await f.client.login({ mode: "discoverable" });
  await f.client.session();
  tamper = true;
  await assert.rejects(f.client.session(), hasCode("reauth"));
  tamper = false;
});

test("two consecutive logins advance the authenticator counter", async () => {
  const f = await setup();
  await f.client.login({ mode: "discoverable" });
  const second = await f.client.login({ mode: "discoverable" });
  assert.equal((await f.client.session()).sessionId, second.sessionId);
  assert.equal(f.auth.signCount, 2);
});

test("the Hono demo app serves registration and WAKE routes", async () => {
  const clock = { now: 5_000_000 };
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN, now: () => clock.now });
  const auth = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "demo-user" });
  demo.credentials.setCredential(auth.credential, "carol");
  const client = new WakeClient({
    baseUrl: ORIGIN,
    getAssertion: assertionFor(auth),
    fetch: async (url, init) => demo.app.fetch(new Request(new URL(String(url), ORIGIN), init)),
    now: () => clock.now,
    sleep: async () => {},
  });
  const login = await client.login({ mode: "username", username: "carol" });
  assert.equal((await client.session()).sessionId, login.sessionId);
  await client.logout();
  await assert.rejects(client.session(), hasCode("reauth"));
  const unknown = await demo.app.fetch(new Request(`${ORIGIN}/nothing`, { method: "POST" }));
  assert.equal(unknown.status, 404);
  const wrongMethod = await demo.app.fetch(new Request(`${ORIGIN}/auth/start`));
  assert.equal(wrongMethod.status, 405);
});

for (const offset of [600_000, -600_000]) {
  test(`client clock ${offset > 0 ? "+" : "-"}10 minutes off: login, session and a lost /auth/complete response`, async () => {
    let dropped = false;
    const bodies: string[] = [];
    const f = await setup(handle => async (req) => {
      if (new URL(req.url).pathname !== "/auth/complete") {
        return handle(req);
      }
      bodies.push(await req.clone().text());
      const response = await handle(req);
      if (!dropped) {
        dropped = true;
        throw new TypeError("network error");
      }
      return response;
    }, offset);
    const login = await f.client.login({ mode: "discoverable" });
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0], bodies[1]);
    const session = await f.client.session();
    assert.equal(session.sessionId, login.sessionId);
    assert.equal(session.serverTime, f.clock.server);
    // The offset learned at login keeps requests fresh: a single transmission.
    assert.equal(f.calls.filter(path => path === "/wake/up").length, 1);
  });
}

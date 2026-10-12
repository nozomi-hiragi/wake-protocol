// KR, TA and ET through the demo app: a real WakeClient against the Hono app in process (spec §9, §10, §11).
import assert from "node:assert/strict";
import { test } from "node:test";
import { WakeClient } from "@wake-protocol/client";
import type { CreatedOperation } from "@wake-protocol/server";
import { SoftAuthenticator } from "@wake-protocol/server/testing";
import { createDemoApp } from "../src/app.ts";
import { assertionFor } from "./helpers.ts";

const RP = "example.com";
const ORIGIN = "https://example.com";
const START = 5_000_000;
const GRACE_MS = 60_000;

const hasCode = (code: string) => (e: unknown) => e instanceof Error && "code" in e && e.code === code;

async function setup() {
  const clock = { now: START };
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN, secret: new Uint8Array(32).fill(7), now: () => clock.now });
  const calls: Request[] = [];
  const fetchImpl: typeof fetch = async (url, init) => {
    const request = new Request(new URL(String(url), ORIGIN), init);
    calls.push(request.clone());
    return demo.app.fetch(request);
  };
  async function user(userId: string, name: string, wrap?: (f: typeof fetch) => typeof fetch) {
    const auth = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId });
    demo.credentials.setCredential(auth.credential, name);
    const client = new WakeClient({
      baseUrl: ORIGIN,
      getAssertion: assertionFor(auth),
      fetch: wrap ? wrap(fetchImpl) : fetchImpl,
      now: () => clock.now,
      sleep: async () => {},
    });
    await client.login({ mode: "discoverable" });
    return { auth, client };
  }
  const alice = await user("u1", "alice");
  const create = (content: string, approverUserId = "u1", lifetimeMs = 600_000): Promise<CreatedOperation> =>
    demo.server.createOperation({ content, approverUserId, expiresAt: clock.now + lifetimeMs });
  return { clock, demo, calls, alice, user, create };
}

test("rekey switches to epoch 1; the old epoch works during the grace period and is retired afterwards", async () => {
  const f = await setup();
  const { client } = f.alice;
  assert.equal((await client.session()).epoch, 0);
  const old = f.calls.filter(r => new URL(r.url).pathname === "/wake/up").at(-1)!;
  const oldBody = new Uint8Array(await old.clone().arrayBuffer());
  const resend = () => f.demo.app.fetch(new Request(`${ORIGIN}/wake/up`, {
    method: "POST",
    headers: { "content-type": "application/wake" },
    body: oldBody,
  }));
  const rekeyed = await client.rekey();
  assert.equal(rekeyed.epoch, 1);
  assert.equal((await client.session()).epoch, 1);
  assert.equal((await resend()).status, 200);
  f.clock.now += GRACE_MS;
  assert.equal((await resend()).status, 200);
  f.clock.now += 1;
  const retired = await resend();
  assert.equal(retired.status, 401);
  assert.deepEqual(await retired.json(), { wakeError: "epoch_retired" });
  // The client itself is on epoch 1 and unaffected.
  assert.equal((await client.session()).epoch, 1);
});

test("a lost kr/complete response is recovered", async () => {
  const f = await setup();
  let up = 0;
  const bob = await f.user("u2", "bob", inner => async (url, init) => {
    const response = await inner(url, init);
    if (String(url).endsWith("/wake/up") && ++up === 2) {
      throw new TypeError("network error");
    }
    return response;
  });
  // up is counted from here: 1 = kr/start, 2 = kr/complete (response lost).
  up = 0;
  const info = await bob.client.rekey();
  assert.ok(up >= 3);
  assert.equal(info.epoch, 1);
  assert.equal((await bob.client.session()).epoch, 1);
});

test("TA: approve is recorded with a decision record and an exportable bundle", async () => {
  const f = await setup();
  const { client } = f.alice;
  const op = await f.create("pay bob 10 EUR");
  const listed = await client.listOperations({ status: "PENDING" });
  assert.deepEqual(listed.operations.map(o => o.operationId), [op.operationId]);
  const seen = await client.getOperation(op.operationId);
  assert.equal(seen.content, "pay bob 10 EUR");
  assert.equal(seen.hashInput, op.hashInput);
  assert.equal(seen.status, "PENDING");
  const result = await client.approve(op.operationId);
  assert.deepEqual(result.ta, { result: "approved", status: "APPROVED" });
  assert.equal(result.kr, undefined);
  const view = await f.demo.server.getOperation(op.operationId);
  assert.equal(view?.status, "APPROVED");
  assert.equal(view?.decision?.kind, "approved");
  assert.equal((await client.getOperation(op.operationId)).status, "APPROVED");
  const bundle = await f.demo.server.exportApprovalBundle(op.operationId);
  assert.equal(bundle?.format, "WAKE/1 ta-bundle");
  assert.equal(bundle?.operationId, op.operationId);
  // A second approval of the same operation is refused and changes nothing.
  await assert.rejects(client.approve(op.operationId), hasCode("already_decided"));
  assert.equal((await f.demo.server.getOperation(op.operationId))?.status, "APPROVED");
});

test("TA: reject", async () => {
  const f = await setup();
  const op = await f.create("delete account");
  assert.deepEqual(await f.alice.client.reject(op.operationId), { result: "rejected", status: "REJECTED" });
  assert.equal((await f.demo.server.getOperation(op.operationId))?.decision?.kind, "rejected");
  await assert.rejects(f.alice.client.approve(op.operationId), hasCode("already_decided"));
});

test("TA: an operation cancelled by the server can no longer be approved", async () => {
  const f = await setup();
  const op = await f.create("cancel me");
  assert.equal(await f.demo.server.cancelOperation(op.operationId), "cancelled");
  assert.equal((await f.alice.client.getOperation(op.operationId)).status, "CANCELLED");
  await assert.rejects(f.alice.client.approve(op.operationId), hasCode("already_decided"));
});

test("TA: an expired operation cannot be approved (both sides of the expiry boundary)", async () => {
  const f = await setup();
  const op = await f.create("short lived", "u1", 1_000);
  f.clock.now += 999;
  assert.equal((await f.alice.client.getOperation(op.operationId)).status, "PENDING");
  f.clock.now += 1;
  assert.equal((await f.alice.client.getOperation(op.operationId)).status, "EXPIRED");
  await assert.rejects(f.alice.client.approve(op.operationId), hasCode("expired"));
});

test("TA: another user cannot see or decide the operation (always not_found)", async () => {
  const f = await setup();
  const bob = await f.user("u2", "bob");
  const op = await f.create("for alice only");
  await assert.rejects(bob.client.getOperation(op.operationId), hasCode("not_found"));
  await assert.rejects(bob.client.approve(op.operationId), hasCode("not_found"));
  await assert.rejects(bob.client.reject(op.operationId), hasCode("not_found"));
  assert.deepEqual((await bob.client.listOperations()).operations, []);
  assert.equal((await f.demo.server.getOperation(op.operationId))?.status, "PENDING");
});

test("TA+KR commits both: the epoch switches on both sides and the bundle exports", async () => {
  const f = await setup();
  const { client } = f.alice;
  const op = await f.create("approve and rekey");
  const result = await client.approve(op.operationId, { rekey: true });
  assert.deepEqual(result.ta, { result: "approved", status: "APPROVED" });
  assert.equal(result.kr?.result, "committed");
  assert.equal((await client.session()).epoch, 1);
  const view = await f.demo.server.getOperation(op.operationId);
  assert.ok(view?.decision?.kind === "approved" && view.decision.th !== null);
  const bundle = await f.demo.server.exportApprovalBundle(op.operationId);
  assert.equal((bundle!.approval as { th: unknown; }).th !== null, true);
});

test("ET: GET /api/me, POST /api/operations and GET /api/operation through wakeFetch", async () => {
  const f = await setup();
  const { client } = f.alice;
  const me = await client.wakeFetch("/api/me");
  assert.equal(me.status, 200);
  assert.match(me.headers.get("content-type")!, /application\/json/);
  const body = await me.json() as Record<string, unknown>;
  assert.equal(body.userId, "u1");
  assert.equal(body.epoch, 0);
  assert.equal(body.authTime, START);
  assert.equal(typeof body.sessionId, "string");

  const created = await client.wakeFetch("/api/operations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ content: "via ET" }),
  });
  assert.equal(created.status, 200);
  const op = await created.json() as { operationId: string; approveUrl: string; };
  assert.match(op.operationId, /^[0-9a-f]{64}$/u);
  assert.equal(op.approveUrl, `/approve/${op.operationId}`);
  const view = await f.demo.server.getOperation(op.operationId);
  assert.equal(view?.content, "via ET");
  assert.equal(view?.approverUserId, "u1");
  assert.equal(view?.expiresAt, START + 600_000);

  const pending = await client.wakeFetch(`/api/operation?id=${op.operationId}`);
  assert.deepEqual(await pending.json(), { status: "PENDING", decidedAt: null });
  await client.approve(op.operationId);
  const done = await (await client.wakeFetch(`/api/operation?id=${op.operationId}`)).json() as Record<string, any>;
  assert.equal(done.status, "APPROVED");
  assert.equal(done.decidedAt, START);
  assert.equal(done.decisionRecord.kind, "approved");
  assert.equal(done.decisionRecord.decidedByUserId, "u1");
});

test("ET: POST /api/operations refuses a 21st pending operation per user and counts only live ones", async () => {
  const f = await setup();
  const { client } = f.alice;
  const post = (content: string) => client.wakeFetch("/api/operations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ content }),
  });
  for (let i = 0; i < 19; i++) {
    assert.equal((await post(`op ${i}`)).status, 200, `op ${i}`);
  }
  // 19 pending: the 20th is still accepted.
  const twentieth = await post("op 19");
  assert.equal(twentieth.status, 200);
  const twentiethId = ((await twentieth.json()) as { operationId: string; }).operationId;
  // 20 pending: refused, and nothing was created.
  const refused = await post("op 20");
  assert.equal(refused.status, 409);
  assert.deepEqual(await refused.json(), { error: { code: "too_many_pending" } });
  // Another user is not affected.
  const bob = await f.user("u2", "bob");
  assert.equal((await bob.client.wakeFetch("/api/operations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ content: "bob's" }),
  })).status, 200);
  // A decided operation frees a slot.
  assert.equal(await f.demo.server.cancelOperation(twentiethId), "cancelled");
  assert.equal((await post("after cancel")).status, 200);
  assert.equal((await post("full again")).status, 409);
  // Expired operations do not count either.
  f.clock.now += 600_000;
  assert.equal((await post("after expiry")).status, 200);
});

test("ET: invalid input, unknown routes and other users' operations", async () => {
  const f = await setup();
  const { client } = f.alice;
  const unknown = await client.wakeFetch("/api/nothing");
  assert.equal(unknown.status, 404);
  const wrongMethod = await client.wakeFetch("/api/me", { method: "POST" });
  assert.equal(wrongMethod.status, 404);
  const post = (body: string) =>
    client.wakeFetch("/api/operations", { method: "POST", headers: { "content-type": "application/json" }, body });
  for (const bad of ["not json", "[]", "{}", '{"content":1}']) {
    const res = await post(bad);
    assert.equal(res.status, 400, bad);
    assert.deepEqual(await res.json(), { error: { code: "invalid_request" } });
  }
  // A content-profile violation is reported as invalid_content (a NUL character).
  const profile = await post(JSON.stringify({ content: "a\u0000b" }));
  assert.equal(profile.status, 400);
  assert.deepEqual(await profile.json(), { error: { code: "invalid_content" } });
  const big = await post(JSON.stringify({ content: "x".repeat(16_384) }));
  assert.equal(big.status, 413);
  assert.equal((await client.wakeFetch("/api/operation")).status, 400);
  assert.equal((await client.wakeFetch(`/api/operation?id=${"A".repeat(64)}`)).status, 400);
  assert.equal((await client.wakeFetch(`/api/operation?id=${"0".repeat(64)}`)).status, 404);

  const bob = await f.user("u2", "bob");
  const op = await f.create("alice's");
  const other = await bob.client.wakeFetch(`/api/operation?id=${op.operationId}`);
  assert.equal(other.status, 404);
  assert.deepEqual(await other.json(), { error: { code: "not_found" } });
});

test("ET is not reachable as plain HTTP, and the Host check and CSP still apply", async () => {
  const f = await setup();
  for (const path of ["/api/me", "/api/operations", "/api/operation"]) {
    for (const method of ["GET", "POST"]) {
      const res = await f.demo.app.fetch(new Request(`${ORIGIN}${path}`, { method }));
      assert.equal(res.status, 404, `${method} ${path}`);
    }
  }
  const wrongHost = await f.demo.app.fetch(new Request("https://evil.example/approve/" + "0".repeat(64)));
  assert.equal(wrongHost.status, 421);
  const page = await f.demo.app.fetch(new Request(`${ORIGIN}/approve/${"0".repeat(64)}`));
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy")!, /default-src 'self'/);
  assert.doesNotMatch(await page.text(), /<script(?![^>]*\bsrc=)/u);
  for (const bad of ["abc", "A".repeat(64), "0".repeat(63)]) {
    assert.equal((await f.demo.app.fetch(new Request(`${ORIGIN}/approve/${bad}`))).status, 404);
  }
});

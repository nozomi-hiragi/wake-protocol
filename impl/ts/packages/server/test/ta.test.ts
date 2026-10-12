// Spec §10.5–§10.10, §6.2: wake/ta/* contexts, approval attempts and decision records.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Bytes, verifyApprovalBundle } from "@wake-protocol/core";
import type { AssertionTamper } from "../src/testing.ts";
import { SoftAuthenticator } from "../src/testing.ts";
import { decode, encode, fixture, login, ORIGIN, RP, sendWire } from "./helpers.ts";
import { krClient, krOpen, krRequest, krWire } from "./kr-helpers.ts";
import { approve, challenge, newOperation, prepareTa, secondUser, setup, ta, taError } from "./ta-helpers.ts";

function same(a: Uint8Array | undefined, b: Uint8Array): void {
  assert.ok(a);
  assert.ok(new Bytes(a).equals(new Bytes(b)));
}

// list

test("list pages across more than 20 operations in (createdAt, operationId) order without duplicates", async () => {
  const { f, client } = await setup();
  const mine: { operationId: string; createdAt: number; }[] = [];
  for (let i = 0; i < 25; i++) {
    // Every third operation shares its createdAt with the previous one to exercise the operationId tie-break.
    if (i % 3 !== 0) {
      f.clock.now += 1;
    }
    mine.push({ operationId: (await newOperation(f, { content: `op ${i}` })).operationId, createdAt: f.clock.now });
  }
  const other = await secondUser(f);
  const foreign = await newOperation(f, { approverUserId: "u2" });
  const expected = [...mine].sort((a, b) => a.createdAt - b.createdAt || (a.operationId < b.operationId ? -1 : 1));
  const first = (await ta(f, client, "list", {})).json as { operations: { operationId: string; }[]; nextCursor: string | null; };
  assert.equal(first.operations.length, 20);
  assert.ok(first.nextCursor);
  const second = (await ta(f, client, "list", { cursor: first.nextCursor })).json as typeof first;
  assert.equal(second.operations.length, 5);
  assert.equal(second.nextCursor, null);
  const ids = [...first.operations, ...second.operations].map(o => o.operationId);
  assert.deepEqual(ids, expected.map(o => o.operationId));
  assert.ok(!ids.includes(foreign.operationId));
  const theirs = (await ta(f, other.client, "list", {})).json as typeof first;
  assert.deepEqual(theirs.operations.map(o => o.operationId), [foreign.operationId]);
  assert.equal(theirs.nextCursor, null);
});

test("list entries carry exactly the §10.6 members", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const result = (await ta(f, client, "list", {})).json as { operations: Record<string, unknown>[]; nextCursor: null; };
  assert.deepEqual(Object.keys(result).sort(), ["nextCursor", "operations"]);
  assert.deepEqual(result.operations[0], {
    operationId: op.operationId,
    content: "Transfer 100 JPY",
    nonce: op.nonce,
    status: "PENDING",
    createdAt: f.clock.now,
    expiresAt: op.expiresAt,
  });
});

for (const [count, hasMore] of [[20, false], [21, true]] as const) {
  test(`list with ${count} operations ${hasMore ? "has" : "has no"} a next page`, async () => {
    const { f, client } = await setup();
    for (let i = 0; i < count; i++) {
      await newOperation(f);
    }
    const result = (await ta(f, client, "list", {})).json as { operations: unknown[]; nextCursor: string | null; };
    assert.equal(result.operations.length, 20);
    assert.equal(result.nextCursor !== null, hasMore);
  });
}

const limits = [[1, true], [20, true], [0, false], [21, false], [1.5, false], ["5", false], [null, false], [true, false]] as const;
for (const [limit, ok] of limits) {
  test(`list limit ${String(limit)}`, async () => {
    const { f, client } = await setup();
    await newOperation(f);
    await newOperation(f);
    const result = await ta(f, client, "list", { limit });
    if (ok) {
      assert.equal((result.json.operations as unknown[]).length, Math.min(limit as number, 2));
    } else {
      assert.deepEqual(result.json, { error: { code: "invalid_request" } });
    }
  });
}

test("list with limit 1 pages through two operations", async () => {
  const { f, client } = await setup();
  const a = await newOperation(f);
  f.clock.now++;
  const b = await newOperation(f);
  const one = (await ta(f, client, "list", { limit: 1 })).json as { operations: { operationId: string; }[]; nextCursor: string; };
  assert.deepEqual(one.operations.map(o => o.operationId), [a.operationId]);
  const two = (await ta(f, client, "list", { limit: 1, cursor: one.nextCursor })).json as typeof one;
  assert.deepEqual(two.operations.map(o => o.operationId), [b.operationId]);
  assert.equal(two.nextCursor, null);
});

test("list filters by status, deriving EXPIRED", async () => {
  const { f, client } = await setup();
  const pending = await newOperation(f);
  const approved = await newOperation(f);
  const rejected = await newOperation(f);
  const cancelled = await newOperation(f);
  const expiring = await newOperation(f, { ttlMs: 1000 });
  const ch = await challenge(f, client, approved.operationId);
  assert.equal((await approve(f, client, await prepareTa(f, client, ch, approved.operationId))).json.operationId, approved.operationId);
  await ta(f, client, "reject", { operationId: rejected.operationId });
  await f.server.cancelOperation(cancelled.operationId);
  f.clock.now += 1000;
  const ids = async (status: string) =>
    ((await ta(f, client, "list", { status })).json.operations as { operationId: string; }[]).map(o => o.operationId);
  assert.deepEqual(await ids("PENDING"), [pending.operationId]);
  assert.deepEqual(await ids("APPROVED"), [approved.operationId]);
  assert.deepEqual(await ids("REJECTED"), [rejected.operationId]);
  assert.deepEqual(await ids("CANCELLED"), [cancelled.operationId]);
  assert.deepEqual(await ids("EXPIRED"), [expiring.operationId]);
});

for (const status of ["pending", "DONE", 1, null, ""]) {
  test(`list rejects status ${JSON.stringify(status)}`, async () => {
    const { f, client } = await setup();
    await taError(f, client, "list", { status }, "invalid_request");
  });
}

for (const cursor of ["", "!!", "AAAA", encode(new TextEncoder().encode("1:abc")), encode(new TextEncoder().encode(`x:${"0".repeat(64)}`)),
  encode(new TextEncoder().encode(`1:${"A".repeat(64)}`)), encode(new Uint8Array([0xff, 0xfe])), 5, null]) {
  test(`list rejects cursor ${JSON.stringify(cursor)}`, async () => {
    const { f, client } = await setup();
    await taError(f, client, "list", { cursor }, "invalid_request");
  });
}

// get / not_found

test("get returns the §10.6 members and decidedAt once decided", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const got = (await ta(f, client, "get", { operationId: op.operationId })).json;
  assert.deepEqual(got, {
    operationId: op.operationId,
    content: "Transfer 100 JPY",
    nonce: op.nonce,
    status: "PENDING",
    createdAt: f.clock.now,
    expiresAt: op.expiresAt,
    decidedAt: null,
  });
  f.clock.now += 7;
  await ta(f, client, "reject", { operationId: op.operationId });
  const after = (await ta(f, client, "get", { operationId: op.operationId })).json;
  assert.equal(after.status, "REJECTED");
  assert.equal(after.decidedAt, f.clock.now);
});

test("every API treats another user's operation and unknown operations as not_found", async () => {
  const { f, client } = await setup();
  const other = await secondUser(f);
  const op = await newOperation(f);
  for (const stranger of [other.client, client]) {
    const target = stranger === client ? "1".repeat(64) : op.operationId;
    await taError(f, stranger, "get", { operationId: target }, "not_found");
    await taError(f, stranger, "challenge", { operationId: target, rekey: false }, "not_found");
    await taError(f, stranger, "reject", { operationId: target }, "not_found");
  }
  const view = await f.server.getOperation(op.operationId);
  assert.equal(view?.status, "PENDING");
});

test("approve with an attempt of another session or user is not_found and leaves it usable", async () => {
  const { f, client } = await setup();
  const other = await secondUser(f);
  const second = krClient(await login(f));
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  await taError(f, second, "approve", prepared.body, "not_found");
  await taError(f, other.client, "approve", prepared.body, "not_found");
  await taError(f, client, "approve", { ...prepared.body, approvalId: encode(new Uint8Array(16)) }, "not_found");
  assert.deepEqual((await approve(f, client, prepared)).json.ta, { result: "approved", status: "APPROVED" });
  assert.equal((await f.server.getOperation(op.operationId))?.status, "APPROVED");
});

// challenge

test("challenge returns the §10.6 members with the user's active credentials", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const result = (await ta(f, client, "challenge", { operationId: op.operationId, rekey: false })).json;
  assert.deepEqual(Object.keys(result).sort(), ["approvalId", "approvalNonce", "expiresAt", "kr", "webauthn"]);
  assert.equal(decode(result.approvalId as string).length, 16);
  assert.equal(decode(result.approvalNonce as string).length, 32);
  assert.equal(result.expiresAt, f.clock.now + 300_000);
  assert.equal(result.kr, null);
  assert.deepEqual(result.webauthn, {
    rpId: RP,
    allowCredentials: [{ type: "public-key", id: encode(f.auth.credential.credentialId) }],
    userVerification: "required",
    timeout: 270_000,
  });
});

test("challenge on a decided operation is already_decided and on an expired one expired, both sides of expiresAt", async () => {
  const { f, client } = await setup();
  const rejected = await newOperation(f);
  const cancelled = await newOperation(f);
  const approved = await newOperation(f);
  const timed = await newOperation(f, { ttlMs: 1000 });
  await ta(f, client, "reject", { operationId: rejected.operationId });
  await f.server.cancelOperation(cancelled.operationId);
  await approve(f, client, await prepareTa(f, client, await challenge(f, client, approved.operationId), approved.operationId));
  for (const op of [rejected, cancelled, approved]) {
    await taError(f, client, "challenge", { operationId: op.operationId, rekey: false }, "already_decided");
  }
  f.clock.now += 999;
  await challenge(f, client, timed.operationId);
  f.clock.now += 1;
  await taError(f, client, "challenge", { operationId: timed.operationId, rekey: false }, "expired");
});

test("the sixth challenge expires the oldest attempt only", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const attempts = [];
  for (let i = 0; i < 5; i++) {
    f.clock.now++;
    attempts.push(await challenge(f, client, op.operationId));
  }
  for (const att of attempts) {
    assert.equal((await f.store.getApproval(decode(att.approvalId), f.clock.now))?.state, "PENDING");
  }
  f.clock.now++;
  attempts.push(await challenge(f, client, op.operationId));
  const states = await Promise.all(attempts.map(async att => (await f.store.getApproval(decode(att.approvalId), f.clock.now))?.state));
  assert.deepEqual(states, ["EXPIRED", "PENDING", "PENDING", "PENDING", "PENDING", "PENDING"]);
  const expired = await prepareTa(f, client, attempts[0]!, op.operationId);
  await taError(f, client, "approve", expired.body, "expired");
  assert.equal((await approve(f, client, await prepareTa(f, client, attempts[1]!, op.operationId))).json.operationId, op.operationId);
});

// The default 30-day hard cap overflows at login before an approval TTL of 300_000 ms can land on
// 2^53-1. These shorter lifetimes leave approvalTtlMs as the longest sum, so that boundary is reachable.
async function setupNearApprovalLimit() {
  const approvalTtlMs = 300_000;
  const f = await fixture({
    approvalTtlMs,
    exchangeTtlMs: 60_000,
    webauthnTimeoutMs: 30_000,
    authLifetimeMs: 2,
    hardCapMs: 2,
    idleTimeoutSec: 1,
    maxOperationLifetimeMs: 10,
    maxActiveApprovals: 1,
    maxPendingRekeys: 1,
  });
  f.clock.now = Number.MAX_SAFE_INTEGER - approvalTtlMs;
  return { f, client: krClient(await login(f)), approvalTtlMs };
}

test("challenge accepts an approval expiration of exactly 2^53-1", async () => {
  const { f, client } = await setupNearApprovalLimit();
  const plain = await newOperation(f, { ttlMs: 2 });
  const bound = await newOperation(f, { ttlMs: 2 });
  const attempt = await challenge(f, client, plain.operationId);
  assert.equal(attempt.expiresAt, Number.MAX_SAFE_INTEGER);
  assert.equal(attempt.kr, null);
  const withKr = await challenge(f, client, bound.operationId, true);
  assert.equal(withKr.expiresAt, Number.MAX_SAFE_INTEGER);
  assert.ok(withKr.kr);
  assert.equal((await f.store.getExchange(decode(withKr.kr.exchangeId), f.clock.now))?.state, "PENDING");
});

test("challenge past the safe-integer approval range is an encrypted internal and stores nothing", async () => {
  const { f, client } = await setupNearApprovalLimit();
  const plain = await newOperation(f, { ttlMs: 2 });
  const bound = await newOperation(f, { ttlMs: 2 });
  const attempt = await challenge(f, client, plain.operationId);
  const withKr = await challenge(f, client, bound.operationId, true);
  assert.ok(withKr.kr);
  const exchangeId = withKr.kr.exchangeId;
  let approvalWrites = 0;
  const createApproval = f.store.createApproval.bind(f.store);
  f.store.createApproval = async start => {
    approvalWrites++;
    return createApproval(start);
  };
  f.clock.now++;
  await taError(f, client, "challenge", { operationId: plain.operationId, rekey: false }, "internal");
  await taError(f, client, "challenge", { operationId: bound.operationId, rekey: true }, "internal");
  assert.equal(approvalWrites, 0);
  assert.equal((await f.store.getApproval(decode(attempt.approvalId), f.clock.now))?.state, "PENDING");
  assert.equal((await f.store.getApproval(decode(withKr.approvalId), f.clock.now))?.state, "PENDING");
  assert.equal((await f.store.getExchange(decode(exchangeId), f.clock.now))?.state, "PENDING");
});

test("maxActiveApprovals is configurable and counts per operation", async () => {
  const { f, client } = await setup({ maxActiveApprovals: 2 });
  const a = await newOperation(f);
  const b = await newOperation(f);
  const first = await challenge(f, client, a.operationId);
  f.clock.now++;
  await challenge(f, client, b.operationId);
  f.clock.now++;
  await challenge(f, client, a.operationId);
  assert.equal((await f.store.getApproval(decode(first.approvalId), f.clock.now))?.state, "PENDING");
  f.clock.now++;
  await challenge(f, client, a.operationId);
  assert.equal((await f.store.getApproval(decode(first.approvalId), f.clock.now))?.state, "EXPIRED");
});

for (const [name, body] of [
  ["rekey missing", (id: string) => ({ operationId: id })],
  ["rekey not boolean", (id: string) => ({ operationId: id, rekey: 0 })],
  ["operationId uppercase", (id: string) => ({ operationId: id.toUpperCase().replace(/E/g, "E"), rekey: false })],
  ["operationId short", (id: string) => ({ operationId: id.slice(1), rekey: false })],
  ["operationId long", (id: string) => ({ operationId: `${id}0`, rekey: false })],
  ["operationId not a string", () => ({ operationId: 1, rekey: false })],
] as const) {
  test(`challenge rejects ${name}`, async () => {
    const { f, client } = await setup();
    const op = await newOperation(f);
    // Digits only would survive upper-casing, so make sure the id has a letter.
    const id = /[a-f]/.test(op.operationId) ? op.operationId : `a${op.operationId.slice(1)}`;
    await taError(f, client, "challenge", body(id), "invalid_request");
  });
}

test("TA requests ignore unknown members and an unknown wake/ta context is invalid_context", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  assert.equal((await ta(f, client, "get", { operationId: op.operationId, extra: [1] })).json.operationId, op.operationId);
  await taError(f, client, "nothing", {}, "invalid_context");
  const request = await krWire(f, client, "wake/ta/get", "[]");
  assert.deepEqual((await krOpen(client, request, await sendWire(f, request))).json, { error: { code: "invalid_request" } });
});

// approve

test("approve stores the authenticator's raw bytes and the bundle verifies offline", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  f.clock.now += 11;
  const ch = await challenge(f, client, op.operationId);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  f.clock.now += 3;
  const result = await approve(f, client, prepared);
  assert.deepEqual(result.json, { operationId: op.operationId, ta: { result: "approved", status: "APPROVED" }, kr: null });
  assert.equal(result.header.epoch, 0);
  const view = await f.server.getOperation(op.operationId);
  assert.equal(view?.status, "APPROVED");
  assert.equal(view?.decidedAt, f.clock.now);
  const d = view?.decision;
  assert.ok(d && d.kind === "approved");
  assert.equal(d.decidedAt, f.clock.now);
  assert.equal(d.decidedByUserId, "u1");
  same(d.decidedByCredentialId, f.auth.credential.credentialId);
  same(d.credentialPublicKey, f.auth.credential.publicKey);
  same(d.sessionId, client.sessionId.toUint8Array());
  same(d.approvalId, decode(ch.approvalId));
  same(d.approvalNonce, decode(ch.approvalNonce));
  assert.equal(d.th, null);
  same(d.authenticatorData, decode(prepared.assertion.response.authenticatorData));
  same(d.clientDataJSON, decode(prepared.assertion.response.clientDataJSON));
  same(d.signature, decode(prepared.assertion.response.signature));
  const bundle = await f.server.exportApprovalBundle(op.operationId);
  assert.ok(bundle);
  assert.equal(bundle.format, "WAKE/1 ta-bundle");
  assert.equal(bundle.rpId, RP);
  assert.equal(bundle.operationId, op.operationId);
  assert.equal(bundle.nonce, op.nonce);
  assert.equal((bundle.approval as { th: unknown; }).th, null);
  assert.equal(await verifyApprovalBundle(bundle, { rpId: RP, origins: [ORIGIN] }), true);
  await assert.rejects(verifyApprovalBundle(bundle, { rpId: RP, origins: ["https://other.example.com"] }));
  assert.equal(await f.server.exportApprovalBundle("2".repeat(64)), null);
});

test("approving advances the credential's sign counter", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const before = (await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount;
  await approve(f, client, await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId));
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount, before + 1);
});

test("a second attempt on a decided operation reports already_decided and keeps the first record", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const first = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  const second = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  assert.equal((await approve(f, client, first)).json.operationId, op.operationId);
  const before = (await f.server.getOperation(op.operationId))!;
  f.clock.now += 5;
  const late = await approve(f, client, second);
  assert.deepEqual(late.json, { operationId: op.operationId, ta: { result: "already_decided", status: "APPROVED" }, kr: null });
  const after = (await f.server.getOperation(op.operationId))!;
  assert.deepEqual(after.decidedAt, before.decidedAt);
  same((after.decision as { signature: Uint8Array; }).signature, decode(first.assertion.response.signature));
  // The second attempt was consumed: it cannot decide anything later either.
  assert.equal((await f.store.getApproval(decode(second.body.approvalId), f.clock.now))?.state, "CONSUMED");
});

test("replaying an approve returns the identical result under a new requestId without verifying again", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  const first = await approve(f, client, prepared);
  const counter = (await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount;
  f.clock.now++;
  const again = await approve(f, client, prepared);
  assert.equal(again.text, first.text);
  assert.ok(!again.header.requestId.equals(first.header.requestId));
  const broken = await ta(f, client, "approve", { ...prepared.body, assertion: { bad: true } });
  assert.equal(broken.text, first.text);
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount, counter);
});

test("a consumed attempt is kept for the retention period after its expiry and then forgotten", async () => {
  const { f, client } = await setup({ completedRetentionMs: 1000 });
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  const first = await approve(f, client, prepared);
  f.clock.now = ch.expiresAt + 999;
  assert.equal((await approve(f, client, prepared)).text, first.text);
  f.clock.now = ch.expiresAt + 1000;
  await taError(f, client, "approve", prepared.body, "not_found");
});

for (const offset of [-1, 0]) {
  test(`approve at operation expiresAt ${offset === 0 ? "" : "- 1 "}${offset === 0 ? "reports expired" : "succeeds"}`, async () => {
    const { f, client } = await setup();
    const op = await newOperation(f, { ttlMs: 60_000 });
    const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
    f.clock.now = op.expiresAt + offset;
    const result = await approve(f, client, prepared);
    const approved = offset < 0;
    assert.deepEqual(result.json, {
      operationId: op.operationId,
      ta: { result: approved ? "approved" : "expired", status: approved ? "APPROVED" : "EXPIRED" },
      kr: null,
    });
    const view = await f.server.getOperation(op.operationId);
    assert.equal(view?.status, approved ? "APPROVED" : "EXPIRED");
    assert.equal(view?.decision?.kind, approved ? "approved" : undefined);
  });
}

for (const offset of [-1, 0]) {
  test(`approve at attempt expiresAt ${offset < 0 ? "- 1 succeeds" : "is expired"}`, async () => {
    const { f, client } = await setup();
    const op = await newOperation(f);
    const ch = await challenge(f, client, op.operationId);
    const prepared = await prepareTa(f, client, ch, op.operationId);
    f.clock.now = ch.expiresAt + offset;
    if (offset < 0) {
      assert.deepEqual((await approve(f, client, prepared)).json.ta, { result: "approved", status: "APPROVED" });
      assert.equal((await f.server.getOperation(op.operationId))?.status, "APPROVED");
    } else {
      await taError(f, client, "approve", prepared.body, "expired");
      assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
    }
  });
}

test("approve with a different operationId is invalid_request and leaves the attempt usable", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const other = await newOperation(f);
  const ch = await challenge(f, client, op.operationId);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  await taError(f, client, "approve", { ...prepared.body, operationId: other.operationId }, "invalid_request");
  assert.equal((await approve(f, client, prepared)).json.operationId, op.operationId);
  assert.equal((await f.server.getOperation(other.operationId))?.status, "PENDING");
});

for (const [name, patch] of [
  ["approvalId short", { approvalId: encode(new Uint8Array(15)) }],
  ["approvalId long", { approvalId: encode(new Uint8Array(17)) }],
  ["approvalId not a string", { approvalId: 1 }],
  ["approvalId non-canonical", { approvalId: `${encode(new Uint8Array(16)).slice(0, -1)}B` }],
  ["operationId uppercase", { operationId: "A".repeat(64) }],
  ["assertion not an object", { assertion: "x" }],
  ["assertion missing", { assertion: undefined }],
  ["kr missing", { kr: undefined }],
  ["kr a string", { kr: "x" }],
  ["kr an array", { kr: [] }],
] as const) {
  test(`approve rejects ${name} as invalid_request`, async () => {
    const { f, client } = await setup();
    const op = await newOperation(f);
    const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
    await taError(f, client, "approve", { ...prepared.body, ...patch }, "invalid_request");
    assert.equal((await approve(f, client, prepared)).json.operationId, op.operationId);
  });
}

// WebAuthn failures leave the attempt untouched

async function failsThenSucceeds(
  name: string,
  run: (s: Awaited<ReturnType<typeof setup>>, op: { operationId: string; }, ch: Awaited<ReturnType<typeof challenge>>) => Promise<void>,
): Promise<void> {
  test(name, async () => {
    const s = await setup();
    const op = await newOperation(s.f);
    const ch = await challenge(s.f, s.client, op.operationId);
    await run(s, op, ch);
    const att = await s.f.store.getApproval(decode(ch.approvalId), s.f.clock.now);
    assert.equal(att?.state, "PENDING");
    assert.equal((await s.f.server.getOperation(op.operationId))?.status, "PENDING");
    const ok = await approve(s.f, s.client, await prepareTa(s.f, s.client, ch, op.operationId));
    assert.deepEqual((ok.json.ta as { result: string; }).result, "approved");
  });
}

for (const [name, tamper] of [
  ["corrupt signature", { corruptSignature: true }],
  ["wrong clientData type", { clientDataType: "webauthn.create" }],
  ["wrong rpId hash", { rpId: "evil.example.com" }],
  ["no user verification", { clearFlags: 0x04 }],
  ["cross-origin", { crossOrigin: true }],
  ["counter not increasing for a non-backup credential", { signCount: 1 }],
] as [string, AssertionTamper][]) {
  await failsThenSucceeds(`approve with ${name} is webauthn_failed`, async ({ f, client }, op, ch) => {
    const bad = await prepareTa(f, client, ch, op.operationId, { tamper });
    await taError(f, client, "approve", bad.body, "webauthn_failed");
  });
}

await failsThenSucceeds("approve signed for another operation's attempt is webauthn_failed", async ({ f, client }, op, ch) => {
  const other = await newOperation(f);
  const otherChallenge = await challenge(f, client, other.operationId);
  const bad = await prepareTa(f, client, ch, op.operationId, { signFor: { ch: otherChallenge, operationId: other.operationId } });
  await taError(f, client, "approve", bad.body, "webauthn_failed");
});

await failsThenSucceeds("approve signed for another operationId is webauthn_failed", async ({ f, client }, op, ch) => {
  const bad = await prepareTa(f, client, ch, op.operationId, { signFor: { ch, operationId: "f".repeat(64) } });
  await taError(f, client, "approve", bad.body, "webauthn_failed");
});

await failsThenSucceeds("a TA+KR signature on a plain TA approve is webauthn_failed", async ({ f, client }, op) => {
  const rekeying = await challenge(f, client, op.operationId, true);
  const bad = await prepareTa(f, client, rekeying, op.operationId, { kr: false, signKr: true });
  await taError(f, client, "approve", bad.body, "webauthn_failed");
  const dropped = await prepareTa(f, client, rekeying, op.operationId, { kr: true, signKr: false });
  await taError(f, client, "approve", dropped.body, "webauthn_failed");
});

await failsThenSucceeds("approve signed by another user's credential is webauthn_failed", async ({ f, client }, op, ch) => {
  const other = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u2" });
  f.credentials.setCredential(other.credential);
  const bad = await prepareTa(f, client, ch, op.operationId, { auth: other });
  await taError(f, client, "approve", bad.body, "webauthn_failed");
});

await failsThenSucceeds("approve with a suspended credential is webauthn_failed", async ({ f, client }, op, ch) => {
  const spare = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential({ ...spare.credential, status: "suspended" });
  const bad = await prepareTa(f, client, ch, op.operationId, { auth: spare });
  await taError(f, client, "approve", bad.body, "webauthn_failed");
});

test("approve requires the origin to be in taOrigins", async () => {
  const { f, client } = await setup({ taOrigins: ["https://approve.example.com"] });
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId);
  await taError(f, client, "approve", (await prepareTa(f, client, ch, op.operationId)).body, "webauthn_failed");
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
});

test("approve requires the origin to equal the session's establishedOrigin even if taOrigins allows another", async () => {
  const other = "https://other.example.com";
  const { f, client } = await setup({ loginOrigins: [ORIGIN, other], taOrigins: [ORIGIN, other] });
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId);
  const bad = await prepareTa(f, client, ch, op.operationId, { tamper: { origin: other } });
  await taError(f, client, "approve", bad.body, "webauthn_failed");
  assert.equal((await approve(f, client, await prepareTa(f, client, ch, op.operationId))).json.operationId, op.operationId);
});

// BE=0 counter race: the loser must not decide anything

test("two concurrent approves of one attempt decide the operation once", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  const results = await Promise.all([approve(f, client, prepared), approve(f, client, prepared)]);
  const texts = new Set(results.map(r => r.text).filter(t => t.includes("approved")));
  assert.equal(texts.size, 1);
  assert.equal((await f.server.getOperation(op.operationId))?.status, "APPROVED");
});

// reject

test("reject records the session user and session, and later approvals are already_decided", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  f.clock.now += 9;
  assert.deepEqual((await ta(f, client, "reject", { operationId: op.operationId })).json, { result: "rejected", status: "REJECTED" });
  const view = await f.server.getOperation(op.operationId);
  assert.equal(view?.status, "REJECTED");
  assert.equal(view?.decidedAt, f.clock.now);
  assert.ok(view?.decision?.kind === "rejected");
  assert.equal(view.decision.decidedByUserId, "u1");
  same(view.decision.sessionId, client.sessionId.toUint8Array());
  const again = await ta(f, client, "reject", { operationId: op.operationId });
  assert.deepEqual(again.json, { result: "already_decided", status: "REJECTED" });
  const late = await approve(f, client, prepared);
  assert.deepEqual(late.json, { operationId: op.operationId, ta: { result: "already_decided", status: "REJECTED" }, kr: null });
  assert.equal((await f.server.getOperation(op.operationId))?.status, "REJECTED");
  assert.equal(await f.server.exportApprovalBundle(op.operationId), null);
});

test("reject after approve or cancel is already_decided with the existing status", async () => {
  const { f, client } = await setup();
  const approved = await newOperation(f);
  const cancelled = await newOperation(f);
  await approve(f, client, await prepareTa(f, client, await challenge(f, client, approved.operationId), approved.operationId));
  await f.server.cancelOperation(cancelled.operationId);
  const afterApprove = await ta(f, client, "reject", { operationId: approved.operationId });
  assert.deepEqual(afterApprove.json, { result: "already_decided", status: "APPROVED" });
  const afterCancel = await ta(f, client, "reject", { operationId: cancelled.operationId });
  assert.deepEqual(afterCancel.json, { result: "already_decided", status: "CANCELLED" });
});

test("approve after cancel is already_decided", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  await f.server.cancelOperation(op.operationId);
  assert.deepEqual((await approve(f, client, prepared)).json.ta, { result: "already_decided", status: "CANCELLED" });
});

for (const offset of [-1, 0]) {
  test(`reject at expiresAt ${offset < 0 ? "- 1 succeeds" : "reports expired"}`, async () => {
    const { f, client } = await setup();
    const op = await newOperation(f, { ttlMs: 1000 });
    f.clock.now = op.expiresAt + offset;
    const result = (await ta(f, client, "reject", { operationId: op.operationId })).json;
    assert.deepEqual(result, offset < 0 ? { result: "rejected", status: "REJECTED" } : { result: "expired", status: "EXPIRED" });
  });
}

// session end

for (const how of ["logout", "revokeSession", "revokeSessionsByUser"] as const) {
  test(`${how} expires the session's pending approval attempts and their exchanges`, async () => {
    const { f, client } = await setup();
    const second = krClient(await login(f));
    const op = await newOperation(f);
    const mine = await challenge(f, client, op.operationId, true);
    const theirs = await challenge(f, second, op.operationId);
    if (how === "logout") {
      await krRequest(f, client, "wake/logout");
    } else if (how === "revokeSession") {
      await f.server.revokeSession(client.sessionId.toUint8Array());
    } else {
      await f.server.revokeSessionsByUser("u1");
    }
    const att = await f.store.getApproval(decode(mine.approvalId), f.clock.now);
    assert.equal(att?.state, "EXPIRED");
    assert.equal((await f.store.getExchange(decode(mine.kr!.exchangeId), f.clock.now))?.state, "SUPERSEDED");
    const survivor = (await f.store.getApproval(decode(theirs.approvalId), f.clock.now))?.state;
    assert.equal(survivor, how === "revokeSessionsByUser" ? "EXPIRED" : "PENDING");
    assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
  });
}

test("an approve after the session is revoked is an outer reauth and decides nothing", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  await f.server.revokeSession(client.sessionId.toUint8Array());
  const request = await krWire(f, client, "wake/ta/approve", prepared.body);
  const response = await sendWire(f, request);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { wakeError: "reauth" });
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
});

test("approving revokes the session when the approving credential was removed after verification", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  const lookup = f.credentials.getCredential.bind(f.credentials);
  let calls = 0;
  f.credentials.getCredential = async credentialId => {
    const credential = await lookup(credentialId);
    // The first lookup is the assertion's; later ones are the post-commit recheck.
    return ++calls > 1 && credential ? { ...credential, status: "deleted" } : credential;
  };
  const request = await krWire(f, client, "wake/ta/approve", prepared.body);
  const response = await sendWire(f, request);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { wakeError: "reauth" });
  assert.equal((await f.store.getSession(client.sessionId.toUint8Array()))?.status, "REVOKED");
  // The credential is re-read before the commit, so nothing was decided.
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
  assert.equal((await f.store.getApproval(decode(prepared.body.approvalId), f.clock.now))?.state, "EXPIRED");
});

test("replaying a consumed approve rechecks the approving credential and revokes the session", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  // Approved with a second credential, so the session's own credentials are not what gets suspended.
  const spare = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential(spare.credential);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId, { auth: spare });
  assert.deepEqual((await approve(f, client, prepared)).json.ta, { result: "approved", status: "APPROVED" });
  f.credentials.setCredential({ ...spare.credential, status: "suspended" });
  const request = await krWire(f, client, "wake/ta/approve", prepared.body);
  const response = await sendWire(f, request);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { wakeError: "reauth" });
  assert.equal((await f.store.getSession(client.sessionId.toUint8Array()))?.status, "REVOKED");
  // The decision was valid when it was made.
  assert.equal((await f.server.getOperation(op.operationId))?.status, "APPROVED");
});

// counters

test("BE=0 counter loss on a pending attempt is an outer retry that decides nothing", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const a = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  const b = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId);
  const requests = await Promise.all([a, b].map(p => krWire(f, client, "wake/ta/approve", p.body)));
  const responses = await Promise.all(requests.map(r => sendWire(f, r)));
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 503]);
  const loser = responses.find(r => r.status === 503)!;
  assert.deepEqual(await loser.json(), { wakeError: "retry" });
  const view = await f.server.getOperation(op.operationId);
  assert.equal(view?.status, "APPROVED");
  const states = await Promise.all([a, b].map(async p => (await f.store.getApproval(decode(p.body.approvalId), f.clock.now))?.state));
  assert.deepEqual(states.sort(), ["CONSUMED", "PENDING"]);
});

test("BE=1 counter regression is accepted, notified once, and not notified again on replay", async () => {
  const events: number[] = [];
  const { f, client } = await setup(
    { onCounterAnomaly: event => { events.push(event.receivedSignCount); } },
    { rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: true, signCount: 10 },
  );
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId), op.operationId, { tamper: { signCount: 3 } });
  const first = await approve(f, client, prepared);
  assert.deepEqual(first.json.ta, { result: "approved", status: "APPROVED" });
  assert.deepEqual(events, [3]);
  assert.equal((await approve(f, client, prepared)).text, first.text);
  assert.deepEqual(events, [3]);
});

// Spec §10.7–§10.8, §9.4: TA+KR approvals decide the TA and KR parts independently.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Bytes, verifyApprovalBundle } from "@wake-protocol/core";
import { SoftAuthenticator } from "../src/testing.ts";
import { decode, encode, ORIGIN, RP, sendWire } from "./helpers.ts";
import { completeKr, krError, krRequest, krStart, krWire, prepareKr } from "./kr-helpers.ts";
import { approve, challenge, newOperation, prepareTa, setup, ta, taError, verifyKrCommitted } from "./ta-helpers.ts";

async function sessionState(s: Awaited<ReturnType<typeof setup>>) {
  const state = await s.f.store.getSession(s.client.sessionId.toUint8Array());
  assert.ok(state);
  return state;
}

test("TA+KR commits both: new epoch keys, verifiable serverFinished, th in the decision record", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const before = await sessionState(s);
  const ch = await challenge(f, client, op.operationId, true);
  assert.deepEqual(Object.keys(ch.kr!).sort(), ["epoch", "exchangeId", "serverNonce", "serverPublicKey"]);
  assert.equal(ch.kr!.epoch, 1);
  const bound = await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now);
  assert.equal(bound?.kind, "rekey");
  assert.ok(bound?.boundApprovalId?.equals((await f.store.getApproval(decode(ch.approvalId), f.clock.now))!.approvalId));
  f.clock.now += 100;
  const prepared = await prepareTa(f, client, ch, op.operationId);
  const result = await approve(f, client, prepared);
  assert.equal(result.header.epoch, 0);
  assert.deepEqual(Object.keys(result.json).sort(), ["kr", "operationId", "ta"]);
  assert.deepEqual(result.json.ta, { result: "approved", status: "APPROVED" });
  await verifyKrCommitted(prepared, result.json.kr as Record<string, unknown>);
  const after = await sessionState(s);
  assert.equal(after.currentEpoch, 1);
  assert.equal(after.authTime, f.clock.now);
  assert.equal(after.hardCapAt, before.hardCapAt);
  assert.equal(after.absoluteExpiresAt, before.absoluteExpiresAt + 100);
  assert.ok(after.currentKeys?.th.equals(prepared.th!));
  assert.ok(after.prevKeys?.th.equals(client.th));
  assert.equal(after.prevValidUntil, f.clock.now + 60_000);
  assert.deepEqual(after.lastAuthCredentialId, f.auth.credential.credentialId);
  assert.equal((await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now))?.state, "COMPLETED");
  assert.equal((await krRequest(f, prepared.next!, "wake/session")).json.epoch, 1);
  const view = await f.server.getOperation(op.operationId);
  assert.ok(view?.decision?.kind === "approved");
  assert.ok(view.decision.th && new Bytes(view.decision.th).equals(prepared.th!));
  const bundle = await f.server.exportApprovalBundle(op.operationId);
  assert.equal((bundle!.approval as { th: string; }).th, encode(prepared.th!.toUint8Array()));
  assert.equal(await verifyApprovalBundle(bundle, { rpId: RP, origins: [ORIGIN] }), true);
});

test("a replayed TA+KR approve returns the identical response with the old epoch's keys", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const prepared = await prepareTa(f, client, await challenge(f, client, op.operationId, true), op.operationId);
  const first = await approve(f, client, prepared);
  f.clock.now++;
  const again = await approve(f, client, prepared);
  assert.equal(again.text, first.text);
  assert.ok(!again.header.requestId.equals(first.header.requestId));
  assert.equal(again.header.epoch, 0);
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount, 2);
});

test("a KR conflict leaves the TA approval intact", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  // A plain KR moves the epoch while the TA+KR attempt is outstanding.
  const plain = await prepareKr(f, client);
  await completeKr(f, client, plain);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  const result = await approve(f, client, prepared);
  assert.deepEqual(result.json, {
    operationId: op.operationId,
    ta: { result: "approved", status: "APPROVED" },
    kr: { result: "conflict" },
  });
  const state = await sessionState(s);
  assert.equal(state.currentEpoch, 1);
  assert.ok(state.currentKeys?.th.equals(plain.th));
  assert.equal((await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now))?.state, "SUPERSEDED");
  assert.equal((await f.server.getOperation(op.operationId))?.status, "APPROVED");
  // Without the plain KR the approve would have used epoch 0; the committed plain epoch still works.
  assert.equal((await krRequest(f, plain.next, "wake/session")).json.epoch, 1);
});

test("an expired KR exchange leaves the TA approval intact and changes no epoch", async () => {
  const s = await setup({ exchangeTtlMs: 100_000, webauthnTimeoutMs: 60_000 });
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  f.clock.now += 100_000;
  const result = await approve(f, client, prepared);
  assert.deepEqual(result.json, {
    operationId: op.operationId,
    ta: { result: "approved", status: "APPROVED" },
    kr: { result: "expired" },
  });
  assert.equal((await sessionState(s)).currentEpoch, 0);
});

test("the KR exchange expiring one millisecond later still commits", async () => {
  const s = await setup({ exchangeTtlMs: 100_000, webauthnTimeoutMs: 60_000 });
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  f.clock.now += 99_999;
  const result = await approve(f, client, prepared);
  await verifyKrCommitted(prepared, result.json.kr as Record<string, unknown>);
  assert.equal((await sessionState(s)).currentEpoch, 1);
});

test("a superseded KR exchange (pending limit) yields kr expired while TA is approved", async () => {
  const s = await setup({ maxPendingRekeys: 1 });
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  await krStart(f, client);
  const result = await approve(f, client, await prepareTa(f, client, ch, op.operationId));
  assert.deepEqual(result.json.ta, { result: "approved", status: "APPROVED" });
  assert.deepEqual(result.json.kr, { result: "expired" });
  assert.equal((await sessionState(s)).currentEpoch, 0);
});

for (const how of ["cancelled", "rejected", "approved elsewhere", "expired"] as const) {
  test(`KR commits even though the operation was ${how} before the approve`, async () => {
    const s = await setup();
    const { f, client } = s;
    const op = await newOperation(f, { ttlMs: 60_000 });
    const ch = await challenge(f, client, op.operationId, true);
    const prepared = await prepareTa(f, client, ch, op.operationId);
    let status = "CANCELLED";
    if (how === "cancelled") {
      await f.server.cancelOperation(op.operationId);
    } else if (how === "rejected") {
      await ta(f, client, "reject", { operationId: op.operationId });
      status = "REJECTED";
    } else if (how === "approved elsewhere") {
      const other = await challenge(f, client, op.operationId);
      await approve(f, client, await prepareTa(f, client, other, op.operationId));
      status = "APPROVED";
    } else {
      f.clock.now = op.expiresAt;
      status = "EXPIRED";
    }
    // The first counter value used must still be accepted: prepare after the other decision.
    const late = how === "approved elsewhere" ? await prepareTa(f, client, ch, op.operationId) : prepared;
    const result = await approve(f, client, late);
    assert.deepEqual(result.json.ta, { result: how === "expired" ? "expired" : "already_decided", status });
    await verifyKrCommitted(late, result.json.kr as Record<string, unknown>);
    assert.equal((await sessionState(s)).currentEpoch, 1);
    const view = await f.server.getOperation(op.operationId);
    assert.equal(view?.status, status);
    if (how !== "approved elsewhere") {
      assert.notEqual(view?.decision?.kind, "approved");
    }
  });
}

test("a bound exchange cannot be completed through wake/kr/complete and stays usable for the approval", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const asPlain = await prepareKr(f, client, {}, f.auth, {
    exchangeId: ch.kr!.exchangeId,
    epoch: ch.kr!.epoch,
    serverNonce: ch.kr!.serverNonce,
    serverPublicKey: ch.kr!.serverPublicKey,
    expiresAt: ch.expiresAt,
    webauthn: ch.webauthn,
  });
  await krError(f, client, "wake/kr/complete", asPlain.body, "not_found");
  assert.equal((await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now))?.state, "PENDING");
  assert.equal((await sessionState(s)).currentEpoch, 0);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  await verifyKrCommitted(prepared, (await approve(f, client, prepared)).json.kr as Record<string, unknown>);
});

test("a plain TA approve on a rekey attempt does not use the offered exchange", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const prepared = await prepareTa(f, client, ch, op.operationId, { kr: false });
  const result = await approve(f, client, prepared);
  assert.deepEqual(result.json, { operationId: op.operationId, ta: { result: "approved", status: "APPROVED" }, kr: null });
  assert.equal((await sessionState(s)).currentEpoch, 0);
  assert.equal((await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now))?.state, "SUPERSEDED");
});

test("a wrong clientFinished is webauthn_failed and changes nothing", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const bad = await prepareTa(f, client, ch, op.operationId, { corruptFinished: true });
  const countBefore = (await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount;
  await taError(f, client, "approve", bad.body, "webauthn_failed");
  // The BE=0 counter is advanced only once the request can no longer fail on the KR part.
  assert.equal((await f.credentials.getCredential(f.auth.credential.credentialId))!.signCount, countBefore);
  assert.equal((await f.store.getApproval(decode(ch.approvalId), f.clock.now))?.state, "PENDING");
  assert.equal((await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now))?.state, "PENDING");
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
  assert.equal((await sessionState(s)).currentEpoch, 0);
  const good = await prepareTa(f, client, ch, op.operationId);
  await verifyKrCommitted(good, (await approve(f, client, good)).json.kr as Record<string, unknown>);
});

test("a KR exchange that is not bound to the attempt is not_found", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const plain = await krStart(f, client);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  const body = { ...prepared.body, kr: { ...(prepared.body.kr as object), exchangeId: plain.exchangeId } };
  await taError(f, client, "approve", body, "not_found");
  const second = await challenge(f, client, op.operationId, true);
  const crossed = { ...prepared.body, kr: { ...(prepared.body.kr as object), exchangeId: second.kr!.exchangeId } };
  await taError(f, client, "approve", crossed, "not_found");
  const unknown = { ...prepared.body, kr: { ...(prepared.body.kr as object), exchangeId: encode(new Uint8Array(16)) } };
  await taError(f, client, "approve", unknown, "not_found");
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
});

test("a kr object on an attempt that offered no rekey is not_found", async () => {
  const s = await setup();
  const { f, client } = s;
  const op = await newOperation(f);
  const rekeying = await challenge(f, client, op.operationId, true);
  const plainAttempt = await challenge(f, client, op.operationId, false);
  const prepared = await prepareTa(f, client, rekeying, op.operationId);
  const body = { ...prepared.body, approvalId: plainAttempt.approvalId };
  await taError(f, client, "approve", body, "not_found");
});

for (const [field, value] of [
  ["exchangeId", encode(new Uint8Array(15))],
  ["clientPublicKey", encode(new Uint8Array(65).fill(4))],
  ["clientPublicKey", "!"],
  ["clientFinished", encode(new Uint8Array(31))],
  ["clientFinished", encode(new Uint8Array(33))],
  ["clientFinished", 7],
] as const) {
  test(`a malformed kr.${field} (${String(value).slice(0, 8)}) is invalid_request`, async () => {
    const { f, client } = await setup();
    const op = await newOperation(f);
    const ch = await challenge(f, client, op.operationId, true);
    const prepared = await prepareTa(f, client, ch, op.operationId);
    await taError(f, client, "approve", { ...prepared.body, kr: { ...(prepared.body.kr as object), [field]: value } }, "invalid_request");
    await verifyKrCommitted(prepared, (await approve(f, client, prepared)).json.kr as Record<string, unknown>);
  });
}

test("challenge with rekey enforces maxPendingRekeys together with plain KR starts", async () => {
  const { f, client } = await setup({ maxPendingRekeys: 2 });
  const op = await newOperation(f);
  const first = await challenge(f, client, op.operationId, true);
  f.clock.now++;
  await krStart(f, client);
  f.clock.now++;
  await challenge(f, client, op.operationId, true);
  assert.equal((await f.store.getExchange(decode(first.kr!.exchangeId), f.clock.now))?.state, "SUPERSEDED");
});

test("an attempt's expiry supersedes its bound exchange", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  f.clock.now = ch.expiresAt;
  assert.equal((await f.store.getApproval(decode(ch.approvalId), f.clock.now))?.state, "EXPIRED");
  assert.equal((await f.store.getExchange(decode(ch.kr!.exchangeId), f.clock.now))?.state, "SUPERSEDED");
});

test("TA+KR commits the epoch once when two attempts race for the same epoch", async () => {
  const s = await setup({}, { rpId: RP, origin: ORIGIN, userId: "u1", backupEligible: true });
  const { f, client } = s;
  const op = await newOperation(f);
  const a = await challenge(f, client, op.operationId, true);
  const b = await challenge(f, client, op.operationId, true);
  const preparedA = await prepareTa(f, client, a, op.operationId);
  const preparedB = await prepareTa(f, client, b, op.operationId);
  const [ra, rb] = await Promise.all([approve(f, client, preparedA), approve(f, client, preparedB)]);
  const results = [ra, rb].map(r => (r.json.kr as { result: string; }).result);
  assert.deepEqual(results.sort(), ["committed", "conflict"]);
  assert.equal((await sessionState(s)).currentEpoch, 1);
  assert.equal((await f.server.getOperation(op.operationId))?.status, "APPROVED");
});

test("TA+KR approve with the old epoch is refused once the grace period is over", async () => {
  const { f, client } = await setup();
  const op = await newOperation(f);
  const ch = await challenge(f, client, op.operationId, true);
  const plain = await prepareKr(f, client);
  await completeKr(f, client, plain);
  const prepared = await prepareTa(f, client, ch, op.operationId);
  f.clock.now += 60_001;
  const request = await krWire(f, client, "wake/ta/approve", prepared.body);
  const response = await sendWire(f, request);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { wakeError: "epoch_retired" });
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
  // The same approve under the new epoch's keys reports the conflict.
  const retried = await krRequest(f, plain.next, "wake/ta/approve", prepared.body);
  assert.deepEqual(retried.json.kr, { result: "conflict" });
  assert.deepEqual(retried.json.ta, { result: "approved", status: "APPROVED" });
});

test("revoking an intermediate TA+KR credential revokes the session after a later KR", async () => {
  const s = await setup();
  const { f, client } = s;
  const b = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  const c = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential(b.credential);
  f.credentials.setCredential(c.credential);
  const op = await newOperation(f);
  const middle = await prepareTa(f, client, await challenge(f, client, op.operationId, true), op.operationId, { auth: b });
  await verifyKrCommitted(middle, (await approve(f, client, middle)).json.kr as Record<string, unknown>);
  const latest = await prepareKr(f, middle.next!, {}, c);
  await completeKr(f, middle.next!, latest);
  assert.deepEqual((await sessionState(s)).authCredentialIds, [
    f.auth.credential.credentialId, b.credential.credentialId, c.credential.credentialId,
  ]);
  await f.server.revokeSessionsByCredential(new Uint8Array([0]));
  assert.equal((await sessionState(s)).status, "ACTIVE");
  await f.server.revokeSessionsByCredential(b.credential.credentialId);
  assert.equal((await sessionState(s)).status, "REVOKED");
});

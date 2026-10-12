// Spec §10.6, §10.8, §10.11: client-side WAKE-TA against an independent fake server.
import assert from "node:assert/strict";
import { test } from "node:test";
import { base64urlnopad } from "@scure/base";
import { WakeError } from "@wake-protocol/core";
import { fixture, hasCode, jsonResponse } from "./fixture.ts";

const login = { mode: "discoverable" } as const;
const CONTENT = "Transfer\\nTo: Alice\\nAmount: 10000 JPY";
const OTHER = "a".repeat(64);

async function ready() {
  const f = await fixture();
  await f.client.login(login);
  f.assertionCalls = 0;
  const op = await f.addOperation(CONTENT);
  return { f, op };
}

const taRequests = (f: Awaited<ReturnType<typeof fixture>>, context: string) => f.taRequests.filter(r => r.context === context);

test("getOperation returns a verified view with the locally assembled hashInput", async () => {
  const { f, op } = await ready();
  const view = await f.client.getOperation(op.operationId);
  assert.equal(view.operationId, op.operationId);
  assert.equal(view.content, CONTENT);
  assert.equal(view.hashInput, op.hashInput);
  assert.equal(view.status, "PENDING");
  assert.equal(view.decidedAt, null);
  assert.equal(view.expiresAt, 1_791_676_800_000);
  assert.deepEqual(f.taRequests[0]!.body, { operationId: op.operationId });
});

for (const [name, id] of [["uppercase", "A".repeat(64)], ["63 characters", "a".repeat(63)], ["non-hex", "g".repeat(64)], ["empty", ""]] as const) {
  test(`getOperation, approve and reject reject a ${name} operationId without sending`, async () => {
    const { f } = await ready();
    const before = f.requests.length;
    await assert.rejects(f.client.getOperation(id), hasCode("bad_request"));
    await assert.rejects(f.client.approve(id), hasCode("bad_request"));
    await assert.rejects(f.client.reject(id), hasCode("bad_request"));
    assert.equal(f.requests.length, before);
  });
}

test("getOperation maps an unknown operation to not_found", async () => {
  const { f } = await ready();
  await assert.rejects(f.client.getOperation(OTHER), hasCode("not_found"));
});

test("getOperation requires a session", async () => {
  const f = await fixture();
  await assert.rejects(f.client.getOperation(OTHER), hasCode("reauth"));
});

test("getOperation: content that does not hash to the REQUESTED id is operation_mismatch", async () => {
  const { f, op } = await ready();
  // Server swaps the content but keeps the (requested) operationId.
  f.taGetMutate = v => { v.content = "Transfer\\nTo: Mallory\\nAmount: 10000 JPY"; };
  await assert.rejects(f.client.getOperation(op.operationId), hasCode("operation_mismatch"));
  // Server answers with a self-consistent but different operation.
  const other = await f.addOperation("Another request");
  f.taGetMutate = v => {
    v.content = "Another request";
    v.operationId = other.operationId;
  };
  await assert.rejects(f.client.getOperation(op.operationId), hasCode("operation_mismatch"));
  // Only the operationId member is altered.
  f.taGetMutate = v => { v.operationId = other.operationId; };
  await assert.rejects(f.client.getOperation(op.operationId), hasCode("operation_mismatch"));
  // Nonce changed.
  f.taGetMutate = v => { v.nonce = "0".repeat(32); };
  await assert.rejects(f.client.getOperation(op.operationId), hasCode("operation_mismatch"));
});

test("getOperation rejects content violating the profile and malformed nonce or members", async () => {
  const { f, op } = await ready();
  for (const content of ["", " lead", "trail ", "tab\there", "é"]) {
    f.taGetMutate = v => { v.content = content; };
    await assert.rejects(f.client.getOperation(op.operationId), hasCode("invalid_content"), JSON.stringify(content));
  }
  for (const nonce of [op.hashInput.slice(-32).toUpperCase(), "abc", 5, null]) {
    f.taGetMutate = v => { v.nonce = nonce; };
    await assert.rejects(f.client.getOperation(op.operationId), hasCode("bad_request"), String(nonce));
  }
  for (const mutate of [
    (v: Record<string, unknown>) => { v.status = "DONE"; },
    (v: Record<string, unknown>) => { v.createdAt = -1; },
    (v: Record<string, unknown>) => { v.expiresAt = "soon"; },
    (v: Record<string, unknown>) => { v.decidedAt = undefined; },
    (v: Record<string, unknown>) => { v.decidedAt = 1.5; },
  ]) {
    f.taGetMutate = mutate;
    await assert.rejects(f.client.getOperation(op.operationId), hasCode("bad_request"));
  }
});

test("listOperations sends only valid options and verifies every entry", async () => {
  const { f, op } = await ready();
  const list = await f.client.listOperations({ status: "PENDING", limit: 20 });
  assert.equal(list.nextCursor, null);
  assert.equal(list.operations.length, 1);
  assert.equal(list.operations[0]!.operationId, op.operationId);
  assert.deepEqual(f.taRequests[0]!.body, { status: "PENDING", limit: 20 });
  await f.client.listOperations();
  assert.deepEqual(f.taRequests[1]!.body, {});
  await f.client.listOperations({ limit: 1, cursor: "abc" });
  assert.deepEqual(f.taRequests[2]!.body, { limit: 1, cursor: "abc" });
  const before = f.requests.length;
  for (const bad of [{ limit: 0 }, { limit: 21 }, { limit: 1.5 }, { cursor: "" }, { status: "DONE" as "PENDING" }]) {
    await assert.rejects(f.client.listOperations(bad), hasCode("bad_request"), JSON.stringify(bad));
  }
  assert.equal(f.requests.length, before);
  f.taListMutate = v => { (v.operations as Record<string, unknown>[])[0]!.content = "forged"; };
  await assert.rejects(f.client.listOperations(), hasCode("operation_mismatch"));
  for (const mutate of [
    (v: Record<string, unknown>) => { v.nextCursor = ""; },
    (v: Record<string, unknown>) => { v.nextCursor = 5; },
    (v: Record<string, unknown>) => { delete v.nextCursor; },
    (v: Record<string, unknown>) => { v.operations = {}; },
    (v: Record<string, unknown>) => { v.operations = new Array(21).fill((v.operations as unknown[])[0]); },
  ]) {
    f.taListMutate = mutate;
    await assert.rejects(f.client.listOperations(), hasCode("bad_request"));
  }
  f.taListMutate = v => { v.nextCursor = "next"; };
  assert.equal((await f.client.listOperations()).nextCursor, "next");
});

test("approve (TA only) signs over the caller's operationId and keeps the epoch", async () => {
  const { f, op } = await ready();
  const result = await f.client.approve(op.operationId);
  assert.deepEqual(result, { operationId: op.operationId, ta: { result: "approved", status: "APPROVED" } });
  assert.equal(f.assertionCalls, 1);
  assert.equal(f.operations.get(op.operationId)!.status, "APPROVED");
  assert.deepEqual(taRequests(f, "wake/ta/challenge")[0]!.body, { operationId: op.operationId, rekey: false });
  const sent = taRequests(f, "wake/ta/approve")[0]!.body;
  assert.equal(sent.kr, null);
  assert.equal(sent.operationId, op.operationId);
  assert.equal((await f.client.session()).epoch, 0);
});

for (const field of ["approvalId", "approvalNonce"] as const) {
  test(`a tampered ${field} in the challenge response makes the server-recomputed binding reject the signature`, async () => {
    const { f, op } = await ready();
    const size = field === "approvalId" ? 16 : 32;
    f.taChallengeMutate = v => { v[field] = base64urlnopad.encode(new Uint8Array(size).fill(7)); };
    // The client signs over what it received; the fake server recomputes ta from its own stored values.
    await assert.rejects(f.client.approve(op.operationId), hasCode("webauthn_failed"));
    assert.equal(f.operations.get(op.operationId)!.status, "PENDING");
  });
}

test("approve rejects malformed challenge responses before asking for a signature", async () => {
  for (const mutate of [
    (v: Record<string, unknown>) => { v.approvalId = base64urlnopad.encode(new Uint8Array(15)); },
    (v: Record<string, unknown>) => { v.approvalNonce = base64urlnopad.encode(new Uint8Array(31)); },
    (v: Record<string, unknown>) => { v.expiresAt = "x"; },
    (v: Record<string, unknown>) => { v.webauthn = null; },
    (v: Record<string, unknown>) => { v.kr = { exchangeId: "AA" }; },
    (v: Record<string, unknown>) => { delete v.kr; },
  ]) {
    const { f, op } = await ready();
    f.taChallengeMutate = mutate;
    await assert.rejects(f.client.approve(op.operationId), hasCode("bad_request"));
    assert.equal(f.assertionCalls, 0);
  }
  const { f, op } = await ready();
  // rekey requested but the server answers kr: null
  f.taChallengeMutate = v => { v.kr = null; };
  await assert.rejects(f.client.approve(op.operationId, { rekey: true }), hasCode("bad_request"));
  assert.equal(f.assertionCalls, 0);
  assert.equal((await f.client.session()).epoch, 0);
});

test("approve maps encrypted errors and checks the approve response", async () => {
  for (const code of ["not_found", "expired", "already_decided", "webauthn_failed", "invalid_request"]) {
    const { f, op } = await ready();
    f.taApproveError = code;
    await assert.rejects(f.client.approve(op.operationId), hasCode(code));
    assert.equal((await f.client.session()).epoch, 0);
  }
  for (const mutate of [
    (v: Record<string, unknown>) => { v.operationId = OTHER; },
    (v: Record<string, unknown>) => { v.ta = { result: "maybe", status: "APPROVED" }; },
    (v: Record<string, unknown>) => { v.ta = { result: "approved" }; },
    (v: Record<string, unknown>) => { v.ta = null; },
    (v: Record<string, unknown>) => { v.kr = { result: "committed" }; },
  ]) {
    const { f, op } = await ready();
    f.taApproveMutate = mutate;
    await assert.rejects(f.client.approve(op.operationId), hasCode("bad_request"));
  }
  const { f, op } = await ready();
  f.taApproveMutate = v => { v.ta = { result: "already_decided", status: "REJECTED" }; };
  assert.deepEqual((await f.client.approve(op.operationId)).ta, { result: "already_decided", status: "REJECTED" });
});

test("TA+KR committed verifies serverFinished and switches epochs", async () => {
  const { f, op } = await ready();
  const result = await f.client.approve(op.operationId, { rekey: true });
  assert.equal(result.ta.result, "approved");
  assert.equal(result.kr!.result, "committed");
  assert.equal((result.kr as { epoch: number }).epoch, 1);
  assert.equal(f.assertionCalls, 1);
  assert.deepEqual(taRequests(f, "wake/ta/challenge")[0]!.body, { operationId: op.operationId, rekey: true });
  const sent = taRequests(f, "wake/ta/approve")[0]!.body;
  assert.deepEqual(Object.keys(sent.kr as object).sort(), ["clientFinished", "clientPublicKey", "exchangeId"]);
  assert.equal((await f.client.session()).epoch, 1);
  // The next rotation chains from the TA+KR transcript hash (the fake server uses its own prevTh).
  assert.equal((await f.client.rekey()).epoch, 2);
  assert.equal((await f.client.session()).epoch, 2);
});

test("TA+KR with a bad serverFinished drops the session", async () => {
  const { f, op } = await ready();
  f.taApproveKrMutate = v => {
    const mac = base64urlnopad.decode(v.serverFinished as string);
    mac[0] = mac[0]! ^ 1;
    v.serverFinished = base64urlnopad.encode(mac);
  };
  await assert.rejects(f.client.approve(op.operationId, { rekey: true }), hasCode("auth_failed"));
  assert.equal(f.client.loggedIn, false);
  assert.ok(!f.requests.some(h => h.context === "wake/session" && h.epoch === 1));
  await assert.rejects(f.client.session(), hasCode("reauth"));
});

test("TA+KR with a wrong epoch or malformed Finished fields drops the session", async () => {
  for (const mutate of [
    (v: Record<string, unknown>) => { v.epoch = 2; },
    (v: Record<string, unknown>) => { v.serverTime = -1; },
    (v: Record<string, unknown>) => { delete v.serverFinished; },
  ]) {
    const { f, op } = await ready();
    f.taApproveKrMutate = mutate;
    await assert.rejects(f.client.approve(op.operationId, { rekey: true }), (e: unknown) => e instanceof WakeError);
    assert.equal(f.client.loggedIn, false);
  }
});

test("TA+KR non-I-JSON completion recovers the epoch even if its stored result is still unreadable", async () => {
  const { f, op } = await ready();
  f.taApproveKrMutate = v => { v.serverTime = 2 ** 53; };
  await assert.rejects(f.client.approve(op.operationId, { rekey: true }), hasCode("bad_request"));
  assert.equal(f.client.loggedIn, true);
  assert.equal((await f.client.session()).epoch, 1);
  assert.deepEqual(f.requests.filter(h => h.context === "wake/ta/approve").map(h => h.epoch), [0, 1]);
});

test("an authenticated TA+KR webauthn_failed keeps the epoch and does not recover", async () => {
  const { f, op } = await ready();
  f.taApproveError = "webauthn_failed";
  await assert.rejects(f.client.approve(op.operationId, { rekey: true }), hasCode("webauthn_failed"));
  assert.equal(f.client.loggedIn, true);
  assert.equal(f.currentEpoch, 0);
  assert.equal(f.taApproveBodies.length, 1);
  assert.deepEqual(f.sleeps, []);
  assert.deepEqual(f.requests.filter(h => h.context === "wake/ta/approve").map(h => h.epoch), [0]);
  assert.ok(!f.requests.some(h => h.epoch === 1));
  assert.equal((await f.client.session()).epoch, 0);
});

for (const result of ["conflict", "expired"] as const) {
  test(`TA+KR ${result} keeps the current epoch and discards the pending generation`, async () => {
    const { f, op } = await ready();
    f.taKrResult = result;
    const info = await f.client.approve(op.operationId, { rekey: true });
    assert.deepEqual(info.kr, { result });
    assert.equal(info.ta.result, "approved");
    assert.equal((await f.client.session()).epoch, 0);
    assert.equal(f.client.loggedIn, true);
    assert.equal(f.requests.at(-1)!.epoch, 0);
  });
}

test("a malformed approve response after a rekey request drops the session (the commit state is unknown)", async () => {
  for (const mutate of [
    (v: Record<string, unknown>) => { (v.kr as Record<string, unknown>).result = "done"; },
    (v: Record<string, unknown>) => { v.kr = null; },
    (v: Record<string, unknown>) => { v.ta = null; },
    (v: Record<string, unknown>) => { v.operationId = OTHER; },
  ]) {
    const { f, op } = await ready();
    f.taApproveMutate = mutate;
    await assert.rejects(f.client.approve(op.operationId, { rekey: true }), hasCode("bad_request"));
    assert.equal(f.client.loggedIn, false);
  }
});

for (const kind of ["network", "502", "retry"] as const) {
  test(`a lost ${kind} approve response resends the same plaintext with a new requestId`, async () => {
    const { f, op } = await ready();
    f.taApproveResponse = (attempt, response) => {
      if (attempt > 1) {
        return response;
      }
      if (kind === "network") {
        throw new TypeError("offline");
      }
      return kind === "502" ? new Response("gateway", { status: 502 }) : jsonResponse({ wakeError: "retry" }, 503);
    };
    const info = await f.client.approve(op.operationId);
    assert.equal(info.ta.result, "approved");
    assert.equal(f.taApproveBodies.length, 2);
    assert.equal(f.taApproveBodies[0], f.taApproveBodies[1]);
    assert.equal(f.assertionCalls, 1);
    const sent = f.requests.filter(h => h.context === "wake/ta/approve");
    assert.equal(sent.length, 2);
    assert.equal(sent[0]!.requestId.equals(sent[1]!.requestId), false);
    assert.equal(sent[0]!.iv.equals(sent[1]!.iv), false);
    assert.deepEqual(f.sleeps, [100]);
  });
}

test("a lost TA+KR approve response is resent and the switch happens once", async () => {
  const { f, op } = await ready();
  f.taApproveResponse = (attempt, response) => {
    if (attempt === 1) {
      throw new TypeError("lost");
    }
    return response;
  };
  const info = await f.client.approve(op.operationId, { rekey: true });
  assert.equal(info.kr!.result, "committed");
  assert.equal(f.taApproveBodies.length, 2);
  assert.equal(f.taApproveBodies[0], f.taApproveBodies[1]);
  assert.deepEqual(f.requests.filter(h => h.context === "wake/ta/approve").map(h => h.epoch), [0, 0]);
  assert.equal((await f.client.session()).epoch, 1);
});

test("replayed TA+KR completion keeps the header-derived offset across the retry delay", async () => {
  const { f, op } = await ready();
  const committedServerTime = f.serverTime;
  let replayIssuedAt = 0;
  f.taApproveResponse = (attempt, response) => {
    if (attempt === 1) {
      // Both clocks move while the committed response is lost. The cached plaintext keeps the commit time.
      f.serverTime += 5_000;
      f.localTime += 5_000;
      throw new TypeError("lost committed response");
    }
    replayIssuedAt = f.serverTime;
    return response;
  };
  const info = await f.client.approve(op.operationId, { rekey: true });
  assert.equal(info.kr?.result, "committed");
  assert.equal(info.kr && "serverTime" in info.kr ? info.kr.serverTime : undefined, committedServerTime);
  assert.equal(replayIssuedAt, committedServerTime + 5_000);
  await f.client.request("custom", new Uint8Array([1]));
  assert.equal(f.requests.at(-1)!.context, "custom");
  assert.equal(f.requests.at(-1)!.issuedAt, replayIssuedAt);
});

test("a lost TA+KR response followed by epoch_retired recovers through wake/session and confirms APPROVED", async () => {
  const { f, op } = await ready();
  f.taApproveResponse = (attempt, response) => {
    if (attempt === 1) {
      throw new TypeError("lost committed response");
    }
    return attempt === 2 ? jsonResponse({ wakeError: "epoch_retired" }, 401) : response;
  };
  const info = await f.client.approve(op.operationId, { rekey: true });
  assert.deepEqual(info.ta, { result: "approved", status: "APPROVED" });
  assert.equal(info.kr!.result, "committed");
  assert.equal((await f.client.session()).epoch, 1);
  assert.equal((await f.client.getOperation(op.operationId)).status, "APPROVED");
  // lost response, retired resend, then the same plaintext sealed with the new epoch
  assert.equal(f.taApproveBodies.length, 3);
  assert.equal(f.taApproveBodies[0], f.taApproveBodies[2]);
  assert.deepEqual(f.requests.filter(h => h.context === "wake/ta/approve").map(h => h.epoch), [0, 0, 1]);
});

test("TA+KR recovery returns the server's replayed result and keeps the session even if the operation is CANCELLED", async () => {
  const { f, op } = await ready();
  f.operations.get(op.operationId)!.status = "CANCELLED";
  f.taApproveMutate = v => {
    if (f.taApproveBodies.length >= 3) {
      v.ta = { result: "already_decided", status: "CANCELLED" };
    }
  };
  f.taApproveResponse = (attempt, response) => {
    if (attempt === 1) {
      throw new TypeError("lost committed response");
    }
    return attempt === 2 ? jsonResponse({ wakeError: "epoch_retired" }, 401) : response;
  };
  const info = await f.client.approve(op.operationId, { rekey: true });
  assert.deepEqual(info.ta, { result: "already_decided", status: "CANCELLED" });
  assert.equal(info.kr!.result, "committed");
  assert.equal(f.client.loggedIn, true);
  assert.equal((await f.client.session()).epoch, 1);
});

test("after TA+KR conflict the kept epoch is dropped as reauth once the server reports it retired", async () => {
  const { f, op } = await ready();
  f.taKrResult = "conflict";
  assert.equal((await f.client.approve(op.operationId, { rekey: true })).kr!.result, "conflict");
  assert.equal(f.client.loggedIn, true);
  f.upAction = () => f.requests.at(-1)!.context === "wake/session" ? jsonResponse({ wakeError: "epoch_retired" }, 401) : undefined;
  await assert.rejects(f.client.session(), hasCode("reauth"));
  assert.equal(f.client.loggedIn, false);
});

test("approve stops at the attempt deadline", async () => {
  const { f, op } = await ready();
  f.taApproveResponse = () => {
    throw new TypeError("offline");
  };
  // The attempt lives 300 s of server time; the fake clock advances by the sleeps only.
  await assert.rejects(f.client.approve(op.operationId), hasCode("expired"));
});

/** Blocks the first assertion after `ready()` resets the counter. A nested rekey's assertion proceeds. */
function holdFirstAssertion(f: Awaited<ReturnType<typeof fixture>>) {
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  let reached!: () => void;
  const arrived = new Promise<void>(resolve => { reached = resolve; });
  f.onAssertion = async () => {
    if (f.assertionCalls !== 1) {
      return;
    }
    reached();
    await blocked;
  };
  return { release, arrived };
}

// Default G_epoch is 60s (§9.5). The approve attempt lives 300s, so it is still inside the deadline.
const PAST_G_EPOCH_MS = 60_001;

function advancePastEpochGrace(f: Awaited<ReturnType<typeof fixture>>) {
  f.localTime += PAST_G_EPOCH_MS;
  f.serverTime += PAST_G_EPOCH_MS;
}

test("a TA-only approve seals with the epoch current after a rekey during WebAuthn", async () => {
  const { f, op } = await ready();
  const held = holdFirstAssertion(f);
  const pending = f.client.approve(op.operationId);
  await held.arrived;
  assert.equal((await f.client.rekey()).epoch, 1);
  advancePastEpochGrace(f);
  held.release();
  const info = await pending;
  assert.deepEqual(info, { operationId: op.operationId, ta: { result: "approved", status: "APPROVED" } });
  assert.equal(f.operations.get(op.operationId)!.status, "APPROVED");
  assert.equal(taRequests(f, "wake/ta/approve")[0]!.body.kr, null);
  assert.deepEqual(f.requests.filter(h => h.context === "wake/ta/approve").map(h => h.epoch), [1]);
  assert.equal((await f.client.session()).epoch, 1);
});

test("a TA-only resend after the epoch moves seals that send with the current epoch", async () => {
  const { f, op } = await ready();
  f.taApproveResponse = async (attempt, response) => {
    if (attempt === 1) {
      assert.equal((await f.client.rekey()).epoch, 1);
      advancePastEpochGrace(f);
      throw new TypeError("lost");
    }
    return response;
  };
  const info = await f.client.approve(op.operationId);
  assert.equal(info.ta.result, "approved");
  assert.equal(f.taApproveBodies.length, 2);
  assert.equal(f.taApproveBodies[0], f.taApproveBodies[1]);
  const sent = f.requests.filter(h => h.context === "wake/ta/approve");
  assert.deepEqual(sent.map(h => h.epoch), [0, 1]);
  assert.equal(sent[0]!.requestId.equals(sent[1]!.requestId), false);
  assert.equal(sent[0]!.iv.equals(sent[1]!.iv), false);
  assert.equal((await f.client.session()).epoch, 1);
});

test("a TA+KR approve stays sealed with the epoch captured before WebAuthn", async () => {
  const { f, op } = await ready();
  const held = holdFirstAssertion(f);
  const pending = f.client.approve(op.operationId, { rekey: true });
  await held.arrived;
  advancePastEpochGrace(f);
  held.release();
  const info = await pending;
  assert.equal(info.ta.result, "approved");
  assert.equal(info.kr!.result, "committed");
  assert.equal((info.kr as { epoch: number }).epoch, 1);
  assert.equal(f.currentEpoch, 1);
  assert.deepEqual(f.requests.filter(h => h.context === "wake/ta/approve").map(h => h.epoch), [0]);
  assert.notEqual(taRequests(f, "wake/ta/approve")[0]!.body.kr, null);
  assert.equal((await f.client.session()).epoch, 1);
});

test("a concurrent rekey while a TA+KR approval is pending is a conflict", async () => {
  const { f, op } = await ready();
  let release!: () => void;
  const blocked = new Promise<void>(r => { release = r; });
  let reached!: () => void;
  const arrived = new Promise<void>(r => { reached = r; });
  f.onAssertion = () => { reached(); };
  f.taApproveResponse = async (_attempt, response) => {
    await blocked;
    return response;
  };
  const pending = f.client.approve(op.operationId, { rekey: true });
  await arrived;
  await assert.rejects(f.client.rekey(), hasCode("conflict"));
  await assert.rejects(f.client.approve(op.operationId, { rekey: true }), hasCode("conflict"));
  release();
  assert.equal((await pending).kr!.result, "committed");
  assert.equal((await f.client.rekey()).epoch, 2);
});

test("reject posts only the operationId and validates the response", async () => {
  const { f, op } = await ready();
  assert.deepEqual(await f.client.reject(op.operationId), { result: "rejected", status: "REJECTED" });
  assert.deepEqual(taRequests(f, "wake/ta/reject")[0]!.body, { operationId: op.operationId });
  assert.equal(f.assertionCalls, 0);
  await assert.rejects(f.client.reject(OTHER), hasCode("not_found"));
});

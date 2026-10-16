// Spec §10.2, §10.9, §10.10, §13: operation creation, cancellation, retrieval and TA options.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { WakeError } from "@wake-protocol/core";
import { createWakeServer, MemoryCredentialStore } from "../src/index.ts";
import type { OperationRecord, WakeServerOptions } from "../src/index.ts";
import { fixture, ORIGIN, RP } from "./helpers.ts";
import { newOperation } from "./ta-helpers.ts";

const DAY = 86_400_000;

function code(expected: string) {
  return (error: unknown) => error instanceof WakeError && error.code === expected;
}

test("createOperation returns operationId, nonce, hashInput and expiresAt that match §10.3", async () => {
  const f = await fixture();
  const op = await newOperation(f, { content: "送金要求\\n送金先: 山田太郎" });
  assert.match(op.operationId, /^[0-9a-f]{64}$/);
  assert.match(op.nonce, /^[0-9a-f]{32}$/);
  assert.equal(op.hashInput, `送金要求\\n送金先: 山田太郎\nWAKE-TA-Nonce: ${op.nonce}`);
  assert.equal(op.operationId, createHash("sha256").update(op.hashInput, "utf8").digest("hex"));
  assert.equal(op.expiresAt, f.clock.now + 3_600_000);
  const view = await f.server.getOperation(op.operationId);
  assert.ok(view);
  assert.equal(view.status, "PENDING");
  assert.equal(view.content, "送金要求\\n送金先: 山田太郎");
  assert.equal(view.nonce, op.nonce);
  assert.equal(view.approverUserId, "u1");
  assert.equal(view.createdAt, f.clock.now);
  assert.equal(view.expiresAt, op.expiresAt);
  assert.equal(view.decidedAt, null);
  assert.equal(view.decision, null);
});

test("two operations with the same content get different nonces and operationIds", async () => {
  const f = await fixture();
  const a = await newOperation(f);
  const b = await newOperation(f);
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.operationId, b.operationId);
});

for (const [name, content] of [
  ["empty", ""],
  ["LF", "a\nb"],
  ["tab", "a\tb"],
  ["leading space", " a"],
  ["trailing ideographic space", "a　"],
  ["not NFC", "é"],
  ["lone surrogate", "a\ud800"],
  ["over 65536 bytes", "a".repeat(65537)],
] as const) {
  test(`createOperation rejects content: ${name}`, async () => {
    const f = await fixture();
    await assert.rejects(newOperation(f, { content }), code("invalid_content"));
  });
}

test("createOperation accepts content of exactly 65536 bytes", async () => {
  const f = await fixture();
  await newOperation(f, { content: "a".repeat(65536) });
});

for (const [name, approverUserId, ok] of [
  ["empty", "", false],
  ["1 byte", "a", true],
  ["256 bytes", `${"あ".repeat(85)}a`, true],
  ["257 bytes", `${"あ".repeat(85)}aa`, false],
  ["lone surrogate", "a\ud800", false],
  ["number", 7, false],
] as const) {
  test(`createOperation approverUserId ${name}`, async () => {
    const f = await fixture();
    const result = newOperation(f, { approverUserId: approverUserId as string });
    if (ok) {
      await result;
    } else {
      await assert.rejects(result, code("invalid_request"));
    }
  });
}

for (const [name, offset, ok] of [
  ["now", 0, false],
  ["before now", -1, false],
  ["now + 1", 1, true],
  ["maximum lifetime", 30 * DAY, true],
  ["maximum lifetime + 1", 30 * DAY + 1, false],
] as const) {
  test(`createOperation expiresAt ${name}`, async () => {
    const f = await fixture();
    const result = f.server.createOperation({ content: "x", approverUserId: "u1", expiresAt: f.clock.now + offset });
    if (ok) {
      await result;
    } else {
      await assert.rejects(result, code("invalid_request"));
    }
  });
}

for (const expiresAt of [Number.NaN, 1.5, Number.POSITIVE_INFINITY, "1" as unknown as number]) {
  test(`createOperation rejects expiresAt ${String(expiresAt)}`, async () => {
    const f = await fixture();
    await assert.rejects(f.server.createOperation({ content: "x", approverUserId: "u1", expiresAt }), code("invalid_request"));
  });
}

test("maxOperationLifetimeMs option moves the creation boundary", async () => {
  const f = await fixture({ maxOperationLifetimeMs: 5000 });
  await newOperation(f, { ttlMs: 5000 });
  await assert.rejects(newOperation(f, { ttlMs: 5001 }), code("invalid_request"));
});

test("a nonce collision draws a new nonce and never returns an existing operation", async () => {
  const f = await fixture();
  const original = f.store.createOperation.bind(f.store);
  const attempts: OperationRecord[] = [];
  f.store.createOperation = async record => {
    attempts.push(record);
    return attempts.length === 1 ? false : original(record);
  };
  const created = await newOperation(f);
  assert.equal(attempts.length, 2);
  assert.notEqual(attempts[0]!.nonce, attempts[1]!.nonce);
  assert.notEqual(attempts[0]!.operationId, attempts[1]!.operationId);
  assert.equal(created.operationId, attempts[1]!.operationId);
  assert.equal(created.nonce, attempts[1]!.nonce);
  assert.equal(await f.server.getOperation(attempts[0]!.operationId), null);
});

test("repeated collisions give up with a plain error", async () => {
  const f = await fixture();
  f.store.createOperation = async () => false;
  await assert.rejects(newOperation(f), (error: unknown) => error instanceof Error && !(error instanceof WakeError));
});

test("the memory store refuses to replace an existing operationId", async () => {
  const f = await fixture();
  const op = await newOperation(f);
  const existing = await f.store.getOperation(op.operationId, f.clock.now);
  assert.ok(existing);
  assert.equal(await f.store.createOperation({ ...existing, content: "other" }), false);
  assert.equal((await f.server.getOperation(op.operationId))?.content, "Transfer 100 JPY");
});

test("getOperation derives EXPIRED exactly at expiresAt and returns null for unknown ids", async () => {
  const f = await fixture();
  const op = await newOperation(f, { ttlMs: 1000 });
  f.clock.now += 999;
  assert.equal((await f.server.getOperation(op.operationId))?.status, "PENDING");
  f.clock.now += 1;
  const view = await f.server.getOperation(op.operationId);
  assert.equal(view?.status, "EXPIRED");
  assert.equal(view?.decidedAt, null);
  assert.equal(await f.server.getOperation("0".repeat(64)), null);
  await assert.rejects(f.server.getOperation("A".repeat(64)), code("invalid_request"));
  await assert.rejects(f.server.getOperation("0".repeat(63)), code("invalid_request"));
});

test("cancelOperation cancels once and records the server as the decider", async () => {
  const f = await fixture();
  const op = await newOperation(f);
  f.clock.now += 5;
  assert.equal(await f.server.cancelOperation(op.operationId), "cancelled");
  const view = await f.server.getOperation(op.operationId);
  assert.equal(view?.status, "CANCELLED");
  assert.equal(view?.decidedAt, f.clock.now);
  assert.deepEqual(view?.decision, { kind: "cancelled", decidedAt: f.clock.now, decidedBy: "server" });
  assert.equal(await f.server.cancelOperation(op.operationId), "already_decided");
  assert.equal(await f.server.exportApprovalBundle(op.operationId), null);
});

test("cancelOperation expiry boundary and unknown operation", async () => {
  const f = await fixture();
  const a = await newOperation(f, { ttlMs: 1000 });
  const b = await newOperation(f, { ttlMs: 1000 });
  f.clock.now += 999;
  assert.equal(await f.server.cancelOperation(a.operationId), "cancelled");
  f.clock.now += 1;
  assert.equal(await f.server.cancelOperation(b.operationId), "expired");
  assert.equal((await f.server.getOperation(b.operationId))?.status, "EXPIRED");
  await assert.rejects(f.server.cancelOperation("1".repeat(64)), code("not_found"));
  await assert.rejects(f.server.cancelOperation("xyz"), code("invalid_request"));
});

// Options

const base: WakeServerOptions = {
  rpId: RP,
  loginOrigins: [ORIGIN],
  secret: new Uint8Array(32),
  credentials: new MemoryCredentialStore(),
};

for (const key of ["approvalTtlMs", "maxActiveApprovals", "maxOperationLifetimeMs"] as const) {
  for (const value of [null, "1", Number.NaN, Number.POSITIVE_INFINITY, -1, 0, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    test(`options rejects ${key} = ${String(value)}`, () => {
      assert.throws(
        () => createWakeServer({ ...base, [key]: value } as WakeServerOptions),
        code("invalid_option"),
      );
    });
  }
  test(`options accepts ${key} = 1 beside its rejected 0`, () => {
    // approvalTtlMs must also leave 30 s for the WebAuthn timeout, so pick a small timeout.
    createWakeServer({ ...base, webauthnTimeoutMs: 1, approvalTtlMs: 30_001, [key]: key === "approvalTtlMs" ? 30_001 : 1 });
  });
}

test("webauthnTimeoutMs may be at most approvalTtlMs - 30 s", () => {
  createWakeServer({ ...base, approvalTtlMs: 300_000, webauthnTimeoutMs: 270_000 });
  assert.throws(() => createWakeServer({ ...base, approvalTtlMs: 299_999, webauthnTimeoutMs: 270_000 }), code("invalid_option"));
  createWakeServer({ ...base, approvalTtlMs: 299_999, webauthnTimeoutMs: 269_999 });
  assert.throws(() => createWakeServer({ ...base, approvalTtlMs: 30_000 }), code("invalid_option"));
});

for (const [name, taOrigins] of [
  ["empty", []],
  ["not an array", ORIGIN],
  ["not strings", [3]],
  ["with a path", [`${ORIGIN}/path`]],
  ["with a trailing slash", [`${ORIGIN}/`]],
  ["opaque", ["file:///a"]],
] as const) {
  test(`options rejects taOrigins ${name}`, () => {
    assert.throws(() => createWakeServer({ ...base, taOrigins } as unknown as WakeServerOptions), code("invalid_option"));
  });
}

test("options accepts explicit taOrigins and the store must provide the TA methods", () => {
  createWakeServer({ ...base, taOrigins: ["https://approve.example.com"] });
  assert.throws(
    () => createWakeServer({ ...base, store: { ...Object.create(null), createExchange() {} } as never }),
    code("invalid_option"),
  );
});

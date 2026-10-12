// Regression tests for credential byte ownership in stored epoch keys.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { SessionId } from "@wake-protocol/core";
import type { EpochKeys, LoginCommit, MemoryWakeStore } from "../src/index.ts";
import { fixture, login } from "./helpers.ts";
import { completeKr, krClient, prepareKr } from "./kr-helpers.ts";
import { approve, challenge, newOperation, prepareTa, verifyKrCommitted } from "./ta-helpers.ts";

async function checkReturnedKeys(
  store: MemoryWakeStore,
  sessionId: SessionId,
  credentialId: Uint8Array,
  hasPrevious: boolean,
): Promise<void> {
  const state = await store.getSession(sessionId.toUint8Array());
  assert.ok(state?.currentKeys);
  assert.deepEqual(state.currentKeys.credentialId, credentialId);
  state.currentKeys.credentialId.fill(0);
  if (hasPrevious) {
    assert.ok(state.prevKeys);
    assert.deepEqual(state.prevKeys.credentialId, credentialId);
    state.prevKeys.credentialId.fill(1);
  }
  const unchanged = await store.getSession(sessionId.toUint8Array());
  assert.deepEqual(unchanged?.currentKeys?.credentialId, credentialId);
  if (hasPrevious) {
    assert.deepEqual(unchanged?.prevKeys?.credentialId, credentialId);
  }
}

test("login copies epoch credential bytes from commit inputs and session views", async () => {
  const f = await fixture();
  let input: LoginCommit | undefined;
  const commit = f.store.commitLogin.bind(f.store);
  f.store.commitLogin = async value => {
    input = value;
    return commit(value);
  };
  const client = await login(f);
  const expected = f.auth.credential.credentialId.slice();
  assert.ok(input?.session.currentKeys);
  input.session.currentKeys.credentialId.fill(2);
  await checkReturnedKeys(f.store, client.sessionId, expected, false);
});

for (const ceremony of ["KR", "TA+KR"] as const) {
  test(`${ceremony} copies epoch credential bytes from commit inputs and current/previous session views`, async () => {
    const f = await fixture();
    const client = krClient(await login(f));
    const expected = f.auth.credential.credentialId.slice();
    let inputKeys: EpochKeys | undefined;
    if (ceremony === "KR") {
      const commit = f.store.commitRekey.bind(f.store);
      f.store.commitRekey = async value => {
        inputKeys = value.currentKeys;
        return commit(value);
      };
      await completeKr(f, client, await prepareKr(f, client));
    } else {
      const commit = f.store.commitApproval.bind(f.store);
      f.store.commitApproval = async value => {
        inputKeys = value.kr?.rekey?.currentKeys;
        return commit(value);
      };
      const operation = await newOperation(f);
      const ch = await challenge(f, client, operation.operationId, true);
      const prepared = await prepareTa(f, client, ch, operation.operationId);
      const result = await approve(f, client, prepared);
      await verifyKrCommitted(prepared, result.json.kr as Record<string, unknown>);
    }
    assert.ok(inputKeys);
    inputKeys.credentialId.fill(2);
    await checkReturnedKeys(f.store, client.sessionId, expected, true);
  });
}

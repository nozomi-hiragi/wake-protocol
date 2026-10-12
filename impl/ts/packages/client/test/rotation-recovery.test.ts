// Spec §9.6, §10.8: unreadable completion outcomes must recover or require reauthentication.
import assert from "node:assert/strict";
import { test } from "node:test";
import { utf8ToBytes } from "@wake-protocol/codec";
import { fixture, hasCode, jsonResponse } from "./fixture.ts";

const login = { mode: "discoverable" } as const;

for (const kind of ["KR", "TA+KR"] as const) {
  const context = kind === "KR" ? "wake/kr/complete" : "wake/ta/approve";
  const rotate = async (f: Awaited<ReturnType<typeof fixture>>) => {
    if (kind === "KR") {
      return (await f.client.rekey()).epoch;
    }
    const op = await f.addOperation("Transfer to Alice");
    const info = await f.client.approve(op.operationId, { rekey: true });
    assert.deepEqual(info.ta, { result: "approved", status: "APPROVED" });
    assert.equal(info.kr!.result, "committed");
    return (info.kr as { epoch: number }).epoch;
  };

  for (const fault of ["ciphertext", "header", "plaintext", "error schema", "internal", "unknown code", "outer JSON"] as const) {
    for (const recovery of [true, false]) {
      test(`${kind} committed with broken ${fault}, recovery=${recovery}, never keeps the old epoch`, async () => {
        const f = await fixture();
        await f.client.login(login);
        f.upPlaintext = (h, plaintext) => {
          if (h.context !== context || h.epoch !== 0) {
            return plaintext;
          }
          const replacement = fault === "plaintext" ? "{" : fault === "error schema" ? '{"error":{"code":1}}'
            : fault === "internal" ? '{"error":{"code":"internal"}}'
            : fault === "unknown code" ? '{"error":{"code":"future_error"}}' : undefined;
          return replacement === undefined ? plaintext : utf8ToBytes(replacement);
        };
        f.upResponse = async (h, response) => {
          if (h.context !== context || h.epoch !== 0) {
            return response;
          }
          if (fault === "outer JSON") {
            return new Response('{"wakeError":"retry","wakeError":"retry"}', {
              status: 503, headers: { "Content-Type": "application/json" },
            });
          }
          if (fault === "ciphertext") {
            const bytes = new Uint8Array(await response.arrayBuffer());
            bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
            return new Response(bytes, { headers: { "Content-Type": "application/wake" } });
          }
          return response;
        };
        if (fault === "header") {
          f.headerMutate = h => {
            if (h.context === context && h.epoch === 0) {
              h.context = "different";
            }
          };
        }
        if (!recovery) {
          f.upAction = () => f.requests.at(-1)!.context === "wake/session"
            ? jsonResponse({ wakeError: "reauth" }, 401) : undefined;
          await assert.rejects(rotate(f), hasCode("reauth"));
          assert.equal(f.client.loggedIn, false);
          await assert.rejects(f.client.session(), hasCode("reauth"));
        } else {
          assert.equal(await rotate(f), 1);
          assert.equal(f.client.loggedIn, true);
          if (kind === "TA+KR") {
            assert.deepEqual(f.requests.filter(h => h.context === context).map(h => h.epoch), [0, 1]);
            assert.equal(f.taApproveBodies[0], f.taApproveBodies[1]);
          }
          assert.equal((await f.client.session()).epoch, 1);
        }
        assert.equal(f.currentEpoch, 1);
        assert.ok(f.requests.some(h => h.context === "wake/session" && h.epoch === 1));
        assert.equal(f.sleeps.length, 0);
      });
    }
  }

  for (const code of ["webauthn_failed", "conflict", "expired", "not_found", "invalid_request", "already_decided"]) {
    test(`${kind} authenticated ${code} preserves the session and current epoch`, async () => {
      const f = await fixture();
      await f.client.login(login);
      if (kind === "KR") {
        f.krCompleteError = code;
      } else {
        f.taApproveError = code;
      }
      await assert.rejects(rotate(f), hasCode(code));
      assert.equal(f.client.loggedIn, true);
      assert.equal(f.currentEpoch, 0);
      assert.ok(!f.requests.some(h => h.context === "wake/session" && h.epoch === 1));
      assert.equal((await f.client.session()).epoch, 0);
    });
  }

  test(`${kind} unexpected failure between retries recovers the sent completion`, async () => {
    const f = await fixture({ sleep: async () => { throw new TypeError("unexpected retry failure"); } });
    await f.client.login(login);
    f.upResponse = (h, response) => {
      if (h.context === context && h.epoch === 0) {
        throw new TypeError("lost committed response");
      }
      return response;
    };
    assert.equal(await rotate(f), 1);
    assert.equal((await f.client.session()).epoch, 1);
  });

  test(`${kind} unexpected clock failure after sending recovers the committed epoch`, async () => {
    let failNow = false;
    let f!: Awaited<ReturnType<typeof fixture>>;
    f = await fixture({ now: () => {
      if (failNow) {
        failNow = false;
        throw new TypeError("unexpected clock failure");
      }
      return f.localTime;
    } });
    await f.client.login(login);
    f.upResponse = (h, response) => {
      if (h.context === context && h.epoch === 0) {
        failNow = true;
      }
      return response;
    };
    assert.equal(await rotate(f), 1);
    assert.equal((await f.client.session()).epoch, 1);
  });

  for (const recovery of [true, false]) {
    test(`${kind} completion lost until its deadline, recovery=${recovery}, never keeps the old epoch`, async () => {
      const f = await fixture();
      await f.client.login(login);
      f.krStartMutate = v => { v.expiresAt = f.serverTime + 1000; };
      f.taChallengeMutate = v => { v.expiresAt = f.serverTime + 1000; };
      f.upResponse = (h, response) => {
        if (h.context === context && h.epoch === 0) {
          throw new TypeError("lost committed response");
        }
        return response;
      };
      if (recovery) {
        assert.equal(await rotate(f), 1);
        assert.equal((await f.client.session()).epoch, 1);
      } else {
        f.upAction = () => f.requests.at(-1)!.context === "wake/session"
          ? jsonResponse({ wakeError: "reauth" }, 401) : undefined;
        await assert.rejects(rotate(f), hasCode("reauth"));
        assert.equal(f.client.loggedIn, false);
      }
      assert.equal(f.currentEpoch, 1);
      assert.equal(f.sleeps.reduce((sum, ms) => sum + ms, 0), 1000);
    });
  }

}

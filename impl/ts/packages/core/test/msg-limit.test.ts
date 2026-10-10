// §8.7 plaintext length limit: seal, parseWire and open enforce it with `too_large`.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_MAX_PLAINTEXT,
  DIR_C2S,
  WakeError,
  aesKey,
  newRequestId,
  newSessionId,
  open,
  parseWire,
  seal,
} from "../src/index.ts";

const header = () => ({
  dir: DIR_C2S,
  sessionId: newSessionId(),
  epoch: 0,
  requestId: newRequestId(),
  issuedAt: 1767225600000,
  context: "POST /api/limit",
}) as const;

const key = async () => aesKey(new Uint8Array(32).fill(7));

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof WakeError && e.code === code);
}

describe("plaintext length limit (§8.7)", () => {
  it("default limit is 1 MiB plus 64 KiB framing room", () => {
    assert.equal(DEFAULT_MAX_PLAINTEXT, 1024 * 1024 + 64 * 1024);
  });

  it("seal rejects plaintext over a custom limit with too_large", async () => {
    const k = await key();
    await expectCode(seal(k, header(), new Uint8Array(17), { maxPlaintext: 16 }), "too_large");
    await expectCode(seal(k, header(), new Uint8Array(DEFAULT_MAX_PLAINTEXT + 1)), "too_large");
  });

  it("a plaintext exactly at the limit round-trips", async () => {
    const k = await key();
    const plaintext = Uint8Array.from({ length: 16 }, (_, i) => i);
    const opts = { maxPlaintext: 16 };
    const wire = await seal(k, header(), plaintext, opts);
    const got = await open(k, wire, DIR_C2S, opts);
    assert.deepEqual(got.plaintext, plaintext);
  });

  it("parseWire and open reject a wire whose ciphertext exceeds a custom limit with too_large", async () => {
    const k = await key();
    const wire = await seal(k, header(), new Uint8Array(40));
    assert.equal(parseWire(wire).sealed.length - 16, 40);
    assert.throws(() => parseWire(wire, { maxPlaintext: 39 }), (e: unknown) => e instanceof WakeError && e.code === "too_large");
    await expectCode(open(k, wire, DIR_C2S, { maxPlaintext: 39 }), "too_large");
    // The limit is checked before decryption: a tampered tag still reports too_large.
    const tampered = Uint8Array.from(wire);
    tampered[tampered.length - 1]! ^= 1;
    await expectCode(open(k, tampered, DIR_C2S, { maxPlaintext: 39 }), "too_large");
    // Within the limit the same wire opens.
    assert.equal((await open(k, wire, DIR_C2S, { maxPlaintext: 40 })).plaintext.length, 40);
  });
});

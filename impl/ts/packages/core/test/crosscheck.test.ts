// Recomputes selected committed vectors with node:crypto, independently of src/.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createCipheriv, createECDH, createHash, createHmac, hkdfSync } from "node:crypto";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_VECTOR_DIR } from "../scripts/generate-vectors.ts";

type Vec = { name: string; input: Record<string, string | number>; expected?: Record<string, string | number>; expectedError?: string };
const load = async (suite: string): Promise<Map<string, Vec>> => {
  const file = JSON.parse(await readFile(join(DEFAULT_VECTOR_DIR, `${suite}.json`), "utf8")) as { vectors: Vec[] };
  return new Map(file.vectors.map((v) => [v.name, v]));
};

const buf = (h: string | number): Buffer => Buffer.from(String(h), "hex");
const u32 = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
/** LP over Buffers, written independently of src/encoding.ts. */
const lpNode = (...fields: Buffer[]): Buffer => Buffer.concat(fields.flatMap((f) => [u32(f.length), f]));
const ascii = (s: string): Buffer => Buffer.from(s, "ascii");

describe("independent cross-checks (node:crypto)", () => {
  it("ECDH shared secrets (leading-zero and ordinary) match node's ECDH", async () => {
    const vs = await load("ecdh");
    for (const name of ["shared-secret-leading-zero", "shared-secret-ordinary"]) {
      const v = vs.get(name)!;
      const ecdh = createECDH("prime256v1");
      ecdh.setPrivateKey(buf(v.input.privateKey!));
      const ss = ecdh.computeSecret(buf(v.input.peerPublicKey!));
      assert.equal(ss.length, 32);
      assert.equal(ss.toString("hex"), v.expected!.sharedSecret);
    }
    const zero = vs.get("shared-secret-leading-zero")!;
    assert.equal(String(zero.expected!.sharedSecret).slice(0, 2), "00");
  });

  it("HKDF keys match node's hkdfSync", async () => {
    const v = (await load("hkdf")).get("ordinary-ss")!;
    const ss = buf(v.input.ss!);
    const th = buf(v.input.th!);
    const k = (info: string) => Buffer.from(hkdfSync("sha256", ss, th, ascii(info), 32)).toString("hex");
    assert.equal(k("WAKE/1 key c2s"), v.expected!.kC2s);
    assert.equal(k("WAKE/1 key s2c"), v.expected!.kS2c);
    assert.equal(k("WAKE/1 finished c2s"), v.expected!.fkC);
    assert.equal(k("WAKE/1 finished s2c"), v.expected!.fkS);
  });

  it("transcript and webauthn challenge hashes match a hand-built LP", async () => {
    const t = (await load("transcript")).get("kx-login-basic")!;
    const i = t.input;
    const th = createHash("sha256")
      .update(
        lpNode(
          ascii("WAKE/1 kx-transcript"),
          Buffer.from([Number(i.mode)]),
          buf(i.exchangeId!),
          buf(i.sessionId!),
          u32(Number(i.epoch)),
          buf(i.prevTh!),
          buf(i.serverNonce!),
          buf(i.serverPublicKey!),
          buf(i.clientPublicKey!),
        ),
      )
      .digest("hex");
    assert.equal(th, t.expected!.th);

    const c = (await load("challenge")).get("ta+kr")!;
    const ch = createHash("sha256")
      .update(lpNode(ascii("WAKE/1 webauthn-challenge"), buf(c.input.th!), buf(c.input.ta!)))
      .digest("hex");
    assert.equal(ch, c.expected!.challenge);
  });

  it("client and server Finished MACs match a hand-built HMAC", async () => {
    const vs = await load("finished");
    const cf = vs.get("client-finished")!;
    const cfMac = createHmac("sha256", buf(cf.input.fkC!))
      .update(lpNode(ascii("WAKE/1 client finished"), buf(cf.input.th!)))
      .digest("hex");
    assert.equal(cfMac, cf.expected!.clientFinished);

    const sf = vs.get("server-finished")!;
    const i = sf.input;
    const sfMac = createHmac("sha256", buf(i.fkS!))
      .update(
        lpNode(
          ascii("WAKE/1 server finished"),
          buf(i.th!),
          buf(i.clientFinished!),
          u64be(Number(i.serverTime)),
          u64be(Number(i.absoluteExpiresAt)),
          u32(Number(i.idleTimeoutSec)),
        ),
      )
      .digest("hex");
    assert.equal(sfMac, sf.expected!.serverFinished);
  });

  it("AES-GCM seal with fixed key and IV matches node's cipher", async () => {
    const vs = await load("msg");
    const v = vs.get("c2s-seal-fixed-iv")!;
    const wire = buf(v.expected!.wire!);
    const hlen = wire.readUInt32BE(0);
    const header = wire.subarray(4, 4 + hlen);
    const cipher = createCipheriv("aes-256-gcm", buf(v.input.key!), buf(v.input.iv!));
    cipher.setAAD(header);
    const ct = Buffer.concat([cipher.update(buf(v.input.plaintext!)), cipher.final(), cipher.getAuthTag()]);
    assert.equal(ct.toString("hex"), wire.subarray(4 + hlen).toString("hex"));
  });

  it("hashInput and operationId for the spec 10.3 example match the spec text", async () => {
    const v = (await load("ta")).get("spec-10.3-example")!;
    assert.equal(v.expected!.hashInputLength, 104);
    const reconstructed = `${v.input.content}\nWAKE-TA-Nonce: ${v.input.nonce}`;
    assert.equal(v.expected!.hashInput, reconstructed);
    assert.equal(Buffer.byteLength(reconstructed, "utf8"), v.expected!.hashInputLength);
    const op = createHash("sha256").update(Buffer.from(String(v.expected!.hashInput), "utf8")).digest("hex");
    assert.equal(op, "1140095b9147435cc75d76b00be2938ebd69885f938afdcc02337c925cedfd74");
    assert.equal(v.expected!.operationId, op);
  });
});

function u64be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

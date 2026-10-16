// Spec Appendix C: offline approval bundle verification, one negative test per step.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { base64urlnopad as b64, hex } from "@scure/base";
import { ecdsaRawToDer, sha256 } from "@wake-protocol/crypto";
import {
  Bytes,
  WakeError,
  asApprovalId,
  asApprovalNonce,
  asRekeyTranscriptHash,
  asSessionId,
  asTaNonce,
  hashInput,
  operationId,
  taBinding,
  taChallenge,
  taKrChallenge,
  verifyApprovalBundle,
} from "../src/index.ts";

const enc = new TextEncoder();
const ORIGIN = "https://example.com";
const RP_ID = "example.com";
const CONTENT = "Transfer\\nTo: Alice\\nAmount: 10000 JPY";
const nonceBytes = new Uint8Array(16).fill(0x3f);
const filled = (n: number, v: number) => new Uint8Array(n).fill(v);

const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
const other = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

interface Options {
  th?: Uint8Array | null;
  type?: string;
  origin?: string;
  extraClientData?: Record<string, unknown>;
  flags?: number;
  authDataLength?: number;
  rpId?: string;
  signWith?: CryptoKeyPair;
  challenge?: string;
}

async function build(o: Options = {}) {
  const id = await operationId(hashInput(CONTENT, asTaNonce(nonceBytes)));
  const approvalId = filled(16, 1);
  const approvalNonce = filled(32, 2);
  const sessionId = filled(32, 3);
  const ta = await taBinding({
    approvalId: asApprovalId(approvalId),
    operationId: id,
    approvalNonce: asApprovalNonce(approvalNonce),
    sessionId: asSessionId(sessionId),
  });
  const th = o.th === undefined ? null : o.th;
  const challenge = th === null ? await taChallenge(ta) : await taKrChallenge(asRekeyTranscriptHash(th), ta);
  const clientData = enc.encode(JSON.stringify({
    type: o.type ?? "webauthn.get",
    challenge: o.challenge ?? b64.encode(challenge.toUint8Array()),
    origin: o.origin ?? ORIGIN,
    crossOrigin: false,
    ...o.extraClientData,
  }));
  const authData = new Uint8Array(o.authDataLength ?? 37);
  authData.set(await sha256(enc.encode(o.rpId ?? RP_ID)), 0);
  authData[32] = o.flags ?? 0x05;
  const signed = Bytes.concat(new Bytes(authData), new Bytes(await sha256(clientData))).toUint8Array();
  const raw = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, (o.signWith ?? pair).privateKey, signed,
  ));
  return {
    format: "WAKE/1 ta-bundle",
    rpId: RP_ID,
    operationId: hex.encode(id.toUint8Array()),
    content: CONTENT,
    nonce: hex.encode(nonceBytes),
    approval: {
      approvalId: b64.encode(approvalId),
      approvalNonce: b64.encode(approvalNonce),
      sessionId: b64.encode(sessionId),
      th: th === null ? null : b64.encode(th),
      credentialPublicKey: b64.encode(spki),
      authenticatorData: b64.encode(authData),
      clientDataJSON: b64.encode(clientData),
      signature: b64.encode(ecdsaRawToDer(raw)),
    },
  };
}

type Bundle = Awaited<ReturnType<typeof build>>;

async function code(bundle: unknown, origins: readonly string[] = [ORIGIN], rpId = RP_ID): Promise<string | undefined> {
  try {
    await verifyApprovalBundle(bundle, { rpId, origins });
  } catch (e) {
    if (e instanceof WakeError) {
      return e.code;
    }
    throw e;
  }
  return undefined;
}

const clone = (b: Bundle): Bundle => structuredClone(b);

describe("approval bundle", () => {
  it("accepts a TA bundle and a TA+KR bundle", async () => {
    assert.equal(await verifyApprovalBundle(await build(), { rpId: RP_ID, origins: [ORIGIN] }), true);
    assert.equal(await verifyApprovalBundle(await build({ th: filled(32, 9) }), { rpId: RP_ID, origins: [ORIGIN] }), true);
  });

  it("accepts JSON text and UTF-8 bytes", async () => {
    const text = JSON.stringify(await build());
    assert.equal(await code(text), undefined);
    assert.equal(await code(enc.encode(text)), undefined);
  });

  it("rejects malformed containers and members", async () => {
    assert.equal(await code(null), "invalid_bundle");
    assert.equal(await code([]), "invalid_bundle");
    assert.equal(await code("not json"), "invalid_bundle");
    assert.equal(await code(enc.encode("[]")), "invalid_bundle");
    assert.equal(await code('{"a":1,"a":2}'), "invalid_bundle");
    const wrongFormat = clone(await build());
    wrongFormat.format = "WAKE/2 ta-bundle";
    assert.equal(await code(wrongFormat), "invalid_bundle");
    const noApproval = { ...await build(), approval: null };
    assert.equal(await code(noApproval), "invalid_bundle");
    const emptyRp = clone(await build());
    emptyRp.rpId = "";
    assert.equal(await code(emptyRp), "invalid_bundle");
  });

  it("step 1: content profile", async () => {
    for (const content of ["", " leading", "trailing　", "tab\there", "é"]) {
      const b = clone(await build());
      b.content = content;
      assert.equal(await code(b), "invalid_content", JSON.stringify(content));
    }
  });

  it("step 2: operationId must match content and nonce, in strict hex", async () => {
    const wrongNonce = clone(await build());
    wrongNonce.nonce = hex.encode(filled(16, 0x40));
    assert.equal(await code(wrongNonce), "bundle_operation_mismatch");
    const wrongContent = clone(await build());
    wrongContent.content += "!";
    assert.equal(await code(wrongContent), "bundle_operation_mismatch");
    const upper = clone(await build());
    upper.operationId = upper.operationId.toUpperCase();
    assert.equal(await code(upper), "invalid_bundle");
    const shortId = clone(await build());
    shortId.operationId = shortId.operationId.slice(1);
    assert.equal(await code(shortId), "invalid_bundle");
    const upperNonce = clone(await build());
    upperNonce.nonce = upperNonce.nonce.toUpperCase().replace(/3F/g, "3F");
    assert.equal(await code(upperNonce), "invalid_bundle");
    const shortNonce = clone(await build());
    shortNonce.nonce = shortNonce.nonce.slice(2);
    assert.equal(await code(shortNonce), "invalid_bundle");
  });

  it("step 3: ta inputs and th select the challenge", async () => {
    for (const key of ["approvalId", "approvalNonce", "sessionId"] as const) {
      const b = clone(await build());
      const bytes = b64.decode(b.approval[key]);
      bytes[0] = bytes[0]! ^ 1;
      b.approval[key] = b64.encode(bytes);
      assert.equal(await code(b), "bundle_challenge_mismatch", key);
    }
    const wrongLength = clone(await build());
    wrongLength.approval.approvalId = b64.encode(filled(15, 1));
    assert.equal(await code(wrongLength), "invalid_bundle");
    // The bundle claims TA only, but the signed challenge covers th.
    const signedWithTh = clone(await build({ th: filled(32, 9) }));
    signedWithTh.approval.th = null;
    assert.equal(await code(signedWithTh), "bundle_challenge_mismatch");
    const signedWithoutTh = clone(await build());
    signedWithoutTh.approval.th = b64.encode(filled(32, 9));
    assert.equal(await code(signedWithoutTh), "bundle_challenge_mismatch");
    const otherTh = clone(await build({ th: filled(32, 9) }));
    otherTh.approval.th = b64.encode(filled(32, 8));
    assert.equal(await code(otherTh), "bundle_challenge_mismatch");
    const shortTh = clone(await build({ th: filled(32, 9) }));
    shortTh.approval.th = b64.encode(filled(31, 9));
    assert.equal(await code(shortTh), "invalid_bundle");
  });

  it("step 4: clientDataJSON type, challenge and origin", async () => {
    assert.equal(await code(await build({ type: "webauthn.create" })), "bundle_client_data_invalid");
    assert.equal(await code(await build({ challenge: b64.encode(filled(32, 7)) })), "bundle_challenge_mismatch");
    // A non-canonical encoding of the right challenge is rejected.
    const good = await build();
    const cd = JSON.parse(new TextDecoder().decode(b64.decode(good.approval.clientDataJSON))) as { challenge: string };
    const padded = await build({ challenge: `${cd.challenge}=` });
    assert.equal(await code(padded), "bundle_challenge_mismatch");
    assert.equal(await code(await build({ origin: "https://evil.example" })), "bundle_origin_invalid");
    assert.equal(await code(await build(), ["https://other.example"]), "bundle_origin_invalid");
    assert.equal(await code(await build(), []), "bundle_origin_invalid");
    assert.equal(await code(await build(), ["https://other.example", ORIGIN]), undefined);
    assert.equal(await code(await build({ extraClientData: { crossOrigin: true } })), "bundle_origin_invalid");
    assert.equal(await code(await build({ extraClientData: { topOrigin: ORIGIN } })), "bundle_origin_invalid");
    const garbage = clone(await build());
    garbage.approval.clientDataJSON = b64.encode(enc.encode("[1]"));
    assert.equal(await code(garbage), "bundle_client_data_invalid");
  });

  it("step 4: authenticatorData rpIdHash and flags", async () => {
    assert.equal(await code(await build({ rpId: "evil.example" })), "bundle_rp_id_mismatch");
    // The bundle claims another rpId and its rpIdHash matches that claim: only the caller's rpId counts.
    const claimed = clone(await build({ rpId: "evil.example" }));
    claimed.rpId = "evil.example";
    assert.equal(await code(claimed), "bundle_rp_id_mismatch");
    assert.equal(await code(claimed, [ORIGIN], "evil.example"), undefined);
    assert.equal(await code(await build(), [ORIGIN], "evil.example"), "bundle_rp_id_mismatch");
    assert.equal(await code(await build(), [ORIGIN], ""), "invalid_option");
    assert.equal(await code(await build({ flags: 0x01 })), "bundle_authenticator_data_invalid");
    assert.equal(await code(await build({ flags: 0x04 })), "bundle_authenticator_data_invalid");
    assert.equal(await code(await build({ flags: 0x00 })), "bundle_authenticator_data_invalid");
    assert.equal(await code(await build({ flags: 0x45 })), "bundle_authenticator_data_invalid");
    assert.equal(await code(await build({ flags: 0x95 })), "bundle_authenticator_data_invalid");
    assert.equal(await code(await build({ flags: 0x15 })), "bundle_authenticator_data_invalid");
    assert.equal(await code(await build({ flags: 0x1d })), undefined);
    const short = clone(await build());
    short.approval.authenticatorData = b64.encode(b64.decode(short.approval.authenticatorData).slice(0, 36));
    assert.equal(await code(short), "bundle_authenticator_data_invalid");
  });

  it("step 5: signature and credential public key", async () => {
    assert.equal(await code(await build({ signWith: other })), "bundle_signature_invalid");
    const flipped = clone(await build());
    const sig = b64.decode(flipped.approval.signature);
    sig[sig.length - 1] = sig[sig.length - 1]! ^ 1;
    flipped.approval.signature = b64.encode(sig);
    assert.equal(await code(flipped), "bundle_signature_invalid");
    const notDer = clone(await build());
    notDer.approval.signature = b64.encode(filled(64, 1));
    assert.equal(await code(notDer), "bundle_signature_invalid");
    const badKey = clone(await build());
    badKey.approval.credentialPublicKey = b64.encode(filled(10, 1));
    assert.equal(await code(badKey), "bundle_public_key_invalid");
    const coseLike = clone(await build());
    coseLike.approval.credentialPublicKey = "!!";
    assert.equal(await code(coseLike), "bundle_public_key_invalid");
    // The data were signed after tampering with clientDataJSON: the signature no longer covers it.
    const tampered = clone(await build());
    const cd = JSON.parse(new TextDecoder().decode(b64.decode(tampered.approval.clientDataJSON))) as Record<string, unknown>;
    cd.extra = 1;
    tampered.approval.clientDataJSON = b64.encode(enc.encode(JSON.stringify(cd)));
    assert.equal(await code(tampered), "bundle_signature_invalid");
  });
});

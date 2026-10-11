// Demo registration (outside WAKE): minimal WebAuthn create() verification.
import assert from "node:assert/strict";
import { test } from "node:test";
import { base64urlnopad } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { sha256 } from "@wake-protocol/crypto";
import { createDemoApp } from "../src/app.ts";

const RP = "localhost";
const ORIGIN = "http://localhost:8787";
const encode = base64urlnopad.encode;

interface Tamper {
  type?: string;
  origin?: string;
  challenge?: string;
  rpId?: string;
  flags?: number;
  alg?: number;
  spki?: Uint8Array;
  rawIdSwap?: boolean;
  cutAuthData?: boolean;
  clientDataJSON?: string;
}

async function post(app: ReturnType<typeof createDemoApp>["app"], path: string, body: unknown) {
  return app.fetch(new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  }));
}

async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { pair, spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)) };
}

async function credentialFor(options: { challenge: string; }, key: Awaited<ReturnType<typeof newKey>>, tamper: Tamper = {}) {
  const rawId = crypto.getRandomValues(new Uint8Array(32));
  const clientData = tamper.clientDataJSON ?? JSON.stringify({
    type: tamper.type ?? "webauthn.create",
    challenge: tamper.challenge ?? options.challenge,
    origin: tamper.origin ?? ORIGIN,
  });
  const header = new Uint8Array(55);
  header.set(await sha256(utf8ToBytes(tamper.rpId ?? RP)));
  header[32] = tamper.flags ?? 0x45;
  new DataView(header.buffer).setUint32(33, 0, false);
  header[53] = rawId.length >> 8;
  header[54] = rawId.length & 0xff;
  const cose = new Uint8Array(77);
  let authData = new Uint8Array([...header, ...(tamper.rawIdSwap ? crypto.getRandomValues(new Uint8Array(32)) : rawId), ...cose]);
  if (tamper.cutAuthData) {
    authData = authData.slice(0, 40);
  }
  return {
    id: encode(rawId),
    rawId: encode(rawId),
    type: "public-key",
    response: {
      clientDataJSON: encode(utf8ToBytes(clientData)),
      authenticatorData: encode(authData),
      publicKey: encode(tamper.spki ?? key.spki),
      publicKeyAlgorithm: tamper.alg ?? -7,
      transports: ["internal"],
    },
  };
}

async function register(tamper: Tamper = {}, name = "alice") {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const optionsResponse = await post(demo.app, "/register/options", { username: name });
  assert.equal(optionsResponse.status, 200);
  const options = await optionsResponse.json() as { challenge: string; };
  const key = await newKey();
  const credential = await credentialFor(options, key, tamper);
  const result = await post(demo.app, "/register/verify", { username: name, credential });
  return { demo, options, key, credential, result, name };
}

test("registration options have the required shape", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const response = await post(demo.app, "/register/options", { username: "alice" });
  assert.equal(response.status, 200);
  const options = await response.json() as Record<string, any>;
  assert.equal(base64urlnopad.decode(options.challenge).length, 32);
  assert.equal(base64urlnopad.decode(options.user.id).length, 16);
  assert.equal(options.user.name, "alice");
  assert.equal(options.rp.id, RP);
  assert.deepEqual(options.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
  assert.deepEqual(options.authenticatorSelection, { residentKey: "required", userVerification: "required" });
  assert.equal(options.attestation, "none");
});

test("a valid registration is stored and usable for WAKE login", async () => {
  const { demo, result, credential } = await register();
  assert.equal(result.status, 200);
  const stored = await demo.credentials.getCredential(base64urlnopad.decode(credential.rawId));
  assert.ok(stored);
  assert.equal(stored.status, "active");
  assert.equal(stored.algorithm, -7);
  assert.equal(stored.signCount, 0);
  assert.equal(stored.backupEligible, false);
  assert.ok(await demo.credentials.findUserByUsername("alice"));
});

test("the BE flag is stored", async () => {
  const { demo, result, credential } = await register({ flags: 0x4d });
  assert.equal(result.status, 200);
  const stored = await demo.credentials.getCredential(base64urlnopad.decode(credential.rawId));
  assert.equal(stored?.backupEligible, true);
});

const rejected: [string, Tamper][] = [
  ["wrong clientData type", { type: "webauthn.get" }],
  ["wrong origin", { origin: "http://localhost:9999" }],
  ["wrong challenge", { challenge: encode(new Uint8Array(32)) }],
  ["wrong rpId hash", { rpId: "example.com" }],
  ["missing UP", { flags: 0x44 }],
  ["missing UV", { flags: 0x41 }],
  ["missing AT", { flags: 0x05 }],
  ["BS without BE", { flags: 0x55 }],
  ["wrong algorithm", { alg: -257 }],
  ["authData credential id differs from rawId", { rawIdSwap: true }],
  ["truncated authData", { cutAuthData: true }],
  ["not a P-256 SPKI", { spki: new Uint8Array(91) }],
  ["duplicate JSON key in clientData", {
    clientDataJSON: `{"type":"webauthn.create","type":"webauthn.create","challenge":"x","origin":"${ORIGIN}"}`,
  }],
];

for (const [name, tamper] of rejected) {
  test(`registration rejects: ${name}`, async () => {
    const { demo, result, credential } = await register(tamper);
    assert.equal(result.status, 400);
    assert.equal(await demo.credentials.getCredential(base64urlnopad.decode(credential.rawId)), null);
  });
}

test("the registration challenge is single use", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const options = await (await post(demo.app, "/register/options", { username: "alice" })).json() as { challenge: string; };
  const key = await newKey();
  const credential = await credentialFor(options, key);
  assert.equal((await post(demo.app, "/register/verify", { username: "alice", credential })).status, 200);
  const replay = await post(demo.app, "/register/verify", { username: "alice", credential });
  assert.notEqual(replay.status, 200);
});

test("a failed verification also consumes the challenge", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const options = await (await post(demo.app, "/register/options", { username: "alice" })).json() as { challenge: string; };
  const key = await newKey();
  const bad = await credentialFor(options, key, { origin: "http://evil.example" });
  assert.equal((await post(demo.app, "/register/verify", { username: "alice", credential: bad })).status, 400);
  const good = await credentialFor(options, key);
  assert.equal((await post(demo.app, "/register/verify", { username: "alice", credential: good })).status, 400);
});

test("the registration challenge expires after five minutes (both sides)", async () => {
  for (const [elapsed, status] of [[299_999, 200], [300_000, 400]] as const) {
    const clock = { now: 1_000_000 };
    const demo = createDemoApp({ rpId: RP, origin: ORIGIN, now: () => clock.now });
    const options = await (await post(demo.app, "/register/options", { username: "alice" })).json() as { challenge: string; };
    const credential = await credentialFor(options, await newKey());
    clock.now += elapsed;
    assert.equal((await post(demo.app, "/register/verify", { username: "alice", credential })).status, status);
  }
});

test("a duplicate username is rejected with 409", async () => {
  const { demo } = await register();
  const again = await post(demo.app, "/register/options", { username: "alice" });
  assert.equal(again.status, 409);
});

test("verify without options, or with a bad body, is a 400", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  assert.equal((await post(demo.app, "/register/verify", { username: "ghost", credential: {} })).status, 400);
  assert.equal((await post(demo.app, "/register/options", "not json")).status, 400);
  assert.equal((await post(demo.app, "/register/options", { username: "" })).status, 400);
  assert.equal((await post(demo.app, "/register/options", '{"username":"a","username":"b"}')).status, 400);
});


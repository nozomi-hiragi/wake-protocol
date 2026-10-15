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
  spki?: Uint8Array | "other";
  rawIdSwap?: boolean;
  rawId?: Uint8Array;
  coseSpki?: Uint8Array | "other";
  cutAuthData?: boolean;
  clientDataJSON?: string | ((challenge: string) => string);
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

async function credentialFor(options: { challenge: string; }, key: Awaited<ReturnType<typeof newKey>>, input: Tamper = {}) {
  const other = input.spki === "other" || input.coseSpki === "other" ? (await newKey()).spki : undefined;
  const tamper = {
    ...input,
    spki: input.spki === "other" ? other : input.spki,
    coseSpki: input.coseSpki === "other" ? other : input.coseSpki,
  };
  const rawId = tamper.rawId ?? crypto.getRandomValues(new Uint8Array(32));
  const clientData = typeof tamper.clientDataJSON === "function" ?
    tamper.clientDataJSON(options.challenge) :
    tamper.clientDataJSON ?? JSON.stringify({
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
  // Not a full CBOR encoding: map header plus the EC2 / ES256 / P-256 entries and the coordinates.
  const point = (tamper.coseSpki ?? key.spki).slice(-64);
  const cose = new Uint8Array([
    0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
    0x21, 0x58, 0x20, ...point.subarray(0, 32),
    0x22, 0x58, 0x20, ...point.subarray(32),
  ]);
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
  ["SPKI differs from the attested COSE_Key", { spki: "other" }],
  ["COSE_Key coordinates differ from the SPKI", { coseSpki: "other" }],
  ["not a P-256 SPKI", { spki: new Uint8Array(91) }],
  ["duplicate JSON key in clientData", {
    clientDataJSON: (challenge: string) => `{"type":"webauthn.create","type":"webauthn.create","challenge":"${challenge}","origin":"${ORIGIN}"}`,
  }],
  ["unsafe integer in clientData", {
    clientDataJSON: (challenge: string) => `{"type":"webauthn.create","challenge":"${challenge}","origin":"${ORIGIN}","unsafe":1e300}`,
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
  assert.equal((await post(demo.app, "/register/options", '{"username":"a","unsafe":1e300}')).status, 400);
});


test("a rawId that is already registered is rejected with 409 and the original credential is kept", async () => {
  const first = await register({}, "alice");
  const rawId = base64urlnopad.decode(first.credential.rawId);
  const optionsResponse = await post(first.demo.app, "/register/options", { username: "mallory" });
  const options = await optionsResponse.json() as { challenge: string; };
  const credential = await credentialFor(options, await newKey(), { rawId });
  const result = await post(first.demo.app, "/register/verify", { username: "mallory", credential });
  assert.equal(result.status, 409);
  assert.deepEqual(await result.json(), { error: "credential_exists" });
  const stored = await first.demo.credentials.getCredential(rawId);
  assert.equal(stored?.userId, (await first.demo.credentials.findUserByUsername("alice"))?.userId);
  assert.equal(await first.demo.credentials.findUserByUsername("mallory"), null);
});

test("a pending registration is not replaced, and an expired one is dropped", async () => {
  const clock = { now: 1_000_000 };
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN, now: () => clock.now });
  assert.equal((await post(demo.app, "/register/options", { username: "alice" })).status, 200);
  const second = await post(demo.app, "/register/options", { username: "alice" });
  assert.equal(second.status, 409);
  assert.deepEqual(await second.json(), { error: "registration_pending" });
  clock.now += 299_999;
  assert.equal((await post(demo.app, "/register/options", { username: "alice" })).status, 409);
  clock.now += 1;
  assert.equal((await post(demo.app, "/register/options", { username: "alice" })).status, 200);
});

test("requests for another Host are rejected with 421 on every route", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  for (const [method, path] of [["GET", "/"], ["GET", "/app.js"], ["POST", "/register/options"], ["POST", "/auth/start"], ["POST", "/wake/up"]]) {
    const response = await demo.app.fetch(new Request(`http://evil.example${path}`, { method }));
    assert.equal(response.status, 421, path);
  }
  assert.equal((await demo.app.fetch(new Request(`${ORIGIN}/`))).status, 200);
});

test("every response carries the CSP header", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const csp = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
  for (const request of [
    new Request(`${ORIGIN}/`),
    new Request(`${ORIGIN}/app.css`),
    new Request(`${ORIGIN}/missing`),
    new Request(`${ORIGIN}/register/options`, { method: "POST", body: "{}" }),
    new Request("http://evil.example/"),
  ]) {
    assert.equal((await demo.app.fetch(request)).headers.get("content-security-policy"), csp, request.url);
  }
});

test("the page has no inline script or style", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const html = await (await demo.app.fetch(new Request(`${ORIGIN}/`))).text();
  assert.doesNotMatch(html, /<style|<script(?![^>]*\bsrc=)| style=/);
});

test("the body limit counts bytes: 64 KiB passes the limit, 64 KiB + 1 is a 400", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const body = (bytes: number) => {
    const prefix = '{"username":"a","pad":"';
    const suffix = '"}';
    return prefix + "x".repeat(bytes - prefix.length - suffix.length) + suffix;
  };
  assert.equal((await post(demo.app, "/register/options", body(65_536))).status, 200);
  assert.equal((await post(demo.app, "/register/options", body(65_537))).status, 400);
  // 3-byte characters: the character count is under the limit, the byte count is over.
  const wide = '{"username":"b","pad":"' + "\u20ac".repeat(21_846) + '"}';
  assert.ok(wide.length < 65_536 && new TextEncoder().encode(wide).length > 65_536);
  assert.equal((await post(demo.app, "/register/options", wide)).status, 400);
});

test("a body that is not valid UTF-8 is a 400", async () => {
  const demo = createDemoApp({ rpId: RP, origin: ORIGIN });
  const bytes = new Uint8Array([...utf8ToBytes('{"username":"a","pad":"'), 0xff, ...utf8ToBytes('"}')]);
  const response = await demo.app.fetch(new Request(`${ORIGIN}/register/options`, { method: "POST", body: bytes }));
  assert.equal(response.status, 400);
});

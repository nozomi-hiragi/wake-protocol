// Tests for WAKE-ET on the server (spec §11).
import assert from "node:assert/strict";
import { test } from "node:test";
import { asciiToBytes, bytesToUtf8, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import {
  Bytes,
  DIR_S2C,
  ET_BODY_MIN,
  ET_BODY_MAX,
  ET_REQUEST_MAX_ENCODED,
  WakeError,
  decodeEtResponse,
  encodeEtRequest,
  open,
  parseWire,
} from "@wake-protocol/core";
import type { EtHeader } from "@wake-protocol/core";
import { createWakeServer, MemoryCredentialStore } from "../src/index.ts";
import type { EtAuth, EtHandler, EtHandlerRequest, EtHandlerResponse } from "../src/index.ts";
import { insertSession, SoftAuthenticator } from "../src/testing.ts";
import { encode, expectError, fixture, login, opened, ORIGIN, response, RP, wire } from "./helpers.ts";
import type { Fixture, Login } from "./helpers.ts";
import { completeKr, krClient, krWire, prepareKr } from "./kr-helpers.ts";

interface Seen {
  req?: EtHandlerRequest;
  auth?: EtAuth;
}

function echoHandler(seen: Seen): EtHandler {
  return (req, auth) => {
    seen.req = req;
    seen.auth = auth;
    return {
      status: 201,
      headers: [["content-type", "text/plain"], ["Set-Cookie", "a=1"], ["set-cookie", "b=2"]],
      body: req.body,
    };
  };
}

async function sendTransport(f: Fixture, bytes: Bytes | Uint8Array): Promise<Response> {
  return response(
    await f.server.handle(
      new Request(`${ORIGIN}/wake/transport`, {
        method: "POST",
        headers: { "content-type": "application/wake" },
        body: new Uint8Array(bytes instanceof Bytes ? bytes.toUint8Array() : bytes),
      }),
    ),
  );
}

function request(
  method: string,
  url: string,
  headers: EtHeader[] = [],
  body = new Uint8Array(),
): Bytes {
  return encodeEtRequest({ method, url, headers, body: new Bytes(body) });
}

/** Builds an EtRequest without any validation, to exercise the receiving side. */
function rawRequest(method: string, url: string, headers: Uint8Array[], body: Uint8Array): Uint8Array {
  return encodeU32LengthPrefixed(
    asciiToBytes("WAKE/1 et-req"),
    asciiToBytes(method),
    asciiToBytes(url),
    encodeU32LengthPrefixed(...headers),
    body,
  );
}

/** Opens an ET response; unlike the shared helper it does not assume a JSON plaintext. */
async function openRaw(l: Login, res: Response) {
  assert.equal(res.status, 200, await res.clone().text());
  assert.match(res.headers.get("content-type")!, /application\/wake/);
  return open(l.s2c, new Uint8Array(await res.arrayBuffer()), DIR_S2C);
}

async function call(f: Fixture, l: Login, plaintext: Bytes | Uint8Array, epoch = 0) {
  const raw = plaintext instanceof Bytes ? plaintext.toUint8Array() : plaintext;
  const res = await sendTransport(f, await wire(f, l, "wake-et", raw, epoch));
  return openRaw(l, res);
}

async function callEt(f: Fixture, l: Login, plaintext: Bytes | Uint8Array, epoch = 0) {
  const out = await call(f, l, plaintext, epoch);
  assert.equal(out.header.context, "wake-et");
  return decodeEtResponse(out.plaintext);
}

function errorBody(body: Bytes): unknown {
  return JSON.parse(bytesToUtf8(body.toUint8Array()));
}

test("ET handler round-trips method, URL, headers and body, and passes the auth object", async () => {
  const seen: Seen = {};
  const f = await fixture({ etHandler: echoHandler(seen) });
  const l = await login(f);
  const body = new Uint8Array([0, 1, 2, 255]);
  const headers: EtHeader[] = [["X-Test", "café"], ["x-test", "two"]];
  const plain = await wire(f, l, "wake-et", request("POST", "/echo?a=1&b=%2F", headers, body).toUint8Array());
  const out = await openRaw(l, await sendTransport(f, plain));
  const res = decodeEtResponse(out.plaintext);
  assert.equal(res.status, 201);
  assert.deepEqual(res.headers, [["content-type", "text/plain"], ["Set-Cookie", "a=1"], ["set-cookie", "b=2"]]);
  assert.deepEqual([...res.body.toUint8Array()], [0, 1, 2, 255]);
  assert.equal(seen.req?.method, "POST");
  assert.equal(seen.req?.url, "/echo?a=1&b=%2F");
  assert.deepEqual(seen.req?.headers, headers);
  assert.deepEqual([...seen.req!.body], [0, 1, 2, 255]);
  const requestHeader = parseWire(plain).header;
  assert.deepEqual(seen.auth, {
    userId: "u1",
    sessionId: l.info.sessionId,
    epoch: 0,
    credentialId: encode(f.auth.credential.credentialId),
    authTime: f.clock.now,
    requestId: encode(requestHeader.requestId.toUint8Array()),
  });
  assert.equal(out.header.context, "wake-et");
  assert.ok(out.header.requestId.equals(requestHeader.requestId));
});

test("ET passes the authTime and credential of the request's epoch during the grace period", async () => {
  const seen: Seen = {};
  const f = await fixture({ etHandler: echoHandler(seen) });
  const old = krClient(await login(f));
  const loginTime = f.clock.now;
  const spare = await SoftAuthenticator.create({ rpId: RP, origin: ORIGIN, userId: "u1" });
  f.credentials.setCredential(spare.credential);
  f.clock.now += 10_000;
  const rekeyTime = f.clock.now;
  const prepared = await prepareKr(f, old, {}, spare);
  await completeKr(f, old, prepared);
  const current = prepared.next;
  f.clock.now += 1_000;
  const plaintext = request("POST", "/echo").toUint8Array();
  const status = async (client: typeof old) => (await sendTransport(f, await krWire(f, client, "wake-et", plaintext))).status;
  assert.equal(await status(old), 200);
  assert.equal(seen.auth?.epoch, 0);
  assert.equal(seen.auth?.authTime, loginTime);
  assert.equal(seen.auth?.credentialId, encode(f.auth.credential.credentialId));
  assert.equal(await status(current), 200);
  assert.equal(seen.auth?.epoch, 1);
  assert.equal(seen.auth?.authTime, rekeyTime);
  assert.equal(seen.auth?.credentialId, encode(spare.credential.credentialId));
});

test("ET passes every well-formed URL and method unchanged to its handler", async () => {
  const seen: Seen = {};
  const f = await fixture({ etHandler: echoHandler(seen) });
  const l = await login(f);
  for (const url of ["/a", "", "a/b", "wake://app/members?id=1", "https://h/a/../b?x=%2f", "//host/x", "/wake/up"]) {
    for (const method of ["GET", "head", "x-Custom"]) {
      assert.equal((await callEt(f, l, request(method, url))).status, 201);
      assert.equal(seen.req?.method, method);
      assert.equal(seen.req?.url, url);
    }
  }
});

test("ET without a handler is disabled and returns null for every HTTP method", async () => {
  const f = await fixture();
  for (const method of ["GET", "POST"]) {
    assert.equal(await f.server.handle(new Request(`${ORIGIN}/wake/transport`, { method })), null);
  }
});

test("ET malformed requests map to 400 with the matching code", async () => {
  const f = await fixture({ etHandler: echoHandler({}) });
  const l = await login(f);
  const cases: [string, Uint8Array, string][] = [
    ["not LP", new Uint8Array([1, 2, 3]), "invalid_request"],
    ["empty", new Uint8Array(), "invalid_request"],
    [
      "wrong label",
      encodeU32LengthPrefixed(
        asciiToBytes("WAKE/1 et-res"),
        asciiToBytes("GET"),
        asciiToBytes("/echo"),
        new Uint8Array(),
        new Uint8Array(),
      ),
      "invalid_request",
    ],
    ["odd header fields", rawRequest("GET", "/echo", [asciiToBytes("a")], new Uint8Array()), "invalid_request"],
    ["bad method", rawRequest("TRACE", "/echo", [], new Uint8Array()), "invalid_method"],
    ["non-token method", rawRequest("bad method", "/echo", [], new Uint8Array()), "invalid_method"],
    ["invalid scheme", rawRequest("GET", "1a:b", [], new Uint8Array()), "invalid_url"],
    ["path with fragment", rawRequest("GET", "/a#b", [], new Uint8Array()), "invalid_url"],
    ["bad percent in path", rawRequest("GET", "/a%zz", [], new Uint8Array()), "invalid_url"],
    ["query with fragment", rawRequest("GET", "/echo?a#b", [], new Uint8Array()), "invalid_url"],
    [
      "bad header name",
      rawRequest("GET", "/echo", [asciiToBytes("bad name"), asciiToBytes("v")], new Uint8Array()),
      "invalid_header",
    ],
    ["GET body", rawRequest("get", "/echo", [], Uint8Array.of(1)), "invalid_request"],
    ["HEAD body", rawRequest("HEAD", "/echo", [], Uint8Array.of(1)), "invalid_request"],
  ];
  for (const [name, bytes, code] of cases) {
    const res = await callEt(f, l, bytes);
    assert.equal(res.status, 400, name);
    assert.deepEqual(errorBody(res.body), { error: { code } }, name);
    assert.deepEqual(res.headers, [["content-type", "application/json"]], name);
  }
});

test("ET body limit is inclusive: at the limit passes, above it is 413 too_large", async () => {
  const seen: Seen = {};
  const f = await fixture({ etHandler: echoHandler(seen), etBodyLimit: ET_BODY_MIN });
  const l = await login(f);
  const ok = await callEt(f, l, request("POST", "/echo", [], new Uint8Array(ET_BODY_MIN)));
  assert.equal(ok.status, 201);
  assert.equal(ok.body.length, ET_BODY_MIN);
  const big = await callEt(f, l, request("POST", "/echo", [], new Uint8Array(ET_BODY_MIN + 1)));
  assert.equal(big.status, 413);
  assert.deepEqual(errorBody(big.body), { error: { code: "too_large" } });
});

test("ET default body limit is the 1 MiB maximum", async () => {
  const f = await fixture({ etHandler: echoHandler({}) });
  const l = await login(f);
  assert.equal((await callEt(f, l, request("POST", "/echo", [], new Uint8Array(ET_BODY_MAX)))).status, 201);
  const over = rawRequest("POST", "/echo", [], new Uint8Array(ET_BODY_MAX + 1));
  const res = await callEt(f, l, over);
  assert.equal(res.status, 413);
});

test("ET rejects other contexts on /wake/transport and wake-et on /wake/up", async () => {
  const f = await fixture({ etHandler: echoHandler({}) });
  const l = await login(f);
  const wrong = await opened(l, await sendTransport(f, await wire(f, l, "wake/session", "{}")));
  assert.deepEqual(wrong.json, { error: { code: "invalid_context" } });
  const up = await response(
    await f.server.handle(
      new Request(`${ORIGIN}/wake/up`, {
        method: "POST",
        headers: { "content-type": "application/wake" },
        body: new Uint8Array((await wire(f, l, "wake-et", request("POST", "/echo").toUint8Array())).toUint8Array()),
      }),
    ),
  );
  assert.deepEqual((await opened(l, up)).json, { error: { code: "invalid_context" } });
});

test("ET stale requests get the plain JSON stale_request, not an EtResponse", async () => {
  const f = await fixture({ etHandler: echoHandler({}) });
  const l = await login(f);
  const limit = 300_000;
  for (const [delta, stale] of [[limit, false], [limit + 1, true], [-limit, false], [-limit - 1, true]] as const) {
    const bytes = await wire(f, l, "wake-et", request("POST", "/echo").toUint8Array(), 0, f.clock.now + delta);
    const out = await openRaw(l, await sendTransport(f, bytes));
    if (stale) {
      assert.equal(out.plaintext.toUint8Array()[0], 0x7b);
      assert.deepEqual(errorBody(out.plaintext), { error: { code: "stale_request" } });
    } else {
      assert.equal(decodeEtResponse(out.plaintext).status, 201);
    }
  }
});

test("ET handler failures return 500 internal without leaking messages", async () => {
  const secret = "SECRET-DETAIL";
  const handlers: Record<string, EtHandler> = {
    "/throw": () => { throw new Error(secret); },
    "/reject": () => Promise.reject(new WakeError("rate_limited", secret)),
    "/status": () => ({ status: 99 }),
    "/status-high": () => ({ status: 600 }),
    "/header": () => ({ status: 200, headers: [["bad name", "v"]] }),
    "/nothing": () => undefined as unknown as EtHandlerResponse,
    "/big": () => ({ status: 200, body: new Uint8Array(ET_BODY_MAX + 1) }),
    "/204": () => ({ status: 204, body: Uint8Array.of(1) }),
    "/205": () => ({ status: 205, body: Uint8Array.of(1) }),
    "/304": () => ({ status: 304, body: Uint8Array.of(1) }),
    "/ok-min": () => ({ status: 200 }),
    "/ok-max": () => ({ status: 599 }),
  };
  const f = await fixture({ etHandler: (req, auth) => handlers[req.url]!(req, auth) });
  const l = await login(f);
  for (const path of ["/throw", "/reject", "/status", "/status-high", "/header", "/nothing", "/big", "/204", "/205", "/304"]) {
    const res = await callEt(f, l, request("GET", path));
    assert.equal(res.status, 500, path);
    assert.deepEqual(errorBody(res.body), { error: { code: "internal" } }, path);
    assert.ok(!bytesToUtf8(res.body.toUint8Array()).includes(secret));
  }
  const min = await callEt(f, l, request("GET", "/ok-min"));
  assert.equal(min.status, 200);
  assert.equal(min.body.length, 0);
  assert.equal((await callEt(f, l, request("GET", "/ok-max"))).status, 599);
});

test("ET handler gets copies: mutating the request cannot affect the next call", async () => {
  let calls = 0;
  const f = await fixture({
    etHandler(req) {
      calls += 1;
      req.body[0] = 9;
      return { status: 200, body: req.body };
    },
  });
  const l = await login(f);
  const bytes = request("POST", "/m", [], new Uint8Array([1]));
  for (let i = 0; i < 2; i++) {
    assert.equal((await callEt(f, l, bytes)).body.toUint8Array()[0], 9);
  }
  assert.equal(calls, 2);
});

for (const row of [
  { epoch: 1, delta: 0, retired: false },
  { epoch: 1, delta: 1, retired: true },
  { epoch: 0, delta: 0, retired: true },
]) {
  test(`ET follows the epoch table ${JSON.stringify(row)}`, async () => {
    const seen: Seen = {};
    const f = await fixture({ etHandler: echoHandler(seen) });
    const l = await login(f);
    const old = await f.store.getSession(l.sessionId.toUint8Array());
    assert.ok(old?.currentKeys);
    const current = await login(f);
    const currentState = await f.store.getSession(current.sessionId.toUint8Array());
    assert.ok(currentState?.currentKeys);
    insertSession(f.store, {
      ...old,
      currentKeys: currentState.currentKeys,
      currentEpoch: 2,
      prevKeys: { ...old.currentKeys },
      prevValidUntil: f.clock.now,
    });
    f.clock.now += row.delta;
    const bytes = await wire(f, l, "wake-et", request("POST", "/echo").toUint8Array(), row.epoch);
    const res = await sendTransport(f, bytes);
    if (row.retired) {
      await expectError(res, 401, "epoch_retired", true);
    } else {
      const out = await openRaw(l, res);
      assert.equal(out.header.epoch, row.epoch);
      assert.equal(decodeEtResponse(out.plaintext).status, 201);
      assert.equal(seen.auth?.epoch, row.epoch);
    }
  });
}

test("ET requires an active session and the POST method", async () => {
  const f = await fixture({ etHandler: echoHandler({}) });
  const l = await login(f);
  const bytes = await wire(f, l, "wake-et", request("POST", "/echo").toUint8Array());
  const get = response(await f.server.handle(new Request(`${ORIGIN}/wake/transport`, { method: "GET" })));
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");
  assert.deepEqual(await get.json(), { wakeError: "bad_request" });
  await f.server.revokeSession(l.sessionId.toUint8Array());
  await expectError(await sendTransport(f, bytes), 401, "reauth", true);
});

test("ET rejects wrong content type and oversized or malformed wire like /wake/up", async () => {
  const f = await fixture({ etHandler: echoHandler({}) });
  const l = await login(f);
  const bytes = await wire(f, l, "wake-et", request("POST", "/echo").toUint8Array());
  const wrongType = response(
    await f.server.handle(
      new Request(`${ORIGIN}/wake/transport`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: new Uint8Array(bytes.toUint8Array()),
      }),
    ),
  );
  await expectError(wrongType, 400, "bad_request", true);
  await expectError(await sendTransport(f, new Uint8Array([1])), 400, "bad_request", true);
});

const noop: EtHandler = () => ({ status: 200 });

const baseOptions = {
  rpId: RP,
  loginOrigins: [ORIGIN],
  secret: new Uint8Array(32),
  credentials: new MemoryCredentialStore(),
};

function invalidOption(error: unknown): boolean {
  return error instanceof WakeError && error.code === "invalid_option";
}

for (const etHandler of [null, 1, "handler", {}, []]) {
  test(`ET rejects non-function etHandler ${JSON.stringify(etHandler)}`, () => {
    assert.throws(() => createWakeServer({ ...baseOptions, etHandler } as never), invalidOption);
  });
}

test("ET accepts an optional function handler", () => {
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etHandler: noop }));
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etHandler: undefined }));
});

test("etBodyLimit must be a safe integer of at least ET_BODY_MIN", () => {
  for (const value of [null, "1", NaN, Infinity, -1, 0, 0.5, ET_BODY_MIN - 1, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => createWakeServer({ ...baseOptions, etBodyLimit: value } as never), invalidOption, String(value));
  }
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etBodyLimit: ET_BODY_MIN }));
});

test("with etHandler, maxPlaintext must cover the worst-case EtRequest for the body limit (both sides)", () => {
  const etHandler = noop;
  const required = ET_REQUEST_MAX_ENCODED;
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etHandler, maxPlaintext: required }));
  assert.throws(() => createWakeServer({ ...baseOptions, etHandler, maxPlaintext: required - 1 }), invalidOption);
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etHandler, etBodyLimit: ET_BODY_MIN, maxPlaintext: required - ET_BODY_MAX + ET_BODY_MIN }));
  assert.throws(
    () => createWakeServer({ ...baseOptions, etHandler, etBodyLimit: ET_BODY_MIN, maxPlaintext: required - ET_BODY_MAX + ET_BODY_MIN - 1 }),
    invalidOption,
  );
  // Raising the limit above the default needs a larger maxPlaintext.
  assert.throws(() => createWakeServer({ ...baseOptions, etHandler, etBodyLimit: ET_BODY_MAX + 1 }), invalidOption);
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etHandler, etBodyLimit: ET_BODY_MAX + 1, maxPlaintext: required + 1 }));
  // Without a handler ET is unused and the plaintext limit is unconstrained.
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, maxPlaintext: 1 }));
});

test("the default maxPlaintext covers the worst-case EtRequest", () => {
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etHandler: noop }));
});

test("ET passes duplicate fields and cross-origin locations unchanged", async () => {
  const headers = [["Content-Type", "a"], ["content-type", "b"], ["Host", "a"], ["host", "b"],
    ["Location", "https://other.example/"], ["location", "//other.example/x"]] as const;
  let seen: readonly EtHeader[] | undefined;
  const f = await fixture({ etHandler: req => { seen = req.headers; return { status: 302, headers }; } });
  const l = await login(f);
  const res = await callEt(f, l, encodeEtRequest({ method: "GET", url: "/a", headers, body: new Bytes([]) }));
  assert.deepEqual(seen, headers);
  assert.deepEqual(res.headers, headers);
});

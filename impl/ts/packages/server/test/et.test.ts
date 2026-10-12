// Tests for WAKE-ET on the server (spec §11).
import assert from "node:assert/strict";
import { test } from "node:test";
import { asciiToBytes, bytesToUtf8, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import {
  Bytes,
  DIR_S2C,
  ET_BODY_MAX,
  ET_REQUEST_MAX_ENCODED,
  WakeError,
  decodeEtResponse,
  encodeEtRequest,
  open,
  parseWire,
} from "@wake-protocol/core";
import type { EtHeader, EtMethod } from "@wake-protocol/core";
import { createWakeServer, MemoryCredentialStore } from "../src/index.ts";
import type { EtAuth, EtRoute, EtRouteRequest, EtRouteResponse } from "../src/index.ts";
import { insertSession } from "../src/testing.ts";
import { encode, expectError, fixture, login, opened, ORIGIN, response, RP, wire } from "./helpers.ts";
import type { Fixture, Login } from "./helpers.ts";

interface Seen {
  req?: EtRouteRequest;
  auth?: EtAuth;
}

function echoRoute(seen: Seen, method: EtMethod = "POST", path = "/echo"): EtRoute {
  return {
    method,
    path,
    handler(req, auth) {
      seen.req = req;
      seen.auth = auth;
      return {
        status: 201,
        headers: [["content-type", "text/plain"], ["Set-Cookie", "a=1"], ["set-cookie", "b=2"]],
        body: req.body,
      };
    },
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
  method: EtMethod,
  path: string,
  query = "",
  headers: EtHeader[] = [],
  body = new Uint8Array(),
): Bytes {
  return encodeEtRequest({ method, path, query, headers, body: new Bytes(body) });
}

/** Builds an EtRequest without any validation, to exercise the receiving side. */
function rawRequest(method: string, path: string, query: string, headers: Uint8Array[], body: Uint8Array): Uint8Array {
  return encodeU32LengthPrefixed(
    asciiToBytes("WAKE/1 et-req"),
    asciiToBytes(method),
    asciiToBytes(path),
    asciiToBytes(query),
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

test("ET route hit round-trips method, query, headers and body, and passes the auth object", async () => {
  const seen: Seen = {};
  const f = await fixture({ routes: [echoRoute(seen)] });
  const l = await login(f);
  const body = new Uint8Array([0, 1, 2, 255]);
  const headers: EtHeader[] = [["X-Test", "café"], ["x-test", "two"]];
  const plain = await wire(f, l, "wake-et", request("POST", "/echo", "a=1&b=%2F", headers, body).toUint8Array());
  const out = await openRaw(l, await sendTransport(f, plain));
  const res = decodeEtResponse(out.plaintext);
  assert.equal(res.status, 201);
  assert.deepEqual(res.headers, [["content-type", "text/plain"], ["Set-Cookie", "a=1"], ["set-cookie", "b=2"]]);
  assert.deepEqual([...res.body.toUint8Array()], [0, 1, 2, 255]);
  assert.equal(seen.req?.method, "POST");
  assert.equal(seen.req?.path, "/echo");
  assert.equal(seen.req?.query, "a=1&b=%2F");
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

test("ET dispatches only on an exact method and path match", async () => {
  const seen: Seen = {};
  const f = await fixture({ routes: [echoRoute(seen, "GET", "/a"), echoRoute(seen, "POST", "/a")] });
  const l = await login(f);
  for (const [method, path] of [["GET", "/a"], ["POST", "/a"]] as const) {
    assert.equal((await callEt(f, l, request(method, path, "q=1"))).status, 201);
  }
  const misses = [
    ["PUT", "/a"], ["DELETE", "/a"], ["GET", "/A"], ["GET", "/a/"], ["GET", "/"], ["GET", "/%61"], ["GET", "/a/."],
  ] as const;
  for (const [method, path] of misses) {
    const res = await callEt(f, l, request(method, path));
    assert.equal(res.status, 404, `${method} ${path}`);
    assert.deepEqual(errorBody(res.body), { error: { code: "route_not_found" } });
    assert.deepEqual(res.headers, [["content-type", "application/json"]]);
  }
});

test("ET without routes answers route_not_found", async () => {
  const f = await fixture();
  const l = await login(f);
  const res = await callEt(f, l, request("GET", "/x"));
  assert.equal(res.status, 404);
  assert.deepEqual(errorBody(res.body), { error: { code: "route_not_found" } });
});

test("ET never forwards /wake/ paths", async () => {
  const f = await fixture({ routes: [echoRoute({}, "GET", "/wakeup")] });
  const l = await login(f);
  for (const path of ["/wake/up", "/wake/transport", "/wake/ta/list"]) {
    assert.equal((await callEt(f, l, request("GET", path))).status, 404);
  }
});

test("ET malformed requests map to 400 with the matching code", async () => {
  const f = await fixture({ routes: [echoRoute({})] });
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
        asciiToBytes(""),
        new Uint8Array(),
        new Uint8Array(),
      ),
      "invalid_request",
    ],
    ["odd header fields", rawRequest("GET", "/echo", "", [asciiToBytes("a")], new Uint8Array()), "invalid_request"],
    ["bad method", rawRequest("TRACE", "/echo", "", [], new Uint8Array()), "invalid_method"],
    ["lower-case method", rawRequest("get", "/echo", "", [], new Uint8Array()), "invalid_method"],
    ["relative path", rawRequest("GET", "echo", "", [], new Uint8Array()), "invalid_path"],
    ["path with fragment", rawRequest("GET", "/a#b", "", [], new Uint8Array()), "invalid_path"],
    ["bad percent in path", rawRequest("GET", "/a%zz", "", [], new Uint8Array()), "invalid_path"],
    ["query with fragment", rawRequest("GET", "/echo", "a#b", [], new Uint8Array()), "invalid_path"],
    [
      "bad header name",
      rawRequest("GET", "/echo", "", [asciiToBytes("bad name"), asciiToBytes("v")], new Uint8Array()),
      "invalid_header",
    ],
    [
      "duplicate content-type",
      rawRequest("GET", "/echo", "", ["content-type", "a", "Content-Type", "b"].map(asciiToBytes), new Uint8Array()),
      "invalid_header",
    ],
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
  const f = await fixture({ routes: [echoRoute(seen)], etBodyLimit: 10 });
  const l = await login(f);
  const ok = await callEt(f, l, request("POST", "/echo", "", [], new Uint8Array(10)));
  assert.equal(ok.status, 201);
  assert.equal(ok.body.length, 10);
  const big = await callEt(f, l, request("POST", "/echo", "", [], new Uint8Array(11)));
  assert.equal(big.status, 413);
  assert.deepEqual(errorBody(big.body), { error: { code: "too_large" } });
});

test("ET default body limit is the 1 MiB maximum", async () => {
  const f = await fixture({ routes: [echoRoute({})] });
  const l = await login(f);
  assert.equal((await callEt(f, l, request("POST", "/echo", "", [], new Uint8Array(ET_BODY_MAX)))).status, 201);
  const over = rawRequest("POST", "/echo", "", [], new Uint8Array(ET_BODY_MAX + 1));
  const res = await callEt(f, l, over);
  assert.equal(res.status, 413);
});

test("ET rejects other contexts on /wake/transport and wake-et on /wake/up", async () => {
  const f = await fixture({ routes: [echoRoute({})] });
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
  const f = await fixture({ routes: [echoRoute({})] });
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
  const bad = (path: string, handler: EtRoute["handler"]): EtRoute => ({ method: "GET", path, handler });
  const f = await fixture({
    routes: [
      bad("/throw", () => {
        throw new Error(secret);
      }),
      bad("/reject", () => Promise.reject(new WakeError("rate_limited", secret))),
      bad("/status", () => ({ status: 99 })),
      bad("/status-high", () => ({ status: 600 })),
      bad("/header", () => ({ status: 200, headers: [["bad name", "v"]] })),
      bad("/location", () => ({ status: 302, headers: [["location", "https://evil.example/"]] })),
      bad("/nothing", () => undefined as unknown as EtRouteResponse),
      bad("/big", () => ({ status: 200, body: new Uint8Array(ET_BODY_MAX + 1) })),
      bad("/ok-min", () => ({ status: 200 })),
      bad("/ok-max", () => ({ status: 599 })),
    ],
  });
  const l = await login(f);
  for (const path of ["/throw", "/reject", "/status", "/status-high", "/header", "/location", "/nothing", "/big"]) {
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
    routes: [{
      method: "POST",
      path: "/m",
      handler(req) {
        calls += 1;
        req.body[0] = 9;
        return { status: 200, body: req.body };
      },
    }],
  });
  const l = await login(f);
  const bytes = request("POST", "/m", "", [], new Uint8Array([1]));
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
    const f = await fixture({ routes: [echoRoute(seen)] });
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
  const f = await fixture({ routes: [echoRoute({})] });
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
  const f = await fixture({ routes: [echoRoute({})] });
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

const noop: EtRoute["handler"] = () => ({ status: 200 });

const baseOptions = {
  rpId: RP,
  loginOrigins: [ORIGIN],
  secret: new Uint8Array(32),
  credentials: new MemoryCredentialStore(),
};

function invalidOption(error: unknown): boolean {
  return error instanceof WakeError && error.code === "invalid_option";
}

for (
  const [name, routes] of [
    ["/wake/ prefix", [{ method: "GET", path: "/wake/up", handler: noop }]],
    ["/wake/ alone", [{ method: "GET", path: "/wake/", handler: noop }]],
    ["duplicate method and path", [{ method: "GET", path: "/a", handler: noop }, { method: "GET", path: "/a", handler: noop }]],
    ["relative path", [{ method: "GET", path: "a", handler: noop }]],
    ["empty path", [{ method: "GET", path: "", handler: noop }]],
    ["path with query", [{ method: "GET", path: "/a?b", handler: noop }]],
    ["path with fragment", [{ method: "GET", path: "/a#b", handler: noop }]],
    ["bad percent encoding", [{ method: "GET", path: "/a%2", handler: noop }]],
    ["too long path", [{ method: "GET", path: `/${"a".repeat(2048)}`, handler: noop }]],
    ["unknown method", [{ method: "TRACE", path: "/a", handler: noop }]],
    ["lower-case method", [{ method: "get", path: "/a", handler: noop }]],
    ["missing handler", [{ method: "GET", path: "/a" }]],
    ["non-function handler", [{ method: "GET", path: "/a", handler: 1 }]],
    ["non-object route", [null]],
    ["routes not an array", {}],
  ] as [string, unknown][]
) {
  test(`ET route registration rejects ${name}`, () => {
    assert.throws(() => createWakeServer({ ...baseOptions, routes } as never), invalidOption);
  });
}

test("ET route registration accepts the same path under different methods and near-miss paths", () => {
  assert.doesNotThrow(() =>
    createWakeServer({
      ...baseOptions,
      routes: [
        { method: "GET", path: "/a", handler: noop },
        { method: "POST", path: "/a", handler: noop },
        { method: "GET", path: "/wake", handler: noop },
        { method: "GET", path: "/wakeup", handler: noop },
        { method: "GET", path: `/${"a".repeat(2047)}`, handler: noop },
      ],
    })
  );
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, routes: [] }));
});

test("etBodyLimit must be a positive safe integer", () => {
  for (const value of [null, "1", NaN, Infinity, -1, 0, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => createWakeServer({ ...baseOptions, etBodyLimit: value } as never), invalidOption, String(value));
  }
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, etBodyLimit: 1 }));
});

test("with routes, maxPlaintext must cover the worst-case EtRequest for the body limit (both sides)", () => {
  const routes = [{ method: "GET", path: "/a", handler: noop }] as const;
  const required = ET_REQUEST_MAX_ENCODED;
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, routes, maxPlaintext: required }));
  assert.throws(() => createWakeServer({ ...baseOptions, routes, maxPlaintext: required - 1 }), invalidOption);
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, routes, etBodyLimit: 100, maxPlaintext: required - ET_BODY_MAX + 100 }));
  assert.throws(
    () => createWakeServer({ ...baseOptions, routes, etBodyLimit: 100, maxPlaintext: required - ET_BODY_MAX + 99 }),
    invalidOption,
  );
  // Raising the limit above the default needs a larger maxPlaintext.
  assert.throws(() => createWakeServer({ ...baseOptions, routes, etBodyLimit: ET_BODY_MAX + 1 }), invalidOption);
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, routes, etBodyLimit: ET_BODY_MAX + 1, maxPlaintext: required + 1 }));
  // Without routes ET is unused and the plaintext limit is unconstrained.
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, maxPlaintext: 1 }));
});

test("the default maxPlaintext covers the worst-case EtRequest", () => {
  assert.doesNotThrow(() => createWakeServer({ ...baseOptions, routes: [{ method: "GET", path: "/a", handler: noop }] }));
});

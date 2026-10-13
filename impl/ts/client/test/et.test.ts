// Spec §8.3, §11: WAKE-ET fetch through POST /wake/transport.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Bytes } from "@wake-protocol/bytes";
import { bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import { encodeEtRequest, encodeEtResponse, ET_BODY_MIN, ET_BODY_MAX, ET_REQUEST_MAX_ENCODED, ET_RESPONSE_MAX_ENCODED, DEFAULT_MAX_PLAINTEXT } from "@wake-protocol/core";
import { WakeClient } from "../src/index.ts";
import { fixture, hasCode, jsonResponse } from "./fixture.ts";

const login = { mode: "discoverable" } as const;

const etResponse = (status: number, headers: [string, string][], body: Uint8Array) =>
  encodeEtResponse({ status, headers, body: new Bytes(body) }).toUint8Array();

test("wakeFetch round-trips method, path, query, repeated headers and a binary body", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.etHandler = () => etResponse(201, [["X-Multi", "a"], ["x-multi", "b"], ["Content-Type", "application/octet-stream"]],
    new Uint8Array([0, 255, 1]));
  const body = new Uint8Array([0, 1, 2, 254, 255]);
  const response = await f.client.wakeFetch("/api/items", {
    method: "PUT",
    query: "a=1&b=%20",
    headers: [["X-Test", "one"], ["x-test", "two"]],
    body,
  });
  assert.equal(f.paths.at(-1), "/wake/transport");
  const seen = f.etRequests[0]!;
  assert.equal(seen.method, "PUT");
  assert.equal(seen.path, "/api/items");
  assert.equal(seen.query, "a=1&b=%20");
  assert.deepEqual(seen.headers, [["X-Test", "one"], ["x-test", "two"]]);
  assert.deepEqual([...seen.body.toUint8Array()], [...body]);
  assert.equal(f.requests.at(-1)!.context, "wake-et");
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("x-multi"), "a, b");
  assert.deepEqual([...new Uint8Array(await response.arrayBuffer())], [0, 255, 1]);
});

test("wakeFetch defaults to GET, splits path?query once and encodes string bodies and record headers as UTF-8", async () => {
  const f = await fixture();
  await f.client.login(login);
  await f.client.wakeFetch("/a?x=1?y", { headers: { "X-A": "b" } });
  assert.equal(f.etRequests[0]!.method, "GET");
  assert.equal(f.etRequests[0]!.path, "/a");
  assert.equal(f.etRequests[0]!.query, "x=1?y");
  assert.deepEqual(f.etRequests[0]!.headers, [["X-A", "b"]]);
  await f.client.wakeFetch("/b", { method: "POST", body: "あ" });
  assert.equal(bytesToUtf8(f.etRequests[1]!.body.toUint8Array()), "あ");
  await assert.rejects(f.client.wakeFetch("/c?x", { query: "y" }), hasCode("invalid_path"));
});

test("wakeFetch validation errors are thrown before anything is sent", async () => {
  const f = await fixture();
  await f.client.login(login);
  const before = f.wires.length;
  await assert.rejects(f.client.wakeFetch("no-slash"), hasCode("invalid_path"));
  await assert.rejects(f.client.wakeFetch("/a%zz"), hasCode("invalid_path"));
  await assert.rejects(f.client.wakeFetch("/a", { method: "TRACE" as never }), hasCode("invalid_method"));
  await assert.rejects(f.client.wakeFetch("/a", { headers: [["Bad Name", "v"]] }), hasCode("invalid_header"));
  await assert.rejects(f.client.wakeFetch("/a", { headers: [["Content-Type", "a"], ["content-type", "b"]] }), hasCode("invalid_header"));
  await assert.rejects(f.client.wakeFetch("/a", { body: new Uint8Array(ET_BODY_MAX + 1) }), hasCode("too_large"));
  assert.equal(f.wires.length, before);
  // Boundary: exactly the limit is sent.
  await f.client.wakeFetch("/a", { method: "POST", body: new Uint8Array(ET_BODY_MAX) });
  assert.equal(f.wires.length, before + 1);
});

test("wakeFetch uses a raised ET body limit for both requests and responses", async () => {
  const bodyLimit = DEFAULT_MAX_PLAINTEXT + 1;
  const maxPlaintext = ET_REQUEST_MAX_ENCODED - ET_BODY_MAX + bodyLimit;
  const f = await fixture({ etBodyLimit: bodyLimit, maxPlaintext });
  f.maxPlaintext = maxPlaintext;
  f.etBodyLimit = bodyLimit;
  await f.client.login(login);
  const body = new Uint8Array(bodyLimit).fill(0xa5);
  f.etHandler = (request) => encodeEtResponse({
    status: 200,
    headers: [],
    body: request.body,
  }, { bodyLimit }).toUint8Array();
  assert.ok(encodeEtRequest({ method: "POST", path: "/echo", query: "", headers: [], body: new Bytes(body) },
    { bodyLimit }).length > DEFAULT_MAX_PLAINTEXT);
  assert.ok(encodeEtResponse({ status: 200, headers: [], body: new Bytes(body) },
    { bodyLimit }).length > DEFAULT_MAX_PLAINTEXT);
  const defaultFixture = await fixture();
  await defaultFixture.client.login(login);
  const sent = defaultFixture.wires.length;
  await assert.rejects(defaultFixture.client.wakeFetch("/echo", { method: "POST", body }), hasCode("too_large"));
  await assert.rejects(defaultFixture.client.request("POST /echo", body), hasCode("too_large"));
  assert.equal(defaultFixture.wires.length, sent);
  const response = await f.client.wakeFetch("/echo", { method: "POST", body });
  assert.deepEqual(f.etRequests[0]!.body.toUint8Array(), body);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), body);
  const before = f.wires.length;
  await assert.rejects(f.client.wakeFetch("/echo", { body: new Uint8Array(bodyLimit + 1) }), hasCode("too_large"));
  assert.equal(f.wires.length, before);
});

test("wakeFetch rejects response bodies above the configured ET body limit", async () => {
  const f = await fixture({ etBodyLimit: ET_BODY_MIN });
  await f.client.login(login);
  f.etHandler = () => etResponse(200, [], new Uint8Array(ET_BODY_MIN + 1));
  await assert.rejects(f.client.wakeFetch("/a"), hasCode("too_large"));
});

for (const limit of [0, -1, 1.5, ET_BODY_MIN - 1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, "1"]) {
  test(`reject invalid ET body limit ${limit}`, () => {
    assert.throws(() => new WakeClient({
      baseUrl: "",
      getAssertion: async () => { throw new Error(); },
      etBodyLimit: limit as number,
    }), hasCode("invalid_option"));
  });
}

for (const limit of [ET_BODY_MIN, ET_BODY_MAX]) {
  test(`accept ET body limit boundary ${limit}`, () => {
    assert.doesNotThrow(() => new WakeClient({
      baseUrl: "",
      getAssertion: async () => { throw new Error(); },
      etBodyLimit: limit,
    }));
  });
}

test("wakeFetch surfaces a 404 route_not_found EtResponse at the minimum body limit", async () => {
  const f = await fixture({ etBodyLimit: ET_BODY_MIN });
  await f.client.login(login);
  f.etHandler = () => etResponse(404, [["Content-Type", "application/json"]], utf8ToBytes('{"error":{"code":"route_not_found"}}'));
  const response = await f.client.wakeFetch("/missing");
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: { code: "route_not_found" } });
});

test("wakeFetch retries a stale_request once on /wake/transport and then fails", async () => {
  const f = await fixture();
  await f.client.login(login);
  let calls = 0;
  f.upPlaintext = (header, plaintext) => {
    if (header.context !== "wake-et") {
      return plaintext;
    }
    calls++;
    return calls === 1 ? utf8ToBytes('{"error":{"code":"stale_request"}}') : plaintext;
  };
  f.etHandler = () => etResponse(200, [], utf8ToBytes("ok"));
  const response = await f.client.wakeFetch("/a");
  assert.equal(await response.text(), "ok");
  assert.equal(calls, 2);
  assert.deepEqual(f.paths.slice(-2), ["/wake/transport", "/wake/transport"]);
  f.upPlaintext = (header, plaintext) => header.context === "wake-et" ? utf8ToBytes('{"error":{"code":"stale_request"}}') : plaintext;
  await assert.rejects(f.client.wakeFetch("/a"), hasCode("stale_request"));
});

test("wakeFetch surfaces other encrypted errors and drops the session on outer reauth", async () => {
  const f = await fixture();
  await f.client.login(login);
  f.upPlaintext = (header, plaintext) => header.context === "wake-et" ? utf8ToBytes('{"error":{"code":"invalid_context"}}') : plaintext;
  await assert.rejects(f.client.wakeFetch("/a"), hasCode("invalid_context"));
  assert.equal(f.client.loggedIn, true);
  f.upPlaintext = undefined;
  f.upAction = () => jsonResponse({ wakeError: "reauth" }, 401);
  await assert.rejects(f.client.wakeFetch("/a"), hasCode("reauth"));
  assert.equal(f.client.loggedIn, false);
  f.upAction = undefined;
  await assert.rejects(f.client.wakeFetch("/a"), hasCode("reauth"));
});

test("request() still refuses the reserved wake-et context", async () => {
  const f = await fixture();
  await f.client.login(login);
  await assert.rejects(f.client.request("wake-et", new Uint8Array(0)), hasCode("bad_request"));
});

for (const limit of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, "1"]) {
  test(`reject invalid plaintext limit ${limit}`, () => {
    assert.throws(() => new WakeClient({
      baseUrl: "", getAssertion: async () => { throw new Error(); }, maxPlaintext: limit as number,
    }), hasCode("invalid_option"));
  });
}

for (const encodedMax of [ET_REQUEST_MAX_ENCODED, ET_RESPONSE_MAX_ENCODED]) {
  test(`reject plaintext limit below ET encoding boundary ${encodedMax}`, () => {
    assert.throws(() => new WakeClient({
      baseUrl: "", getAssertion: async () => { throw new Error(); }, maxPlaintext: encodedMax - 1,
    }), hasCode("invalid_option"));
  });
}

test("accept exact worst-case ET plaintext limit and reject raised body limit without room", () => {
  const options = { baseUrl: "", getAssertion: async () => { throw new Error(); } };
  assert.doesNotThrow(() => new WakeClient({ ...options, maxPlaintext: ET_REQUEST_MAX_ENCODED }));
  assert.throws(() => new WakeClient({ ...options, etBodyLimit: ET_BODY_MAX + 1 }), hasCode("invalid_option"));
  assert.throws(() => new WakeClient({ ...options, etBodyLimit: Number.MAX_SAFE_INTEGER,
    maxPlaintext: Number.MAX_SAFE_INTEGER }), hasCode("invalid_option"));
});

test("wakeFetch exposes a null body for the 204/205/304 null-body statuses even when the ET body is non-empty", async () => {
  const f = await fixture();
  await f.client.login(login);
  for (const status of [204, 205, 304]) {
    f.etHandler = () => etResponse(status, [], new Uint8Array([1, 2, 3]));
    const response = await f.client.wakeFetch("/x");
    assert.equal(response.status, status);
    assert.equal(response.body, null);
  }
});

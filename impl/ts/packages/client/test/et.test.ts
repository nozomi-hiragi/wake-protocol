// Spec §8.3, §11: WAKE-ET fetch through POST /wake/transport.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Bytes } from "@wake-protocol/bytes";
import { bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import { encodeEtResponse } from "@wake-protocol/core";
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
  await assert.rejects(f.client.wakeFetch("/a", { body: new Uint8Array(1024 * 1024 + 1) }), hasCode("too_large"));
  assert.equal(f.wires.length, before);
  // Boundary: exactly the limit is sent.
  await f.client.wakeFetch("/a", { method: "POST", body: new Uint8Array(1024 * 1024) });
  assert.equal(f.wires.length, before + 1);
});

test("wakeFetch surfaces a 404 route_not_found EtResponse as a Response", async () => {
  const f = await fixture();
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

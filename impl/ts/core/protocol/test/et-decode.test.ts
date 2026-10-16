// Raw received ET framing and semantics (spec §11.2–11.4, §12.4).
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Byte2 } from "@wake-protocol/bytes";
import { asciiToBytes, encodeU32LengthPrefixed } from "@wake-protocol/codec";
import {
  type EtOptions,
  type EtRequest,
  type EtResponse,
  Bytes,
  ET_BODY_MAX,
  ET_HEADERS_MAX,
  ET_URL_MAX,
  WakeError,
  decodeEtRequest,
  decodeEtResponse,
} from "../src/index.ts";

const ascii = asciiToBytes;
const lp = encodeU32LengthPrefixed;
const empty = new Uint8Array(0);
const body = Uint8Array.of(0xff, 0, 0x80);
const headers = lp(ascii("X-Opaque"), Uint8Array.of(0x80, 0xff));
const hasCode = (code: string) => (e: unknown): boolean => e instanceof WakeError && e.code === code;
const append = (wire: Uint8Array, tail: Uint8Array): Uint8Array => Uint8Array.from([...wire, ...tail]);
const replace = (fields: Uint8Array[], index: number, value: Uint8Array): Uint8Array =>
  lp(...fields.map((field, i) => i === index ? value : field));

interface DecoderCase {
  kind: string;
  fields: () => Uint8Array[];
  headerIndex: number;
  bodyIndex: number;
  decode: (wire: Uint8Array, opts?: EtOptions) => EtRequest | EtResponse;
}

const decoders: DecoderCase[] = [
  {
    kind: "request",
    fields: () => [ascii("WAKE/1 et-req"), ascii("POST"), ascii("/"), headers, body],
    headerIndex: 3,
    bodyIndex: 4,
    decode: decodeEtRequest,
  },
  {
    kind: "response",
    fields: () => [ascii("WAKE/1 et-res"), new Byte2(200).toUint8Array(), headers, body],
    headerIndex: 2,
    bodyIndex: 3,
    decode: decodeEtResponse,
  },
];

for (const { kind, fields, headerIndex, bodyIndex, decode } of decoders) {
  describe(`raw ET ${kind} decoder`, () => {
    const structural: [string, (f: Uint8Array[]) => Uint8Array][] = [
      ["truncated outer length prefix", () => Uint8Array.of(0, 0, 0)],
      ["truncated outer field", (f) => lp(...f).slice(0, -1)],
      ["missing outer field", (f) => lp(...f.slice(0, -1))],
      ["trailing outer field", (f) => lp(...f, empty)],
      ["trailing outer bytes", (f) => append(lp(...f), Uint8Array.of(0, 0, 0))],
      ["wrong label of the correct width", (f) => {
        const label = f[0]!.slice();
        label[0] = 0x58;
        return replace(f, 0, label);
      }],
      ["wrong label width", (f) => replace(f, 0, f[0]!.slice(1))],
      ["non-ASCII label byte", (f) => {
        const label = f[0]!.slice();
        label[0] = 0x80;
        return replace(f, 0, label);
      }],
      ["truncated nested length prefix", (f) => replace(f, headerIndex, Uint8Array.of(0, 0, 0))],
      ["truncated nested field", (f) => replace(f, headerIndex, lp(ascii("x"), ascii("value")).slice(0, -1))],
      ["trailing nested bytes", (f) => replace(f, headerIndex, append(headers, Uint8Array.of(0)))],
      ["odd header field count", (f) => replace(f, headerIndex, lp(ascii("x"), ascii("value"), ascii("y")))],
    ];
    for (const [name, wire] of structural) {
      it(`${name} yields invalid_request`, () => {
        assert.throws(() => decode(wire(fields())), hasCode("invalid_request"));
      });
    }

    const invalidHeaders: [string, Uint8Array][] = [
      ["non-ASCII header name", lp(Uint8Array.of(0x80), empty)],
      ["invalid header name token", lp(ascii("bad name"), empty)],
      ["control byte in header value", lp(ascii("x"), Uint8Array.of(0))],
      ["CRLF in header value", lp(ascii("x"), ascii("a\r\nb"))],
      ["headers over the limit", lp(ascii("x"), ascii("a".repeat(ET_HEADERS_MAX)))],
    ];
    for (const [name, value] of invalidHeaders) {
      it(`${name} preserves invalid_header`, () => {
        assert.throws(() => decode(replace(fields(), headerIndex, value)), hasCode("invalid_header"));
      });
    }

    it("body over the default limit preserves too_large", () => {
      assert.throws(() => decode(replace(fields(), bodyIndex, new Uint8Array(ET_BODY_MAX + 1))), hasCode("too_large"));
    });

    it("body over a custom limit preserves too_large", () => {
      assert.throws(() => decode(lp(...fields()), { bodyLimit: body.length - 1 }), hasCode("too_large"));
      assert.ok(decode(lp(...fields()), { bodyLimit: body.length }).body.equals(new Bytes(body)));
    });

    it("valid obs-text and binary body bytes remain unchanged", () => {
      const decoded = decode(lp(...fields()));
      assert.deepEqual(decoded.headers, [["X-Opaque", "\u0080\u00ff"]]);
      assert.ok(decoded.body.equals(new Bytes(body)));
    });
  });
}

describe("raw ET request field semantics", () => {
  const cases: [string, number, Uint8Array, string][] = [
    ["forbidden method", 1, ascii("TRACE"), "invalid_method"],
    ["non-ASCII method", 1, Uint8Array.of(0x80), "invalid_method"],
    ["empty method", 1, empty, "invalid_method"],
    ["non-ASCII URL", 2, Uint8Array.of(0x2f, 0x80), "invalid_url"],
    ["control byte in URL", 2, Uint8Array.of(0x2f, 0), "invalid_url"],
    ["malformed escape", 2, ascii("/%zz"), "invalid_url"],
    ["URL over the limit", 2, ascii("/".repeat(ET_URL_MAX + 1)), "invalid_url"],
    ["fragment", 2, ascii("/?q=#fragment"), "invalid_url"],
  ];
  for (const [name, index, value, code] of cases) {
    it(`${name} preserves ${code}`, () => {
      assert.throws(() => decodeEtRequest(replace(decoders[0]!.fields(), index, value)), hasCode(code));
    });
  }
});

describe("raw ET response status and location", () => {
  for (const width of [0, 1, 3, 4]) {
    it(`status width ${width} yields invalid_request`, () => {
      assert.throws(() => decodeEtResponse(replace(decoders[1]!.fields(), 1, new Uint8Array(width))), hasCode("invalid_request"));
    });
  }
  for (const status of [0, 199, 600, 0xffff]) {
    it(`status ${status} yields invalid_request`, () => {
      assert.throws(() => decodeEtResponse(replace(decoders[1]!.fields(), 1, new Byte2(status).toUint8Array())), hasCode("invalid_request"));
    });
  }
  for (const status of [200, 599]) {
    it(`accepts boundary status ${status}`, () => {
      assert.equal(decodeEtResponse(replace(decoders[1]!.fields(), 1, new Byte2(status).toUint8Array())).status, status);
    });
  }
  it("cross-origin response location passes through", () => {
    const value = lp(ascii("location"), ascii("//other.example/path"));
    assert.deepEqual(decodeEtResponse(replace(decoders[1]!.fields(), 2, value)).headers, [["location", "//other.example/path"]]);
  });
});

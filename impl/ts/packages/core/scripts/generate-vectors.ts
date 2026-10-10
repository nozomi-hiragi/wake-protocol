// Deterministic generator for spec/test-vectors/*.json (spec §16).
// Usage: node scripts/generate-vectors.ts [outDir]
// All inputs are fixed hex constants below; re-running reproduces the files byte for byte.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  type Bytes,
  ascii,
  concat,
  deriveKeys,
  encodeHeader,
  fromHex,
  hex,
  type MsgHeader,
  lp,
  u32,
  u64,
  u8,
  utf8,
  WakeError,
} from "../src/index.ts";
import { type Obj, SUITES, runCase } from "./vector-ops.ts";

export const DEFAULT_VECTOR_DIR = fileURLToPath(new URL("../../../../../spec/test-vectors/", import.meta.url));

// --- fixed constants (generated once with openssl rand; do not change casually) ---

const EXCH_1 = "462704469d023c210a1b7a841c0b3f76"; // 16B
const EXCH_2 = "5f80b324f9d6cf60e7241f12471f4f81"; // 16B
const APPROVAL_ID = "66707e356f982360de73f318a91e3483"; // 16B
const REQUEST_ID = "75e11e8acc3eb3aa5f34c720679c76b0"; // 16B
const SESSION_1 = "6ae5e6afe9ddf0f51e088a26d86e7ca5f3e3b2a916be67fd280f6a9e47450dcf"; // 32B
const SESSION_2 = "54b4facc2138349ae1a3113ec9e29eb02445ad13dcff035c8a3adf9f0af907cc";
const SESSION_3 = "ca8bf24e74c35e22937af7defddae539c1187a6042d6a4be57ccedbc17f6aee8";
const SERVER_NONCE_1 = "2f7ea4169e2eac5587faafaea8a3bb53126dc7704c53e4a736e162cbb1026c11";
const SERVER_NONCE_2 = "a7c9c668964907b0de9b8aa04ed2db88bdfd7edc3b54ac29a94dcf1a89f53fa9";
const PREV_TH = "56bf02c1f4d778f15bbc510da3b345a55289fadde5fc270f532f55d540964a2b";
const TH_KX = "2277f2fb3cbca5e681a570f8d3128c48e592bcc251a077ddf16afd68a2a51acc";
const TH_KR = "bdc23d49b16439f253b228a4497722a00e08f042bc584dc779393fc6b6143608";
const HKDF_TH = "0768d3fdf020fd90c339fb19ce8e0507375ab33dd3cd1ac5a934322ec44f5c23";
const TA = "a998bff7c68ab2a1a6c662dbbfe8cd13eede79749ebd80c360a0285637ce3077";
const MSG_KEY_C2S = "4a8a52c9f376ad121109a773c4b7cf7237dfacf95b06b21cd5e48dc3fb8c7585";
const MSG_KEY_S2C = "87507f3dcb6460d74fc5a95c7cc04fdfcae8064308b5516848afb8045ee4eea5";
const IV_C2S = "d7f3eaf80af8c74c3b50e6e3";
const IV_S2C = "31f3b21c1fbf58b2549f4501";
const APPROVAL_NONCE = "c3bbfa5148d6ffd2659fb689a588621b0bf45cfbe9785ccda8afa18a6bf542a0";
/** The spec §10.3 example operationId, used as a raw 32-byte operationId. */
const SPEC_OPERATION_ID = "5f1a2b8b66ca83af403465063939c4217af81e4d9e6e90eb13194bcefda4b461";
/** The spec §10.3 example TA Nonce. */
const SPEC_TA_NONCE = "3f9a1c7e5b2d4f6081a3c5e7092b4d6f";

// P-256 key pairs (found with node:crypto createECDH; see the report for the search).
// A_D/B_D: the pair whose shared secret starts with 0x00. C_D/D: an ordinary pair.
const A_D = "e4214c50bc9799c658fefce613a203c48f53fbc60b54a392bb007173df7f9930";
const A_PUB =
  "040f50dcb740cbe559c37ac5be1c691de1c2e8eaf93964f66b7f55c7292b92dea58ad10ee854bc954f70866178cddddcea6c099a0e3b6cbcffa37f136938c6e8e1";
const B_D = "7d9966b3ffd524cbf09f86507ab56093cd087193601d6d8f239ff2b02f156751";
const B_PUB =
  "043b835b358e22e8e8b9027ec9b67ba135ba6b6e8f82b8bbaf62349bfc69b2d83e4ae6ba059970089616c45b6f9043ecf85b2a9db77b0bb8c835dac8765ae9be02";
const C_D = "f629f30f4f1434ae5545385bab37dd1768c7df61f7abab439e07a3b4de754d5f";
const C_PUB =
  "04ca7d7f18235556a643d6b1957ce05e7cb7d6c29c30c813b5887af2058125523231880d51586cd63b87679912f7550f65239e3d6171996e8dc02e09d78f178e14";
const D_PUB =
  "04e52a2545234e543e6b14da30b65cc6e3b7502f2bcdeae103999d143ff91bbab5ad274bda6a51275c299ec32dde6c43898587bf9e59bb7a8c622a9157ebdfce8d";
/** ECDH(A_D, B_PUB) = ECDH(B_D, A_PUB); first byte 0x00. */
const SS_ZERO = "003353938717ba44c354a54a0f668a0d4b8a5295eb29a4180b2896111ccbb277";
/** ECDH(C_D, D_PUB). */
const SS_NORMAL = "759931c025a9690df5f8c194330fd1ceda28fb563844fc80b6636a3bf79b62df";

const TIME_SERVER = 1767225600000; // 2026-01-01T00:00:00Z
const TIME_EXPIRES = 1767229200000; // +1h

interface Case {
  name: string;
  input: Obj;
  /** Expected WAKE error code. Present for negative vectors only. */
  error?: string;
}

export type Vector =
  | { name: string; input: Obj; expected: Obj }
  | { name: string; input: Obj; expectedError: string };

export interface SuiteFile {
  wake: "WAKE/1";
  suite: string;
  vectors: Vector[];
}

// --- msg helpers: build raw headers so that malformed variants can be produced ---

function rawHeader(f: {
  label?: string;
  dir?: number;
  sid: Bytes;
  epoch: number;
  rid: Bytes;
  issuedAt: number;
  context: Bytes;
  iv: Bytes;
}): Bytes {
  return lp(
    ascii(f.label ?? "WAKE/1 msg"),
    u8(f.dir ?? 1),
    f.sid,
    u32(f.epoch),
    f.rid,
    u64(f.issuedAt),
    f.context,
    f.iv,
  );
}

function wireOf(header: Bytes, ciphertext: Bytes): Bytes {
  return concat(u32(header.length), header, ciphertext);
}

/** Two-character hex of a single byte. */
const byteHex = (b: number): string => b.toString(16).padStart(2, "0");

async function msgCases(): Promise<Case[]> {
  const CONTEXT = "POST /api/transfer";
  const c2sHeader: MsgHeader = {
    dir: 1,
    sessionId: fromHex(SESSION_1),
    epoch: 1,
    requestId: fromHex(REQUEST_ID),
    issuedAt: TIME_SERVER,
    context: CONTEXT,
    iv: fromHex(IV_C2S),
  };
  const s2cHeader: MsgHeader = {
    dir: 2,
    sessionId: fromHex(SESSION_1),
    epoch: 1,
    requestId: fromHex(REQUEST_ID),
    issuedAt: TIME_SERVER + 500,
    context: "wake-et",
    iv: fromHex(IV_S2C),
  };
  const plainC2s = hex(utf8('{"ok":true}'));
  const plainS2c = hex(utf8('{"status":"ok"}'));

  // A valid c2s wire, used as the base for the negative cases.
  const baseWire = await runCase("msg", {
    kind: "seal",
    key: MSG_KEY_C2S,
    dir: c2sHeader.dir,
    sessionId: SESSION_1,
    epoch: c2sHeader.epoch,
    requestId: REQUEST_ID,
    issuedAt: TIME_SERVER,
    context: CONTEXT,
    iv: IV_C2S,
    plaintext: plainC2s,
  });
  const base = fromHex(baseWire.wire as string);
  const H = encodeHeader(c2sHeader);
  const C = base.slice(4 + H.length); // ciphertext ‖ tag
  const s2cWire = await runCase("msg", {
    kind: "seal",
    key: MSG_KEY_S2C,
    ...hdrInput(s2cHeader),
    plaintext: plainS2c,
  });

  const ridOffset = 4 + 14 + 5 + 36 + 8 + 4; // wire prefix + label + dir + sid + epoch + rid length; the first requestId byte

  const tampered = new Uint8Array(base);
  tampered[tampered.length - 1]! ^= 0x01;
  const aad = new Uint8Array(base);
  aad[ridOffset]! ^= 0x01;

  const ctxBytes = concat(ascii("POST /x"), Uint8Array.of(0x7f));

  return [
    {
      name: "c2s-header",
      input: { kind: "header", ...hdrInput(c2sHeader) },
    },
    {
      name: "s2c-header",
      input: { kind: "header", ...hdrInput(s2cHeader) },
    },
    {
      name: "c2s-seal-fixed-iv",
      input: { kind: "seal", key: MSG_KEY_C2S, ...hdrInput(c2sHeader), plaintext: plainC2s },
    },
    {
      name: "s2c-seal-fixed-iv",
      input: { kind: "seal", key: MSG_KEY_S2C, ...hdrInput(s2cHeader), plaintext: plainS2c },
    },
    {
      name: "c2s-open",
      input: { kind: "open", wire: baseWire.wire as string, key: MSG_KEY_C2S, expectDir: 1 },
    },
    {
      name: "trailing-byte-in-header",
      input: { kind: "open", wire: hex(wireOf(concat(H, Uint8Array.of(0)), C)), key: MSG_KEY_C2S, expectDir: 1 },
      error: "bad_request",
    },
    {
      name: "fixed-length-mismatch-sid31",
      input: {
        kind: "open",
        wire: hex(
          wireOf(
            rawHeader({
              sid: fromHex(SESSION_1).slice(0, 31),
              epoch: 1,
              rid: fromHex(REQUEST_ID),
              issuedAt: TIME_SERVER,
              context: ascii(CONTEXT),
              iv: fromHex(IV_C2S),
            }),
            C,
          ),
        ),
        key: MSG_KEY_C2S,
        expectDir: 1,
      },
      error: "bad_request",
    },
    {
      name: "label-mismatch",
      input: {
        kind: "open",
        wire: hex(
          wireOf(
            rawHeader({
              label: "WAKE/1 mzg",
              sid: fromHex(SESSION_1),
              epoch: 1,
              rid: fromHex(REQUEST_ID),
              issuedAt: TIME_SERVER,
              context: ascii(CONTEXT),
              iv: fromHex(IV_C2S),
            }),
            C,
          ),
        ),
        key: MSG_KEY_C2S,
        expectDir: 1,
      },
      error: "bad_request",
    },
    {
      name: "tag-tampered",
      input: { kind: "open", wire: hex(tampered), key: MSG_KEY_C2S, expectDir: 1 },
      error: "reauth",
    },
    {
      name: "aad-byte-tampered-requestId",
      input: { kind: "open", wire: hex(aad), key: MSG_KEY_C2S, expectDir: 1 },
      error: "reauth",
    },
    {
      name: "context-contains-0x7f",
      input: {
        kind: "open",
        wire: hex(wireOf(rawHeader({ sid: fromHex(SESSION_1), epoch: 1, rid: fromHex(REQUEST_ID), issuedAt: TIME_SERVER, context: ctxBytes, iv: fromHex(IV_C2S) }), C)),
        key: MSG_KEY_C2S,
        expectDir: 1,
      },
      error: "bad_request",
    },
    {
      name: "dir-reversed-s2c-wire-to-c2s-receiver",
      input: { kind: "open", wire: s2cWire.wire as string, key: MSG_KEY_C2S, expectDir: 1 },
      error: "bad_request",
    },
  ];
}

function hdrInput(h: {
  dir: number;
  sessionId: Bytes;
  epoch: number;
  requestId: Bytes;
  issuedAt: number;
  context: string;
  iv: Bytes;
}): Obj {
  return {
    dir: h.dir,
    sessionId: hex(h.sessionId),
    epoch: h.epoch,
    requestId: hex(h.requestId),
    issuedAt: h.issuedAt,
    context: h.context,
    iv: hex(h.iv),
  };
}

// Negative vector for dir reversal is built in buildSuites; see below.

async function buildSuites(): Promise<SuiteFile[]> {
  const ecdhZero = { privateKey: A_D, publicKey: A_PUB, peerPublicKey: B_PUB };
  const keys = await deriveKeys(fromHex(SS_NORMAL), fromHex(HKDF_TH));
  const clientFinishedInput = { kind: "client", fkC: hex(keys.fkC), th: HKDF_TH };
  const clientFinishedValue = (await runCase("finished", clientFinishedInput)).clientFinished as string;

  const cases: Array<[string, Case[]]> = [];

  cases.push([
    "lp",
    [
      { name: "empty-field", input: { fields: [""] } },
      { name: "spec-example-ab-empty", input: { fields: [hex(ascii("ab")), ""] } },
      { name: "nested", input: { fields: ["00000002616200000000", "7a"] } },
      { name: "no-fields", input: { fields: [] } },
      { name: "u8-255", input: { kind: "u8", value: 255 } },
      { name: "u16-0x1234", input: { kind: "u16", value: 0x1234 } },
      { name: "u32-deadbeef", input: { kind: "u32", value: 0xdeadbeef } },
      { name: "u64-2pow53-minus-1", input: { kind: "u64", value: Number.MAX_SAFE_INTEGER } },
    ],
  ]);

  cases.push([
    "transcript",
    [
      {
        name: "kx-login-basic",
        input: {
          mode: 1,
          exchangeId: EXCH_1,
          sessionId: SESSION_1,
          epoch: 0,
          prevTh: "",
          serverNonce: SERVER_NONCE_1,
          serverPublicKey: A_PUB,
          clientPublicKey: C_PUB,
        },
      },
      {
        name: "kr-rekey",
        input: {
          mode: 2,
          exchangeId: EXCH_2,
          sessionId: SESSION_2,
          epoch: 1,
          prevTh: PREV_TH,
          serverNonce: SERVER_NONCE_2,
          serverPublicKey: B_PUB,
          clientPublicKey: D_PUB,
        },
      },
      {
        name: "kx-login-with-nonzero-epoch",
        input: {
          mode: 1,
          exchangeId: EXCH_1,
          sessionId: SESSION_1,
          epoch: 1,
          prevTh: "",
          serverNonce: SERVER_NONCE_1,
          serverPublicKey: A_PUB,
          clientPublicKey: C_PUB,
        },
        error: "bad_request",
      },
      {
        name: "kr-rekey-with-empty-prevTh",
        input: {
          mode: 2,
          exchangeId: EXCH_2,
          sessionId: SESSION_2,
          epoch: 1,
          prevTh: "",
          serverNonce: SERVER_NONCE_2,
          serverPublicKey: B_PUB,
          clientPublicKey: D_PUB,
        },
        error: "bad_request",
      },
    ],
  ]);

  cases.push([
    "challenge",
    [
      { name: "kx", input: { ceremony: "kx", th: TH_KX, ta: "" } },
      { name: "kr", input: { ceremony: "kr", th: TH_KR, ta: "" } },
      { name: "ta", input: { ceremony: "ta", th: "", ta: TA } },
      { name: "ta+kr", input: { ceremony: "ta+kr", th: TH_KR, ta: TA } },
      { name: "both-empty", input: { ceremony: "kx", th: "", ta: "" }, error: "bad_request" },
      { name: "kx-with-ta", input: { ceremony: "kx", th: TH_KX, ta: TA }, error: "bad_request" },
      { name: "ta-with-th", input: { ceremony: "ta", th: TH_KR, ta: TA }, error: "bad_request" },
      { name: "ta+kr-without-th", input: { ceremony: "ta+kr", th: "", ta: TA }, error: "bad_request" },
    ],
  ]);

  cases.push([
    "ecdh",
    [
      { name: "shared-secret-leading-zero", input: ecdhZero },
      {
        name: "shared-secret-leading-zero-reverse",
        input: { privateKey: B_D, publicKey: B_PUB, peerPublicKey: A_PUB },
      },
      { name: "shared-secret-ordinary", input: { privateKey: C_D, publicKey: C_PUB, peerPublicKey: D_PUB } },
      {
        name: "compressed-point",
        input: { privateKey: A_D, publicKey: A_PUB, peerPublicKey: "02" + B_PUB.slice(2, 66) },
        error: "invalid_public_key",
      },
      {
        name: "hybrid-point",
        input: { privateKey: A_D, publicKey: A_PUB, peerPublicKey: "06" + B_PUB.slice(2) },
        error: "invalid_public_key",
      },
      {
        name: "point-not-on-curve",
        input: { privateKey: A_D, publicKey: A_PUB, peerPublicKey: "04" + "00".repeat(31) + "01" + "00".repeat(31) + "02" },
        error: "invalid_public_key",
      },
      {
        name: "wrong-length-64",
        input: { privateKey: A_D, publicKey: A_PUB, peerPublicKey: B_PUB.slice(0, 128) },
        error: "invalid_public_key",
      },
      {
        name: "wrong-length-66",
        input: { privateKey: A_D, publicKey: A_PUB, peerPublicKey: B_PUB + "00" },
        error: "invalid_public_key",
      },
    ],
  ]);

  cases.push([
    "hkdf",
    [
      { name: "ordinary-ss", input: { ss: SS_NORMAL, th: HKDF_TH } },
      { name: "leading-zero-ss", input: { ss: SS_ZERO, th: TH_KR } },
    ],
  ]);

  cases.push([
    "finished",
    [
      { name: "client-finished", input: clientFinishedInput },
      {
        name: "server-finished",
        input: {
          kind: "server",
          fkS: hex(keys.fkS),
          th: HKDF_TH,
          clientFinished: clientFinishedValue,
          serverTime: TIME_SERVER,
          absoluteExpiresAt: TIME_EXPIRES,
          idleTimeoutSec: 1800,
        },
      },
    ],
  ]);

  cases.push(["msg", await msgCases()]);

  const specContent = "送金要求\n送金先: 山田太郎\n金額: 10000 JPY";
  cases.push([
    "ta",
    [
      { name: "spec-10.3-example", input: { content: specContent, nonce: SPEC_TA_NONCE } },
      {
        name: "emoji-and-japanese",
        input: { content: "承認をお願いします 👍🏽\n金額: 500 JPY", nonce: APPROVAL_ID },
      },
      {
        name: "zwj-family-sequence",
        input: { content: "家族への送金 👨‍👩‍👧\n金額: 3000 JPY", nonce: REQUEST_ID },
      },
      {
        name: "ta-binding",
        input: {
          approvalId: APPROVAL_ID,
          operationId: SPEC_OPERATION_ID,
          approvalNonce: APPROVAL_NONCE,
          sessionId: SESSION_3,
        },
      },
    ],
  ]);

  cases.push([
    "ta-profile",
    [
      { name: "accepts-zwj-and-lf", input: { content: "家族 👨‍👩‍👧\n二行目" } },
      { name: "accepts-zwnj", input: { content: "ژ‌ژ" } },
      { name: "not-nfc", input: { content: "café" }, error: "invalid_content" },
      { name: "contains-cr", input: { content: "a\rb" }, error: "invalid_content" },
      { name: "contains-tab", input: { content: "a\tb" }, error: "invalid_content" },
      { name: "bidi-rlo", input: { content: "abc‮def" }, error: "invalid_content" },
      { name: "trailing-space", input: { content: "abc " }, error: "invalid_content" },
      { name: "trailing-lf", input: { content: "abc\n" }, error: "invalid_content" },
      { name: "space-before-lf", input: { content: "abc \ndef" }, error: "invalid_content" },
      { name: "trailing-ideographic-space", input: { content: "abc　" }, error: "invalid_content" },
      { name: "line-separator", input: { content: "a b" }, error: "invalid_content" },
      { name: "empty", input: { content: "" }, error: "invalid_content" },
    ],
  ]);

  cases.push([
    "utf8",
    [
      { name: "encode-japanese", input: { text: "送金" } },
      { name: "encode-zwj-family", input: { text: "👨‍👩‍👧" } },
      { name: "decode-japanese", input: { bytes: "e698a5" } },
      { name: "invalid-continuation", input: { bytes: "c328" }, error: "invalid_utf8" },
      { name: "encoded-surrogate", input: { bytes: "eda080" }, error: "invalid_utf8" },
      { name: "five-byte-sequence", input: { bytes: "f888808080" }, error: "invalid_utf8" },
      { name: "overlong-slash", input: { bytes: "c0af" }, error: "invalid_utf8" },
      { name: "truncated-three-byte", input: { bytes: "e282" }, error: "invalid_utf8" },
      { name: "invalid-lead-byte", input: { bytes: "ff" }, error: "invalid_utf8" },
    ],
  ]);

  cases.push([
    "base64url",
    [
      { name: "empty", input: { bytes: "" } },
      { name: "one-byte", input: { bytes: "01" } },
      { name: "two-bytes", input: { bytes: "0102" } },
      { name: "three-bytes", input: { bytes: "010203" } },
      { name: "decode-three-bytes", input: { base64url: "AQID" } },
      { name: "decode-url-alphabet", input: { base64url: "_-8" } },
      { name: "padding-equals", input: { base64url: "AQ==" }, error: "invalid_base64url" },
      { name: "non-zero-trailing-bits", input: { base64url: "AB" }, error: "invalid_base64url" },
      { name: "non-zero-trailing-bits-3", input: { base64url: "AAF" }, error: "invalid_base64url" },
      { name: "plus-outside-alphabet", input: { base64url: "A+A" }, error: "invalid_base64url" },
      { name: "slash-outside-alphabet", input: { base64url: "A/A" }, error: "invalid_base64url" },
      { name: "impossible-length", input: { base64url: "AAAAA" }, error: "invalid_base64url" },
    ],
  ]);

  const body = hex(utf8('{"amount":10000}'));
  cases.push([
    "et",
    [
      {
        name: "request-get-minimal",
        input: { kind: "request", method: "GET", path: "/api/items", query: "", headers: [], body: "" },
      },
      {
        name: "request-post-with-headers-and-query",
        input: {
          kind: "request",
          method: "POST",
          path: "/api/transfer",
          query: "a=1&b=%20x",
          headers: [
            ["content-type", "application/json"],
            ["idempotency-key", "k-1"],
          ],
          body,
        },
      },
      {
        name: "request-patch-root",
        input: { kind: "request", method: "PATCH", path: "/", query: "", headers: [], body: "" },
      },
      {
        name: "response-200-with-headers",
        input: {
          kind: "response",
          status: 200,
          headers: [
            ["content-type", "application/json"],
            ["cache-control", "no-store"],
          ],
          body: hex(utf8('{"ok":true}')),
        },
      },
      {
        name: "response-404-relative-location",
        input: { kind: "response", status: 404, headers: [["location", "/api/x"]], body: "" },
      },
      {
        name: "request-method-trace",
        input: { kind: "request", method: "TRACE", path: "/api", query: "", headers: [], body: "" },
        error: "invalid_method",
      },
      {
        name: "request-query-raw-space",
        input: { kind: "request", method: "GET", path: "/api", query: "a=b c", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-path-double-slash",
        input: { kind: "request", method: "GET", path: "/a//b", query: "", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-path-dot-dot",
        input: { kind: "request", method: "GET", path: "/a/../b", query: "", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-path-encoded-slash-lowercase",
        input: { kind: "request", method: "GET", path: "/a/%2f", query: "", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-path-encoded-slash-uppercase",
        input: { kind: "request", method: "GET", path: "/a/%2F", query: "", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-path-encoded-unreserved",
        input: { kind: "request", method: "GET", path: "/%41", query: "", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-path-under-wake",
        input: { kind: "request", method: "GET", path: "/wake/x", query: "", headers: [], body: "" },
        error: "invalid_path",
      },
      {
        name: "request-header-cookie",
        input: { kind: "request", method: "GET", path: "/api", query: "", headers: [["cookie", "a=b"]], body: "" },
        error: "invalid_header",
      },
      {
        name: "request-header-value-crlf",
        input: {
          kind: "request",
          method: "GET",
          path: "/api",
          query: "",
          headers: [["content-type", "text/plain\r\nSet-Cookie: x=1"]],
          body: "",
        },
        error: "invalid_header",
      },
      {
        name: "response-set-cookie",
        input: { kind: "response", status: 200, headers: [["set-cookie", "a=b"]], body: "" },
        error: "invalid_header",
      },
    ],
  ]);

  const out: SuiteFile[] = [];
  for (const suite of SUITES) {
    const entry = cases.find(([s]) => s === suite);
    if (!entry) throw new Error(`no cases for suite ${suite}`);
    out.push({ wake: "WAKE/1", suite, vectors: await materialize(suite, entry[1]) });
  }
  return out;
}

/** Runs each case through the implementation and records its expected value or error code. */
async function materialize(suite: string, cases: Case[]): Promise<Vector[]> {
  const vectors: Vector[] = [];
  for (const c of cases) {
    const where = `${suite}/${c.name}`;
    if (c.error === undefined) {
      vectors.push({ name: c.name, input: c.input, expected: await runCase(suite, c.input) });
      continue;
    }
    try {
      await runCase(suite, c.input);
    } catch (e) {
      if (e instanceof WakeError && e.code === c.error) {
        vectors.push({ name: c.name, input: c.input, expectedError: c.error });
        continue;
      }
      throw new Error(`${where}: expected ${c.error}, got ${String(e)}`);
    }
    throw new Error(`${where}: expected ${c.error}, but the input was accepted`);
  }
  return vectors;
}

/** Generates all suites and writes them into `dir`. Returns the file paths written. */
export async function writeSuites(dir: string = DEFAULT_VECTOR_DIR): Promise<string[]> {
  await mkdir(dir, { recursive: true });
  const paths: string[] = [];
  for (const file of await buildSuites()) {
    const path = join(dir, `${file.suite}.json`);
    await writeFile(path, JSON.stringify(file, null, 2) + "\n");
    paths.push(path);
  }
  return paths;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const dir = process.argv[2] ?? DEFAULT_VECTOR_DIR;
  const paths = await writeSuites(dir);
  console.log(`wrote ${paths.length} suites to ${dir}`);
}

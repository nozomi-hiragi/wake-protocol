// Shared by scripts/generate-vectors.ts and test/vectors.test.ts: maps a vector
// input (hex strings, see spec §16) to the implementation's output.
import {
  type Bytes,
  type EtHeader,
  type EtMethod,
  type MsgHeader,
  type ServerFinishedInput,
  EMPTY,
  WakeError,
  aesKey,
  asApprovalId,
  asApprovalNonce,
  asClientFinishedMac,
  asExchangeId,
  asFinishedKeyC,
  asFinishedKeyS,
  asIv,
  asLoginTranscriptHash,
  asOperationId,
  asRekeyTranscriptHash,
  asRequestId,
  asServerNonce,
  asSessionId,
  asSharedSecret,
  asTaBindingHash,
  asTaNonce,
  asTranscriptHash,
  b64u,
  checkContent,
  clientFinished,
  createOperationIdentity,
  deriveKeys,
  ecdh,
  encodeChallengeInput,
  encodeEtRequest,
  encodeEtResponse,
  encodeHeader,
  encodeLoginTranscript,
  encodeRekeyTranscript,
  encodeTaBinding,
  fromB64u,
  fromHex,
  hex,
  krChallenge,
  kxChallenge,
  loginTranscriptHash,
  lp,
  open as openWire,
  parseEcPublicKey,
  readUtf8,
  rekeyTranscriptHash,
  serverFinished,
  taBinding,
  taChallenge,
  taKrChallenge,
  u16,
  u32,
  u64,
  u8,
  utf8,
} from "../src/index.ts";
import { importEcdhPrivateKey, sealWithIv } from "../src/testing.ts";

export type Obj = Record<string, unknown>;

export const SUITES = [
  "lp",
  "transcript",
  "challenge",
  "ecdh",
  "hkdf",
  "finished",
  "msg",
  "ta",
  "ta-profile",
  "utf8",
  "base64url",
  "et",
] as const;

function str(o: Obj, k: string): string {
  const v = o[k];
  if (typeof v !== "string") throw new Error(`input.${k} must be a string`);
  return v;
}

function num(o: Obj, k: string): number {
  const v = o[k];
  if (typeof v !== "number") throw new Error(`input.${k} must be a number`);
  return v;
}

function bytes(o: Obj, k: string): Bytes {
  return fromHex(str(o, k));
}

/** "" means ε (absent), per the hex convention of spec §16. */
function optBytes(o: Obj, k: string): Bytes | null {
  const s = str(o, k);
  return s === "" ? null : fromHex(s);
}

function bigintOf(v: number): bigint {
  if (!Number.isInteger(v)) throw new WakeError("invalid_integer", "not an integer");
  return BigInt(v);
}

function headersOf(o: Obj, k: string): EtHeader[] {
  const v = o[k];
  if (!Array.isArray(v)) throw new Error(`input.${k} must be an array`);
  return v.map((p) => {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== "string" || typeof p[1] !== "string") {
      throw new Error(`input.${k} entries must be [name, value]`);
    }
    return [p[0], p[1]] as const;
  });
}

function msgHeaderOf(o: Obj): MsgHeader {
  const dir = num(o, "dir");
  if (dir !== 1 && dir !== 2) throw new Error("input.dir must be 1 or 2");
  return {
    dir,
    sessionId: asSessionId(bytes(o, "sessionId")),
    epoch: num(o, "epoch"),
    requestId: asRequestId(bytes(o, "requestId")),
    issuedAt: num(o, "issuedAt"),
    context: str(o, "context"),
    iv: asIv(bytes(o, "iv")),
  };
}

/** Runs one vector input through the implementation. Throws WakeError on rejection. */
export async function runCase(suite: string, o: Obj): Promise<Obj> {
  switch (suite) {
    case "lp": {
      if (Array.isArray(o.fields)) {
        const fields = (o.fields as string[]).map((s) => fromHex(s));
        return { encoded: hex(lp(...fields)) };
      }
      const value = num(o, "value");
      const kind = str(o, "kind");
      const enc = kind === "u8" ? u8(value) : kind === "u16" ? u16(value) : kind === "u32" ? u32(value) : u64(bigintOf(value));
      return { encoded: hex(enc) };
    }

    case "transcript": {
      const mode = num(o, "mode");
      const epoch = num(o, "epoch");
      const prevTh = bytes(o, "prevTh");
      const common = {
        exchangeId: asExchangeId(bytes(o, "exchangeId")),
        sessionId: asSessionId(bytes(o, "sessionId")),
        serverNonce: asServerNonce(bytes(o, "serverNonce")),
        serverPublicKey: await parseEcPublicKey(bytes(o, "serverPublicKey")),
        clientPublicKey: await parseEcPublicKey(bytes(o, "clientPublicKey")),
      };
      // Mode-specific shape (KX: epoch 0 and prevTh ε; KR: prevTh 32B) is a boundary concern.
      if (mode === 1) {
        if (epoch !== 0) throw new WakeError("bad_request", "login epoch must be 0");
        if (prevTh.length !== 0) throw new WakeError("bad_request", "login prevTh must be empty");
        return { encoded: hex(encodeLoginTranscript(common)), th: hex(await loginTranscriptHash(common)) };
      }
      if (mode === 2) {
        const t = { ...common, epoch, prevTh: asTranscriptHash(prevTh) };
        return { encoded: hex(encodeRekeyTranscript(t)), th: hex(await rekeyTranscriptHash(t)) };
      }
      throw new WakeError("bad_request", "unknown mode");
    }

    case "challenge": {
      // Each ceremony fixes which of th / ta is present; reject other shapes here.
      const ceremony = str(o, "ceremony");
      const th = optBytes(o, "th");
      const ta = optBytes(o, "ta");
      const shape = (needTh: boolean, needTa: boolean): void => {
        if (needTh !== (th !== null) || needTa !== (ta !== null)) {
          throw new WakeError("bad_request", "undefined challenge combination");
        }
      };
      switch (ceremony) {
        case "kx": {
          shape(true, false);
          const t = asLoginTranscriptHash(th!);
          return { encoded: hex(encodeChallengeInput(t, EMPTY)), challenge: hex(await kxChallenge(t)) };
        }
        case "kr": {
          shape(true, false);
          const t = asRekeyTranscriptHash(th!);
          return { encoded: hex(encodeChallengeInput(t, EMPTY)), challenge: hex(await krChallenge(t)) };
        }
        case "ta": {
          shape(false, true);
          const a = asTaBindingHash(ta!);
          return { encoded: hex(encodeChallengeInput(EMPTY, a)), challenge: hex(await taChallenge(a)) };
        }
        case "ta+kr": {
          shape(true, true);
          const t = asRekeyTranscriptHash(th!);
          const a = asTaBindingHash(ta!);
          return { encoded: hex(encodeChallengeInput(t, a)), challenge: hex(await taKrChallenge(t, a)) };
        }
        default:
          throw new WakeError("bad_request", "unknown ceremony");
      }
    }

    case "ecdh": {
      const priv = await importEcdhPrivateKey(bytes(o, "privateKey"), await parseEcPublicKey(bytes(o, "publicKey")));
      return { sharedSecret: hex(await ecdh(priv, await parseEcPublicKey(bytes(o, "peerPublicKey")))) };
    }

    case "hkdf": {
      const k = await deriveKeys(asSharedSecret(bytes(o, "ss")), asTranscriptHash(bytes(o, "th")));
      return { kC2s: hex(k.kC2s), kS2c: hex(k.kS2c), fkC: hex(k.fkC), fkS: hex(k.fkS) };
    }

    case "finished": {
      if (o.kind === "client") {
        const mac = await clientFinished(asFinishedKeyC(bytes(o, "fkC")), asTranscriptHash(bytes(o, "th")));
        return { clientFinished: hex(mac) };
      }
      const input: ServerFinishedInput = {
        th: asTranscriptHash(bytes(o, "th")),
        clientFinished: asClientFinishedMac(bytes(o, "clientFinished")),
        serverTime: num(o, "serverTime"),
        absoluteExpiresAt: num(o, "absoluteExpiresAt"),
        idleTimeoutSec: num(o, "idleTimeoutSec"),
      };
      return { serverFinished: hex(await serverFinished(asFinishedKeyS(bytes(o, "fkS")), input)) };
    }

    case "msg": {
      switch (str(o, "kind")) {
        case "header":
          return { header: hex(encodeHeader(msgHeaderOf(o))) };
        case "seal": {
          const key = await aesKey(bytes(o, "key"));
          const wire = await sealWithIv(key, msgHeaderOf(o), bytes(o, "plaintext"));
          return { wire: hex(wire) };
        }
        case "open": {
          const key = await aesKey(bytes(o, "key"));
          const { plaintext } = await openWire(key, bytes(o, "wire"), num(o, "expectDir"));
          return { plaintext: hex(plaintext) };
        }
        default:
          throw new Error("unknown msg kind");
      }
    }

    case "ta": {
      if (o.content !== undefined) {
        const id = await createOperationIdentity(str(o, "content"), asTaNonce(bytes(o, "nonce")));
        return { hashInput: id.hashInput, hashInputLength: utf8(id.hashInput).length, operationId: id.operationId };
      }
      const b = {
        approvalId: asApprovalId(bytes(o, "approvalId")),
        operationId: asOperationId(bytes(o, "operationId")),
        approvalNonce: asApprovalNonce(bytes(o, "approvalNonce")),
        sessionId: asSessionId(bytes(o, "sessionId")),
      };
      return { encoded: hex(encodeTaBinding(b)), ta: hex(await taBinding(b)) };
    }

    case "ta-profile": {
      checkContent(str(o, "content"));
      return { accepted: true };
    }

    case "utf8": {
      if (o.text !== undefined) return { bytes: hex(utf8(str(o, "text"))) };
      return { text: readUtf8(bytes(o, "bytes")) };
    }

    case "base64url": {
      if (o.base64url !== undefined) return { bytes: hex(fromB64u(str(o, "base64url"))) };
      return { base64url: b64u(bytes(o, "bytes")) };
    }

    case "et": {
      if (o.kind === "request") {
        const enc = encodeEtRequest({
          method: str(o, "method") as EtMethod,
          path: str(o, "path"),
          query: str(o, "query"),
          headers: headersOf(o, "headers"),
          body: bytes(o, "body"),
        });
        return { encoded: hex(enc) };
      }
      const enc = encodeEtResponse({
        status: num(o, "status"),
        headers: headersOf(o, "headers"),
        body: bytes(o, "body"),
      });
      return { encoded: hex(enc) };
    }

    default:
      throw new Error(`unknown suite ${suite}`);
  }
}


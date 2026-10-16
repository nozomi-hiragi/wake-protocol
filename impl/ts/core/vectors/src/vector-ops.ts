// Maps a vector input to the implementation's output.
import { hex, base64urlnopad } from "@scure/base";
import {
  type EtHeader,
  type MsgHeader,
  type ServerFinishedInput,
  WakeError,
  aesKey,
  asApprovalId,
  asApprovalNonce,
  asClientFinishedMac,
  asC2sKey,
  asS2cKey,
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
  DIR_C2S,
  DIR_S2C,
  checkContent,
  clientFinished,
  createOperationIdentity,
  deriveKeys,
  ecdh,
  encodeEtRequest,
  encodeEtResponse,
  encodeHeader,
  encodeLoginTranscript,
  encodeRekeyTranscript,
  encodeTaBinding,
  krChallenge,
  kxChallenge,
  loginTranscriptHash,
  open as openWire,
  parseEcPublicKey,
  rekeyTranscriptHash,
  serverFinished,
  taBinding,
  taChallenge,
  taKrChallenge,
  Bytes,
} from "@wake-protocol/core";
import {
  EMPTY,
  Byte,
  Byte2,
  Byte4,
  Byte8,
} from "@wake-protocol/bytes";
import { encodeU32LengthPrefixed, bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import { encodeChallengeInput, importEcdhPrivateKey, sealWithIv } from "@wake-protocol/core/testing";

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

// Map generic codec failures to the vector's expected WAKE error code.
function remap<T>(code: string, fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof RangeError || e instanceof TypeError || e instanceof SyntaxError) throw new WakeError(code, e.message);
    throw e;
  }
}

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
  return new Bytes(hex.decode(str(o, k)));
}

/** "" means ε (absent), per the hex convention of spec §16. */
function optBytes(o: Obj, k: string): Bytes | null {
  const s = str(o, k);
  return s === "" ? null : new Bytes(hex.decode(s));
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
        const fields = (o.fields as string[]).map((s) => hex.decode(s));
        return { encoded: hex.encode(encodeU32LengthPrefixed(...fields)) };
      }
      const value = num(o, "value");
      const kind = str(o, "kind");
      const enc = kind === "u8" ? new Byte(value) : kind === "u16" ? new Byte2(value) : kind === "u32" ? new Byte4(value) : new Byte8(bigintOf(value));
      return { encoded: hex.encode(enc.toUint8Array()) };
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
        return { encoded: hex.encode((encodeLoginTranscript(common)).toUint8Array()), th: hex.encode((await loginTranscriptHash(common)).toUint8Array()) };
      }
      if (mode === 2) {
        const t = { ...common, epoch, prevTh: asTranscriptHash(prevTh) };
        return { encoded: hex.encode(remap("bad_request", () => encodeRekeyTranscript(t)).toUint8Array()), th: hex.encode((await rekeyTranscriptHash(t)).toUint8Array()) };
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
          return { encoded: hex.encode((encodeChallengeInput(t, EMPTY)).toUint8Array()), challenge: hex.encode((await kxChallenge(t)).toUint8Array()) };
        }
        case "kr": {
          shape(true, false);
          const t = asRekeyTranscriptHash(th!);
          return { encoded: hex.encode((encodeChallengeInput(t, EMPTY)).toUint8Array()), challenge: hex.encode((await krChallenge(t)).toUint8Array()) };
        }
        case "ta": {
          shape(false, true);
          const a = asTaBindingHash(ta!);
          return { encoded: hex.encode((encodeChallengeInput(EMPTY, a)).toUint8Array()), challenge: hex.encode((await taChallenge(a)).toUint8Array()) };
        }
        case "ta+kr": {
          shape(true, true);
          const t = asRekeyTranscriptHash(th!);
          const a = asTaBindingHash(ta!);
          return { encoded: hex.encode((encodeChallengeInput(t, a)).toUint8Array()), challenge: hex.encode((await taKrChallenge(t, a)).toUint8Array()) };
        }
        default:
          throw new WakeError("bad_request", "unknown ceremony");
      }
    }

    case "ecdh": {
      const priv = await importEcdhPrivateKey(bytes(o, "privateKey"), await parseEcPublicKey(bytes(o, "publicKey")));
      return { sharedSecret: hex.encode((await ecdh(priv, await parseEcPublicKey(bytes(o, "peerPublicKey")))).toUint8Array()) };
    }

    case "hkdf": {
      const k = await deriveKeys(asSharedSecret(bytes(o, "ss")), asTranscriptHash(bytes(o, "th")));
      return { kC2s: hex.encode(k.kC2s.toUint8Array()), kS2c: hex.encode(k.kS2c.toUint8Array()), fkC: hex.encode(k.fkC.toUint8Array()), fkS: hex.encode(k.fkS.toUint8Array()) };
    }

    case "finished": {
      if (o.kind === "client") {
        const mac = await clientFinished(asFinishedKeyC(bytes(o, "fkC")), asTranscriptHash(bytes(o, "th")));
        return { clientFinished: hex.encode(mac.toUint8Array()) };
      }
      const input: ServerFinishedInput = {
        th: asTranscriptHash(bytes(o, "th")),
        clientFinished: asClientFinishedMac(bytes(o, "clientFinished")),
        serverTime: num(o, "serverTime"),
        absoluteExpiresAt: num(o, "absoluteExpiresAt"),
        idleTimeoutSec: num(o, "idleTimeoutSec"),
      };
      return { serverFinished: hex.encode((await serverFinished(asFinishedKeyS(bytes(o, "fkS")), input)).toUint8Array()) };
    }

    case "msg": {
      switch (str(o, "kind")) {
        case "header":
          return { header: hex.encode((encodeHeader(msgHeaderOf(o))).toUint8Array()) };
        case "seal": {
          const header = msgHeaderOf(o);
          const raw = bytes(o, "key");
          const key = await aesKey(header.dir === 1 ? asC2sKey(raw) : asS2cKey(raw));
          const wire = await sealWithIv(key, header, bytes(o, "plaintext"));
          return { wire: hex.encode(wire.toUint8Array()) };
        }
        case "open": {
          const expectDir = num(o, "expectDir");
          if (expectDir !== 1 && expectDir !== 2) throw new WakeError("bad_request", "unexpected dir");
          const raw = bytes(o, "key");
          const wire = bytes(o, "wire");
          const opts = o.maxPlaintext === undefined ? undefined : { maxPlaintext: num(o, "maxPlaintext") };
          const { plaintext } = expectDir === DIR_C2S
            ? await openWire(await aesKey(asC2sKey(raw)), wire, DIR_C2S, opts)
            : await openWire(await aesKey(asS2cKey(raw)), wire, DIR_S2C, opts);
          return { plaintext: hex.encode(plaintext.toUint8Array()) };
        }
        default:
          throw new Error("unknown msg kind");
      }
    }

    case "ta": {
      if (o.content !== undefined) {
        const id = await createOperationIdentity(str(o, "content"), asTaNonce(bytes(o, "nonce")));
        return { hashInput: id.hashInput, hashInputLength: utf8ToBytes(id.hashInput).length, operationId: id.operationId };
      }
      const b = {
        approvalId: asApprovalId(bytes(o, "approvalId")),
        operationId: asOperationId(bytes(o, "operationId")),
        approvalNonce: asApprovalNonce(bytes(o, "approvalNonce")),
        sessionId: asSessionId(bytes(o, "sessionId")),
      };
      return { encoded: hex.encode((encodeTaBinding(b)).toUint8Array()), ta: hex.encode((await taBinding(b)).toUint8Array()) };
    }

    case "ta-profile": {
      checkContent(str(o, "content"));
      return { accepted: true };
    }

    case "utf8": {
      if (o.text !== undefined) return { bytes: hex.encode((remap("invalid_utf8", () => utf8ToBytes(str(o, "text"))))) };
      return { text: remap("invalid_utf8", () => bytesToUtf8((bytes(o, "bytes")).toUint8Array())) };
    }

    case "base64url": {
      if (o.base64url !== undefined) {
        const input = str(o, "base64url");
        let decoded: Uint8Array;
        try {
          decoded = base64urlnopad.decode(input);
        } catch (e) {
          throw new WakeError("invalid_base64url", e instanceof Error ? e.message : String(e));
        }
        return { bytes: hex.encode(decoded) };
      }
      return { base64url: base64urlnopad.encode((bytes(o, "bytes")).toUint8Array()) };
    }

    case "et": {
      if (o.kind === "request") {
        const enc = encodeEtRequest({
          method: str(o, "method"),
          url: str(o, "url"),
          headers: headersOf(o, "headers"),
          body: bytes(o, "body"),
        });
        return { encoded: hex.encode(enc.toUint8Array()) };
      }
      const enc = encodeEtResponse({
        status: num(o, "status"),
        headers: headersOf(o, "headers"),
        body: bytes(o, "body"),
      });
      return { encoded: hex.encode(enc.toUint8Array()) };
    }

    default:
      throw new Error(`unknown suite ${suite}`);
  }
}


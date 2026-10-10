// Shared by scripts/generate-vectors.ts and test/vectors.test.ts: maps a vector
// input (hex strings, see spec §16) to the implementation's output.
import {
  type Bytes,
  type Ceremony,
  type EtHeader,
  type EtMethod,
  type MsgHeader,
  type ServerFinishedInput,
  type TranscriptInput,
  b64u,
  checkContent,
  createOperationIdentity,
  clientFinished,
  deriveKeys,
  ecdh,
  encodeChallengeInput,
  encodeEtRequest,
  encodeEtResponse,
  encodeHeader,
  encodeTaBinding,
  encodeTranscript,
  fromB64u,
  fromHex,
  hex,
  importEcdhPrivateKey,
  lp,
  aesKey,
  open as openWire,
  readUtf8,
  sealWithIv,
  serverFinished,
  taBinding,
  transcriptHash,
  u16,
  u32,
  u64,
  u8,
  utf8,
  webauthnChallenge,
} from "../src/index.ts";

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
    sessionId: bytes(o, "sessionId"),
    epoch: num(o, "epoch"),
    requestId: bytes(o, "requestId"),
    issuedAt: num(o, "issuedAt"),
    context: str(o, "context"),
    iv: bytes(o, "iv"),
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
      const enc = kind === "u8" ? u8(value) : kind === "u16" ? u16(value) : kind === "u32" ? u32(value) : u64(value);
      return { encoded: hex(enc) };
    }

    case "transcript": {
      const t: TranscriptInput = {
        mode: num(o, "mode") as TranscriptInput["mode"],
        exchangeId: bytes(o, "exchangeId"),
        sessionId: bytes(o, "sessionId"),
        epoch: num(o, "epoch"),
        prevTh: bytes(o, "prevTh"),
        serverNonce: bytes(o, "serverNonce"),
        serverPublicKey: bytes(o, "serverPublicKey"),
        clientPublicKey: bytes(o, "clientPublicKey"),
      };
      return { encoded: hex(encodeTranscript(t)), th: hex(await transcriptHash(t)) };
    }

    case "challenge": {
      const ceremony = str(o, "ceremony") as Ceremony;
      const th = optBytes(o, "th");
      const ta = optBytes(o, "ta");
      return {
        encoded: hex(encodeChallengeInput(ceremony, th, ta)),
        challenge: hex(await webauthnChallenge(ceremony, th, ta)),
      };
    }

    case "ecdh": {
      const priv = await importEcdhPrivateKey(bytes(o, "privateKey"), bytes(o, "publicKey"));
      return { sharedSecret: hex(await ecdh(priv, bytes(o, "peerPublicKey"))) };
    }

    case "hkdf": {
      const k = await deriveKeys(bytes(o, "ss"), bytes(o, "th"));
      return { kC2s: hex(k.kC2s), kS2c: hex(k.kS2c), fkC: hex(k.fkC), fkS: hex(k.fkS) };
    }

    case "finished": {
      if (o.kind === "client") {
        return { clientFinished: hex(await clientFinished(bytes(o, "fkC"), bytes(o, "th"))) };
      }
      const input: ServerFinishedInput = {
        th: bytes(o, "th"),
        clientFinished: bytes(o, "clientFinished"),
        serverTime: num(o, "serverTime"),
        absoluteExpiresAt: num(o, "absoluteExpiresAt"),
        idleTimeoutSec: num(o, "idleTimeoutSec"),
      };
      return { serverFinished: hex(await serverFinished(bytes(o, "fkS"), input)) };
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
        const id = await createOperationIdentity(str(o, "content"), bytes(o, "nonce"));
        return { hashInput: id.hashInput, hashInputLength: utf8(id.hashInput).length, operationId: id.operationId };
      }
      const b = {
        approvalId: bytes(o, "approvalId"),
        operationId: bytes(o, "operationId"),
        approvalNonce: bytes(o, "approvalNonce"),
        sessionId: bytes(o, "sessionId"),
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


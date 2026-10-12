// Public API of the WAKE reference implementation (spec §4–§11).
// Test-only helpers (fixed IV, fixed private keys) live in ./testing.ts.
export { Bytes } from "@wake-protocol/bytes";
export { WakeError } from "./spec/errors.ts";
export { LABELS } from "./spec/labels.ts";
export { decodeBase64urlField, parseJsonObject } from "./spec/json.ts";
export {
  type ApprovalId,
  type ApprovalNonce,
  type C2sKey,
  type ClientFinishedMac,
  type EcPublicKey,
  type ExchangeId,
  type FinishedKeyC,
  type FinishedKeyS,
  type Iv,
  type LoginTranscriptHash,
  type OperationId,
  type RekeyTranscriptHash,
  type RequestId,
  type S2cKey,
  type ServerFinishedMac,
  type ServerNonce,
  type SessionId,
  type SharedSecret,
  type TaBindingHash,
  type TaNonce,
  type TranscriptHash,
  type WebAuthnChallenge,
  asApprovalId,
  asApprovalNonce,
  asC2sKey,
  asClientFinishedMac,
  asExchangeId,
  asFinishedKeyC,
  asFinishedKeyS,
  asIv,
  asLoginTranscriptHash,
  asOperationId,
  asRekeyTranscriptHash,
  asRequestId,
  asS2cKey,
  asServerFinishedMac,
  asServerNonce,
  asSessionId,
  asSharedSecret,
  asTaBindingHash,
  asTaNonce,
  asTranscriptHash,
  asWebAuthnChallenge,
} from "./spec/types.ts";
export { type C2sCryptoKey, type S2cCryptoKey, type FinishedCryptoKeyC, type FinishedCryptoKeyS, aesKey, hmacKey } from "./spec/crypto.ts";
export {
  type EphemeralKeyPair,
  ecdh,
  generateEphemeral,
  parseEcPublicKey,
} from "./keys/ecdh.ts";
export {
  newApprovalId,
  newApprovalNonce,
  newExchangeId,
  newIv,
  newRequestId,
  newServerNonce,
  newSessionId,
  newTaNonce,
} from "./keys/ids.ts";
export {
  type KeySchedule,
  deriveKeys,
} from "./kx/schedule.ts";
export {
  type LoginTranscriptInput,
  type RekeyTranscriptInput,
  MODE_LOGIN,
  MODE_REKEY,
  encodeLoginTranscript,
  encodeRekeyTranscript,
  loginTranscriptHash,
  rekeyTranscriptHash,
} from "./kx/transcript.ts";
export {
  type ServerFinishedInput,
  clientFinished,
  serverFinished,
  verifyClientFinished,
  verifyServerFinished,
} from "./kx/finished.ts";
export {
  type TaBindingInput,
  encodeTaBinding,
  taBinding,
} from "./kx/binding.ts";
export {
  krChallenge,
  kxChallenge,
  taChallenge,
  taKrChallenge,
} from "./kx/challenge.ts";
export {
  type MsgHeader,
  type MsgOptions,
  type ParsedWire,
  DEFAULT_MAX_PLAINTEXT,
  DIR_C2S,
  DIR_S2C,
  checkContext,
  checkPlaintextLength,
  encodeHeader,
  parseWire,
} from "./msg/header.ts";
export {
  type SealInput,
  open,
  openParsed,
  seal,
} from "./msg/aead.ts";
export {
  checkContent,
} from "./ta/content.ts";
export {
  createOperationIdentity,
  hashInput,
  operationId,
  parseOperationIdHex,
} from "./ta/operation.ts";
export {
  type EtHeader,
  type EtMethod,
  type EtOptions,
  type EtRequest,
  type EtResponse,
  ET_BODY_MAX,
  ET_HEADERS_MAX,
  ET_METHODS,
  ET_PATH_MAX,
  ET_QUERY_MAX,
  ET_REQUEST_MAX_ENCODED,
  ET_RESPONSE_MAX_ENCODED,
  ET_REQ_LABEL,
  ET_RES_LABEL,
} from "./et/types.ts";
export {
  checkMethod,
  checkPath,
  checkQuery,
  checkRequestHeaders,
  checkResponseHeaders,
  checkStatus,
} from "./et/validate.ts";
export {
  decodeEtRequest,
  decodeEtResponse,
  encodeEtRequest,
  encodeEtResponse,
} from "./et/codec.ts";

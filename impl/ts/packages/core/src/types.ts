// Distinct types for fixed-length byte strings (spec §4–§5, §8, §10).
// Branded types are erased at runtime; the as* functions are the boundary
// where external bytes are length-checked and branded.
import type { Bytes } from "./encoding.ts";
import { fail } from "./errors.ts";

export type Brand<B extends string> = Bytes & { readonly __brand: B };

export type SessionId = Brand<"SessionId">; // 32B
export type ExchangeId = Brand<"ExchangeId">; // 16B
export type RequestId = Brand<"RequestId">; // 16B
export type ApprovalId = Brand<"ApprovalId">; // 16B
export type ServerNonce = Brand<"ServerNonce">; // 32B
export type ApprovalNonce = Brand<"ApprovalNonce">; // 32B
export type TaNonce = Brand<"TaNonce">; // 16B
export type Iv = Brand<"Iv">; // 12B
export type LoginTranscriptHash = Brand<"LoginTranscriptHash">; // 32B, mode 0x01
export type RekeyTranscriptHash = Brand<"RekeyTranscriptHash">; // 32B, mode 0x02
/** A stored transcript hash whose mode is not tracked in the type (e.g. prevTh, key schedule input). */
export type TranscriptHash = LoginTranscriptHash | RekeyTranscriptHash;
export type TaBindingHash = Brand<"TaBindingHash">; // 32B
export type WebAuthnChallenge = Brand<"WebAuthnChallenge">; // 32B
export type SharedSecret = Brand<"SharedSecret">; // 32B
export type OperationId = Brand<"OperationId">; // 32B raw
export type ClientFinishedMac = Brand<"ClientFinishedMac">; // 32B
export type ServerFinishedMac = Brand<"ServerFinishedMac">; // 32B
export type C2sKey = Brand<"C2sKey">; // 32B
export type S2cKey = Brand<"S2cKey">; // 32B
export type FinishedKeyC = Brand<"FinishedKeyC">; // 32B
export type FinishedKeyS = Brand<"FinishedKeyS">; // 32B
/** 65-byte SEC1 uncompressed P-256 point, validated by parseEcPublicKey. */
export type EcPublicKey = Brand<"EcPublicKey">;

function fixed<T extends Bytes>(name: string, len: number): (b: Bytes) => T {
  return (b) => {
    if (b.length !== len) fail("bad_request", `${name} must be ${len} bytes`);
    return b as T;
  };
}

export const asSessionId = fixed<SessionId>("sessionId", 32);
export const asExchangeId = fixed<ExchangeId>("exchangeId", 16);
export const asRequestId = fixed<RequestId>("requestId", 16);
export const asApprovalId = fixed<ApprovalId>("approvalId", 16);
export const asServerNonce = fixed<ServerNonce>("serverNonce", 32);
export const asApprovalNonce = fixed<ApprovalNonce>("approvalNonce", 32);
export const asTaNonce = fixed<TaNonce>("taNonce", 16);
export const asIv = fixed<Iv>("iv", 12);
export const asLoginTranscriptHash = fixed<LoginTranscriptHash>("th", 32);
export const asRekeyTranscriptHash = fixed<RekeyTranscriptHash>("th", 32);
export const asTranscriptHash = fixed<TranscriptHash>("th", 32);
export const asTaBindingHash = fixed<TaBindingHash>("ta", 32);
export const asWebAuthnChallenge = fixed<WebAuthnChallenge>("challenge", 32);
export const asSharedSecret = fixed<SharedSecret>("sharedSecret", 32);
export const asOperationId = fixed<OperationId>("operationId", 32);
export const asClientFinishedMac = fixed<ClientFinishedMac>("clientFinished", 32);
export const asServerFinishedMac = fixed<ServerFinishedMac>("serverFinished", 32);
export const asC2sKey = fixed<C2sKey>("kC2s", 32);
export const asS2cKey = fixed<S2cKey>("kS2c", 32);
export const asFinishedKeyC = fixed<FinishedKeyC>("fkC", 32);
export const asFinishedKeyS = fixed<FinishedKeyS>("fkS", 32);

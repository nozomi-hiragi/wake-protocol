// Spec §4.6, §5.3–5.4, §8.3, §10.3: random fixed-length WAKE values.
import { randomBytes } from "@wake-protocol/crypto";
import {
  type ApprovalId,
  type ApprovalNonce,
  type ExchangeId,
  type Iv,
  type RequestId,
  type ServerNonce,
  type SessionId,
  type TaNonce,
  asApprovalId,
  asApprovalNonce,
  asExchangeId,
  asIv,
  asRequestId,
  asServerNonce,
  asSessionId,
  asTaNonce,
} from "../spec/types.ts";

// Random generators return branded values of the spec's fixed lengths.
export const newSessionId = (): SessionId => asSessionId(randomBytes(32));
export const newExchangeId = (): ExchangeId => asExchangeId(randomBytes(16));
export const newRequestId = (): RequestId => asRequestId(randomBytes(16));
export const newApprovalId = (): ApprovalId => asApprovalId(randomBytes(16));
export const newServerNonce = (): ServerNonce => asServerNonce(randomBytes(32));
export const newApprovalNonce = (): ApprovalNonce => asApprovalNonce(randomBytes(32));
export const newTaNonce = (): TaNonce => asTaNonce(randomBytes(16));
/** Fresh 96-bit GCM IV (§8.3). */
export const newIv = (): Iv => asIv(randomBytes(12));

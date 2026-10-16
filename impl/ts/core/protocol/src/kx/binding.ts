// Spec §5.4: TA approval binding.
import { Bytes } from "@wake-protocol/bytes";
import { sha256 } from "@wake-protocol/crypto";
import { LABELS } from "../spec/labels.ts";
import { labeled } from "../spec/domain.ts";
import {
  type ApprovalId,
  type ApprovalNonce,
  type OperationId,
  type SessionId,
  type TaBindingHash,
  asTaBindingHash,
} from "../spec/types.ts";

export interface TaBindingInput {
  approvalId: ApprovalId;
  operationId: OperationId;
  approvalNonce: ApprovalNonce;
  sessionId: SessionId;
}

export function encodeTaBinding(t: TaBindingInput): Bytes {
  return labeled(LABELS.taApprove, t.approvalId, t.operationId, t.approvalNonce, t.sessionId);
}

export async function taBinding(t: TaBindingInput): Promise<TaBindingHash> {
  return asTaBindingHash(await sha256(encodeTaBinding(t).toUint8Array()));
}

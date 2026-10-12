// Spec §10.9: wake/ta/reject needs the session only (no WebAuthn); the approver alone may reject.
import { WakeError } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { OperationStatus, SessionRecord } from "../store/types.ts";
import { operationIdParam } from "./params.ts";

export async function rejectOperation(
  body: Record<string, unknown>,
  session: SessionRecord,
  options: ServerOptions,
): Promise<unknown> {
  const operationId = operationIdParam(body.operationId);
  const result = await options.store.rejectOperation(operationId, session.userId, session.sessionId.toUint8Array(), options.now());
  if (result === "not_found") {
    throw new WakeError("not_found");
  }
  if (result === "rejected") {
    return { result, status: "REJECTED" };
  }
  const op = await options.store.getOperation(operationId, options.now());
  const status: OperationStatus = op?.status ?? "EXPIRED";
  return { result, status };
}

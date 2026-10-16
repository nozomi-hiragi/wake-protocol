// Spec §10.3, §10.4, §10.6, §10.11: strict parsing and verification of WAKE-TA operations.
import { hex } from "@scure/base";
import {
  WakeError,
  asTaNonce,
  checkContent,
  hashInput,
  operationId,
  parseOperationIdHex,
} from "@wake-protocol/core";
import { integer, object } from "./json.ts";

export const OPERATION_STATUSES = ["PENDING", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED"] as const;
export type OperationStatus = typeof OPERATION_STATUSES[number];

export interface OperationSummary {
  operationId: string;
  content: string;
  nonce: string;
  status: OperationStatus;
  createdAt: number;
  expiresAt: number;
}

/** An operation whose operationId was recomputed from content and nonce (§10.11 steps 3-4). */
export interface VerifiedOperation extends OperationSummary {
  /** Assembled locally (§10.3); never received. */
  hashInput: string;
  decidedAt: number | null;
}

export interface OperationList {
  operations: OperationSummary[];
  nextCursor: string | null;
}

export type TaApproveResult = "approved" | "already_decided" | "expired";
export type TaRejectResult = "rejected" | "already_decided" | "expired";

function status(value: unknown): OperationStatus {
  if (typeof value !== "string" || !(OPERATION_STATUSES as readonly string[]).includes(value)) {
    throw new WakeError("bad_request");
  }
  return value as OperationStatus;
}

/**
 * Validates one received operation. `requestedId` is the identifier the user asked for; the response's own
 * operationId is only compared against the recomputed value, never trusted.
 */
export async function verifyOperation(value: unknown, requestedId?: string): Promise<OperationSummary> {
  const o = object(value);
  if (typeof o.content !== "string" || typeof o.nonce !== "string" || typeof o.operationId !== "string") {
    throw new WakeError("bad_request");
  }
  checkContent(o.content);
  if (!/^[0-9a-f]{32}$/u.test(o.nonce)) {
    throw new WakeError("bad_request");
  }
  parseOperationIdHex(o.operationId);
  const input = hashInput(o.content, asTaNonce(hex.decode(o.nonce)));
  const computed = hex.encode((await operationId(input)).toUint8Array());
  if (computed !== (requestedId ?? o.operationId) || computed !== o.operationId) {
    throw new WakeError("operation_mismatch");
  }
  return {
    operationId: computed,
    content: o.content,
    nonce: o.nonce,
    status: status(o.status),
    createdAt: integer(o.createdAt),
    expiresAt: integer(o.expiresAt),
  };
}

export async function verifiedOperation(value: unknown, requestedId: string): Promise<VerifiedOperation> {
  const summary = await verifyOperation(value, requestedId);
  const o = object(value);
  const decidedAt = o.decidedAt === null ? null : integer(o.decidedAt);
  return {
    ...summary,
    hashInput: hashInput(summary.content, asTaNonce(hex.decode(summary.nonce))),
    decidedAt,
  };
}

export async function parseOperationList(value: Record<string, unknown>): Promise<OperationList> {
  if (!Array.isArray(value.operations) || value.operations.length > 20) {
    throw new WakeError("bad_request");
  }
  const operations = await Promise.all(value.operations.map((entry) => verifyOperation(entry)));
  if (value.nextCursor !== null && (typeof value.nextCursor !== "string" || value.nextCursor.length === 0)) {
    throw new WakeError("bad_request");
  }
  return { operations, nextCursor: value.nextCursor };
}

export function parseResult<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    throw new WakeError("bad_request");
  }
  return value as T;
}

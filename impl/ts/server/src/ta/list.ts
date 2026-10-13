// Spec §10.6: wake/ta/list and wake/ta/get (only the approver sees an operation).
import { base64urlnopad } from "@scure/base";
import { bytesToUtf8, utf8ToBytes } from "@wake-protocol/codec";
import { decodeBase64urlField, WakeError } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { OperationQuery, OperationRecord, OperationStatus, SessionRecord } from "../store/types.ts";
import { operationIdParam } from "./params.ts";

const STATUSES: readonly OperationStatus[] = ["PENDING", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED"];
const MAX_LIMIT = 20;

export function operationJson(op: OperationRecord): Record<string, unknown> {
  return {
    operationId: op.operationId,
    content: op.content,
    nonce: op.nonce,
    status: op.status,
    createdAt: op.createdAt,
    expiresAt: op.expiresAt,
  };
}

// The cursor is opaque to clients: base64url of "<createdAt>:<operationId>" of the last returned record.
function encodeCursor(op: OperationRecord): string {
  return base64urlnopad.encode(utf8ToBytes(`${op.createdAt}:${op.operationId}`));
}

function decodeCursor(value: unknown): NonNullable<OperationQuery["after"]> {
  const raw = decodeBase64urlField(value, "invalid_request");
  let text: string;
  try {
    text = bytesToUtf8(raw);
  } catch {
    throw new WakeError("invalid_request");
  }
  const match = /^(0|[1-9][0-9]{0,15}):([0-9a-f]{64})$/u.exec(text);
  if (!match || !Number.isSafeInteger(Number(match[1]))) {
    throw new WakeError("invalid_request");
  }
  return { createdAt: Number(match[1]), operationId: match[2]! };
}

function parseQuery(body: Record<string, unknown>, session: SessionRecord, now: number): OperationQuery {
  const limit = body.limit === undefined ? MAX_LIMIT : body.limit;
  if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    throw new WakeError("invalid_request");
  }
  if (body.status !== undefined && !STATUSES.includes(body.status as OperationStatus)) {
    throw new WakeError("invalid_request");
  }
  return {
    approverUserId: session.userId,
    limit,
    now,
    ...(body.status !== undefined ? { status: body.status as OperationStatus } : {}),
    ...(body.cursor !== undefined ? { after: decodeCursor(body.cursor) } : {}),
  };
}

export async function listOperations(
  body: Record<string, unknown>,
  session: SessionRecord,
  options: ServerOptions,
): Promise<unknown> {
  const query = parseQuery(body, session, options.now());
  // One extra record tells whether another page exists.
  const found = await options.store.listOperations({ ...query, limit: query.limit + 1 });
  const page = found.slice(0, query.limit);
  return {
    operations: page.map(operationJson),
    nextCursor: found.length > query.limit ? encodeCursor(page.at(-1)!) : null,
  };
}

export async function getOperation(
  body: Record<string, unknown>,
  session: SessionRecord,
  options: ServerOptions,
): Promise<unknown> {
  const operationId = operationIdParam(body.operationId);
  const op = await options.store.getOperation(operationId, options.now());
  if (!op || op.approverUserId !== session.userId) {
    throw new WakeError("not_found");
  }
  return { ...operationJson(op), decidedAt: op.decision?.decidedAt ?? null };
}

// Spec §10.6, §12.2: routing of the wake/ta/* contexts.
import { WakeError } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { SessionRecord } from "../store/types.ts";
import { approve } from "./approve.ts";
import { challengeApproval } from "./challenge.ts";
import { getOperation, listOperations } from "./list.ts";
import { rejectOperation } from "./reject.ts";

const handlers = {
  "wake/ta/list": listOperations,
  "wake/ta/get": getOperation,
  "wake/ta/challenge": challengeApproval,
  "wake/ta/approve": approve,
  "wake/ta/reject": rejectOperation,
} as const;

export function isTaContext(context: string): boolean {
  return Object.hasOwn(handlers, context);
}

export function dispatchTa(
  context: string,
  body: Record<string, unknown>,
  session: SessionRecord,
  options: ServerOptions,
): Promise<unknown> {
  if (!isTaContext(context)) {
    throw new WakeError("invalid_context");
  }
  return handlers[context as keyof typeof handlers](body, session, options);
}

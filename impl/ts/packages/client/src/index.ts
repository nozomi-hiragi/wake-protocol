// Public API of the WAKE client (spec §6.1, §7.7, §8, §9, §12.2).
export { WakeClient } from "./client.ts";
export type { WakeClientOptions, SessionInfo, WakeSessionInfo, RekeyInfo, ApproveOptions, ApproveInfo, TaKrResult, WakeFetchInit } from "./client.ts";
export { segmentHashInput } from "./display.ts";
export type { DisplaySegment, SegmentKind, SegmentOptions } from "./display.ts";
export { OPERATION_STATUSES } from "./ta.ts";
export type {
  OperationList,
  OperationStatus,
  OperationSummary,
  TaApproveResult,
  TaRejectResult,
  VerifiedOperation,
} from "./ta.ts";
export { navigatorGetAssertion } from "./assertion.ts";
export type { GetAssertion, GetAssertionOptions, AuthenticationResponseJSON } from "./assertion.ts";

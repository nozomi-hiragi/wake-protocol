// Public API of the WAKE client (spec §6.1, §7.7, §8, §12.2).
export { WakeClient } from "./client.ts";
export type { WakeClientOptions, SessionInfo, WakeSessionInfo } from "./client.ts";
export { navigatorGetAssertion } from "./assertion.ts";
export type { GetAssertion, GetAssertionOptions, AuthenticationResponseJSON } from "./assertion.ts";

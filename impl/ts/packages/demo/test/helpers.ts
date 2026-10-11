// Shared test helpers for the demo package.
import type { AuthenticationResponseJSON, GetAssertion } from "@wake-protocol/client";
import type { SoftAuthenticator } from "@wake-protocol/server/testing";

// The test authenticator reports `type` as a plain string; WebAuthn always returns "public-key".
export function assertionFor(auth: SoftAuthenticator): GetAssertion {
  return async options => await auth.getAssertion(options) as AuthenticationResponseJSON;
}

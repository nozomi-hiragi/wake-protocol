// Spec §6.4, §7.5, §9.4: counter CAS before commit and replayable max update after commit.
import { WakeError } from "@wake-protocol/core";
import type { ServerOptions } from "../options.ts";
import type { SignCountUpdate } from "../store/types.ts";
import type { VerifiedAssertion } from "./verify.ts";

export async function prepareSignCountUpdate(
  verified: VerifiedAssertion,
  options: ServerOptions,
): Promise<{ accepted: boolean; update?: SignCountUpdate }> {
  const credential = verified.credential;
  if (!credential.backupEligible && verified.signCount > credential.signCount) {
    const accepted = await options.credentials.compareAndSetSignCount(
      credential.credentialId,
      credential.signCount,
      verified.signCount,
    );
    return { accepted };
  }
  return {
    accepted: true,
    update: {
      credentialId: credential.credentialId.slice(),
      userId: credential.userId,
      signCount: verified.signCount,
      storedSignCount: credential.signCount,
      anomaly: verified.counterAnomaly,
    },
  };
}

/** Clearing is atomic, so replay retries max updates and anomaly notification fires at most once. */
export async function applySignCountUpdate(
  update: SignCountUpdate,
  exchangeId: Uint8Array,
  options: ServerOptions,
): Promise<void> {
  await options.credentials.updateSignCount(update.credentialId, update.signCount);
  if (!await options.store.clearSignCountUpdate(exchangeId) || !update.anomaly) {
    return;
  }
  try {
    await options.onCounterAnomaly?.({
      credentialId: update.credentialId.slice(),
      userId: update.userId,
      storedSignCount: update.storedSignCount,
      receivedSignCount: update.signCount,
    });
  } catch {
    throw new WakeError("retry");
  }
}

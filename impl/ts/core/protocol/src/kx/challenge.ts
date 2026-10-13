// Spec §5.5: WebAuthn challenges.
import { Bytes, EMPTY } from "@wake-protocol/bytes";
import { sha256 } from "@wake-protocol/crypto";
import { LABELS } from "../spec/labels.ts";
import { labeled } from "../spec/domain.ts";
import {
  type LoginTranscriptHash,
  type RekeyTranscriptHash,
  type TaBindingHash,
  type WebAuthnChallenge,
  asWebAuthnChallenge,
} from "../spec/types.ts";

/**
 * §5.5 encoding only: LP(label, th, ta). Which of th / ta is ε is decided by
 * the ceremony-specific generators below, not here.
 */
export function encodeChallengeInput(th: Bytes, ta: Bytes): Bytes {
  return labeled(LABELS.webauthnChallenge, th, ta);
}

async function challenge(th: Bytes, ta: Bytes): Promise<WebAuthnChallenge> {
  return asWebAuthnChallenge(await sha256(encodeChallengeInput(th, ta).toUint8Array()));
}

/** KX: th only. */
export const kxChallenge = (th: LoginTranscriptHash): Promise<WebAuthnChallenge> => challenge(th, EMPTY);
/** KR: th only. */
export const krChallenge = (th: RekeyTranscriptHash): Promise<WebAuthnChallenge> => challenge(th, EMPTY);
/** TA: ta only. */
export const taChallenge = (ta: TaBindingHash): Promise<WebAuthnChallenge> => challenge(EMPTY, ta);
/** TA combined with KR: both. */
export const taKrChallenge = (th: RekeyTranscriptHash, ta: TaBindingHash): Promise<WebAuthnChallenge> =>
  challenge(th, ta);

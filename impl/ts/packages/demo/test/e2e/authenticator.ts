// CDP virtual authenticators are per page. A new page copies credentials from the page that registered.
import type { CDPSession, Page } from "@playwright/test";

export interface VirtualAuthenticator {
  cdp: CDPSession;
  authenticatorId: string;
}

export async function addVirtualAuthenticator(page: Page): Promise<VirtualAuthenticator> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  return { cdp, authenticatorId };
}

/** Copies resident credentials onto another page's authenticator (same user, new CDP session). */
export async function copyCredentials(from: VirtualAuthenticator, to: VirtualAuthenticator): Promise<void> {
  const { credentials } = await from.cdp.send("WebAuthn.getCredentials", { authenticatorId: from.authenticatorId });
  if (credentials.length === 0) {
    throw new Error("virtual authenticator has no credential to copy");
  }
  for (const credential of credentials) {
    await to.cdp.send("WebAuthn.addCredential", {
      authenticatorId: to.authenticatorId,
      credential: { ...credential, rpId: credential.rpId ?? "localhost" },
    });
  }
}

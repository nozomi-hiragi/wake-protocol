// Spec §6.1, §7.7: browser WebAuthn assertion adapter.
import { base64urlnopad } from "@scure/base";
import { decodeBinary } from "./json.ts";

export interface GetAssertionOptions {
  challenge: Uint8Array;
  rpId: string;
  allowCredentials: {
    type: "public-key";
    id: string;
    transports?: string[];
  }[];
  userVerification: "required";
  timeout: number;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: "public-key";
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
  };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: string | null;
}

export type GetAssertion = (options: GetAssertionOptions) => Promise<AuthenticationResponseJSON>;

/** Uses WebAuthn Level 3 toJSON when available, with an ArrayBuffer fallback. */
export const navigatorGetAssertion: GetAssertion = async (options) => {
  const credential = await globalThis.navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: new Uint8Array(options.challenge),
      allowCredentials: options.allowCredentials.map((c) => ({
        type: c.type,
        id: new Uint8Array(decodeBinary(c.id)),
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
    },
  });
  if (!credential || credential.type !== "public-key") {
    throw new TypeError("No public-key assertion returned");
  }
  const publicKey = credential as PublicKeyCredential;
  if (typeof publicKey.toJSON === "function") {
    return publicKey.toJSON() as AuthenticationResponseJSON;
  }
  const response = publicKey.response as AuthenticatorAssertionResponse;
  const encode = (buffer: ArrayBuffer) => base64urlnopad.encode(new Uint8Array(buffer));
  return {
    id: publicKey.id,
    rawId: encode(publicKey.rawId),
    type: "public-key",
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
      userHandle: response.userHandle === null ? null : encode(response.userHandle),
    },
    clientExtensionResults: publicKey.getClientExtensionResults() as Record<string, unknown>,
    authenticatorAttachment: publicKey.authenticatorAttachment,
  };
};

// Test-only software WebAuthn authenticator (spec §6.1–§6.4).
import { base64urlnopad } from "@scure/base";
import { utf8ToBytes } from "@wake-protocol/codec";
import { ecdsaRawToDer, randomBytes, sha256 } from "@wake-protocol/crypto";
import type { WakeCredential } from "./store/types.ts";

export interface GetAssertionOptions {
  challenge: Uint8Array;
  rpId: string;
  allowCredentials: readonly { type: "public-key"; id: string; transports?: readonly string[]; }[];
  userVerification: "required";
  timeout: number;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
  };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: "platform";
}

export interface AssertionTamper {
  type?: string;
  clientDataType?: string;
  origin?: string;
  crossOrigin?: unknown;
  topOrigin?: unknown;
  challenge?: Uint8Array | string;
  rpId?: string;
  rpIdHash?: Uint8Array;
  flags?: number;
  setFlags?: number;
  clearFlags?: number;
  extraAuthData?: Uint8Array;
  authenticatorData?: Uint8Array;
  signCount?: number;
  counter?: "fixed";
  userHandle?: Uint8Array | "omit" | null;
  credentialId?: Uint8Array | string;
  rawId?: Uint8Array | string;
  corruptSignature?: boolean;
  signatureDer?: "non-minimal" | "trailing" | "wrong-tag" | "negative" | "long-form";
  signature?: Uint8Array;
  clientDataJSON?: Uint8Array | string;
}

export interface SoftAuthenticatorInit {
  rpId: string;
  origin: string;
  userId: string;
  userHandle?: Uint8Array;
  backupEligible?: boolean;
  signCount?: number;
  credentialIdLength?: number;
}

function encoded(value: Uint8Array | string): string {
  return typeof value === "string" ? value : base64urlnopad.encode(value);
}

function malformedDer(der: Uint8Array, variant: NonNullable<AssertionTamper["signatureDer"]>): Uint8Array {
  switch (variant) {
    case "trailing":
      return new Uint8Array([...der, 0]);
    case "wrong-tag": {
      const result = der.slice();
      result[0] = 0x31;
      return result;
    }
    case "long-form":
      return new Uint8Array([0x30, 0x81, der[1]!, ...der.slice(2)]);
    case "non-minimal":
      return new Uint8Array([0x30, der[1]! + 1, 0x02, der[3]! + 1, 0, ...der.slice(4)]);
    case "negative": {
      const integer = der[4] === 0 ? 2 : 4 + der[3]!;
      const result = new Uint8Array([...der.slice(0, integer + 2), ...der.slice(integer + 3)]);
      result[1] = result[1]! - 1;
      result[integer + 1] = result[integer + 1]! - 1;
      return result;
    }
  }
}

export class SoftAuthenticator {
  readonly credential: WakeCredential;
  signCount: number;
  readonly #privateKey: CryptoKey;
  readonly #rpId: string;
  readonly #origin: string;

  private constructor(init: SoftAuthenticatorInit, privateKey: CryptoKey, publicKey: Uint8Array) {
    this.#privateKey = privateKey;
    this.#rpId = init.rpId;
    this.#origin = init.origin;
    this.signCount = init.signCount ?? 0;
    this.credential = {
      credentialId: randomBytes(init.credentialIdLength ?? 32),
      userId: init.userId,
      userHandle: init.userHandle?.slice() ?? randomBytes(32),
      publicKey,
      algorithm: -7,
      signCount: this.signCount,
      backupEligible: init.backupEligible ?? false,
      status: "active",
      transports: ["internal", "hybrid"],
    };
  }

  static async create(init: SoftAuthenticatorInit): Promise<SoftAuthenticator> {
    const count = init.signCount ?? 0;
    const length = init.credentialIdLength ?? 32;
    if (!Number.isInteger(count) || count < 0 || count > 0xffffffff) {
      throw new RangeError("invalid signCount");
    }
    if (!Number.isInteger(length) || length < 1 || length > 65536) {
      throw new RangeError("invalid credentialIdLength");
    }
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    return new SoftAuthenticator(init, pair.privateKey, publicKey);
  }

  async getAssertion(options: GetAssertionOptions, tamper: AssertionTamper = {}): Promise<AuthenticationResponseJSON> {
    const id = base64urlnopad.encode(this.credential.credentialId);
    if (options.rpId !== this.#rpId ||
      (options.allowCredentials.length > 0 && !options.allowCredentials.some(item => item.type === "public-key" && item.id === id))) {
      const error = new Error("credential is not allowed");
      error.name = "NotAllowedError";
      throw error;
    }
    if (tamper.counter !== "fixed") {
      this.signCount++;
    }
    const count = tamper.signCount ?? this.signCount;
    if (!Number.isInteger(count) || count < 0 || count > 0xffffffff) {
      throw new RangeError("invalid signCount");
    }
    const data: Record<string, unknown> = {
      type: tamper.clientDataType ?? "webauthn.get",
      challenge: encoded(tamper.challenge ?? options.challenge),
      origin: tamper.origin ?? this.#origin,
    };
    if ("crossOrigin" in tamper) {
      data.crossOrigin = tamper.crossOrigin;
    }
    if ("topOrigin" in tamper) {
      data.topOrigin = tamper.topOrigin;
    }
    const clientData = typeof tamper.clientDataJSON === "string"
      ? utf8ToBytes(tamper.clientDataJSON)
      : tamper.clientDataJSON?.slice() ?? utf8ToBytes(JSON.stringify(data));
    const rpHash = tamper.rpIdHash ?? await sha256(utf8ToBytes(tamper.rpId ?? this.#rpId));
    const authData = new Uint8Array(37 + (tamper.extraAuthData?.length ?? 0));
    authData.set(rpHash.subarray(0, 32));
    authData[32] = (
      (tamper.flags ?? (0x05 | (this.credential.backupEligible ? 0x08 : 0)))
      | (tamper.setFlags ?? 0)
    ) & ~(tamper.clearFlags ?? 0);
    new DataView(authData.buffer).setUint32(33, count, false);
    if (tamper.extraAuthData) {
      authData.set(tamper.extraAuthData, 37);
    }
    const receivedAuthData = tamper.authenticatorData?.slice() ?? authData;
    const signed = new Uint8Array(receivedAuthData.length + 32);
    signed.set(receivedAuthData);
    signed.set(await sha256(clientData), receivedAuthData.length);
    let signature: Uint8Array;
    do {
      const rawSignature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.#privateKey, signed));
      signature = tamper.signature?.slice() ?? ecdsaRawToDer(rawSignature);
    } while (!tamper.signature && (
      (tamper.signatureDer === "negative" && signature[4] !== 0 && signature[6 + signature[3]!] !== 0)
      || (tamper.signatureDer === "non-minimal" && signature[4] === 0)
    ));
    if (tamper.signatureDer) {
      signature = malformedDer(signature, tamper.signatureDer);
    }
    if (tamper.corruptSignature) {
      signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    }
    const response: AuthenticationResponseJSON["response"] = {
      clientDataJSON: base64urlnopad.encode(clientData),
      authenticatorData: base64urlnopad.encode(receivedAuthData),
      signature: base64urlnopad.encode(signature),
    };
    if (tamper.userHandle !== "omit") {
      response.userHandle = tamper.userHandle === null ?
        null :
        base64urlnopad.encode(tamper.userHandle ?? this.credential.userHandle);
    }
    return {
      id: encoded(tamper.credentialId ?? id),
      rawId: encoded(tamper.rawId ?? id),
      type: tamper.type ?? "public-key",
      response,
      clientExtensionResults: {},
      authenticatorAttachment: "platform"
    };
  }
}
